import { createClient } from "https://esm.sh/@supabase/supabase-js@2.105.1";

type StraicoModelSettings = {
  documentAnalysis: string;
  productResearch: string;
  chat: string;
  ragChat: string;
  dataRedactionMode: "strict" | "balanced";
};

type StraicoChoice = {
  message?: {
    content?: string;
  };
};

type StraicoCompletionPayload = {
  data?: {
    completion?: {
      choices?: StraicoChoice[];
    };
    completions?: Record<
      string,
      {
        completion?: {
          choices?: StraicoChoice[];
        };
      }
    >;
  };
};

type StraicoModelOption = {
  id: string;
  name: string;
  provider?: string;
  description?: string;
  features: string[];
  costLabel: string;
  inputCoinsPer100Words?: number;
  outputCoinsPer100Words?: number;
  maxCoinsPerMessage?: number;
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const DEFAULT_MODELS: StraicoModelSettings = {
  documentAnalysis: "google/gemini-2.0-flash-001",
  productResearch: "openai/gpt-4o-mini",
  chat: "openai/gpt-4o-mini",
  ragChat: "openai/gpt-4o-mini",
  dataRedactionMode: "strict",
};

const FALLBACK_MODEL_OPTIONS: StraicoModelOption[] = [
  {
    id: "google/gemini-2.0-flash-001",
    name: "Gemini 2.0 Flash",
    provider: "google",
    description: "Vision e documenti, consigliato per scontrini, foto e PDF.",
    features: ["image_input", "vision", "documents"],
    costLabel: "Costo da catalogo Straico live non disponibile",
  },
  {
    id: "openai/gpt-4o-mini",
    name: "GPT-4o mini",
    provider: "openai",
    description: "Chat, RAG e arricchimento prodotti leggero.",
    features: ["chat", "vision"],
    costLabel: "Costo da catalogo Straico live non disponibile",
  },
];

const STRAICO_BASE_URL = "https://api.straico.com";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });

const requireEnv = (key: string) => {
  const value = Deno.env.get(key);
  if (!value) throw new Error(`${key} non configurata`);
  return value;
};

const firstBalancedJsonObject = (content: string) => {
  const start = content.indexOf("{");
  if (start < 0) return "";

  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let index = start; index < content.length; index += 1) {
    const char = content[index];

    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === "\\") {
      escaped = inString;
      continue;
    }

    if (char === '"') {
      inString = !inString;
      continue;
    }

    if (inString) continue;
    if (char === "{") depth += 1;
    if (char === "}") depth -= 1;
    if (depth === 0) return content.slice(start, index + 1);
  }

  return "";
};

const extractJson = <T>(content: string, fallback: T): T => {
  const candidates = [
    content.trim(),
    content.match(/```(?:json)?\s*([\s\S]*?)```/i)?.[1]?.trim() || "",
    firstBalancedJsonObject(content),
  ].filter(Boolean);

  try {
    for (const candidate of candidates) {
      try {
        return JSON.parse(candidate) as T;
      } catch {
        // Try the next candidate: providers often wrap JSON in prose or markdown fences.
      }
    }
    return fallback;
  } catch {
    return fallback;
  }
};

const getSupabase = () =>
  createClient(requireEnv("SUPABASE_URL"), requireEnv("SUPABASE_SERVICE_ROLE_KEY"), {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

const getRequestSupabase = (authorization: string) =>
  createClient(requireEnv("SUPABASE_URL"), requireEnv("SUPABASE_ANON_KEY"), {
    global: {
      headers: {
        Authorization: authorization,
      },
    },
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

const getPublicSupabaseUrl = (fallback?: string) =>
  (
    Deno.env.get("SUPABASE_PUBLIC_URL") ||
    Deno.env.get("API_EXTERNAL_URL") ||
    fallback ||
    "https://pfdb.evolvemarketing.cloud"
  ).replace(/\/$/, "");

const serviceRoleRest = async <T>(
  publicSupabaseUrl: string | undefined,
  path: string,
  init: RequestInit,
): Promise<{ data: T | null; error: string | null }> => {
  try {
    const serviceKey = requireEnv("SUPABASE_SERVICE_ROLE_KEY");
    const response = await fetch(`${getPublicSupabaseUrl(publicSupabaseUrl)}/rest/v1/${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
        ...(init.headers || {}),
      },
    });
    const text = await response.text();
    const data = text ? (JSON.parse(text) as T) : null;
    if (!response.ok) return { data, error: JSON.stringify(data || text) };
    return { data, error: null };
  } catch (error) {
    return { data: null, error: logErrorMessage(error) };
  }
};

const assertUser = async (authorization: string | null) => {
  if (!authorization) throw new Error("Authorization mancante");
  const supabase = getSupabase();
  const token = authorization.replace(/^Bearer\s+/i, "");
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) throw new Error("Sessione non valida");
  return data.user;
};

const assertSuperAdmin = (user: { app_metadata?: Record<string, unknown> }) => {
  if (!user.app_metadata?.is_super_admin) throw new Error("superadmin required");
};

const LOG_SECRET_KEY_PATTERN = /(authorization|bearer|token|secret|password|api[_-]?key|apikey|service[_-]?role)/i;
const MAX_LOG_STRING_LENGTH = 1800;
const MAX_LOG_ARRAY_ITEMS = 12;
const MAX_LOG_OBJECT_KEYS = 80;

const sanitizeLogValue = (value: unknown, depth = 0): unknown => {
  if (value === null || value === undefined) return value;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.startsWith("data:")) return `[data-url ${value.slice(0, 32)}...]`;
    if (value.length > MAX_LOG_STRING_LENGTH) return `${value.slice(0, MAX_LOG_STRING_LENGTH)}...[truncated]`;
    try {
      const url = new URL(value);
      for (const key of Array.from(url.searchParams.keys())) {
        if (LOG_SECRET_KEY_PATTERN.test(key)) url.searchParams.set(key, "[redacted]");
      }
      return url.toString();
    } catch {
      return value;
    }
  }
  if (Array.isArray(value)) {
    if (depth > 4) return `[array ${value.length}]`;
    return value.slice(0, MAX_LOG_ARRAY_ITEMS).map((item) => sanitizeLogValue(item, depth + 1));
  }
  if (typeof value === "object") {
    if (depth > 4) return "[object]";
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .slice(0, MAX_LOG_OBJECT_KEYS)
        .map(([key, item]) => [
          key,
          LOG_SECRET_KEY_PATTERN.test(key) ? "[redacted]" : sanitizeLogValue(item, depth + 1),
        ]),
    );
  }
  return String(value);
};

const logErrorMessage = (error: unknown) => {
  if (error instanceof Error) return error.message;
  const record = error && typeof error === "object" ? (error as Record<string, unknown>) : null;
  if (typeof record?.message === "string") return record.message;
  if (typeof record?.error === "string") return record.error;
  return String(error || "Errore sconosciuto");
};

const missingSchemaColumnName = (error: unknown) => {
  const message = logErrorMessage(error);
  const quotedBeforeColumn = message.match(/['"]([a-zA-Z0-9_]+)['"]\s+column/i);
  if (quotedBeforeColumn?.[1]) return quotedBeforeColumn[1].toLowerCase();
  const afterColumn = message.match(/column\s+['"]?([a-zA-Z0-9_]+)['"]?/i);
  if (afterColumn?.[1]) return afterColumn[1].toLowerCase();
  const beforeSchemaCache = message.match(/([a-zA-Z0-9_]+)['"]?\s+in the schema cache/i);
  return beforeSchemaCache?.[1]?.toLowerCase() || null;
};

const isMissingSchemaColumnError = (error: unknown, column: string) => {
  const message = logErrorMessage(error).toLowerCase();
  const normalizedColumn = column.toLowerCase();
  const missingColumn = missingSchemaColumnName(error);
  if (missingColumn === normalizedColumn) return true;
  return (
    message.includes(`'${normalizedColumn}' column`) ||
    message.includes(`column '${normalizedColumn}'`) ||
    message.includes(`column "${normalizedColumn}"`) ||
    message.includes(`column ${normalizedColumn}`) ||
    message.includes(`${normalizedColumn}' in the schema cache`)
  );
};

type ProductEnrichmentEventLog = {
  step: string;
  provider?: string;
  status: "started" | "success" | "failed" | "skipped" | "rejected";
  durationMs?: number;
  request?: unknown;
  response?: unknown;
  error?: string;
};

type ProductEnrichmentLogger = (event: ProductEnrichmentEventLog) => Promise<void>;

const getUserHouseholdId = async (userId: string) => {
  try {
    const { data } = await getSupabase()
      .from("household_members")
      .select("household_id")
      .eq("user_id", userId)
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();
    return data?.household_id ? String(data.household_id) : null;
  } catch {
    return null;
  }
};

const createProductEnrichmentRun = async (input: {
  authorization: string;
  publicSupabaseUrl?: string;
  productId?: string;
  householdId?: string | null;
  userId: string;
  productName: string;
  merchantName?: string;
  category?: string;
  requestedBy?: string;
  modelProductResearch?: string;
  modelVision?: string;
  input: unknown;
}) => {
  const payload = {
    productId: input.productId,
    householdId: input.householdId || null,
    productName: input.productName,
    merchantName: input.merchantName,
    category: input.category,
    requestedBy: input.requestedBy || "catalog_ui",
    modelProductResearch: input.modelProductResearch,
    modelVision: input.modelVision,
    input: sanitizeLogValue(input.input),
  };

  try {
    const { data, error } = await getRequestSupabase(input.authorization).rpc("create_product_enrichment_run_log", {
      payload,
    });
    if (!error && data) return String(data);
    if (error) console.error("product_enrichment_run_rpc_failed", error.message);
  } catch (error) {
    console.error("product_enrichment_run_rpc_failed", logErrorMessage(error));
  }

  try {
    const { data, error } = await getSupabase()
      .from("product_enrichment_runs")
      .insert({
        product_id: input.productId,
        household_id: input.householdId || null,
        user_id: input.userId,
        product_name: input.productName,
        merchant_name: input.merchantName,
        category: input.category,
        requested_by: input.requestedBy || "catalog_ui",
        status: "started",
        model_product_research: input.modelProductResearch,
        model_vision: input.modelVision,
        input_json: payload.input,
      })
      .select("id")
      .single();
    if (!error && data?.id) return String(data.id);
    if (error) console.error("product_enrichment_run_direct_failed", error.message);
  } catch (error) {
    console.error("product_enrichment_run_direct_failed", logErrorMessage(error));
  }

  const { data: restData, error: restError } = await serviceRoleRest<Array<{ id?: string }>>(
    input.publicSupabaseUrl,
    "product_enrichment_runs?select=id",
    {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify({
        product_id: input.productId,
        household_id: input.householdId || null,
        user_id: input.userId,
        product_name: input.productName,
        merchant_name: input.merchantName,
        category: input.category,
        requested_by: input.requestedBy || "catalog_ui",
        status: "started",
        model_product_research: input.modelProductResearch,
        model_vision: input.modelVision,
        input_json: payload.input,
      }),
    },
  );
  if (restData?.[0]?.id) return String(restData[0].id);
  if (restError) console.error("product_enrichment_run_rest_failed", restError);

  return null;
};

const logProductEnrichmentEvent = async (
  authorization: string,
  publicSupabaseUrl: string | undefined,
  runId: string | null,
  event: ProductEnrichmentEventLog,
) => {
  if (!runId) return;
  const payload = {
    step: event.step,
    provider: event.provider,
    status: event.status,
    durationMs: event.durationMs,
    request: sanitizeLogValue(event.request || {}),
    response: sanitizeLogValue(event.response || {}),
    error: event.error,
  };

  try {
    const { error } = await getRequestSupabase(authorization).rpc("append_product_enrichment_event_log", {
      target_run_id: runId,
      payload,
    });
    if (!error) return;
    console.error("product_enrichment_event_rpc_failed", error.message);
  } catch (error) {
    console.error("product_enrichment_event_rpc_failed", logErrorMessage(error));
  }

  try {
    const { error } = await getSupabase().from("product_enrichment_events").insert({
      run_id: runId,
      step: event.step,
      provider: event.provider,
      status: event.status,
      duration_ms: event.durationMs,
      request_json: payload.request,
      response_json: payload.response,
      error_message: event.error,
    });
    if (!error) return;
    console.error("product_enrichment_event_direct_failed", error.message);
  } catch (error) {
    console.error("product_enrichment_event_direct_failed", logErrorMessage(error));
    // Diagnostics must never break the user-facing enrichment flow.
  }

  const { error: restError } = await serviceRoleRest(publicSupabaseUrl, "product_enrichment_events", {
    method: "POST",
    body: JSON.stringify({
      run_id: runId,
      step: event.step,
      provider: event.provider,
      status: event.status,
      duration_ms: event.durationMs,
      request_json: payload.request,
      response_json: payload.response,
      error_message: event.error,
    }),
  });
  if (restError) console.error("product_enrichment_event_rest_failed", restError);
};

const finishProductEnrichmentRun = async (
  authorization: string,
  publicSupabaseUrl: string | undefined,
  runId: string | null,
  patch: {
    status: "success" | "no_image" | "failed" | "guardrail_rejected";
    imageSaved?: boolean;
    imageUrl?: string | null;
    imageSearchStatus?: string | null;
    candidatesFound?: number;
    candidatesReviewed?: number;
    lastRejectReason?: string | null;
    durationMs?: number;
    output?: unknown;
  },
) => {
  if (!runId) return;
  const payload = {
    status: patch.status,
    imageSaved: Boolean(patch.imageSaved),
    imageUrl: patch.imageUrl || null,
    imageSearchStatus: patch.imageSearchStatus || null,
    candidatesFound: patch.candidatesFound || 0,
    candidatesReviewed: patch.candidatesReviewed || 0,
    lastRejectReason: patch.lastRejectReason || null,
    durationMs: patch.durationMs,
    output: sanitizeLogValue(patch.output || {}),
  };

  try {
    const { error } = await getRequestSupabase(authorization).rpc("finish_product_enrichment_run_log", {
      target_run_id: runId,
      payload,
    });
    if (!error) return;
    console.error("product_enrichment_finish_rpc_failed", error.message);
  } catch (error) {
    console.error("product_enrichment_finish_rpc_failed", logErrorMessage(error));
  }

  try {
    const { error } = await getSupabase()
      .from("product_enrichment_runs")
      .update({
        status: patch.status,
        image_saved: Boolean(patch.imageSaved),
        image_url: patch.imageUrl || null,
        image_search_status: patch.imageSearchStatus || null,
        candidates_found: patch.candidatesFound || 0,
        candidates_reviewed: patch.candidatesReviewed || 0,
        last_reject_reason: patch.lastRejectReason || null,
        duration_ms: patch.durationMs,
        output_json: payload.output,
        updated_at: new Date().toISOString(),
      })
      .eq("id", runId);
    if (!error) return;
    console.error("product_enrichment_finish_direct_failed", error.message);
  } catch (error) {
    console.error("product_enrichment_finish_direct_failed", logErrorMessage(error));
    // Best-effort audit trail.
  }

  const { error: restError } = await serviceRoleRest(
    publicSupabaseUrl,
    `product_enrichment_runs?id=eq.${encodeURIComponent(runId)}`,
    {
      method: "PATCH",
      body: JSON.stringify({
        status: patch.status,
        image_saved: Boolean(patch.imageSaved),
        image_url: patch.imageUrl || null,
        image_search_status: patch.imageSearchStatus || null,
        candidates_found: patch.candidatesFound || 0,
        candidates_reviewed: patch.candidatesReviewed || 0,
        last_reject_reason: patch.lastRejectReason || null,
        duration_ms: patch.durationMs,
        output_json: payload.output,
        updated_at: new Date().toISOString(),
      }),
    },
  );
  if (restError) console.error("product_enrichment_finish_rest_failed", restError);
};

const getModelSettings = async (): Promise<StraicoModelSettings> => {
  const supabase = getSupabase();
  const { data } = await supabase
    .from("app_settings")
    .select("value_json")
    .eq("key", "straico_models")
    .maybeSingle();

  return { ...DEFAULT_MODELS, ...((data?.value_json as Partial<StraicoModelSettings> | null) || {}) };
};

type StraicoUsageContext = {
  activity: string;
  userId?: string;
  userEmail?: string;
  householdId?: string | null;
  productEnrichmentRunId?: string | null;
  model?: string;
};

const localRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" ? (value as Record<string, unknown>) : {};

const wordCount = (value: string) => value.trim().split(/\s+/).filter(Boolean).length;

const textFromStraicoPayload = (payload: unknown, model?: string) => {
  const data = localRecord(localRecord(payload).data);
  const direct = localRecord(data.completion);
  const directText = String(localRecord(localRecord((direct.choices as unknown[])?.[0]).message).content || "");
  if (directText) return directText;
  const completions = localRecord(data.completions);
  const selectedCompletion = model ? localRecord(completions[model]) : localRecord(Object.values(completions)[0]);
  return String(localRecord(localRecord((localRecord(selectedCompletion.completion).choices as unknown[])?.[0]).message).content || "");
};

const findStraicoCredits = (value: unknown, depth = 0): number | undefined => {
  if (depth > 5 || value === null || value === undefined) return undefined;
  if (typeof value !== "object") return undefined;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const normalizedKey = key.toLowerCase();
    const isCreditKey =
      /(coins?_used|credits?_used|total_coins?|total_credits?|overall_coins?|overall_credits?|coins?_spent|credits?_spent)/.test(normalizedKey);
    const number = Number(item);
    if (isCreditKey && Number.isFinite(number)) return number;
    const nested = findStraicoCredits(item, depth + 1);
    if (nested !== undefined) return nested;
  }
  return undefined;
};

const logStraicoUsage = async (input: {
  path: string;
  body: unknown;
  context?: StraicoUsageContext;
  status: "success" | "failed";
  durationMs: number;
  responsePayload?: unknown;
  errorMessage?: string;
}) => {
  if (!input.context?.activity) return;
  const body = localRecord(input.body);
  const model = input.context.model || String(body.model || (Array.isArray(body.models) ? body.models[0] : "") || body.smart_llm_selector || "");
  const message = String(body.message || "");
  const output = input.responsePayload ? textFromStraicoPayload(input.responsePayload, model) : "";
  const actualCredits = input.responsePayload ? findStraicoCredits(input.responsePayload) : undefined;
  try {
    const { error } = await getSupabase().from("straico_usage_events").insert({
      user_id: input.context.userId,
      user_email: input.context.userEmail,
      household_id: input.context.householdId || null,
      product_enrichment_run_id: input.context.productEnrichmentRunId || null,
      activity: input.context.activity,
      endpoint: input.path,
      model,
      status: input.status,
      input_chars: message.length,
      output_chars: output.length,
      input_words: wordCount(message),
      output_words: wordCount(output),
      actual_total_credits: actualCredits,
      duration_ms: input.durationMs,
      request_json: sanitizeLogValue({
        model,
        endpoint: input.path,
        smart: body.smart_llm_selector,
        inputChars: message.length,
        images: Array.isArray(body.images) ? body.images.length : 0,
        fileUrls: Array.isArray(body.file_urls) ? body.file_urls.length : 0,
      }),
      response_json: sanitizeLogValue({
        outputChars: output.length,
        actualCredits,
      }),
      error_message: input.errorMessage,
    });
    if (error) console.error("straico_usage_insert_failed", error.message);
  } catch (error) {
    console.error("straico_usage_insert_failed", logErrorMessage(error));
  }
};

const postStraico = async (path: string, body: unknown, context?: StraicoUsageContext) => {
  const startedAt = performance.now();
  let response: Response;
  try {
    response = await fetch(`${STRAICO_BASE_URL}${path}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${requireEnv("STRAICO_API_KEY")}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  } catch (error) {
    await logStraicoUsage({
      path,
      body,
      context,
      status: "failed",
      durationMs: Math.round(performance.now() - startedAt),
      errorMessage: logErrorMessage(error),
    });
    throw error;
  }

  if (!response.ok) {
    const payload = await response.text().catch(() => "");
    await logStraicoUsage({
      path,
      body,
      context,
      status: "failed",
      durationMs: Math.round(performance.now() - startedAt),
      errorMessage: payload || `Straico error ${response.status}`,
    });
    throw new Error(payload || `Straico error ${response.status}`);
  }

  const payload = await response.json() as StraicoCompletionPayload;
  await logStraicoUsage({
    path,
    body,
    context,
    status: "success",
    durationMs: Math.round(performance.now() - startedAt),
    responsePayload: payload,
  });
  return payload;
};

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" ? (value as Record<string, unknown>) : {};

const asStringArray = (value: unknown): string[] => {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item)).filter(Boolean);
};

const asOptionalNumber = (value: unknown) => {
  const number = Number(value);
  return Number.isFinite(number) ? number : undefined;
};

const getNestedNumber = (record: Record<string, unknown>, keys: string[]) => {
  for (const key of keys) {
    const value = key.split(".").reduce<unknown>((current, segment) => asRecord(current)[segment], record);
    const number = asOptionalNumber(value);
    if (number !== undefined) return number;
  }
  return undefined;
};

const toMillis = (value: unknown) => {
  const time = typeof value === "string" ? Date.parse(value) : Number(value);
  return Number.isFinite(time) ? time : 0;
};

const getExactCount = async (supabase: ReturnType<typeof getSupabase>, table: string) => {
  const { count, error } = await supabase.from(table).select("*", { count: "exact", head: true });
  if (error) throw new Error(`admin_count_${table}_failed: ${error.message}`);
  return count || 0;
};

const getExactCountExcludingStatus = async (
  supabase: ReturnType<typeof getSupabase>,
  table: string,
  excludedStatus: string,
) => {
  const { count, error } = await supabase
    .from(table)
    .select("*", { count: "exact", head: true })
    .neq("status", excludedStatus);
  if (error) throw new Error(`admin_count_${table}_failed: ${error.message}`);
  return count || 0;
};

const selectAdminRows = async <T>(
  supabase: ReturnType<typeof getSupabase>,
  table: string,
  columns: string,
): Promise<T[]> => {
  const { data, error } = await supabase.from(table).select(columns);
  if (error) throw new Error(`admin_select_${table}_failed: ${error.message}`);
  return (data || []) as T[];
};

const listAdminAuthUsers = async (supabase: ReturnType<typeof getSupabase>) => {
  const users: Array<{
    id: string;
    email?: string;
    created_at?: string;
    last_sign_in_at?: string;
    email_confirmed_at?: string;
    app_metadata?: Record<string, unknown>;
    user_metadata?: Record<string, unknown>;
  }> = [];

  for (let page = 1; page <= 10; page += 1) {
    const { data, error } = await supabase.auth.admin.listUsers({ page, perPage: 200 });
    if (error) throw new Error(`admin_auth_users_failed: ${error.message}`);
    const batch = data.users || [];
    users.push(...batch);
    if (batch.length < 200) break;
  }

  return users;
};

const getAdminPlatformOverview = async () => {
  const supabase = getSupabase();
  const [
    authUsers,
    householdsCount,
    transactionsCount,
    documentsCount,
    productsCount,
    profiles,
    households,
    memberships,
    transactionRefs,
    documentRefs,
  ] = await Promise.all([
    listAdminAuthUsers(supabase),
    getExactCount(supabase, "households"),
    getExactCountExcludingStatus(supabase, "transactions", "deleted"),
    getExactCountExcludingStatus(supabase, "documents", "rejected"),
    getExactCount(supabase, "products"),
    selectAdminRows<{ user_id: string; display_name?: string; created_at?: string }>(
      supabase,
      "user_profiles",
      "user_id,display_name,created_at",
    ),
    selectAdminRows<{ id: string; name: string; created_by?: string; created_at?: string }>(
      supabase,
      "households",
      "id,name,created_by,created_at",
    ),
    selectAdminRows<{ household_id: string; user_id: string; role?: string; created_at?: string }>(
      supabase,
      "household_members",
      "household_id,user_id,role,created_at",
    ),
    selectAdminRows<{ household_id: string; status?: string }>(supabase, "transactions", "household_id,status"),
    selectAdminRows<{ household_id: string; status?: string }>(supabase, "documents", "household_id,status"),
  ]);

  const profileByUserId = new Map(profiles.map((profile) => [profile.user_id, profile]));
  const householdById = new Map(households.map((household) => [household.id, household]));
  const authUserById = new Map(authUsers.map((authUser) => [authUser.id, authUser]));
  const firstMembershipByUserId = new Map<string, { household_id: string; role?: string; created_at?: string }>();
  const membersCountByHouseholdId = new Map<string, number>();

  memberships.forEach((membership) => {
    membersCountByHouseholdId.set(
      membership.household_id,
      (membersCountByHouseholdId.get(membership.household_id) || 0) + 1,
    );
    const current = firstMembershipByUserId.get(membership.user_id);
    if (!current || toMillis(membership.created_at) < toMillis(current.created_at)) {
      firstMembershipByUserId.set(membership.user_id, membership);
    }
  });

  const transactionsCountByHouseholdId = new Map<string, number>();
  transactionRefs.forEach((transaction) => {
    if (transaction.status === "deleted") return;
    transactionsCountByHouseholdId.set(
      transaction.household_id,
      (transactionsCountByHouseholdId.get(transaction.household_id) || 0) + 1,
    );
  });

  const documentsCountByHouseholdId = new Map<string, number>();
  documentRefs.forEach((document) => {
    if (document.status === "rejected") return;
    documentsCountByHouseholdId.set(
      document.household_id,
      (documentsCountByHouseholdId.get(document.household_id) || 0) + 1,
    );
  });

  const users = authUsers
    .map((authUser) => {
      const profile = profileByUserId.get(authUser.id);
      const metadata = asRecord(authUser.user_metadata || {});
      const membership = firstMembershipByUserId.get(authUser.id);
      const household = membership ? householdById.get(membership.household_id) : undefined;
      const email = authUser.email || "";
      return {
        id: authUser.id,
        email: email || "Email non disponibile",
        name:
          asStringValue(profile?.display_name) ||
          asStringValue(metadata.name) ||
          asStringValue(metadata.full_name) ||
          email.split("@")[0] ||
          "Utente",
        isSuperAdmin: Boolean(asRecord(authUser.app_metadata || {}).is_super_admin),
        householdId: household?.id,
        householdName: household?.name,
        role: membership?.role,
        createdAt: toMillis(authUser.created_at || profile?.created_at),
        lastSignInAt: authUser.last_sign_in_at ? toMillis(authUser.last_sign_in_at) : undefined,
        emailConfirmed: Boolean(authUser.email_confirmed_at),
      };
    })
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, 200);

  const householdSummaries = households
    .map((household) => {
      const owner = household.created_by ? authUserById.get(household.created_by) : undefined;
      const ownerProfile = household.created_by ? profileByUserId.get(household.created_by) : undefined;
      const ownerMetadata = asRecord(owner?.user_metadata || {});
      return {
        id: household.id,
        name: household.name || "Famiglia",
        ownerUserId: household.created_by,
        ownerEmail: owner?.email || undefined,
        ownerName:
          asStringValue(ownerProfile?.display_name) ||
          asStringValue(ownerMetadata.name) ||
          asStringValue(ownerMetadata.full_name) ||
          owner?.email?.split("@")[0] ||
          undefined,
        membersCount: membersCountByHouseholdId.get(household.id) || 0,
        transactionsCount: transactionsCountByHouseholdId.get(household.id) || 0,
        documentsCount: documentsCountByHouseholdId.get(household.id) || 0,
        createdAt: toMillis(household.created_at),
      };
    })
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, 200);

  return {
    counts: {
      users: authUsers.length,
      households: householdsCount,
      transactions: transactionsCount,
      documents: documentsCount,
      products: productsCount,
    },
    users,
    households: householdSummaries,
  };
};

const modelCostLabel = (input?: number, output?: number, max?: number, rawCost?: string) => {
  if (rawCost) return rawCost;
  const parts: string[] = [];
  if (input !== undefined) parts.push(`in ${input} coin/100 parole`);
  if (output !== undefined) parts.push(`out ${output} coin/100 parole`);
  if (max !== undefined) parts.push(`max ${max} coin/msg`);
  return parts.length ? parts.join(" · ") : "Costo non disponibile";
};

const normalizeModelOption = (raw: unknown): StraicoModelOption | null => {
  const record = asRecord(raw);
  const id = String(record.id || record.model || record.slug || record.api_name || record.name || "").trim();
  if (!id) return null;

  const pricing = asRecord(record.pricing || record.price || record.cost || record.costs);
  const input = getNestedNumber(record, [
    "inputCoinsPer100Words",
    "input_coins_per_100_words",
    "coins_per_100_words",
    "cost_per_100_words",
    "input_cost",
    "pricing.input",
    "price.input",
    "cost.input",
  ]) ?? getNestedNumber(pricing, ["input", "input_cost", "coins_per_100_words", "cost_per_100_words"]);
  const output = getNestedNumber(record, [
    "outputCoinsPer100Words",
    "output_coins_per_100_words",
    "output_cost",
    "pricing.output",
    "price.output",
    "cost.output",
  ]) ?? getNestedNumber(pricing, ["output", "output_cost"]);
  const max = getNestedNumber(record, [
    "maxCoinsPerMessage",
    "max_coins_per_message",
    "max_cost",
    "pricing.max",
    "price.max",
    "cost.max",
  ]) ?? getNestedNumber(pricing, ["max", "max_cost", "total"]);
  const rawCost = typeof record.costLabel === "string"
    ? record.costLabel
    : typeof record.cost_label === "string"
      ? record.cost_label
      : typeof record.pricing === "string"
        ? record.pricing
        : undefined;

  return {
    id,
    name: String(record.label || record.display_name || record.name || id),
    provider: record.provider ? String(record.provider) : id.includes("/") ? id.split("/")[0] : undefined,
    description: record.description ? String(record.description) : undefined,
    features: Array.from(new Set([
      ...asStringArray(record.features),
      ...asStringArray(record.capabilities),
    ])),
    inputCoinsPer100Words: input,
    outputCoinsPer100Words: output,
    maxCoinsPerMessage: max,
    costLabel: modelCostLabel(input, output, max, rawCost),
  };
};

const flattenModelsPayload = (payload: unknown): unknown[] => {
  if (Array.isArray(payload)) return payload;
  const record = asRecord(payload);
  const data = record.data;
  if (Array.isArray(data)) return data;
  const dataRecord = asRecord(data);
  for (const key of ["models", "chat", "llms", "items", "results"]) {
    const value = dataRecord[key] ?? record[key];
    if (Array.isArray(value)) return value;
  }
  return Object.values(dataRecord).flatMap((value) => (Array.isArray(value) ? value : []));
};

const fetchStraicoModels = async () => {
  try {
    const response = await fetch(`${STRAICO_BASE_URL}/v2/models`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${requireEnv("STRAICO_API_KEY")}`,
        Accept: "application/json",
      },
    });

    if (!response.ok) return FALLBACK_MODEL_OPTIONS;

    const payload = await response.json();
    const models = flattenModelsPayload(payload)
      .map(normalizeModelOption)
      .filter((model): model is StraicoModelOption => Boolean(model))
      .sort((a, b) => `${a.provider || ""} ${a.name}`.localeCompare(`${b.provider || ""} ${b.name}`));

    return models.length ? models : FALLBACK_MODEL_OPTIONS;
  } catch {
    return FALLBACK_MODEL_OPTIONS;
  }
};

const completionV0 = async (
  message: string,
  options: { model?: string; smart?: "quality" | "balance" | "budget" },
  usage?: StraicoUsageContext,
) => {
  const body = options.smart
    ? { smart_llm_selector: options.smart, message, temperature: 0.35, max_tokens: 2200, replace_failed_models: true }
    : { model: options.model || DEFAULT_MODELS.chat, message, temperature: 0.35, max_tokens: 2200, replace_failed_models: true };
  const data = await postStraico("/v0/prompt/completion", body, { ...usage, model: options.model || usage?.model || DEFAULT_MODELS.chat });
  return String(data?.data?.completion?.choices?.[0]?.message?.content || "");
};

const completionV1 = async (
  message: string,
  input: { model?: string; images?: string[]; fileUrls?: string[] },
  usage?: StraicoUsageContext,
) => {
  const model = input.model || DEFAULT_MODELS.documentAnalysis;
  const data = await postStraico("/v1/prompt/completion", {
    models: [model],
    message,
    images: input.images?.slice(0, 4),
    file_urls: input.fileUrls?.slice(0, 4),
    temperature: 0.2,
    max_tokens: 3000,
    replace_failed_models: true,
  }, { ...usage, model });
  return String(data?.data?.completions?.[model]?.completion?.choices?.[0]?.message?.content || "");
};

const fetchOpenFoodFactsCandidate = async (productName: string) => {
  const query = productName.replace(/\b(sconto|fidaty|fidati|punti|totale|iva|pos)\b/gi, "").trim();
  if (query.length < 3) return null;

  try {
    const url = new URL("https://world.openfoodfacts.org/cgi/search.pl");
    url.searchParams.set("search_terms", query);
    url.searchParams.set("search_simple", "1");
    url.searchParams.set("action", "process");
    url.searchParams.set("json", "1");
    url.searchParams.set("page_size", "5");
    url.searchParams.set("fields", "product_name,brands,categories,image_front_url,image_url,quantity");

    const response = await fetch(url.toString(), {
      headers: { Accept: "application/json", "User-Agent": "FinanceCompass/1.0 product-enrichment" },
    });
    if (!response.ok) return null;

    const payload = await response.json() as {
      products?: Array<{
        product_name?: string;
        brands?: string;
        categories?: string;
        image_front_url?: string;
        image_url?: string;
        quantity?: string;
      }>;
    };
    const candidate = payload.products?.find((product) => product.image_front_url || product.image_url);
    if (!candidate) return null;

    return {
      name: candidate.product_name,
      brand: candidate.brands?.split(",")[0]?.trim(),
      weight: candidate.quantity,
      imageUrl: candidate.image_front_url || candidate.image_url,
      merchantCategories: candidate.categories?.split(",").slice(0, 6).map((item) => item.trim()).filter(Boolean),
      imageSource: "openfoodfacts",
      imageConfidence: 0.72,
    };
  } catch {
    return null;
  }
};

type ProductImageCandidate = {
  externalRefId?: string;
  name?: string;
  brand?: string;
  weight?: string;
  imageUrl: string;
  imageSource: string;
  imageSourceUrl?: string;
  merchantCategories?: string[];
  contextText?: string;
  imageConfidence: number;
};

type ProductImageVisionReview = {
  accepted: boolean;
  confidence: number;
  reason?: string;
};

const asStringValue = (value: unknown) => (typeof value === "string" ? value.trim() : "");

const asBooleanValue = (value: unknown) => value === true || (typeof value === "string" && value.toLowerCase() === "true");

const normalizeSearchTerm = (value: string) =>
  value
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();

const nonProductReceiptLinePattern =
  /\b(sconto|sconti|fidaty|fidati|punti|totale|subtotale|iva|pagamento|pos|resto|buono|coupon|promozione|risparmio|lotteria)\b/i;

const industrialHallucinationPattern =
  /\b(automazione|industriale|interruttore|protezione|guardmaster|rockwell|allen bradley|siemens|schneider|sensore|plc|contattore|motore)\b/i;

const safeSearchName = (value: string) =>
  value
    .replace(nonProductReceiptLinePattern, " ")
    .replace(/\s+/g, " ")
    .trim();

const isUnsafeGroceryEnrichment = (
  rawName: string,
  currentCategory: string | undefined,
  product: Record<string, unknown>,
) => {
  const proposedText = [
    product.name,
    product.category,
    product.subcategory,
    product.brand,
    product.notes,
    ...(Array.isArray(product.merchantCategories) ? product.merchantCategories : []),
  ]
    .map(asStringValue)
    .filter(Boolean)
    .join(" ");
  const sourceLooksGrocery =
    /(alimentari|alimentazione|spesa|supermercato|frutta|verdura|pane|pasta|carne|pesce|bevande|igiene|animali|pet|cane|gatto|ultima|gourmet|friskies|frsk|revelations|nutri|esselunga|coop|conad|carrefour|lidl|eurospin)/i.test(
      `${rawName} ${currentCategory || ""}`,
    );
  return sourceLooksGrocery && industrialHallucinationPattern.test(proposedText);
};

const keepOnlySafeProductResearch = (
  rawName: string,
  currentCategory: string | undefined,
  product: Record<string, unknown>,
) => {
  const unsafe = isUnsafeGroceryEnrichment(rawName, currentCategory, product);
  const aliases = Array.isArray(product.aliases)
    ? product.aliases.map(asStringValue).filter((alias) => alias && !industrialHallucinationPattern.test(alias))
    : [];

  product.name = rawName;
  if (currentCategory) product.category = currentCategory;
  product.aliases = Array.from(new Set([rawName, ...aliases]));

  if (unsafe) {
    delete product.subcategory;
    delete product.brand;
    delete product.weight;
    delete product.unit;
    product.confidence = Math.min(asOptionalNumber(product.confidence) ?? 0.5, 0.45);
    product.enrichmentSource = "guardrail_rejected_ai_enrichment";
    product.notes = "Arricchimento AI scartato: proposta incompatibile con una riga scontrino GDO.";
    product.merchantCategories = [currentCategory || "Alimentari"];
  }

  return { product, unsafe };
};

const officialSupermarketCatalogSources = [
  { key: "esselunga", tokens: ["esselunga", "s lunga", "slunga"], domains: ["spesaonline.esselunga.it", "esselunga.it"] },
  { key: "coop", tokens: ["coop"], domains: ["easycoop.com", "coopshop.it", "coop.it"] },
  { key: "conad", tokens: ["conad"], domains: ["spesaonline.conad.it", "conad.it"] },
  { key: "carrefour", tokens: ["carrefour"], domains: ["carrefour.it"] },
  { key: "bennet", tokens: ["bennet"], domains: ["bennet.com"] },
  { key: "eurospin", tokens: ["eurospin"], domains: ["eurospin.it"] },
  { key: "lidl", tokens: ["lidl"], domains: ["lidl.it"] },
  { key: "aldi", tokens: ["aldi"], domains: ["aldi.it"] },
  { key: "md", tokens: ["md", "md spa"], domains: ["mdspa.it"] },
  { key: "dm", tokens: ["dm", "dm drogerie"], domains: ["dm-drogeriemarkt.it"] },
];

const officialCatalogSourceForMerchant = (merchantName?: string) => {
  const normalizedMerchant = normalizeSearchTerm(merchantName || "");
  if (!normalizedMerchant) return undefined;
  const merchantTokens = normalizedMerchant.split(" ").filter(Boolean);
  return officialSupermarketCatalogSources
    .find((source) =>
      source.tokens.some((token) => {
        const normalizedToken = normalizeSearchTerm(token);
        return normalizedToken.length <= 2
          ? merchantTokens.includes(normalizedToken)
          : normalizedMerchant.includes(normalizedToken);
      }),
    );
};

const officialDomainsForMerchant = (merchantName?: string) => {
  const source = officialCatalogSourceForMerchant(merchantName);
  return source?.domains || [];
};

const upsertReceiptMatchIndex = async (input: {
  householdId?: string | null;
  userId?: string;
  rawName: string;
  merchantName?: string;
  canonicalName: string;
  brand?: string;
  category?: string;
  productId?: string;
  externalRefId?: string;
  confidence: number;
  matchSource: string;
}) => {
  const source = officialCatalogSourceForMerchant(input.merchantName);
  if (!source || !input.householdId || !input.rawName.trim() || !input.canonicalName.trim()) return;
  try {
    const { error } = await getSupabase().from("product_receipt_match_index").upsert({
      household_id: input.householdId,
      merchant_key: source.key,
      merchant_name: input.merchantName,
      raw_name: input.rawName,
      raw_normalized_name: normalizeSearchTerm(input.rawName),
      canonical_name: input.canonicalName,
      brand: input.brand || null,
      category: input.category || null,
      product_id: input.productId || null,
      external_ref_id: input.externalRefId || null,
      confidence: Math.max(0, Math.min(1, input.confidence)),
      match_source: input.matchSource,
      match_count: 1,
      last_matched_at: new Date().toISOString(),
      updated_by: input.userId || null,
    }, { onConflict: "household_id,merchant_key,raw_normalized_name" });
    if (error) console.error("receipt_match_index_upsert_failed", error.message);
  } catch (error) {
    console.error("receipt_match_index_upsert_failed", logErrorMessage(error));
  }
};

const isOfficialMerchantCatalogUrl = (value: string, merchantName?: string) => {
  const normalizedValue = normalizeSearchTerm(value);
  return officialDomainsForMerchant(merchantName).some((domain) => normalizedValue.includes(normalizeSearchTerm(domain)));
};

const productImageSearchQueries = (input: { rawName: string; product: Record<string, unknown>; merchantName?: string }) => {
  const rawName = safeSearchName(asStringValue(input.rawName));
  const merchantName = safeSearchName(asStringValue(input.merchantName));
  const brand = asStringValue(input.product.brand);
  const weight = asStringValue(input.product.weight);
  const officialDomains = officialDomainsForMerchant(merchantName);
  const normalizedRaw = normalizeSearchTerm(rawName);
  const brandIsGrounded = Boolean(brand && normalizedRaw.includes(normalizeSearchTerm(brand)));
  const safeWeight = /^[\d.,]+\s?(g|gr|kg|ml|l|cl|pz|x\s?\d+)$/i.test(weight) ? weight : "";
  const base = [brandIsGrounded ? brand : "", rawName, safeWeight].filter(Boolean).join(" ").replace(/\s+/g, " ").trim();
  const freshProduceExclusions =
    isFreshProduceProductName(rawName)
      ? "-yogurt -muller -kefir -confettura -marmellata -succo -nettare -frullato -dessert -cheesecake -crostata -gelato -mousse"
      : "";
  const freshProduceQueries = isFreshProduceProductName(rawName)
    ? [
        ...officialDomains.slice(0, 2).map((domain) => `site:${domain} ${base || rawName} frutta fresca vaschetta ${freshProduceExclusions}`),
        merchantName ? `${base || rawName} ${merchantName} frutta fresca vaschetta ${freshProduceExclusions}` : "",
        `${base || rawName} frutta fresca vaschetta confezione ${freshProduceExclusions}`,
      ]
    : [];
  const queries = [
    ...freshProduceQueries,
    ...officialDomains.slice(0, 2).map((domain) => `site:${domain} ${base || rawName}`),
    ...officialDomains.slice(0, 1).map((domain) => `${rawName} ${merchantName} site:${domain}`),
    merchantName ? `${base} ${merchantName} prodotto confezione sfondo bianco` : "",
    `${base} prodotto confezione sfondo bianco`,
    `${base} immagine prodotto`,
    merchantName ? `${rawName} ${merchantName} prodotto supermercato` : `${rawName} prodotto supermercato`,
  ]
    .map((query) => query.replace(/\b(sconto|fidaty|fidati|punti|totale|iva|pos)\b/gi, "").replace(/\s+/g, " ").trim())
    .filter((query) => query.length >= 4);
  return Array.from(new Set(queries)).slice(0, 4);
};

const catalogTokenStopwords = new Set([
  "a",
  "al",
  "alla",
  "con",
  "da",
  "del",
  "dell",
  "della",
  "di",
  "e",
  "g",
  "gr",
  "il",
  "in",
  "la",
  "le",
  "l",
  "ml",
  "per",
  "pz",
  "x",
  "prodotto",
  "supermercato",
]);

const expandCatalogAbbreviations = (value: string, merchantKey?: string) => {
  let next = ` ${normalizeSearchTerm(value)} `;
  next = next
    .replace(/\bc\s+cola\b/g, " coca cola ")
    .replace(/\blat\b/g, " lattina ")
    .replace(/\blatt\b/g, " lattina ")
    .replace(/\b(\d{2,4})x(\d{1,3})\b/g, " $1 $2 ")
    .replace(/\bsg\b/g, " sgusciate ")
    .replace(/\bnat\b/g, " naturale ")
    .replace(/\bfriz\b/g, " frizzante ")
    .replace(/\b6bt\b/g, " 6 bottiglie ")
    .replace(/\bbt\b/g, " bottiglie ");
  if (merchantKey === "esselunga") next = next.replace(/\bsl\b/g, " esselunga ");
  return normalizeSearchTerm(next);
};

const catalogTokens = (value: string, merchantKey?: string) =>
  expandCatalogAbbreviations(value, merchantKey)
    .split(" ")
    .filter((token) => token.length >= 2 && !catalogTokenStopwords.has(token) && !/^\d+$/.test(token));

const officialCatalogSearchPhrases = (rawName: string, product: Record<string, unknown>, merchantKey?: string) => {
  const aliases = Array.isArray(product.aliases) ? product.aliases.map(asStringValue) : [];
  const brand = asStringValue(product.brand);
  const productName = asStringValue(product.name);
  const phrases = [
    rawName,
    productName,
    ...aliases,
    brand ? `${brand} ${rawName}` : "",
    brand && productName ? `${brand} ${productName}` : "",
  ]
    .map(safeSearchName)
    .filter((value) => value.length >= 3);
  return Array.from(new Set(phrases.map((value) => expandCatalogAbbreviations(value, merchantKey)).filter(Boolean))).slice(0, 12);
};

const officialCatalogSearchTokens = (rawName: string, product: Record<string, unknown>, merchantKey?: string) => {
  const tokens = officialCatalogSearchPhrases(rawName, product, merchantKey)
    .flatMap((phrase) => catalogTokens(phrase, merchantKey))
    .filter((token) => token !== merchantKey && token.length >= 3);
  return Array.from(new Set(tokens)).slice(0, 8);
};

const scoreOfficialCatalogRef = (productName: string, ref: Record<string, unknown>, merchantKey?: string) => {
  const inputTokens = catalogTokens(productName, merchantKey)
    .filter((token) => token !== merchantKey && token.length >= 3);
  const candidateText = [
    ref.source_name,
    ref.source_normalized_name,
    ref.source_description,
    ref.source_brand,
    ref.source_weight,
    ref.source_unit,
    ref.source_category,
    ...(Array.isArray(ref.source_aliases) ? ref.source_aliases : []),
  ]
    .map(asStringValue)
    .join(" ");
  if (isFreshProduceProductName(productName) && freshProduceIncompatiblePattern.test(normalizeSearchTerm(candidateText))) {
    return -1;
  }
  const candidateTokens = new Set(catalogTokens(candidateText, merchantKey));
  if (!inputTokens.length || !candidateTokens.size) return 0;
  const matched = new Set(
    inputTokens.filter(
      (token) =>
        candidateTokens.has(token) ||
        (token.length >= 5 &&
          Array.from(candidateTokens).some((candidateToken) => candidateToken.length >= 5 && candidateToken.includes(token))),
    ),
  );
  if (!inputTokens.some((token) => token.length >= 4 && matched.has(token))) return 0;
  const coverage = matched.size / inputTokens.length;
  const precision = matched.size / Math.max(1, Math.min(candidateTokens.size, inputTokens.length + 4));
  const hasImage = Boolean(asStringValue(ref.source_image_public_url) || asStringValue(ref.source_image_url));
  return Math.min(1, coverage * 0.7 + precision * 0.22 + (hasImage ? 0.08 : 0));
};

const fetchOfficialCatalogImageCandidates = async (input: {
  rawName: string;
  product: Record<string, unknown>;
  merchantName?: string;
  logger?: ProductEnrichmentLogger;
}): Promise<ProductImageCandidate[]> => {
  const source = officialCatalogSourceForMerchant(input.merchantName);
  const startedAt = performance.now();
  if (!source) {
    await input.logger?.({
      step: "image_search",
      provider: "official_catalog",
      status: "skipped",
      request: { productName: input.rawName, merchantName: input.merchantName },
      response: { reason: "merchant_not_supported" },
    });
    return [];
  }

  try {
    const supabase = getSupabase();
    const { data: catalogSource, error: sourceError } = await supabase
      .from("retail_catalog_sources")
      .select("id")
      .eq("merchant_key", source.key)
      .eq("enabled", true)
      .maybeSingle();
    if (sourceError || !catalogSource?.id) {
      await input.logger?.({
        step: "image_search",
        provider: "official_catalog",
        status: "failed",
        durationMs: Math.round(performance.now() - startedAt),
        request: { merchantKey: source.key, productName: input.rawName },
        error: sourceError?.message || "catalog_source_not_found",
      });
      return [];
    }

    const searchPhrases = officialCatalogSearchPhrases(input.rawName, input.product, source.key);
    const tokens = officialCatalogSearchTokens(input.rawName, input.product, source.key);
    const rowsById = new Map<string, Record<string, unknown>>();
    const selectColumns = [
      "id",
      "source_name",
      "source_normalized_name",
      "source_description",
      "source_brand",
      "source_weight",
      "source_unit",
      "source_category",
      "source_aliases",
      "source_product_url",
      "source_image_url",
      "source_image_public_url",
      "source_image_storage_path",
      "confidence",
    ];
    for (const token of tokens) {
      let data: Record<string, unknown>[] | null = null;
      let error: { message?: string } | null = null;
      const availableSelectColumns = [...selectColumns];
      for (let attempt = 0; attempt < selectColumns.length; attempt += 1) {
        const result = await supabase
          .from("product_external_refs")
          .select(availableSelectColumns.join(","))
          .eq("source_id", catalogSource.id)
          .or(`source_normalized_name.ilike.%${token}%,source_name.ilike.%${token}%,source_brand.ilike.%${token}%`)
          .limit(60);
        data = (result.data || null) as Record<string, unknown>[] | null;
        error = result.error;
        const missingColumn = missingSchemaColumnName(error);
        if (error && missingColumn && availableSelectColumns.includes(missingColumn)) {
          availableSelectColumns.splice(availableSelectColumns.indexOf(missingColumn), 1);
          continue;
        }
        break;
      }
      if (error) {
        await input.logger?.({
          step: "image_search",
          provider: "official_catalog",
          status: "failed",
          durationMs: Math.round(performance.now() - startedAt),
          request: { merchantKey: source.key, token, productName: input.rawName },
          error: error.message,
        });
        return [];
      }
      (data || []).forEach((row) => rowsById.set(String(row.id), asRecord(row)));
    }

    const candidates = Array.from(rowsById.values())
      .map((row) => ({
        row,
        score: Math.max(...searchPhrases.map((phrase) => scoreOfficialCatalogRef(phrase, row, source.key)), 0),
      }))
      .filter(({ row, score }) => score >= 0.46 && (asStringValue(row.source_image_public_url) || asStringValue(row.source_image_url)))
      .sort((a, b) => b.score - a.score)
      .slice(0, 6)
      .map(({ row, score }) => ({
        externalRefId: asStringValue(row.id) || undefined,
        name: asStringValue(row.source_name) || safeSearchName(input.rawName),
        brand: asStringValue(row.source_brand) || asStringValue(input.product.brand) || undefined,
        weight: asStringValue(row.source_weight) || asStringValue(input.product.weight) || undefined,
        imageUrl: asStringValue(row.source_image_public_url) || asStringValue(row.source_image_url),
        imageSource: `official_catalog_${source.key}`,
        imageSourceUrl: asStringValue(row.source_product_url) || asStringValue(row.source_image_url),
        merchantCategories: [
          "Catalogo ufficiale",
          source.key,
          asStringValue(row.source_category),
          asStringValue(row.source_name),
        ].filter(Boolean),
        contextText: [
          asStringValue(row.source_name),
          asStringValue(row.source_description),
          asStringValue(row.source_brand),
          asStringValue(row.source_product_url),
          asStringValue(row.source_image_url),
        ].filter(Boolean).join(" "),
        imageConfidence: Math.max(0.72, Math.min(0.96, score)),
      }));

    await input.logger?.({
      step: "image_search",
      provider: "official_catalog",
      status: "success",
      durationMs: Math.round(performance.now() - startedAt),
      request: { merchantKey: source.key, productName: input.rawName, searchPhrases, tokens },
      response: {
        rawResults: rowsById.size,
        selectedCandidates: candidates.map((candidate) => ({
          name: candidate.name,
          imageUrl: candidate.imageUrl,
          sourceUrl: candidate.imageSourceUrl,
          confidence: candidate.imageConfidence,
        })),
      },
    });

    return candidates;
  } catch (error) {
    await input.logger?.({
      step: "image_search",
      provider: "official_catalog",
      status: "failed",
      durationMs: Math.round(performance.now() - startedAt),
      request: { merchantKey: source.key, productName: input.rawName },
      error: logErrorMessage(error),
    });
    return [];
  }
};

const trustedProductImageSourcePattern =
  /(esselunga|coop|conad|carrefour|pam|selex|despar|iper|crai|bennet|tigros|eurospin|lidl|aldi|mdspa|dm-drogeriemarkt|supermercato|supermercati|spesaonline|openfoodfacts|amazon|everli|cortilia|alce nero|barilla|mulino bianco|lavazza|granoro|rummo|granolo|granarolo|muller|dash|dixan|rio mare|mutti|findus|cameo|galbani|parmalat|nescafe|san benedetto|sant'anna|norda|levissima|lete|ferrarelle|rocchetta|sangemini|surgiva|panna|smeraldina|valfrutta|bauli|ferrero)/i;

const cleanPackshotPattern = /(packshot|confezione|prodotto|product|white|bianco|png|frontale|front)/i;
const noisyImagePattern = /(recipe|ricetta|scaffale|shelf|volantino|catalogo|banner|promo|offerta|blog|news|article|ingredienti|ingredients)/i;
const freshProduceProductPattern =
  /\b(lamponi|lampone|mirtilli|mirtillo|fragole|fragola|more|ribes|ribesrosso|uva|pere|pera|mele|mela|banane|banana|kiwi|pesche|pesca|albicocche|albicocca|ciliegie|ciliegia|limoni|limone|arance|arancia|mandarini|mandarino|avocado|pomodorini|pomodori|pomodoro|insalata|zucchine|zucchina|carote|carota)\b/i;
const freshProduceIncompatiblePattern =
  /\b(yogurt|yomo|muller|fage|vipiteno|kefir|skyr|frullato|smoothie|succo|nettare|bevanda|drink|confettura|marmellata|composta|crema|dessert|cheesecake|crostata|torta|gelato|sorbetto|mousse|barretta|barrette|biscotto|biscotti|caramelle|gelee|infuso|tisana|te|integratore|maschera|viso|shampoo|salsa|sciroppo|ripieni|ricoperti|cioccolato|cacao)\b/i;
const commodityGroceryPattern =
  /\b(acqua|norda|naturale|frizzante|minerale|latte|pomodorini|avocado|limone|lemonsoda|bevanda|pollo|biscotti|farro|orzo|orzoro)\b/i;
const groceryCommerceSourcePattern =
  /(\.it\/|spesa|supermercato|supermercati|alimentari|bevande|drink|casa|shop|store|prodotto|product)/i;
const nonOverridableVisionRejectPattern =
  /(unrelated|industrial|logo_only|shelf_or_recipe|ricetta|scaffale)/i;
const differentProductVisionRejectPattern =
  /(different_product|marca diversa|brand diverso|prodotto diverso|non corrisponde)/i;

const isFreshProduceProductName = (productName: string) => {
  const normalized = normalizeSearchTerm(productName);
  return freshProduceProductPattern.test(normalized) && !freshProduceIncompatiblePattern.test(normalized);
};

const productImageCandidateContext = (candidate: ProductImageCandidate) =>
  normalizeSearchTerm(
    [
      candidate.name,
      candidate.brand,
      candidate.weight,
      candidate.imageUrl,
      candidate.imageSource,
      candidate.imageSourceUrl,
      candidate.contextText,
      ...(candidate.merchantCategories || []),
    ]
      .filter(Boolean)
      .join(" "),
  );

const rejectIncompatibleProductImageCandidate = (productName: string, candidate: ProductImageCandidate) =>
  isFreshProduceProductName(productName) && freshProduceIncompatiblePattern.test(productImageCandidateContext(candidate));

const scoreProductImageCandidate = (item: Record<string, unknown>, productName: string, merchantName?: string) => {
  const haystack = normalizeSearchTerm(
    [
      item.title,
      item.source,
      item.sourceUrl,
      item.pageUrl,
      item.origin,
      item.contextUrl,
      item.displayedUrl,
      item.snippet,
      item.imageUrl,
      item.link,
      item.raw_link,
    ]
      .map(asStringValue)
      .filter(Boolean)
      .join(" "),
  );
  const tokens = normalizeSearchTerm(productName)
    .split(" ")
    .filter((token) => token.length >= 3 && !["prod", "prodotto", "conf", "confezione", "supermercato"].includes(token));
  if (industrialHallucinationPattern.test(haystack) && !industrialHallucinationPattern.test(productName)) {
    return -100;
  }
  if (isFreshProduceProductName(productName) && freshProduceIncompatiblePattern.test(haystack)) {
    return -120;
  }
  const matches = tokens.filter((token) => haystack.includes(token)).length;
  const trustedDomain = trustedProductImageSourcePattern.test(haystack);
  const officialMerchantDomain = isOfficialMerchantCatalogUrl(haystack, merchantName);
  const merchantTokens = normalizeSearchTerm(merchantName || "")
    .split(" ")
    .filter((token) => token.length >= 3);
  const merchantMatch = merchantTokens.some((token) => haystack.includes(token));
  const producerDomain = /(\.it|\.com|\.eu)/i.test(haystack);
  const cleanPackshot = cleanPackshotPattern.test(haystack);
  const noisyImage = noisyImagePattern.test(haystack);
  return matches * 8 + (officialMerchantDomain ? 34 : 0) + (trustedDomain ? 14 : 0) + (merchantMatch ? 8 : 0) + (producerDomain ? 2 : 0) + (cleanPackshot ? 5 : 0) - (noisyImage ? 8 : 0);
};

const productImageTokenMatches = (productName: string, candidate: ProductImageCandidate) => {
  const haystack = productImageCandidateContext(candidate);
  const tokens = expandCatalogAbbreviations(productName)
    .split(" ")
    .filter((token) => token.length >= 3 && !["con", "per", "del", "dell", "della", "prodotto", "mousse"].includes(token));
  return tokens.filter((token) => haystack.includes(token)).length;
};

const isVisionTechnicalFailure = (reason?: string) =>
  /vision_(fetch_failed|review_failed|model_error)|fetch_failed|model_error|timeout|network/i.test(reason || "");

const isCommodityGroceryProduct = (input: {
  productName: string;
  product: Record<string, unknown>;
}) => {
  const productText = `${input.productName} ${asStringValue(input.product.name)} ${asStringValue(input.product.brand)} ${asStringValue(input.product.category)}`;
  return commodityGroceryPattern.test(productText);
};

const hasStrongCommodityProductEvidence = (input: {
  candidate: ProductImageCandidate;
  productName: string;
  product: Record<string, unknown>;
  merchantName?: string;
}) => {
  if (!isCommodityGroceryProduct(input)) return false;
  const candidateText = `${input.candidate.imageUrl} ${input.candidate.imageSourceUrl || ""} ${input.candidate.imageSource || ""} ${input.candidate.brand || ""} ${(input.candidate.merchantCategories || []).join(" ")}`;
  if (industrialHallucinationPattern.test(candidateText) && !industrialHallucinationPattern.test(input.productName)) return false;
  if (noisyImagePattern.test(candidateText)) return false;

  const directProductImage =
    /\.(jpe?g|png|webp)(\?|$)/i.test(input.candidate.imageUrl) ||
    /m\.media-amazon\.com|images[-.]openfoodfacts|cdn|media|wp-content|uploads/i.test(input.candidate.imageUrl);
  if (!directProductImage) return false;

  const fallbackScore = scoreProductImageCandidate(
    {
      title: input.candidate.imageSource === "openfoodfacts" ? input.candidate.name : "",
      source: input.candidate.imageSource,
      sourceUrl: input.candidate.imageSourceUrl,
      imageUrl: input.candidate.imageUrl,
      link: input.candidate.imageSourceUrl,
      snippet: [input.candidate.brand, input.candidate.weight, ...(input.candidate.merchantCategories || [])].join(" "),
    },
    input.productName,
    input.merchantName,
  );
  const tokenMatches = productImageTokenMatches(input.productName, input.candidate);
  const sourceLooksLikeGroceryCommerce = groceryCommerceSourcePattern.test(candidateText);

  return sourceLooksLikeGroceryCommerce && tokenMatches >= 2 && fallbackScore >= 24;
};

const shouldAcceptTrustedCandidateWhenVisionFails = (input: {
  candidate: ProductImageCandidate;
  productName: string;
  product: Record<string, unknown>;
  merchantName?: string;
}) => {
  if (!/^https?:\/\//i.test(input.candidate.imageUrl)) return false;
  if (industrialHallucinationPattern.test(`${input.candidate.imageUrl} ${input.candidate.imageSourceUrl || ""}`)) return false;

  const fallbackScore = scoreProductImageCandidate(
    {
      title: input.candidate.imageSource === "openfoodfacts" ? input.candidate.name : "",
      source: input.candidate.imageSource,
      sourceUrl: input.candidate.imageSourceUrl,
      imageUrl: input.candidate.imageUrl,
      link: input.candidate.imageSourceUrl,
      snippet: [input.candidate.brand, input.candidate.weight, ...(input.candidate.merchantCategories || [])].join(" "),
    },
    input.productName,
    input.merchantName,
  );
  const tokenMatches = productImageTokenMatches(input.productName, input.candidate);
  const requiredMatches = normalizeSearchTerm(input.productName).split(" ").filter((token) => token.length >= 4).length <= 1 ? 1 : 2;
  const trustedSource =
    trustedProductImageSourcePattern.test(`${input.candidate.imageSourceUrl || ""} ${input.candidate.imageUrl} ${input.candidate.imageSource}`) ||
    input.candidate.imageSource === "openfoodfacts";
  const directProductImage =
    /\.(jpe?g|png|webp)(\?|$)/i.test(input.candidate.imageUrl) ||
    /m\.media-amazon\.com|images[-.]openfoodfacts|cdn|media/i.test(input.candidate.imageUrl);

  const trustedCandidate = trustedSource && directProductImage && tokenMatches >= requiredMatches && fallbackScore >= 18;
  return trustedCandidate || hasStrongCommodityProductEvidence(input);
};

const shouldAcceptTrustedCandidateDespiteVisionReject = (input: {
  candidate: ProductImageCandidate;
  productName: string;
  product: Record<string, unknown>;
  merchantName?: string;
  review: ProductImageVisionReview;
}) => {
  if (!/^https?:\/\//i.test(input.candidate.imageUrl)) return false;
  const candidateText = `${input.candidate.imageUrl} ${input.candidate.imageSourceUrl || ""} ${input.candidate.imageSource || ""} ${input.candidate.brand || ""}`;
  if (industrialHallucinationPattern.test(candidateText) && !industrialHallucinationPattern.test(input.productName)) return false;
  if (nonOverridableVisionRejectPattern.test(input.review.reason || "")) return false;

  const fallbackScore = scoreProductImageCandidate(
    {
      title: input.candidate.imageSource === "openfoodfacts" ? input.candidate.name : "",
      source: input.candidate.imageSource,
      sourceUrl: input.candidate.imageSourceUrl,
      imageUrl: input.candidate.imageUrl,
      link: input.candidate.imageSourceUrl,
      snippet: [input.candidate.brand, input.candidate.weight, ...(input.candidate.merchantCategories || [])].join(" "),
    },
    input.productName,
    input.merchantName,
  );
  const tokenMatches = productImageTokenMatches(input.productName, input.candidate);
  const productText = `${input.productName} ${asStringValue(input.product.name)} ${asStringValue(input.product.brand)} ${asStringValue(input.product.category)}`;
  const commodityProduct = commodityGroceryPattern.test(productText);
  const trustedSource =
    trustedProductImageSourcePattern.test(`${input.candidate.imageSourceUrl || ""} ${input.candidate.imageUrl} ${input.candidate.imageSource}`) ||
    input.candidate.imageSource === "openfoodfacts";
  const directProductImage =
    /\.(jpe?g|png|webp)(\?|$)/i.test(input.candidate.imageUrl) ||
    /m\.media-amazon\.com|images[-.]openfoodfacts|cdn|media/i.test(input.candidate.imageUrl);
  const requiredMatches = commodityProduct ? 1 : 2;
  const visionSaysDifferentProduct = differentProductVisionRejectPattern.test(input.review.reason || "");
  if (visionSaysDifferentProduct && !(commodityProduct && tokenMatches >= 2 && fallbackScore >= 34)) return false;

  const trustedCandidate = trustedSource && directProductImage && tokenMatches >= requiredMatches && fallbackScore >= (commodityProduct ? 22 : 34);
  return trustedCandidate || (commodityProduct && hasStrongCommodityProductEvidence(input));
};

const fetchSerpApiGoogleImageCandidates = async (input: {
  rawName: string;
  product: Record<string, unknown>;
  merchantName?: string;
  logger?: ProductEnrichmentLogger;
}): Promise<ProductImageCandidate[]> => {
  const apiKey = Deno.env.get("SERPAPI_API_KEY");
  if (!apiKey) {
    await input.logger?.({
      step: "image_search",
      provider: "serpapi_google_images_light",
      status: "skipped",
      request: { rawName: input.rawName, merchantName: input.merchantName },
      error: "SERPAPI_API_KEY missing",
    });
    return [];
  }

  const query = productImageSearchQueries(input)[0];
  if (!query) {
    await input.logger?.({
      step: "image_search",
      provider: "serpapi_google_images_light",
      status: "skipped",
      request: { rawName: input.rawName, merchantName: input.merchantName },
      error: "empty_search_query",
    });
    return [];
  }

  const url = new URL("https://serpapi.com/search.json");
  url.searchParams.set("engine", "google_images_light");
  url.searchParams.set("q", query);
  url.searchParams.set("google_domain", "google.it");
  url.searchParams.set("gl", "it");
  url.searchParams.set("hl", "it");
  url.searchParams.set("safe", "active");
  url.searchParams.set("filter", "1");
  url.searchParams.set("api_key", apiKey);

  const startedAt = performance.now();
  try {
    const response = await fetch(url.toString(), {
      headers: { Accept: "application/json", "User-Agent": "FinanceCompass/1.0 product-image-search" },
      signal: AbortSignal.timeout(25000),
    });
    if (!response.ok) {
      await input.logger?.({
        step: "image_search",
        provider: "serpapi_google_images_light",
        status: "failed",
        durationMs: Math.round(performance.now() - startedAt),
        request: { query, gl: "it", hl: "it", safe: "active" },
        response: { httpStatus: response.status, body: await response.text().catch(() => "") },
      });
      return [];
    }

    const payload = await response.json() as { images_results?: unknown[] };
    const rows = Array.isArray(payload.images_results) ? payload.images_results : [];
    const productName = safeSearchName(input.rawName);
    const seen = new Set<string>();

    const candidates = rows
      .map((row) => asRecord(row))
      .map((row) => {
        const original = asStringValue(row.original);
        if (!/^https?:\/\//i.test(original) || seen.has(original) || Boolean(row.unsafe)) return null;
        seen.add(original);
        const score = scoreProductImageCandidate(row, productName, input.merchantName) + (row.is_product === true ? 16 : 0);
        return {
          candidate: {
            name: productName,
            brand: undefined,
            weight: asStringValue(input.product.weight) || undefined,
            imageUrl: original,
            imageSource: "serpapi_google_images_light",
            imageSourceUrl: asStringValue(row.link) || asStringValue(row.raw_link) || original,
            merchantCategories: ["Google Images Light", "SerpApi", asStringValue(row.source), asStringValue(row.title)].filter(Boolean),
            contextText: [
              asStringValue(row.title),
              asStringValue(row.source),
              asStringValue(row.link),
              asStringValue(row.raw_link),
              asStringValue(row.snippet),
              asStringValue(row.original),
            ].filter(Boolean).join(" "),
            imageConfidence: Math.min(0.9, 0.6 + Math.max(0, Math.min(score, 30)) / 100),
          } satisfies ProductImageCandidate,
          score,
        };
      })
      .filter((entry): entry is { candidate: ProductImageCandidate; score: number } => Boolean(entry))
      .filter((entry) => entry.score > 0 && !rejectIncompatibleProductImageCandidate(productName, entry.candidate))
      .sort((a, b) => b.score - a.score)
      .map((entry) => entry.candidate)
      .slice(0, 8);
    await input.logger?.({
      step: "image_search",
      provider: "serpapi_google_images_light",
      status: "success",
      durationMs: Math.round(performance.now() - startedAt),
      request: { query, gl: "it", hl: "it", safe: "active", maxResultsUsed: 8 },
      response: {
        rawResults: rows.length,
        selectedCandidates: candidates.map((candidate) => ({
          imageUrl: candidate.imageUrl,
          sourceUrl: candidate.imageSourceUrl,
          source: candidate.imageSource,
          confidence: candidate.imageConfidence,
        })),
      },
    });
    return candidates;
  } catch (error) {
    await input.logger?.({
      step: "image_search",
      provider: "serpapi_google_images_light",
      status: "failed",
      durationMs: Math.round(performance.now() - startedAt),
      request: { query, gl: "it", hl: "it", safe: "active" },
      error: logErrorMessage(error),
    });
    return [];
  }
};

const extractApifyImageUrl = (item: Record<string, unknown>) => {
  const candidates = [
    item.imageUrl,
    item.originalUrl,
    item.originalImageUrl,
    item.fullImageUrl,
    item.contentUrl,
    item.url,
    item.image,
    item.thumbnailUrl,
  ];
  for (const candidate of candidates) {
    const value = asStringValue(candidate);
    if (/^https?:\/\//i.test(value)) return value;
  }
  return "";
};

const extractApifySourceUrl = (item: Record<string, unknown>) => {
  const candidates = [item.sourceUrl, item.pageUrl, item.origin, item.contextUrl, item.link, item.hostPageUrl];
  for (const candidate of candidates) {
    const value = asStringValue(candidate);
    if (/^https?:\/\//i.test(value)) return value;
  }
  return undefined;
};

const scoreApifyImageCandidate = (item: Record<string, unknown>, productName: string, merchantName?: string) => {
  const haystack = normalizeSearchTerm(
    [
      item.title,
      item.source,
      item.sourceUrl,
      item.pageUrl,
      item.origin,
      item.contextUrl,
      item.displayedUrl,
      item.snippet,
      item.imageUrl,
    ]
      .map(asStringValue)
      .filter(Boolean)
      .join(" "),
  );
  const tokens = normalizeSearchTerm(productName)
    .split(" ")
    .filter((token) => token.length >= 3 && !["prod", "prodotto", "conf", "gr"].includes(token));
  if (industrialHallucinationPattern.test(haystack) && !industrialHallucinationPattern.test(productName)) {
    return -100;
  }
  const matches = tokens.filter((token) => haystack.includes(token)).length;
  const trustedDomain = trustedProductImageSourcePattern.test(haystack);
  const officialMerchantDomain = isOfficialMerchantCatalogUrl(haystack, merchantName);
  const merchantTokens = normalizeSearchTerm(merchantName || "")
    .split(" ")
    .filter((token) => token.length >= 3);
  const merchantMatch = merchantTokens.some((token) => haystack.includes(token));
  const producerDomain = /(\.it|\.com|\.eu)/i.test(haystack);
  const cleanPackshot = cleanPackshotPattern.test(haystack);
  const noisyImage = noisyImagePattern.test(haystack);
  return matches * 8 + (officialMerchantDomain ? 34 : 0) + (trustedDomain ? 12 : 0) + (merchantMatch ? 8 : 0) + (producerDomain ? 2 : 0) + (cleanPackshot ? 5 : 0) - (noisyImage ? 8 : 0);
};

const fetchApifyGoogleImageCandidates = async (input: {
  rawName: string;
  product: Record<string, unknown>;
  merchantName?: string;
  logger?: ProductEnrichmentLogger;
}): Promise<ProductImageCandidate[]> => {
  const token = Deno.env.get("APIFY_API_TOKEN");
  if (!token) {
    await input.logger?.({
      step: "image_search",
      provider: "apify_google_images",
      status: "skipped",
      request: { rawName: input.rawName, merchantName: input.merchantName },
      error: "APIFY_API_TOKEN missing",
    });
    return [];
  }

  const queries = productImageSearchQueries(input);
  if (!queries.length) {
    await input.logger?.({
      step: "image_search",
      provider: "apify_google_images",
      status: "skipped",
      request: { rawName: input.rawName, merchantName: input.merchantName },
      error: "empty_search_query",
    });
    return [];
  }

  const actorId = Deno.env.get("APIFY_GOOGLE_IMAGES_ACTOR_ID") || "tnudF2IxzORPhg4r8";
  const url = new URL(`https://api.apify.com/v2/acts/${encodeURIComponent(actorId)}/run-sync-get-dataset-items`);
  url.searchParams.set("timeout", "90");
  url.searchParams.set("clean", "true");

  const startedAt = performance.now();
  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        queries,
        maxResultsPerQuery: 8,
      }),
      signal: AbortSignal.timeout(100000),
    });
    if (!response.ok) {
      await input.logger?.({
        step: "image_search",
        provider: "apify_google_images",
        status: "failed",
        durationMs: Math.round(performance.now() - startedAt),
        request: { actorId, queries, maxResultsPerQuery: 8 },
        response: { httpStatus: response.status, body: await response.text().catch(() => "") },
      });
      return [];
    }

    const payload = await response.json();
    const rows = Array.isArray(payload) ? payload : flattenModelsPayload(payload);
    const productName = safeSearchName(input.rawName);
    const seen = new Set<string>();

    const candidates = rows
      .map((row) => asRecord(row))
      .map((row) => {
        const imageUrl = extractApifyImageUrl(row);
        if (!imageUrl || seen.has(imageUrl)) return null;
        seen.add(imageUrl);
        const score = scoreApifyImageCandidate(row, productName, input.merchantName);
        return {
          candidate: {
            name: productName,
            brand: undefined,
            weight: asStringValue(input.product.weight) || undefined,
            imageUrl,
            imageSource: "apify_google_images",
            imageSourceUrl: extractApifySourceUrl(row) || imageUrl,
            merchantCategories: ["Google Images", "Apify", asStringValue(row.title), asStringValue(row.source)].filter(Boolean),
            contextText: [
              asStringValue(row.title),
              asStringValue(row.source),
              asStringValue(row.sourceUrl),
              asStringValue(row.pageUrl),
              asStringValue(row.origin),
              asStringValue(row.contextUrl),
              asStringValue(row.displayedUrl),
              asStringValue(row.snippet),
              imageUrl,
            ].filter(Boolean).join(" "),
            imageConfidence: Math.min(0.86, 0.58 + Math.max(0, Math.min(score, 28)) / 100),
          } satisfies ProductImageCandidate,
          score,
        };
      })
      .filter((entry): entry is { candidate: ProductImageCandidate; score: number } => Boolean(entry))
      .filter((entry) => entry.score > 0 && !rejectIncompatibleProductImageCandidate(productName, entry.candidate))
      .sort((a, b) => b.score - a.score)
      .map((entry) => entry.candidate)
      .slice(0, 6);
    await input.logger?.({
      step: "image_search",
      provider: "apify_google_images",
      status: "success",
      durationMs: Math.round(performance.now() - startedAt),
      request: { actorId, queries, maxResultsPerQuery: 8 },
      response: {
        rawResults: rows.length,
        selectedCandidates: candidates.map((candidate) => ({
          imageUrl: candidate.imageUrl,
          sourceUrl: candidate.imageSourceUrl,
          source: candidate.imageSource,
          confidence: candidate.imageConfidence,
        })),
      },
    });
    return candidates;
  } catch (error) {
    await input.logger?.({
      step: "image_search",
      provider: "apify_google_images",
      status: "failed",
      durationMs: Math.round(performance.now() - startedAt),
      request: { actorId, queries, maxResultsPerQuery: 8 },
      error: logErrorMessage(error),
    });
    return [];
  }
};

const PRODUCT_IMAGE_MAX_BYTES = 6 * 1024 * 1024;
const PRODUCT_IMAGE_BUCKET = "product-images";
const PRODUCT_IMAGE_VISION_REVIEW_LIMIT = 3;

const getExternalSupabaseUrl = () => {
  const configured = (
    Deno.env.get("PRODUCT_IMAGE_PUBLIC_BASE_URL") ||
    Deno.env.get("SUPABASE_PUBLIC_URL") ||
    Deno.env.get("API_EXTERNAL_URL") ||
    "https://pfdb.evolvemarketing.cloud"
  ).replace(/\/$/, "");
  try {
    const url = new URL(configured);
    if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|kong)$/i.test(url.hostname)) {
      return "https://pfdb.evolvemarketing.cloud";
    }
  } catch {
    return "https://pfdb.evolvemarketing.cloud";
  }
  return configured;
};

const publicStorageUrl = (bucket: string, path: string) =>
  `${getExternalSupabaseUrl()}/storage/v1/object/public/${bucket}/${path
    .split("/")
    .map(encodeURIComponent)
    .join("/")}`;

const normalizeStorageSegment = (value: string) =>
  value
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "product";

const extensionFromContentType = (contentType: string) => {
  if (contentType.includes("png")) return "png";
  if (contentType.includes("webp")) return "webp";
  return "jpg";
};

const isSupportedImageContentType = (contentType: string) =>
  ["image/jpeg", "image/jpg", "image/png", "image/webp"].some((allowed) => contentType.includes(allowed));

const sha256Short = async (value: ArrayBuffer | string) => {
  const input = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", input);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 18);
};

const mirrorProductImageToStorage = async (input: {
  sourceUrl: string;
  productName: string;
  productId?: string;
}) => {
  try {
    const response = await fetch(input.sourceUrl, {
      headers: {
        Accept: "image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8",
        "User-Agent": "FinanceCompass/1.0 product-image-mirror",
      },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return null;

    const contentType = response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() || "image/jpeg";
    if (!isSupportedImageContentType(contentType)) return null;

    const declaredSize = Number(response.headers.get("content-length") || 0);
    if (declaredSize > PRODUCT_IMAGE_MAX_BYTES) return null;

    const bytes = await response.arrayBuffer();
    if (!bytes.byteLength || bytes.byteLength > PRODUCT_IMAGE_MAX_BYTES) return null;

    const ext = extensionFromContentType(contentType);
    const sourceHash = await sha256Short(`${input.sourceUrl}:${bytes.byteLength}`);
    const folder = input.productId
      ? normalizeStorageSegment(input.productId)
      : normalizeStorageSegment(input.productName);
    const path = `catalog/${folder}/${sourceHash}.${ext}`;
    const supabase = getSupabase();

    const { error } = await supabase.storage.from(PRODUCT_IMAGE_BUCKET).upload(path, bytes, {
      contentType,
      cacheControl: "31536000",
      upsert: true,
    });
    if (error) return null;

    const publicUrl = publicStorageUrl(PRODUCT_IMAGE_BUCKET, path);

    return {
      publicUrl,
      storagePath: path,
      contentType,
      size: bytes.byteLength,
    };
  } catch {
    return null;
  }
};

const removeProductImageFromStorage = async (storagePath: string) => {
  try {
    await getSupabase().storage.from(PRODUCT_IMAGE_BUCKET).remove([storagePath]);
  } catch {
    // Best effort cleanup: a rejected image must not block product enrichment.
  }
};

const ESSELUNGA_CATALOG_SOURCE = {
  merchant_key: "esselunga",
  merchant_name: "Esselunga",
  official_domains: ["spesaonline.esselunga.it", "esselunga.it"],
  search_domains: ["spesaonline.esselunga.it"],
  scrape_status: "importing",
  scrape_notes: "Catalogo ufficiale Esselunga usato come knowledge base locale per matching prodotti GDO.",
};

const decodeCatalogHtml = (value: unknown) =>
  String(value || "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();

const esselungaProductCodeFromUrl = (url: string) => url.match(/\/prodotto\/(\d+)\//)?.[1] || "";

const esselungaSlugFromUrl = (url: string) => {
  try {
    return decodeURIComponent(url.split("/").filter(Boolean).pop() || "").replace(/-/g, " ");
  } catch {
    return "";
  }
};

const isEsselungaProductUrl = (url: string) =>
  /^https:\/\/spesaonline\.esselunga\.it\/commerce\/nav\/supermercato\/store\/prodotto\/\d+\//i.test(url);

const fetchEsselungaCatalogProduct = async (url: string) => {
  const code = esselungaProductCodeFromUrl(url);
  if (!code) throw new Error("esselunga_product_code_missing");
  const response = await fetch(`https://spesaonline.esselunga.it/commerce/resources/displayable/detail/code/${code}`, {
    headers: {
      Accept: "application/json",
      "User-Agent": "FinanceCompassCatalogImporter/1.0 (+https://personalfinancecompass.vercel.app)",
      "X-PAGE-PATH": "supermercato",
      Referer: url,
    },
    signal: AbortSignal.timeout(15000),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`esselunga_http_${response.status}:${text.slice(0, 160)}`);
  const payload = JSON.parse(text) as Record<string, unknown>;
  const product = asRecord(payload.displayableProduct || payload.product || payload);
  if (!asStringValue(product.description)) throw new Error("esselunga_product_without_description");
  return product;
};

const bestEsselungaImageUrl = (product: Record<string, unknown>) => {
  const images = Array.isArray(product.images) ? product.images.map(asRecord) : [];
  return (
    asStringValue(product.imageURL) ||
    asStringValue(images.find((image) => image.big)?.big) ||
    asStringValue(images.find((image) => image.medium)?.medium) ||
    asStringValue(images.find((image) => image.small)?.small)
  );
};

const ensureEsselungaCatalogSource = async () => {
  const { data, error } = await getSupabase()
    .from("retail_catalog_sources")
    .upsert({ ...ESSELUNGA_CATALOG_SOURCE, updated_at: new Date().toISOString() }, { onConflict: "merchant_key" })
    .select("id")
    .single();
  if (error) throw new Error(`retail_catalog_sources_upsert_failed:${error.message}`);
  return String(data.id);
};

const mirrorOfficialCatalogImageToStorage = async (input: {
  sourceUrl: string;
  sourceKey: string;
  productCode: string;
  productName: string;
  referer?: string;
}) => {
  if (!input.sourceUrl) return {};
  const response = await fetch(input.sourceUrl, {
    headers: {
      Accept: "image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8",
      "User-Agent": "FinanceCompassCatalogImporter/1.0",
      ...(input.referer ? { Referer: input.referer } : {}),
    },
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw new Error(`official_image_download_${response.status}`);
  const contentType = response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() || "image/jpeg";
  if (!isSupportedImageContentType(contentType)) throw new Error(`official_image_content_type_${contentType}`);
  const declaredSize = Number(response.headers.get("content-length") || 0);
  if (declaredSize > PRODUCT_IMAGE_MAX_BYTES) throw new Error("official_image_too_large");
  const bytes = await response.arrayBuffer();
  if (!bytes.byteLength || bytes.byteLength > PRODUCT_IMAGE_MAX_BYTES) throw new Error("official_image_invalid_size");
  const ext = extensionFromContentType(contentType);
  const hash = await sha256Short(bytes);
  const path = `official/${normalizeStorageSegment(input.sourceKey)}/${normalizeStorageSegment(input.productCode || input.productName)}/${hash}.${ext}`;
  const { error } = await getSupabase().storage.from(PRODUCT_IMAGE_BUCKET).upload(path, bytes, {
    contentType,
    cacheControl: "31536000",
    upsert: true,
  });
  if (error) throw new Error(`official_image_upload_failed:${error.message}`);
  return {
    storagePath: path,
    publicUrl: publicStorageUrl(PRODUCT_IMAGE_BUCKET, path),
  };
};

const esselungaProductToExternalRef = (
  url: string,
  product: Record<string, unknown>,
  imageMirror: { storagePath?: string; publicUrl?: string } = {},
) => {
  const name = decodeCatalogHtml(product.description);
  const slugAlias = esselungaSlugFromUrl(url);
  const unitValue = asStringValue(product.unitValue);
  const unitText = asStringValue(product.unitText);
  const brand = asStringValue(product.brand);
  const code = asStringValue(product.code) || asStringValue(product.productId) || asStringValue(product.id) || esselungaProductCodeFromUrl(url);
  const aliases = Array.from(
    new Set(
      [
        name,
        slugAlias,
        brand ? `${brand} ${name}` : "",
        asStringValue(product.barcode),
        code,
      ].filter(Boolean),
    ),
  );
  const price = Number(product.discountedPrice ?? product.price);
  return {
    source_product_id: code,
    source_product_url: url,
    source_image_url: bestEsselungaImageUrl(product) || null,
    source_image_storage_path: imageMirror.storagePath || null,
    source_image_public_url: imageMirror.publicUrl || null,
    source_name: name,
    source_normalized_name: normalizeSearchTerm([name, brand, unitValue, unitText, slugAlias].filter(Boolean).join(" ")),
    source_description: decodeCatalogHtml(
      [
        product.htmlDescription,
        product.familyAttributes,
        product.originRawMaterialText,
        product.longDescription,
        product.label,
      ]
        .filter(Boolean)
        .join(" "),
    ),
    source_brand: brand || null,
    source_weight: [unitValue, unitText].filter(Boolean).join(" ") || null,
    source_unit: unitText || null,
    source_category: [product.productType, product.grmCode, product.subGrmCode].map(asStringValue).filter(Boolean).join(" / ") || null,
    source_aliases: aliases,
    source_price: Number.isFinite(price) ? price : null,
    source_currency: "EUR",
    confidence: 0.95,
    metadata: {
      barcode: asStringValue(product.barcode) || null,
      vat: product.vat ?? null,
      unitValue: unitValue || null,
      unitText: unitText || null,
      outOfStock: Boolean(product.outOfStock),
      importedFrom: "esselunga_displayable_detail_code",
    },
    last_seen_at: new Date().toISOString(),
  };
};

type EsselungaCatalogImportItemResult = {
  status: "ok" | "failed";
  url: string;
  code?: string;
  name?: string;
  imageSaved?: boolean;
  imageError?: string;
  error?: string;
};

const upsertProductExternalRefWithSchemaFallback = async (payload: Record<string, unknown>) => {
  const supabase = getSupabase();
  const upsertPayload: Record<string, unknown> = { ...payload };
  let error: { message?: string } | null = null;
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const result = await supabase.from("product_external_refs").upsert(upsertPayload, { onConflict: "source_id,source_product_url" });
    error = result.error;
    const missingColumn = missingSchemaColumnName(error);
    if (error && missingColumn && Object.prototype.hasOwnProperty.call(upsertPayload, missingColumn)) {
      delete upsertPayload[missingColumn];
      continue;
    }
    break;
  }
  if (error) throw new Error(`product_external_refs_upsert_failed:${error.message}`);
};

const importOneEsselungaCatalogUrl = async (sourceId: string, url: string, skipImages: boolean) => {
  const product = await fetchEsselungaCatalogProduct(url);
  const productCode = asStringValue(product.code) || esselungaProductCodeFromUrl(url);
  const productName = decodeCatalogHtml(product.description);
  let imageMirror: { storagePath?: string; publicUrl?: string } = {};
  let imageError: string | undefined;
  let imagesSaved = 0;
  let imageWarnings = 0;

  if (!skipImages) {
    try {
      imageMirror = await mirrorOfficialCatalogImageToStorage({
        sourceUrl: bestEsselungaImageUrl(product),
        sourceKey: "esselunga",
        productCode,
        productName,
        referer: url,
      });
      if (imageMirror.publicUrl) imagesSaved += 1;
    } catch (error) {
      imageWarnings += 1;
      imageError = logErrorMessage(error);
    }
  }

  const ref = esselungaProductToExternalRef(url, product, imageMirror);
  await upsertProductExternalRefWithSchemaFallback({ ...ref, source_id: sourceId });

  return {
    imagesSaved,
    imageWarnings,
    result: {
      status: "ok" as const,
      url,
      code: productCode,
      name: ref.source_name,
      imageSaved: Boolean(imageMirror.publicUrl),
      imageError,
    },
  };
};

const importEsselungaCatalogUrls = async (input: { urls?: unknown; skipImages?: boolean; max?: unknown }) => {
  const rawUrls = Array.isArray(input.urls) ? input.urls : [];
  const urls = Array.from(new Set(rawUrls.map(asStringValue).filter(isEsselungaProductUrl))).slice(
    0,
    Math.max(1, Math.min(Number(input.max) || 75, 150)),
  );
  const startedAt = performance.now();
  const sourceId = await ensureEsselungaCatalogSource();
  const results: EsselungaCatalogImportItemResult[] = [];
  let ok = 0;
  let failed = 0;
  let imagesSaved = 0;
  let imageWarnings = 0;

  for (const url of urls) {
    try {
      const imported = await importOneEsselungaCatalogUrl(sourceId, url, Boolean(input.skipImages));
      ok += 1;
      imagesSaved += imported.imagesSaved;
      imageWarnings += imported.imageWarnings;
      results.push(imported.result);
    } catch (error) {
      failed += 1;
      results.push({ status: "failed", url, code: esselungaProductCodeFromUrl(url), error: logErrorMessage(error) });
    }
  }

  await getSupabase()
    .from("retail_catalog_sources")
    .update({
      scrape_status: failed ? "partial" : "ready",
      last_scraped_at: new Date().toISOString(),
      scrape_notes: `Import Esselunga: ${ok} ok, ${failed} errori, ${imagesSaved} immagini salvate, ${imageWarnings} warning immagini.`,
      updated_at: new Date().toISOString(),
    })
    .eq("id", sourceId);

  return {
    sourceId,
    receivedUrls: rawUrls.length,
    validUrls: urls.length,
    ok,
    failed,
    imagesSaved,
    imageWarnings,
    durationMs: Math.round(performance.now() - startedAt),
    results: results.slice(0, 40),
  };
};

const mapCatalogImportJobItemResult = (item: Record<string, unknown>): EsselungaCatalogImportItemResult => ({
  status: item.status === "ok" ? "ok" : "failed",
  url: String(item.url || ""),
  code: item.code ? String(item.code) : undefined,
  name: item.product_name ? String(item.product_name) : undefined,
  imageSaved: Boolean(item.image_saved),
  imageError: item.image_error ? String(item.image_error) : undefined,
  error: item.error_message ? String(item.error_message) : undefined,
});

const getCatalogImportJobStatus = async (jobId?: string) => {
  const supabase = getSupabase();
  let query = supabase
    .from("retail_catalog_import_jobs")
    .select("*")
    .eq("merchant_key", "esselunga")
    .order("created_at", { ascending: false })
    .limit(1);
  if (jobId) query = supabase.from("retail_catalog_import_jobs").select("*").eq("id", jobId).limit(1);

  const { data: jobs, error } = await query;
  if (error) throw new Error(`retail_catalog_import_jobs_select_failed:${error.message}`);
  const job = jobs?.[0] as Record<string, unknown> | undefined;
  if (!job) return null;

  const { data: items } = await supabase
    .from("retail_catalog_import_job_items")
    .select("status, url, code, product_name, image_saved, image_error, error_message, processed_at, position")
    .eq("job_id", job.id)
    .neq("status", "queued")
    .order("position", { ascending: false })
    .limit(40);

  return {
    id: String(job.id),
    sourceId: String(job.source_id || ""),
    merchantKey: String(job.merchant_key || "esselunga"),
    status: String(job.status || "queued"),
    totalUrls: Number(job.total_urls || 0),
    processedUrls: Number(job.processed_urls || 0),
    ok: Number(job.ok_count || 0),
    failed: Number(job.failed_count || 0),
    imagesSaved: Number(job.images_saved || 0),
    imageWarnings: Number(job.image_warnings || 0),
    chunkSize: Number(job.chunk_size || 60),
    skipImages: Boolean(job.skip_images),
    errorMessage: job.error_message ? String(job.error_message) : undefined,
    createdAt: job.created_at || null,
    startedAt: job.started_at || null,
    finishedAt: job.finished_at || null,
    updatedAt: job.updated_at || null,
    results: (items || []).map((item) => mapCatalogImportJobItemResult(asRecord(item))).reverse(),
  };
};

const createEsselungaCatalogImportJob = async (
  input: { urls?: unknown; skipImages?: boolean; chunkSize?: unknown },
  userId?: string,
) => {
  const rawUrls = Array.isArray(input.urls) ? input.urls : [];
  const urls = Array.from(new Set(rawUrls.map(asStringValue).filter(isEsselungaProductUrl))).slice(0, 50000);
  if (!urls.length) throw new Error("Nessun URL prodotto Esselunga valido");

  const sourceId = await ensureEsselungaCatalogSource();
  const chunkSize = Math.max(1, Math.min(Number(input.chunkSize) || 60, 120));
  const supabase = getSupabase();
  const { data: job, error } = await supabase
    .from("retail_catalog_import_jobs")
    .insert({
      source_id: sourceId,
      merchant_key: "esselunga",
      status: "queued",
      total_urls: urls.length,
      chunk_size: chunkSize,
      skip_images: Boolean(input.skipImages),
      started_by_user_id: userId || null,
    })
    .select("id")
    .single();
  if (error) throw new Error(`retail_catalog_import_jobs_insert_failed:${error.message}`);

  const rows = urls.map((url, index) => ({
    job_id: job.id,
    url,
    position: index,
    status: "queued",
    code: esselungaProductCodeFromUrl(url),
  }));
  for (let cursor = 0; cursor < rows.length; cursor += 1000) {
    const { error: itemsError } = await supabase.from("retail_catalog_import_job_items").insert(rows.slice(cursor, cursor + 1000));
    if (itemsError) throw new Error(`retail_catalog_import_job_items_insert_failed:${itemsError.message}`);
  }

  await supabase
    .from("retail_catalog_sources")
    .update({
      scrape_status: "queued",
      scrape_notes: `Job Esselunga creato: 0/${urls.length} URL processati.`,
      updated_at: new Date().toISOString(),
    })
    .eq("id", sourceId);

  return await getCatalogImportJobStatus(String(job.id));
};

const processEsselungaCatalogImportJob = async (jobId: string, limit?: unknown) => {
  const supabase = getSupabase();
  const { data: job, error } = await supabase
    .from("retail_catalog_import_jobs")
    .select("*")
    .eq("id", jobId)
    .maybeSingle();
  if (error) throw new Error(`retail_catalog_import_jobs_select_failed:${error.message}`);
  if (!job) throw new Error("Job import catalogo non trovato");
  if (["completed", "failed", "canceled"].includes(String(job.status))) return await getCatalogImportJobStatus(jobId);

  const sourceId = String(job.source_id || "");
  const chunkSize = Math.max(1, Math.min(Number(limit) || Number(job.chunk_size) || 60, 120));
  const { data: items, error: itemsError } = await supabase
    .from("retail_catalog_import_job_items")
    .select("id, url, position")
    .eq("job_id", jobId)
    .in("status", ["queued", "processing"])
    .order("position", { ascending: true })
    .limit(chunkSize);
  if (itemsError) throw new Error(`retail_catalog_import_job_items_select_failed:${itemsError.message}`);

  if (!items?.length) {
    await supabase
      .from("retail_catalog_import_jobs")
      .update({ status: "completed", finished_at: new Date().toISOString(), updated_at: new Date().toISOString() })
      .eq("id", jobId);
    await supabase
      .from("retail_catalog_sources")
      .update({
        scrape_status: Number(job.failed_count || 0) ? "partial" : "ready",
        last_scraped_at: new Date().toISOString(),
        scrape_notes: `Job Esselunga concluso: ${Number(job.ok_count || 0)} ok, ${Number(job.failed_count || 0)} errori, ${Number(job.images_saved || 0)} immagini salvate.`,
        updated_at: new Date().toISOString(),
      })
      .eq("id", sourceId);
    return await getCatalogImportJobStatus(jobId);
  }

  const itemIds = items.map((item) => item.id);
  await supabase
    .from("retail_catalog_import_jobs")
    .update({
      status: "running",
      started_at: job.started_at || new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    .eq("id", jobId);
  await supabase.from("retail_catalog_import_job_items").update({ status: "processing" }).in("id", itemIds);

  let ok = 0;
  let failed = 0;
  let imagesSaved = 0;
  let imageWarnings = 0;
  const results: EsselungaCatalogImportItemResult[] = [];

  for (const item of items) {
    const url = String(item.url || "");
    try {
      const imported = await importOneEsselungaCatalogUrl(sourceId, url, Boolean(job.skip_images));
      ok += 1;
      imagesSaved += imported.imagesSaved;
      imageWarnings += imported.imageWarnings;
      results.push(imported.result);
      await supabase
        .from("retail_catalog_import_job_items")
        .update({
          status: "ok",
          code: imported.result.code || esselungaProductCodeFromUrl(url),
          product_name: imported.result.name || null,
          image_saved: Boolean(imported.result.imageSaved),
          image_error: imported.result.imageError || null,
          error_message: null,
          processed_at: new Date().toISOString(),
        })
        .eq("id", item.id);
    } catch (error) {
      failed += 1;
      const message = logErrorMessage(error);
      const failedResult = { status: "failed" as const, url, code: esselungaProductCodeFromUrl(url), error: message };
      results.push(failedResult);
      await supabase
        .from("retail_catalog_import_job_items")
        .update({
          status: "failed",
          code: failedResult.code,
          error_message: message,
          processed_at: new Date().toISOString(),
        })
        .eq("id", item.id);
    }
  }

  const processedUrls = Number(job.processed_urls || 0) + items.length;
  const totalUrls = Number(job.total_urls || 0);
  const isCompleted = processedUrls >= totalUrls;
  const nextOk = Number(job.ok_count || 0) + ok;
  const nextFailed = Number(job.failed_count || 0) + failed;
  const nextImagesSaved = Number(job.images_saved || 0) + imagesSaved;
  const nextImageWarnings = Number(job.image_warnings || 0) + imageWarnings;

  await supabase
    .from("retail_catalog_import_jobs")
    .update({
      status: isCompleted ? "completed" : "running",
      processed_urls: processedUrls,
      ok_count: nextOk,
      failed_count: nextFailed,
      images_saved: nextImagesSaved,
      image_warnings: nextImageWarnings,
      finished_at: isCompleted ? new Date().toISOString() : null,
      updated_at: new Date().toISOString(),
    })
    .eq("id", jobId);

  await supabase
    .from("retail_catalog_sources")
    .update({
      scrape_status: isCompleted ? (nextFailed ? "partial" : "ready") : "running",
      last_scraped_at: isCompleted ? new Date().toISOString() : job.last_scraped_at,
      scrape_notes: `Job Esselunga: ${processedUrls}/${totalUrls} URL, ${nextOk} ok, ${nextFailed} errori, ${nextImagesSaved} immagini salvate.`,
      updated_at: new Date().toISOString(),
    })
    .eq("id", sourceId);

  const status = await getCatalogImportJobStatus(jobId);
  return status ? { ...status, results: [...(status.results || []), ...results].slice(-40) } : status;
};

const getRetailCatalogSourceOverview = async () => {
  const supabase = getSupabase();
  const { data: sources, error } = await supabase
    .from("retail_catalog_sources")
    .select("id, merchant_key, merchant_name, enabled, scrape_status, scrape_notes, last_scraped_at, updated_at")
    .order("merchant_name", { ascending: true });
  if (error) throw new Error(`retail_catalog_sources_select_failed:${error.message}`);
  return await Promise.all(
    (sources || []).map(async (source) => {
      const { count } = await supabase
        .from("product_external_refs")
        .select("*", { count: "exact", head: true })
        .eq("source_id", source.id);
      return {
        id: source.id,
        merchantKey: source.merchant_key,
        merchantName: source.merchant_name,
        enabled: Boolean(source.enabled),
        scrapeStatus: source.scrape_status || "idle",
        scrapeNotes: source.scrape_notes || "",
        lastScrapedAt: source.last_scraped_at || null,
        updatedAt: source.updated_at || null,
        refsCount: count || 0,
      };
    }),
  );
};

const reviewProductImageWithVision = async (input: {
  productName: string;
  product: Record<string, unknown>;
  imageUrl: string;
  model: string;
  usage?: StraicoUsageContext;
}): Promise<ProductImageVisionReview> => {
  try {
    const content = await completionV1(
      `Verifica se l'immagine mostra davvero il prodotto cercato.

Prodotto cercato: ${input.productName}
Nome normalizzato: ${asStringValue(input.product.name) || "non disponibile"}
Marca: ${asStringValue(input.product.brand) || "non disponibile"}
Formato/peso: ${asStringValue(input.product.weight) || "non disponibile"}

Rispondi SOLO con JSON:
{
  "match": boolean,
  "confidence": numero da 0 a 1,
  "visualProductName": string,
  "reason": string,
  "rejectReason": "different_product | generic_photo | logo_only | shelf_or_recipe | unreadable | unknown"
}

Regole:
- Accetta se l'immagine mostra in modo plausibile la confezione/prodotto coerente con nome, marca o linea prodotto.
- Prediligi immagini pulite tipo packshot: prodotto singolo, frontale, ben illuminato, sfondo bianco o neutro.
- Non rigettare solo per differenze minori di formato, numero pezzi, lingua del packaging o restyling grafico, se marca e linea prodotto sono corrette.
- Per prodotti GDO con nome descrittivo incompleto, accetta una immagine della stessa linea/gusto quando la fonte candidato e coerente.
- Per frutta/verdura o prodotti sfusi generici puoi accettare una foto generica del prodotto se non esiste marca specifica.
- Se il prodotto cercato e frutta fresca semplice (es. "LAMPONI 125 G"), non accettare yogurt, kefir, dessert, confetture, succhi, barrette, torte o prodotti "al lampone": servono frutti freschi/vaschetta/confezione.
- Rifiuta foto di ricette, scaffali, loghi, banner promozionali, ingredienti generici quando il prodotto cercato ha una marca, o prodotti simili ma di marca/gusto/formato diverso.
- A parita di corrispondenza, abbassa molto la confidence per immagini ambientate, promozionali, con sfondo caotico o con piu prodotti non chiaramente pertinenti.
- Se non sei sicuro, match=false.`,
      { model: input.model, images: [input.imageUrl] },
      input.usage,
    );
    const review = extractJson<Record<string, unknown>>(content, {});
    const confidence = Math.max(0, Math.min(1, asOptionalNumber(review.confidence) ?? 0));
    return {
      accepted: asBooleanValue(review.match) && confidence >= 0.62,
      confidence,
      reason: asStringValue(review.reason) || asStringValue(review.rejectReason) || undefined,
    };
  } catch {
    return {
      accepted: false,
      confidence: 0,
      reason: "vision_fetch_failed_or_model_error",
    };
  }
};

const receiptPrompt = (text?: string, documentKind?: string) => `Sei un assistente finanziario AI specializzato in documenti di spesa familiari.

Analizza scontrini, fatture, bonifici, ricevute, movimenti bancari ed estratti conto. Estrai i dati in JSON valido.

Per scontrini devi estrarre ogni singola riga prodotto: nome esatto, quantita, prezzo pagato, prezzo unitario, prezzo pieno se visibile, sconto, IVA, testo riga originale, categoria, confidenza.

Per estratti conto devi estrarre ogni movimento in "movements".
Se visibili, estrai anche periodo, saldo iniziale e saldo finale: "periodStart", "periodEnd", "openingBalance", "closingBalance".
I formati tabellari CSV/Excel possono avere intestazioni molto diverse: Data operazione, Data valuta, Causale, Descrizione, Dare, Avere, Entrate, Uscite, Importo, Saldo, Divisa. Devi adattarti alla banca senza inventare righe.

Per estratti carta di credito devi estrarre ogni singola spesa in "movements". Non contare il pagamento/addebito carta come prodotto. Il totale carta va in "amount" come spesa negativa se visibile, ma le righe restano in "movements".

Per wallet, PayPal e prepagate devi distinguere ricariche/trasferimenti da spese merchant: le ricariche sono movimenti tecnici, le spese merchant sono movimenti reali.

Rispondi SOLO con questo JSON:
{
  "documentType": "receipt | bank_statement | credit_card_statement | wallet_statement | prepaid_statement | invoice | transfer | other",
  "amount": numero,
  "category": "Alimentari | Casa | Trasporti | Svago | Salute | Animali domestici | Cura personale | Entrate | Altro",
  "merchantName": string,
  "merchantAddress": string,
  "periodStart": "YYYY-MM-DD",
  "periodEnd": "YYYY-MM-DD",
  "openingBalance": numero,
  "closingBalance": numero,
  "transactionDate": "YYYY-MM-DD",
  "transactionTime": "HH:mm",
  "paymentMethod": string,
  "items": [{ "name": string, "quantity": numero, "price": numero, "unitPrice": numero, "normalPrice": numero, "discountAmount": numero, "discountLabel": string, "vatRate": numero, "rawText": string, "category": string, "confidence": numero }],
  "movements": [{ "description": string, "amount": numero, "date": "YYYY-MM-DD", "category": string, "type": "income | expense", "confidence": numero, "recurringHint": boolean }],
  "insights": [string],
  "summary": string
}

Regole:
- Spese negative in amount, entrate positive.
- Non inventare importi o date mancanti.
- Per ogni prodotto, "rawText" deve essere la riga originale esatta letta dallo scontrino, senza espansioni web.
- Il campo "name" deve restare ancorato a "rawText": puoi sciogliere abbreviazioni evidenti di marca/prodotto solo se almeno marca o linea sono presenti nella riga originale.
- Se non sei sicuro dell'espansione, usa come "name" il testo prodotto dello scontrino ripulito da IVA/prezzo, abbassa "confidence" sotto 0.60 e aggiungi un insight "Riga da verificare".
- Se il merchant/supermercato e visibile, usalo come contesto per capire reparto e prodotto, ma non basta da solo per cambiare identita alla riga.
- Se uno scontrino non e GDO/supermercato o contiene servizi/negozi particolari, estrai righe generiche conservative e non forzare catalogazione prodotto: categoria "Altro" o categoria evidente, confidence bassa se incerto.
- Se "name" e molto piu lungo o semanticamente diverso da "rawText", la confidence deve essere bassa; se non ci sono token comuni significativi, conserva "rawText" pulito come nome.
- Non usare conoscenza web per trasformare codici o abbreviazioni ambigue in prodotti non dimostrati dalla riga originale.
- Non includere mai totali, subtotali, IVA, pagamento carta, ricevute POS, resto, coupon, buoni, punti fedelta o righe sconto come prodotti.
- Esempi da NON mettere in "items": "SCONTO FIDATY", "Sconto Fidaty", "Totale sconti", "Punti Fidaty", "Buono/Coupon", "Pagamento", "Resto", "IVA", "Totale", "Subtotale".
- Se uno sconto e chiaramente collegato a un prodotto, valorizza "discountAmount" e "discountLabel" su quel prodotto; se lo sconto e generico, mettilo negli insight e non come prodotto.
- Per scontrini supermercato, righe come "ULTIMA MAN&RIS 440G", "GOURMET", "FRSK/FRISKIES", "REVELATIONS" sono prodotti per animali domestici: non espanderle in prodotti industriali solo perche contengono codici/formati come 440G.
- Esempio: se leggi "6BT NORDA NAT" puoi classificarlo come bevanda/acqua Norda, ma non devi cambiare brand o formato oltre quanto e plausibile dalla riga.
- Negli estratti CSV/Excel ignora righe di intestazione, saldi, totali e note; se importo e separato in Dare/Avere, Dare/Uscite sono negative e Avere/Entrate positive.
- Negli estratti carta distingui spese merchant, rimborsi e addebito sul conto: le spese/rimborsi vanno in movements; l'addebito carta non e una riga prodotto.
- Per foto/PDF difficili usa confidenza bassa e warning negli insight.
${documentKind && documentKind !== "auto" ? `- L'utente ha indicato tipo documento probabile: ${documentKind}. Usalo come hint, ma correggilo se il documento dimostra altro.` : ""}
${text ? `\nTESTO DOCUMENTO:\n${text}` : ""}`;

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  try {
    const authorization = request.headers.get("Authorization");
    const publicSupabaseUrl = getPublicSupabaseUrl(new URL(request.url).origin);
    const user = await assertUser(authorization);
    const { action, args } = await request.json();
    const models = await getModelSettings();

    if (action === "health") {
      return json({
        straicoConfigured: Boolean(Deno.env.get("STRAICO_API_KEY")),
        productImageSearch: {
          serpApiConfigured: Boolean(Deno.env.get("SERPAPI_API_KEY")),
          apifyConfigured: Boolean(Deno.env.get("APIFY_API_TOKEN")),
          apifyActorConfigured: Boolean(Deno.env.get("APIFY_GOOGLE_IMAGES_ACTOR_ID")),
        },
        models,
      });
    }

    if (action === "models") {
      assertSuperAdmin(user);
      return json({
        models: await fetchStraicoModels(),
        fetchedAt: new Date().toISOString(),
      });
    }

    if (action === "catalog_sources") {
      assertSuperAdmin(user);
      return json({
        sources: await getRetailCatalogSourceOverview(),
        fetchedAt: new Date().toISOString(),
      });
    }

    if (action === "catalog_import_esselunga") {
      assertSuperAdmin(user);
      return json({
        importResult: await importEsselungaCatalogUrls({
          urls: args?.urls,
          max: args?.max,
          skipImages: Boolean(args?.skipImages),
        }),
        fetchedAt: new Date().toISOString(),
      });
    }

    if (action === "catalog_import_esselunga_job_create") {
      assertSuperAdmin(user);
      return json({
        job: await createEsselungaCatalogImportJob(
          {
            urls: args?.urls,
            skipImages: Boolean(args?.skipImages),
            chunkSize: args?.chunkSize,
          },
          user.id,
        ),
        fetchedAt: new Date().toISOString(),
      });
    }

    if (action === "catalog_import_job_status") {
      assertSuperAdmin(user);
      return json({
        job: await getCatalogImportJobStatus(args?.jobId ? String(args.jobId) : undefined),
        fetchedAt: new Date().toISOString(),
      });
    }

    if (action === "catalog_import_job_process") {
      assertSuperAdmin(user);
      return json({
        job: await processEsselungaCatalogImportJob(String(args?.jobId || ""), args?.limit),
        fetchedAt: new Date().toISOString(),
      });
    }

    if (action === "platform_overview") {
      assertSuperAdmin(user);
      return json({
        overview: await getAdminPlatformOverview(),
        fetchedAt: new Date().toISOString(),
      });
    }

    if (action === "receipt_analyze") {
      const images = args?.images as string[] | undefined;
      const text = args?.text as string | undefined;
      const documentKind = args?.documentKind ? String(args.documentKind) : undefined;
      const householdId = await getUserHouseholdId(user.id);
      const usage = {
        activity: "document_analysis",
        userId: user.id,
        userEmail: user.email,
        householdId,
        model: images?.length || args?.fileUrls?.length ? models.documentAnalysis : models.chat,
      };
      const content =
        images?.length || args?.fileUrls?.length
          ? await completionV1(receiptPrompt(text, documentKind), {
              images,
              fileUrls: args?.fileUrls,
              model: models.documentAnalysis,
            }, usage)
          : await completionV0(receiptPrompt(text, documentKind), { model: models.chat }, usage);
      return json({ analysis: extractJson(content, { summary: content || "Documento analizzato" }) });
    }

    if (action === "product_enrich") {
      const runStartedAt = performance.now();
      const productName = String(args?.productName || "");
      const currentCategory = args?.currentCategory ? String(args.currentCategory) : undefined;
      const allowImageSearch = Boolean(args?.allowImageSearch);
      const productId = args?.productId ? String(args.productId) : undefined;
      const merchantName = args?.merchantName ? String(args.merchantName) : undefined;
      const householdId = await getUserHouseholdId(user.id);
      const runId = await createProductEnrichmentRun({
        authorization: authorization!,
        publicSupabaseUrl,
        productId,
        householdId,
        userId: user.id,
        productName,
        merchantName,
        category: currentCategory,
        modelProductResearch: models.productResearch,
        modelVision: models.documentAnalysis,
        input: {
          action,
          productName,
          currentCategory,
          allowImageSearch,
          productId,
          merchantName,
          constraints: [
            "catalog only",
            "no API keys in browser",
            "GDO image search only",
            "store mirrored images in Supabase Storage",
          ],
        },
      });
      const logger: ProductEnrichmentLogger = (event) =>
        logProductEnrichmentEvent(authorization!, publicSupabaseUrl, runId, event);
      const merchantHint = merchantName
        ? `\nSupermercato/merchant dello scontrino: "${merchantName}". Usalo solo come contesto per marca, reparto e ricerca immagini: non inventare prodotti fuori dalla riga originale.`
        : "";
      const productResearchPrompt = `Sei un esperto di prodotti del mercato italiano. Arricchisci una voce prodotto per un catalogo globale.

Rispondi SOLO con JSON:
{
  "name": string,
  "category": string,
  "subcategory": string,
  "brand": string,
  "weight": string,
  "unit": string,
  "typicalPriceRange": { "min": numero, "max": numero },
  "aliases": [string],
  "merchantCategories": [string],
  "enrichmentSource": "straico",
  "imageUrl": string | null,
  "imageSource": string | null,
  "imageStoragePath": string | null,
  "imageSourceUrl": string | null,
  "imageConfidence": numero,
  "confidence": numero,
  "notes": string
}

Regole immagini:
- Non inventare URL immagine.
- Le immagini automatiche sono consentite solo se il backend passa una fonte verificata.
- Se non hai una fonte verificata, lascia "imageUrl": null.

Regole anti-allucinazione:
- Non trasformare abbreviazioni da scontrino in prodotti di settori diversi.
- Se la categoria attuale e' alimentare/GDO, non proporre prodotti industriali, elettronici, ricambi, automazione o B2B.
- Il nome originale dello scontrino resta la fonte primaria: puoi suggerire marca/formato solo se coerenti, non sostituire il prodotto.
- Il supermercato/merchant deve essere incluso nel ragionamento di ricerca immagini e reparto, ma non deve mai giustificare un prodotto non coerente con il testo originale.
- Se il prodotto non e abbastanza certo, lascia nome/categoria originali e confidence sotto 0.65; l'utente lo correggera inline.
- I codici peso/formato come "440G" non bastano mai per cambiare identita o settore del prodotto.
- Esempio importante: "ULTIMA MAN&RIS 440G" da scontrino Esselunga e' una riga GDO/pet food, non "Guardmaster 440G-MZ" e non Rockwell Automation. Se non sai espandere l'abbreviazione, lascia il nome originale e confidenza bassa.

Prodotto: "${productName}"${currentCategory ? `, categoria attuale: "${currentCategory}"` : ""}${merchantHint}`;
      let content = "";
      const metadataStartedAt = performance.now();
      try {
        content = await completionV0(productResearchPrompt, { model: models.productResearch }, {
          activity: "product_metadata_research",
          userId: user.id,
          userEmail: user.email,
          householdId,
          productEnrichmentRunId: runId,
          model: models.productResearch,
        });
      } catch (error) {
        await logger({
          step: "product_metadata_research",
          provider: "straico",
          status: "failed",
          durationMs: Math.round(performance.now() - metadataStartedAt),
          request: { model: models.productResearch, productName, currentCategory, merchantName, prompt: productResearchPrompt },
          error: logErrorMessage(error),
        });
        await finishProductEnrichmentRun(authorization!, publicSupabaseUrl, runId, {
          status: "failed",
          durationMs: Math.round(performance.now() - runStartedAt),
          output: { error: logErrorMessage(error) },
        });
        throw error;
      }
      const extractedProduct = extractJson(content, {
        name: productName,
        category: currentCategory || "Altro",
        confidence: 0.5,
        enrichmentSource: "straico",
      }) as Record<string, unknown>;
      const { product, unsafe } = keepOnlySafeProductResearch(productName, currentCategory, extractedProduct);
      await logger({
        step: "product_metadata_research",
        provider: "straico",
        status: unsafe ? "rejected" : "success",
        durationMs: Math.round(performance.now() - metadataStartedAt),
        request: { model: models.productResearch, productName, currentCategory, merchantName, prompt: productResearchPrompt },
        response: { rawContent: content, extractedProduct, safeProduct: product, unsafe },
        error: unsafe ? "metadata_incompatible_with_receipt_line_guardrail" : undefined,
      });

      let imageCandidate: ProductImageCandidate | null = null;
      let mirroredImage: Awaited<ReturnType<typeof mirrorProductImageToStorage>> | null = null;
      let imageVisionReview: ProductImageVisionReview | null = null;
      let imageSearchStatus = allowImageSearch ? "no_candidates" : "disabled";
      let imageSearchCandidatesFound = 0;
      let imageSearchCandidatesReviewed = 0;
      let imageSearchLastRejectReason: string | null = null;
      if (allowImageSearch && unsafe) {
        imageSearchStatus = "guardrail_rejected";
        imageSearchLastRejectReason = "ai_product_metadata_incompatible_with_receipt_line";
        await logger({
          step: "image_search_guardrail",
          provider: "financecompass",
          status: "rejected",
          request: { productName, currentCategory, merchantName, allowImageSearch },
          response: { imageSearchStatus, imageSearchLastRejectReason, product },
          error: imageSearchLastRejectReason,
        });
      }
      if (allowImageSearch && !unsafe) {
        const officialSource = officialCatalogSourceForMerchant(merchantName);
        const candidateProviders: Array<() => Promise<ProductImageCandidate[]>> = [
          () => fetchOfficialCatalogImageCandidates({ rawName: productName, product, merchantName, logger }),
        ];
        if (!officialSource) {
          candidateProviders.push(
            () => fetchSerpApiGoogleImageCandidates({ rawName: productName, product, merchantName, logger }),
            () => fetchApifyGoogleImageCandidates({ rawName: productName, product, merchantName, logger }),
            async () => {
              const startedAt = performance.now();
              const candidate = await fetchOpenFoodFactsCandidate(productName);
              await logger({
                step: "image_search",
                provider: "openfoodfacts",
                status: candidate?.imageUrl ? "success" : "success",
                durationMs: Math.round(performance.now() - startedAt),
                request: { productName },
                response: {
                  selectedCandidates: candidate?.imageUrl
                    ? [{
                        imageUrl: candidate.imageUrl,
                        source: candidate.imageSource,
                        confidence: candidate.imageConfidence,
                        name: candidate.name,
                        brand: candidate.brand,
                      }]
                    : [],
                },
              });
              return candidate?.imageUrl ? [candidate] : [];
            },
          );
        } else {
          await logger({
            step: "image_search_policy",
            provider: "financecompass",
            status: "success",
            request: { productName, merchantName, merchantKey: officialSource.key },
            response: {
              policy: "official_catalog_only_for_known_supermarket",
              disabledFallbackProviders: ["serpapi_google_images_light", "apify_google_images", "openfoodfacts"],
            },
          });
        }

        let visionReviews = 0;
        for (const getCandidates of candidateProviders) {
          if (visionReviews >= PRODUCT_IMAGE_VISION_REVIEW_LIMIT) break;
          const candidates = await getCandidates();
          imageSearchCandidatesFound += candidates.length;
          for (const candidate of candidates) {
            if (visionReviews >= PRODUCT_IMAGE_VISION_REVIEW_LIMIT) break;
            if (rejectIncompatibleProductImageCandidate(productName, candidate)) {
              imageSearchStatus = "guardrail_rejected";
              imageSearchLastRejectReason = "fresh_produce_incompatible_candidate";
              await logger({
                step: "image_candidate_guardrail",
                provider: candidate.imageSource,
                status: "rejected",
                request: {
                  productName,
                  merchantName,
                  candidateImageUrl: candidate.imageUrl,
                  candidateSourceUrl: candidate.imageSourceUrl,
                  candidateContext: candidate.contextText,
                },
                error: imageSearchLastRejectReason,
              });
              continue;
            }
            const mirrorStartedAt = performance.now();
            const mirrored = await mirrorProductImageToStorage({
              sourceUrl: candidate.imageUrl,
              productName: candidate.name || asStringValue(product.name) || productName,
              productId,
            });
            if (!mirrored?.publicUrl) {
              imageSearchStatus = "candidate_download_failed";
              await logger({
                step: "candidate_download_and_storage",
                provider: candidate.imageSource,
                status: "failed",
                durationMs: Math.round(performance.now() - mirrorStartedAt),
                request: {
                  sourceUrl: candidate.imageUrl,
                  sourcePage: candidate.imageSourceUrl,
                  productName: candidate.name || productName,
                },
                error: "download_or_storage_upload_failed",
              });
              continue;
            }
            await logger({
              step: "candidate_download_and_storage",
              provider: candidate.imageSource,
              status: "success",
              durationMs: Math.round(performance.now() - mirrorStartedAt),
              request: {
                sourceUrl: candidate.imageUrl,
                sourcePage: candidate.imageSourceUrl,
                productName: candidate.name || productName,
              },
              response: {
                publicUrl: mirrored.publicUrl,
                storagePath: mirrored.storagePath,
                contentType: mirrored.contentType,
                size: mirrored.size,
              },
            });

            visionReviews += 1;
            imageSearchCandidatesReviewed = visionReviews;
            const visionStartedAt = performance.now();
            const review = await reviewProductImageWithVision({
              productName,
              product,
              imageUrl: candidate.imageUrl,
              model: models.documentAnalysis,
              usage: {
                activity: "product_image_vision_review",
                userId: user.id,
                userEmail: user.email,
                householdId,
                productEnrichmentRunId: runId,
                model: models.documentAnalysis,
              },
            });
            const fallbackAccepted =
              !review.accepted &&
              isVisionTechnicalFailure(review.reason) &&
              shouldAcceptTrustedCandidateWhenVisionFails({ candidate, productName, product, merchantName });
            const trustedSourceOverrideAccepted =
              !review.accepted &&
              !fallbackAccepted &&
              shouldAcceptTrustedCandidateDespiteVisionReject({ candidate, productName, product, merchantName, review });
            const finalReview = fallbackAccepted
              ? {
                  accepted: true,
                  confidence: Math.max(candidate.imageConfidence, 0.68),
                  reason: `trusted_source_fallback_after_${review.reason || "vision_error"}`,
                }
              : trustedSourceOverrideAccepted
                ? {
                    accepted: true,
                    confidence: Math.max(candidate.imageConfidence, 0.66),
                    reason: `trusted_source_override_after_${review.reason || "vision_rejected"}`,
                  }
              : review;
            await logger({
              step: "vision_image_review",
              provider: "straico",
              status: finalReview.accepted ? "success" : "rejected",
              durationMs: Math.round(performance.now() - visionStartedAt),
              request: {
                model: models.documentAnalysis,
                productName,
                candidateImageUrl: candidate.imageUrl,
                candidateSourceUrl: candidate.imageSourceUrl,
                mirroredStorageUrl: mirrored.publicUrl,
              },
              response: {
                accepted: finalReview.accepted,
                confidence: finalReview.confidence,
                reason: finalReview.reason,
                visionAccepted: review.accepted,
                visionConfidence: review.confidence,
                visionReason: review.reason,
                fallbackAccepted,
                trustedSourceOverrideAccepted,
              },
              error: finalReview.accepted ? undefined : finalReview.reason || "vision_rejected",
            });

            if (finalReview.accepted) {
              imageCandidate = candidate;
              mirroredImage = mirrored;
              imageVisionReview = finalReview;
              imageSearchStatus = "accepted";
              imageSearchLastRejectReason = null;
              await upsertReceiptMatchIndex({
                householdId,
                userId: user.id,
                rawName: productName,
                merchantName,
                canonicalName: candidate.name || asStringValue(product.name) || productName,
                brand: candidate.brand || asStringValue(product.brand) || undefined,
                category: asStringValue(product.category) || currentCategory,
                productId,
                externalRefId: candidate.externalRefId,
                confidence: Math.max(candidate.imageConfidence, finalReview.confidence),
                matchSource: candidate.imageSource?.startsWith("official_catalog") ? "official_catalog_image_enrichment" : "image_enrichment",
              });
              break;
            }
            imageSearchStatus = "vision_rejected";
            imageSearchLastRejectReason = finalReview.reason || null;
            await removeProductImageFromStorage(mirrored.storagePath);
            await logger({
              step: "storage_cleanup",
              provider: PRODUCT_IMAGE_BUCKET,
              status: "success",
              request: { storagePath: mirrored.storagePath, reason: finalReview.reason || "vision_rejected" },
              response: { removed: true },
            });
          }
          if (mirroredImage?.publicUrl) {
            break;
          }
        }
        if (officialSource && !mirroredImage?.publicUrl && imageSearchCandidatesFound === 0) {
          imageSearchStatus = "official_catalog_missing";
          imageSearchLastRejectReason = "official_catalog_missing_or_not_imported";
          await logger({
            step: "image_search_policy",
            provider: "financecompass",
            status: "skipped",
            request: { productName, merchantName, merchantKey: officialSource.key },
            response: {
              reason: imageSearchLastRejectReason,
              fallbackProvidersSkipped: true,
            },
          });
        }
      }

      if (allowImageSearch && imageCandidate?.imageUrl && mirroredImage?.publicUrl) {
        product.name = productName;
        product.brand = product.brand || imageCandidate.brand;
        product.weight = product.weight || imageCandidate.weight;
        product.imageUrl = mirroredImage.publicUrl;
        product.imageSource = `${imageCandidate.imageSource}->${PRODUCT_IMAGE_BUCKET}`;
        product.imageSourceUrl = imageCandidate.imageSourceUrl || imageCandidate.imageUrl;
        product.imageStoragePath = mirroredImage.storagePath;
        product.imageConfidence = imageCandidate.imageConfidence;
        product.imageVisionConfidence = imageVisionReview?.confidence ?? null;
        product.imageVisionReason = imageVisionReview?.reason || null;
        product.imageSearchStatus = imageSearchStatus;
        product.imageSearchCandidatesFound = imageSearchCandidatesFound;
        product.imageSearchCandidatesReviewed = imageSearchCandidatesReviewed;
        product.imageSearchLastRejectReason = null;
        product.enrichmentSource = `straico+${imageCandidate.imageSource}+storage`;
        product.merchantCategories = Array.from(
          new Set([
            ...((Array.isArray(product.merchantCategories) ? product.merchantCategories : []) as string[]),
            ...(imageCandidate.merchantCategories || []),
          ]),
        );
      } else {
        product.imageUrl = null;
        product.imageSource = null;
        product.imageSourceUrl = null;
        product.imageStoragePath = null;
        product.imageVisionConfidence = null;
        product.imageVisionReason = null;
        product.imageSearchStatus = imageSearchStatus;
        product.imageSearchCandidatesFound = imageSearchCandidatesFound;
        product.imageSearchCandidatesReviewed = imageSearchCandidatesReviewed;
        product.imageSearchLastRejectReason = imageSearchLastRejectReason;
      }

      const imageSaved = Boolean(allowImageSearch && product.imageUrl);
      const finalRunStatus = allowImageSearch
        ? unsafe
          ? "guardrail_rejected"
          : imageSaved
            ? "success"
            : "no_image"
        : "success";
      await finishProductEnrichmentRun(authorization!, publicSupabaseUrl, runId, {
        status: finalRunStatus,
        imageSaved,
        imageUrl: asStringValue(product.imageUrl) || null,
        imageSearchStatus,
        candidatesFound: imageSearchCandidatesFound,
        candidatesReviewed: imageSearchCandidatesReviewed,
        lastRejectReason: imageSaved ? null : imageSearchLastRejectReason || asStringValue(product.imageVisionReason) || null,
        durationMs: Math.round(performance.now() - runStartedAt),
        output: {
          product,
          imageSaved,
          imageSearchStatus,
          imageSearchCandidatesFound,
          imageSearchCandidatesReviewed,
          imageSearchLastRejectReason: imageSaved ? null : imageSearchLastRejectReason,
        },
      });

      return json({
        product,
      });
    }

    if (action === "advisor_ask") {
      const answer = await completionV0(
        `Sei il copilota finanziario di una famiglia. Rispondi in italiano, in modo pratico.

Usa SOLO i dati nel contesto. Se un dato manca, dillo e suggerisci l'azione successiva.
Il contesto e' un RAG privato del tenant: contiene dati minimizzati/redatti e identificativi Fonte.
Quando rispondi a domande su importi, date, carta, trend o anomalie, cita le fonti rilevanti nel testo usando gli identificativi Fonte disponibili.
Non chiedere dati personali non necessari e non ricostruire dati redatti.

CONTESTO:
${args?.financialContext || ""}

DOMANDA:
${args?.question || ""}`,
        { model: models.ragChat || models.chat },
        {
          activity: "rag_chat",
          userId: user.id,
          userEmail: user.email,
          householdId: await getUserHouseholdId(user.id),
          model: models.ragChat || models.chat,
        },
      );
      return json({ answer });
    }

    return json({ error: "unknown_action" }, 400);
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "Errore Straico" }, 500);
  }
});
