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

const extractJson = <T>(content: string, fallback: T): T => {
  try {
    const match = content.match(/\{[\s\S]*\}/);
    return match ? (JSON.parse(match[0]) as T) : fallback;
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

const getModelSettings = async (): Promise<StraicoModelSettings> => {
  const supabase = getSupabase();
  const { data } = await supabase
    .from("app_settings")
    .select("value_json")
    .eq("key", "straico_models")
    .maybeSingle();

  return { ...DEFAULT_MODELS, ...((data?.value_json as Partial<StraicoModelSettings> | null) || {}) };
};

const postStraico = async (path: string, body: unknown) => {
  const response = await fetch(`${STRAICO_BASE_URL}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${requireEnv("STRAICO_API_KEY")}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const payload = await response.text().catch(() => "");
    throw new Error(payload || `Straico error ${response.status}`);
  }

  return response.json() as Promise<StraicoCompletionPayload>;
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

const completionV0 = async (message: string, options: { model?: string; smart?: "quality" | "balance" | "budget" }) => {
  const body = options.smart
    ? { smart_llm_selector: options.smart, message, temperature: 0.35, max_tokens: 2200, replace_failed_models: true }
    : { model: options.model || DEFAULT_MODELS.chat, message, temperature: 0.35, max_tokens: 2200, replace_failed_models: true };
  const data = await postStraico("/v0/prompt/completion", body);
  return String(data?.data?.completion?.choices?.[0]?.message?.content || "");
};

const completionV1 = async (message: string, input: { model?: string; images?: string[]; fileUrls?: string[] }) => {
  const model = input.model || DEFAULT_MODELS.documentAnalysis;
  const data = await postStraico("/v1/prompt/completion", {
    models: [model],
    message,
    images: input.images?.slice(0, 4),
    file_urls: input.fileUrls?.slice(0, 4),
    temperature: 0.2,
    max_tokens: 3000,
    replace_failed_models: true,
  });
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
  name?: string;
  brand?: string;
  weight?: string;
  imageUrl: string;
  imageSource: string;
  imageSourceUrl?: string;
  merchantCategories?: string[];
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

const productImageSearchQueries = (input: { rawName: string; product: Record<string, unknown> }) => {
  const rawName = asStringValue(input.rawName);
  const name = asStringValue(input.product.name) || rawName;
  const brand = asStringValue(input.product.brand);
  const weight = asStringValue(input.product.weight);
  const base = [brand, name, weight].filter(Boolean).join(" ").replace(/\s+/g, " ").trim();
  const queries = [
    `${base} prodotto confezione sfondo bianco`,
    `${base} immagine prodotto`,
    `${rawName} prodotto supermercato`,
  ]
    .map((query) => query.replace(/\b(sconto|fidaty|fidati|punti|totale|iva|pos)\b/gi, "").replace(/\s+/g, " ").trim())
    .filter((query) => query.length >= 4);
  return Array.from(new Set(queries)).slice(0, 2);
};

const trustedProductImageSourcePattern =
  /(esselunga|coop|conad|carrefour|pam|selex|despar|iper|crai|bennet|tigros|supermercato|supermercati|spesaonline|openfoodfacts|amazon|everli|cortilia|alce nero|barilla|mulino bianco|lavazza|granoro|rummo|granolo|granarolo|muller|dash|dixan|rio mare|mutti|findus|cameo|galbani|parmalat|nescafe|san benedetto|sant'anna|valfrutta|bauli|ferrero)/i;

const cleanPackshotPattern = /(packshot|confezione|prodotto|product|white|bianco|png|frontale|front)/i;
const noisyImagePattern = /(recipe|ricetta|scaffale|shelf|volantino|catalogo|banner|promo|offerta|blog|news|article|ingredienti|ingredients)/i;

const scoreProductImageCandidate = (item: Record<string, unknown>, productName: string) => {
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
  const matches = tokens.filter((token) => haystack.includes(token)).length;
  const trustedDomain = trustedProductImageSourcePattern.test(haystack);
  const producerDomain = /(\.it|\.com|\.eu)/i.test(haystack);
  const cleanPackshot = cleanPackshotPattern.test(haystack);
  const noisyImage = noisyImagePattern.test(haystack);
  return matches * 8 + (trustedDomain ? 14 : 0) + (producerDomain ? 2 : 0) + (cleanPackshot ? 5 : 0) - (noisyImage ? 8 : 0);
};

const fetchSerpApiGoogleImageCandidates = async (input: {
  rawName: string;
  product: Record<string, unknown>;
}): Promise<ProductImageCandidate[]> => {
  const apiKey = Deno.env.get("SERPAPI_API_KEY");
  if (!apiKey) return [];

  const query = productImageSearchQueries(input)[0];
  if (!query) return [];

  const url = new URL("https://serpapi.com/search.json");
  url.searchParams.set("engine", "google_images_light");
  url.searchParams.set("q", query);
  url.searchParams.set("google_domain", "google.it");
  url.searchParams.set("gl", "it");
  url.searchParams.set("hl", "it");
  url.searchParams.set("safe", "active");
  url.searchParams.set("filter", "1");
  url.searchParams.set("api_key", apiKey);

  try {
    const response = await fetch(url.toString(), {
      headers: { Accept: "application/json", "User-Agent": "FinanceCompass/1.0 product-image-search" },
      signal: AbortSignal.timeout(25000),
    });
    if (!response.ok) return [];

    const payload = await response.json() as { images_results?: unknown[] };
    const rows = Array.isArray(payload.images_results) ? payload.images_results : [];
    const productName = asStringValue(input.product.name) || input.rawName;
    const seen = new Set<string>();

    return rows
      .map((row) => asRecord(row))
      .map((row) => {
        const original = asStringValue(row.original);
        if (!/^https?:\/\//i.test(original) || seen.has(original) || Boolean(row.unsafe)) return null;
        seen.add(original);
        const score = scoreProductImageCandidate(row, productName) + (row.is_product === true ? 16 : 0);
        return {
          candidate: {
            name: productName,
            brand: asStringValue(input.product.brand) || undefined,
            weight: asStringValue(input.product.weight) || undefined,
            imageUrl: original,
            imageSource: "serpapi_google_images_light",
            imageSourceUrl: asStringValue(row.link) || asStringValue(row.raw_link) || original,
            merchantCategories: ["Google Images Light", "SerpApi", asStringValue(row.source)].filter(Boolean),
            imageConfidence: Math.min(0.9, 0.6 + Math.max(0, Math.min(score, 30)) / 100),
          } satisfies ProductImageCandidate,
          score,
        };
      })
      .filter((entry): entry is { candidate: ProductImageCandidate; score: number } => Boolean(entry))
      .sort((a, b) => b.score - a.score)
      .map((entry) => entry.candidate)
      .slice(0, 8);
  } catch {
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

const scoreApifyImageCandidate = (item: Record<string, unknown>, productName: string) => {
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
  const matches = tokens.filter((token) => haystack.includes(token)).length;
  const trustedDomain = trustedProductImageSourcePattern.test(haystack);
  const producerDomain = /(\.it|\.com|\.eu)/i.test(haystack);
  const cleanPackshot = cleanPackshotPattern.test(haystack);
  const noisyImage = noisyImagePattern.test(haystack);
  return matches * 8 + (trustedDomain ? 12 : 0) + (producerDomain ? 2 : 0) + (cleanPackshot ? 5 : 0) - (noisyImage ? 8 : 0);
};

const fetchApifyGoogleImageCandidates = async (input: {
  rawName: string;
  product: Record<string, unknown>;
}): Promise<ProductImageCandidate[]> => {
  const token = Deno.env.get("APIFY_API_TOKEN");
  if (!token) return [];

  const queries = productImageSearchQueries(input);
  if (!queries.length) return [];

  const actorId = Deno.env.get("APIFY_GOOGLE_IMAGES_ACTOR_ID") || "tnudF2IxzORPhg4r8";
  const url = new URL(`https://api.apify.com/v2/acts/${encodeURIComponent(actorId)}/run-sync-get-dataset-items`);
  url.searchParams.set("timeout", "90");
  url.searchParams.set("clean", "true");

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
    if (!response.ok) return [];

    const payload = await response.json();
    const rows = Array.isArray(payload) ? payload : flattenModelsPayload(payload);
    const productName = asStringValue(input.product.name) || input.rawName;
    const seen = new Set<string>();

    return rows
      .map((row) => asRecord(row))
      .map((row) => {
        const imageUrl = extractApifyImageUrl(row);
        if (!imageUrl || seen.has(imageUrl)) return null;
        seen.add(imageUrl);
        const score = scoreApifyImageCandidate(row, productName);
        return {
          candidate: {
            name: productName,
            brand: asStringValue(input.product.brand) || undefined,
            weight: asStringValue(input.product.weight) || undefined,
            imageUrl,
            imageSource: "apify_google_images",
            imageSourceUrl: extractApifySourceUrl(row) || imageUrl,
            merchantCategories: ["Google Images", "Apify"],
            imageConfidence: Math.min(0.86, 0.58 + Math.max(0, Math.min(score, 28)) / 100),
          } satisfies ProductImageCandidate,
          score,
        };
      })
      .filter((entry): entry is { candidate: ProductImageCandidate; score: number } => Boolean(entry))
      .sort((a, b) => b.score - a.score)
      .map((entry) => entry.candidate)
      .slice(0, 6);
  } catch {
    return [];
  }
};

const PRODUCT_IMAGE_MAX_BYTES = 6 * 1024 * 1024;
const PRODUCT_IMAGE_BUCKET = "product-images";
const PRODUCT_IMAGE_VISION_REVIEW_LIMIT = 3;

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

    const { data } = supabase.storage.from(PRODUCT_IMAGE_BUCKET).getPublicUrl(path);
    if (!data.publicUrl) return null;

    return {
      publicUrl: data.publicUrl,
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

const reviewProductImageWithVision = async (input: {
  productName: string;
  product: Record<string, unknown>;
  imageUrl: string;
  model: string;
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
- Accetta solo se l'immagine mostra la confezione/prodotto coerente con nome e marca.
- Prediligi immagini pulite tipo packshot: prodotto singolo, frontale, ben illuminato, sfondo bianco o neutro.
- Per frutta/verdura o prodotti sfusi generici puoi accettare una foto generica del prodotto se non esiste marca specifica.
- Rifiuta foto di ricette, scaffali, loghi, banner promozionali, ingredienti generici quando il prodotto cercato ha una marca, o prodotti simili ma di marca/gusto/formato diverso.
- A parita di corrispondenza, abbassa molto la confidence per immagini ambientate, promozionali, con sfondo caotico o con piu prodotti non chiaramente pertinenti.
- Se non sei sicuro, match=false.`,
      { model: input.model, images: [input.imageUrl] },
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
      reason: "vision_review_failed",
    };
  }
};

const receiptPrompt = (text?: string, documentKind?: string) => `Sei un assistente finanziario AI specializzato in documenti di spesa familiari.

Analizza scontrini, fatture, bonifici, ricevute, movimenti bancari ed estratti conto. Estrai i dati in JSON valido.

Per scontrini devi estrarre ogni singola riga prodotto: nome esatto, quantita, prezzo pagato, prezzo unitario, prezzo pieno se visibile, sconto, IVA, testo riga originale, categoria, confidenza.

Per estratti conto devi estrarre ogni movimento in "movements".
Se visibili, estrai anche periodo, saldo iniziale e saldo finale: "periodStart", "periodEnd", "openingBalance", "closingBalance".

Per estratti carta di credito devi estrarre ogni singola spesa in "movements". Non contare il pagamento/addebito carta come prodotto. Il totale carta va in "amount" come spesa negativa se visibile, ma le righe restano in "movements".

Per wallet, PayPal e prepagate devi distinguere ricariche/trasferimenti da spese merchant: le ricariche sono movimenti tecnici, le spese merchant sono movimenti reali.

Rispondi SOLO con questo JSON:
{
  "documentType": "receipt | bank_statement | credit_card_statement | wallet_statement | prepaid_statement | invoice | transfer | other",
  "amount": numero,
  "category": "Alimentari | Casa | Trasporti | Svago | Salute | Entrate | Altro",
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
- Non includere mai totali, subtotali, IVA, pagamento carta, ricevute POS, resto, coupon, buoni, punti fedelta o righe sconto come prodotti.
- Esempi da NON mettere in "items": "SCONTO FIDATY", "Sconto Fidaty", "Totale sconti", "Punti Fidaty", "Buono/Coupon", "Pagamento", "Resto", "IVA", "Totale", "Subtotale".
- Se uno sconto e chiaramente collegato a un prodotto, valorizza "discountAmount" e "discountLabel" su quel prodotto; se lo sconto e generico, mettilo negli insight e non come prodotto.
- Per foto/PDF difficili usa confidenza bassa e warning negli insight.
${documentKind && documentKind !== "auto" ? `- L'utente ha indicato tipo documento probabile: ${documentKind}. Usalo come hint, ma correggilo se il documento dimostra altro.` : ""}
${text ? `\nTESTO DOCUMENTO:\n${text}` : ""}`;

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  try {
    const user = await assertUser(request.headers.get("Authorization"));
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

    if (action === "receipt_analyze") {
      const images = args?.images as string[] | undefined;
      const text = args?.text as string | undefined;
      const documentKind = args?.documentKind ? String(args.documentKind) : undefined;
      const content =
        images?.length || args?.fileUrls?.length
          ? await completionV1(receiptPrompt(text, documentKind), {
              images,
              fileUrls: args?.fileUrls,
              model: models.documentAnalysis,
            })
          : await completionV0(receiptPrompt(text, documentKind), { model: models.chat });
      return json({ analysis: extractJson(content, { summary: content || "Documento analizzato" }) });
    }

    if (action === "product_enrich") {
      const productName = String(args?.productName || "");
      const currentCategory = args?.currentCategory ? String(args.currentCategory) : undefined;
      const allowImageSearch = Boolean(args?.allowImageSearch);
      const productId = args?.productId ? String(args.productId) : undefined;
      const content = await completionV0(
        `Sei un esperto di prodotti del mercato italiano. Arricchisci una voce prodotto per un catalogo globale.

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

Prodotto: "${productName}"${currentCategory ? `, categoria attuale: "${currentCategory}"` : ""}`,
        { model: models.productResearch },
      );
      const product = extractJson(content, {
        name: productName,
        category: currentCategory || "Altro",
        confidence: 0.5,
        enrichmentSource: "straico",
      }) as Record<string, unknown>;

      let imageCandidate: ProductImageCandidate | null = null;
      let mirroredImage: Awaited<ReturnType<typeof mirrorProductImageToStorage>> | null = null;
      let imageVisionReview: ProductImageVisionReview | null = null;
      let imageSearchStatus = allowImageSearch ? "no_candidates" : "disabled";
      let imageSearchCandidatesFound = 0;
      let imageSearchCandidatesReviewed = 0;
      let imageSearchLastRejectReason: string | null = null;
      if (allowImageSearch) {
        const candidateProviders: Array<() => Promise<ProductImageCandidate[]>> = [
          () => fetchSerpApiGoogleImageCandidates({ rawName: productName, product }),
          () => fetchApifyGoogleImageCandidates({ rawName: productName, product }),
          async () => {
            const candidate = await fetchOpenFoodFactsCandidate(productName);
            return candidate?.imageUrl ? [candidate] : [];
          },
        ];

        let visionReviews = 0;
        for (const getCandidates of candidateProviders) {
          if (visionReviews >= PRODUCT_IMAGE_VISION_REVIEW_LIMIT) break;
          const candidates = await getCandidates();
          imageSearchCandidatesFound += candidates.length;
          for (const candidate of candidates) {
            if (visionReviews >= PRODUCT_IMAGE_VISION_REVIEW_LIMIT) break;
            const mirrored = await mirrorProductImageToStorage({
              sourceUrl: candidate.imageUrl,
              productName: candidate.name || asStringValue(product.name) || productName,
              productId,
            });
            if (!mirrored?.publicUrl) {
              imageSearchStatus = "candidate_download_failed";
              continue;
            }

            visionReviews += 1;
            imageSearchCandidatesReviewed = visionReviews;
            const review = await reviewProductImageWithVision({
              productName,
              product,
              imageUrl: mirrored.publicUrl,
              model: models.documentAnalysis,
            });

            if (review.accepted) {
              imageCandidate = candidate;
              mirroredImage = mirrored;
              imageVisionReview = review;
              imageSearchStatus = "accepted";
              break;
            }
            imageSearchStatus = "vision_rejected";
            imageSearchLastRejectReason = review.reason || null;
            await removeProductImageFromStorage(mirrored.storagePath);
          }
          if (mirroredImage?.publicUrl) {
            break;
          }
        }
      }

      if (allowImageSearch && imageCandidate?.imageUrl && mirroredImage?.publicUrl) {
        product.name = product.name || imageCandidate.name || productName;
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
      );
      return json({ answer });
    }

    return json({ error: "unknown_action" }, 400);
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "Errore Straico" }, 500);
  }
});
