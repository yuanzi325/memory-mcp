import { randomUUID, timingSafeEqual, createHash } from "node:crypto";
import express from "express";
import { createClient } from "@supabase/supabase-js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as z from "zod";

const app = express();
app.use(express.json({ limit: "1mb" }));

const sessions = new Map();
const authCodes = new Map();
const accessTokens = new Map();
const refreshTokensByHash = new Map(); // SHA256(token) → { clientId, expiresAt }
const pendingAuths = new Map();        // pendingId → { clientId, redirectUri, codeChallenge, state, expiresAt }
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  "";
// SUPABASE_TABLE backs legacy vault_state data and OAuth refresh-token state.
// OAuth refresh tokens use row id = OAUTH_STATE_ROW_ID.
// vault_briefing reads legacy frontend state from row id = SUPABASE_ROW_ID.
// Memory CRUD reads/writes public.memories directly via MEMORY_TABLE.
const SUPABASE_TABLE = process.env.SUPABASE_TABLE || "vault_state";
const SUPABASE_ROW_ID = process.env.SUPABASE_ROW_ID || "main";
const MEMORY_TABLE = process.env.MEMORY_TABLE || "memories";
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || "";
const MCP_OAUTH_CLIENT_ID = process.env.MCP_OAUTH_CLIENT_ID || "";
const MCP_OAUTH_CLIENT_SECRET = process.env.MCP_OAUTH_CLIENT_SECRET || "";
const PUBLIC_BASE_URL = (process.env.MCP_OAUTH_ISSUER || process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
const MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS = Number(process.env.MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS) || 3600;
const MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS = Number(process.env.MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS) || 30 * 24 * 3600;
const OAUTH_STATE_ROW_ID = process.env.OAUTH_STATE_ROW_ID || "oauth_state";
const FRONTEND_ALLOWED_EMAILS = process.env.FRONTEND_ALLOWED_EMAILS
  ? process.env.FRONTEND_ALLOWED_EMAILS.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)
  : [];
const FRONTEND_ALLOWED_USER_IDS = process.env.FRONTEND_ALLOWED_USER_IDS
  ? process.env.FRONTEND_ALLOWED_USER_IDS.split(",").map((s) => s.trim()).filter(Boolean)
  : [];
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";
const STR_LIMITS = {
  title: 200,
  note: 5000,
  content: 100000,
  summary: 100000,
  keyword: 200,
  type: 100,
  short: 200,
};
const KEYWORDS_MAX = 100;

let supabaseClient = null;

function log(level, category, data = {}) {
  console.log(
    JSON.stringify({
      time: new Date().toISOString(),
      level,
      category,
      ...data,
    })
  );
}

function makeResult(structuredContent, text) {
  return {
    structuredContent,
    content: [{ type: "text", text }],
  };
}

function hasSupabaseConfig() {
  return Boolean(SUPABASE_URL && SUPABASE_KEY);
}

function hasAuthConfig() {
  return Boolean(MCP_AUTH_TOKEN);
}

function hasOAuthConfig() {
  return Boolean(MCP_OAUTH_CLIENT_ID && MCP_OAUTH_CLIENT_SECRET && PUBLIC_BASE_URL);
}

function hasAnyAuthConfig() {
  return hasAuthConfig() || hasOAuthConfig();
}

function verifyPKCE(codeVerifier, codeChallenge) {
  const hash = createHash("sha256").update(codeVerifier).digest("base64url");
  return hash === codeChallenge;
}

function hashToken(token) {
  return createHash("sha256").update(String(token)).digest("hex");
}

function htmlEscape(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function isValidOAuthToken(token) {
  if (!token || !hasOAuthConfig()) return false;
  const entry = accessTokens.get(token);
  if (!entry) return false;
  if (Date.now() > entry.expiresAt) {
    accessTokens.delete(token);
    return false;
  }
  return true;
}

function isValidRefreshToken(token) {
  if (!token || !hasOAuthConfig()) return null;
  const hash = hashToken(token);
  const entry = refreshTokensByHash.get(hash);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    refreshTokensByHash.delete(hash);
    return null;
  }
  return entry;
}

function constantTimeEquals(a = "", b = "") {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";
  const value = Array.isArray(header) ? header[0] : header;
  const match = /^Bearer\s+(.+)$/i.exec(value || "");
  return match?.[1] || "";
}

function isAuthorized(req) {
  const token = getBearerToken(req);
  if (!token) return false;
  if (hasAuthConfig() && constantTimeEquals(token, MCP_AUTH_TOKEN)) return true;
  if (isValidOAuthToken(token)) return true;
  return false;
}

function getSupabaseClient() {
  if (supabaseClient) return supabaseClient;
  if (!hasSupabaseConfig()) {
    throw new Error(
      "Missing SUPABASE_URL or Supabase key. Set SUPABASE_SERVICE_ROLE_KEY (preferred), SUPABASE_KEY, or SUPABASE_ANON_KEY."
    );
  }
  supabaseClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
  return supabaseClient;
}

function setCORSHeaders(req, res) {
  const origin = FRONTEND_ORIGIN === "*" ? "*" : FRONTEND_ORIGIN;
  res.set("Access-Control-Allow-Origin", origin);
  res.set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
}

async function requireFrontendAuth(req, res, next) {
  const token = getBearerToken(req);
  if (!token) {
    return res.status(401).json({ error: "Missing Authorization header" });
  }
  try {
    const client = getSupabaseClient();
    const { data: { user }, error } = await client.auth.getUser(token);
    if (error || !user) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    const email = (user.email || "").toLowerCase();
    const uid = user.id || "";
    const hasEmailList = FRONTEND_ALLOWED_EMAILS.length > 0;
    const hasIdList = FRONTEND_ALLOWED_USER_IDS.length > 0;
    if (!hasEmailList && !hasIdList) {
      return res.status(403).json({ error: "frontend allowlist not configured" });
    }
    const allowedByEmail = hasEmailList && FRONTEND_ALLOWED_EMAILS.includes(email);
    const allowedById = hasIdList && FRONTEND_ALLOWED_USER_IDS.includes(uid);
    if (!allowedByEmail && !allowedById) {
      return res.status(403).json({ error: "Forbidden" });
    }
    req.frontendUser = user;
    next();
  } catch (err) {
    log("warn", "api", { event: "frontend_auth_failed", message: err instanceof Error ? err.message : String(err) });
    return res.status(500).json({ error: "Auth check failed" });
  }
}

async function loadOAuthState() {
  if (!hasSupabaseConfig() || !hasOAuthConfig()) return;
  try {
    const client = getSupabaseClient();
    const { data, error } = await client
      .from(SUPABASE_TABLE)
      .select("state_json")
      .eq("id", OAUTH_STATE_ROW_ID)
      .maybeSingle();
    if (error) throw toDbError("loadOAuthState", error);
    const tokens = data?.state_json?.refresh_tokens;
    if (!Array.isArray(tokens)) return;
    const now = Date.now();
    let loaded = 0;
    for (const entry of tokens) {
      if (entry?.hash && entry.expiresAt > now) {
        refreshTokensByHash.set(entry.hash, { clientId: entry.clientId, expiresAt: entry.expiresAt });
        loaded++;
      }
    }
    log("info", "oauth", { event: "oauth_state_loaded", refresh_tokens: loaded });
  } catch (err) {
    log("warn", "oauth", { event: "oauth_state_load_failed", message: toDbError("loadOAuthState", err).message });
  }
}

async function saveOAuthState() {
  if (!hasSupabaseConfig() || !hasOAuthConfig()) return;
  try {
    const client = getSupabaseClient();
    const refresh_tokens = Array.from(refreshTokensByHash.entries()).map(([hash, data]) => ({
      hash,
      clientId: data.clientId,
      expiresAt: data.expiresAt,
    }));
    const { error } = await client.from(SUPABASE_TABLE).upsert({
      id: OAUTH_STATE_ROW_ID,
      state_json: { refresh_tokens },
      updated_at: new Date().toISOString(),
    });
    if (error) throw toDbError("saveOAuthState", error);
  } catch (err) {
    log("warn", "oauth", { event: "oauth_state_save_failed", message: toDbError("saveOAuthState", err).message });
  }
}

function ensureObject(value, fallback = {}) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : fallback;
}

function ensureArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeString(value, max) {
  const text = value == null ? "" : String(value);
  return text.length > max ? text.slice(0, max) : text;
}

function clampNumber(value, min, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, number));
}

function splitKeywords(value) {
  if (Array.isArray(value)) {
    return value
      .slice(0, KEYWORDS_MAX)
      .map((item) => safeString(item, STR_LIMITS.keyword).trim())
      .filter(Boolean);
  }
  if (typeof value === "string") {
    return value
      .split(/[，,、;；\n]/)
      .slice(0, KEYWORDS_MAX)
      .map((item) => item.trim())
      .map((item) => safeString(item, STR_LIMITS.keyword))
      .filter(Boolean);
  }
  return [];
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUuid(value) {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

function nullIfEmpty(value) {
  return value === "" || value == null ? null : value;
}

// Fields that don't have dedicated columns in public.memories but used to live
// at the top level of the legacy state_json.memories item.  We persist them
// inside the `raw` jsonb column so nothing is lost across the migration.
const RAW_COMPAT_FIELDS = [
  "why_precious",
  "today_snapshot",
  "resolved",
  "pinned",
  "protected",
  "_archived",
  "valence",
  "arousal",
  "activation_count",
  "last_active",
];

function buildMemoryRow(input = {}) {
  const layer = safeString(input.layer || "daily", STR_LIMITS.type).trim() || "daily";
  const content = safeString(input.content || "", STR_LIMITS.content);
  const importance = Math.round(clampNumber(input.importance, 1, 10, 2));
  const keywords = splitKeywords(input.keywords);

  let profiles;
  if (Array.isArray(input.profiles) && input.profiles.length) {
    profiles = input.profiles
      .map((value) => safeString(value, STR_LIMITS.short).trim())
      .filter(Boolean);
  } else if (typeof input.profiles === "string" && input.profiles.trim()) {
    // Same delimiter set as splitKeywords so callers can pass
    // "shared,personal" or "shared、personal" etc.
    profiles = input.profiles
      .split(/[，,、;；\n]/)
      .map((item) => safeString(item, STR_LIMITS.short).trim())
      .filter(Boolean);
  } else {
    profiles = [];
  }
  if (!profiles.length) profiles = ["shared"];

  const raw = ensureObject(input.raw, {});
  for (const field of RAW_COMPAT_FIELDS) {
    if (input[field] !== undefined) raw[field] = input[field];
  }
  if (
    input.protected === undefined &&
    raw.protected === undefined &&
    ["core", "treasure", "diary"].includes(layer)
  ) {
    raw.protected = true;
  }
  if (raw.valence !== undefined) {
    raw.valence = clampNumber(raw.valence, 0, 1, 0.5);
  }
  if (raw.arousal !== undefined) {
    raw.arousal = clampNumber(raw.arousal, 0, 1, 0.3);
  }

  const row = {
    layer,
    sub_layer: nullIfEmpty(safeString(input.sub_layer || "", STR_LIMITS.type).trim()),
    title: nullIfEmpty(safeString(input.title || "", STR_LIMITS.title).trim()),
    content,
    importance,
    date: safeString(input.date || new Date().toISOString(), STR_LIMITS.short),
    author: nullIfEmpty(safeString(input.author || "", STR_LIMITS.short).trim()),
    mood: nullIfEmpty(safeString(input.mood || "", STR_LIMITS.short).trim()),
    keywords,
    profiles,
    raw,
  };

  if (isValidUuid(input.id)) {
    row.id = input.id.toLowerCase();
  }
  if (input.legacy_id !== undefined && input.legacy_id !== null) {
    const legacy = safeString(input.legacy_id, STR_LIMITS.short).trim();
    if (legacy) row.legacy_id = legacy;
  }

  return row;
}

function denormalizeMemoryRow(row) {
  if (!row) return null;
  const raw = ensureObject(row.raw, {});
  const denormalized = {
    id: row.id ?? "",
    legacy_id: row.legacy_id ?? "",
    layer: row.layer ?? "",
    sub_layer: row.sub_layer ?? "",
    title: row.title ?? "",
    content: row.content ?? "",
    importance: typeof row.importance === "number" ? row.importance : Number(row.importance) || 0,
    date: row.date ?? "",
    author: row.author ?? "",
    mood: row.mood ?? "",
    keywords: ensureArray(row.keywords),
    profiles: ensureArray(row.profiles),
    name: row.name ?? raw.name ?? "",
    domain: ensureArray(row.domain ?? raw.domain),
    tags: ensureArray(row.tags ?? raw.tags),
    bucket_id: row.bucket_id ?? raw.bucket_id ?? "",
    bucket_type: row.bucket_type ?? raw.bucket_type ?? "",
    why_precious: typeof raw.why_precious === "string" ? raw.why_precious : "",
    today_snapshot: typeof raw.today_snapshot === "string" ? raw.today_snapshot : "",
    resolved: raw.resolved ?? row.resolved ?? false,
    pinned: raw.pinned ?? row.pinned ?? false,
    protected: raw.protected ?? row.protected ?? false,
    _archived: Boolean(raw._archived ?? row._archived),
    digested: raw.digested ?? row.digested ?? false,
    activation_count:
      raw.activation_count ?? row.activation_count ?? 0,
    last_active: raw.last_active ?? row.last_active ?? "",
    created_at: row.created_at ?? "",
    updated_at: row.updated_at ?? "",
    raw,
  };
  const valence = raw.valence ?? row.valence;
  const arousal = raw.arousal ?? row.arousal;
  if (typeof valence === "number") denormalized.valence = valence;
  if (typeof arousal === "number") denormalized.arousal = arousal;
  return denormalized;
}

function toDbError(context, err) {
  if (err instanceof Error) return err;
  const msg = err?.message || String(err) || "unknown error";
  const parts = [msg];
  if (err?.code) parts.push(`code=${err.code}`);
  if (err?.details) parts.push(`details=${err.details}`);
  if (err?.hint) parts.push(`hint=${err.hint}`);
  const readable = parts.length > 1 ? `${parts[0]} (${parts.slice(1).join(", ")})` : parts[0];
  const out = new Error(`${context}: ${readable}`);
  out.code = err?.code;
  return out;
}

async function readMemoryById(id) {
  if (!isValidUuid(id)) return null;
  const client = getSupabaseClient();
  const { data, error } = await client
    .from(MEMORY_TABLE)
    .select("*")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toDbError("Supabase readMemoryById failed", error);
  return data || null;
}

async function readMemoryByLegacyId(legacyId) {
  if (!legacyId) return null;
  const client = getSupabaseClient();
  const { data, error } = await client
    .from(MEMORY_TABLE)
    .select("*")
    .eq("legacy_id", legacyId)
    .maybeSingle();
  if (error) throw toDbError("Supabase readMemoryByLegacyId failed", error);
  return data || null;
}

async function readMemoryRows({ layer, sub_layer, limit = 10, offset = 0 } = {}) {
  const client = getSupabaseClient();
  let query = client
    .from(MEMORY_TABLE)
    .select("*")
    .order("updated_at", { ascending: false, nullsFirst: false })
    .order("created_at", { ascending: false, nullsFirst: false })
    .order("date", { ascending: false, nullsFirst: false });
  if (layer) query = query.eq("layer", layer);
  if (sub_layer) query = query.eq("sub_layer", sub_layer);
  const cap = Math.max(1, Math.min(2000, Number(limit) || 10));
  const off = Math.max(0, Number(offset) || 0);
  query = query.range(off, off + cap - 1);
  const { data, error } = await query;
  if (error) throw toDbError("Supabase readMemoryRows failed", error);
  return ensureArray(data);
}

function escapeOrValue(value) {
  return String(value).replace(/[(),%*]/g, " ").trim();
}

async function queryMemoryRows({
  q,
  layer,
  sub_layer,
  author,
  keywords,
  min_importance,
  max_importance,
  limit = 10,
} = {}) {
  const client = getSupabaseClient();
  let query = client.from(MEMORY_TABLE).select("*");

  if (layer) query = query.eq("layer", layer);
  if (sub_layer) query = query.eq("sub_layer", sub_layer);
  if (author && String(author).trim()) {
    query = query.ilike("author", `%${escapeOrValue(author)}%`);
  }
  if (Number.isFinite(Number(min_importance))) {
    query = query.gte("importance", Math.floor(Number(min_importance)));
  }
  if (Number.isFinite(Number(max_importance))) {
    query = query.lte("importance", Math.ceil(Number(max_importance)));
  }

  const kwList = splitKeywords(keywords);
  if (kwList.length) {
    // overlap: row matches if ANY of the requested keywords is present.
    // contains() would require ALL of them which is too strict for search.
    if (typeof query.overlaps === "function") {
      query = query.overlaps("keywords", kwList);
    } else {
      const literal = `{${kwList
        .map((k) => `"${String(k).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`)
        .join(",")}}`;
      query = query.filter("keywords", "ov", literal);
    }
  }

  if (q && String(q).trim()) {
    const safe = escapeOrValue(q);
    if (safe) {
      const pattern = `%${safe}%`;
      query = query.or(
        `title.ilike.${pattern},content.ilike.${pattern},author.ilike.${pattern},mood.ilike.${pattern}`
      );
    }
  }

  query = query
    .order("updated_at", { ascending: false, nullsFirst: false })
    .order("created_at", { ascending: false, nullsFirst: false })
    .order("date", { ascending: false, nullsFirst: false });

  // Fetch with headroom so JS-side raw->_archived/_resolved filters can still
  // satisfy `limit` after dropping a few rows.
  const cap = Math.max(1, Math.min(2000, (Number(limit) || 10) * 3));
  query = query.limit(cap);

  const { data, error } = await query;
  if (error) throw toDbError("Supabase queryMemoryRows failed", error);
  return ensureArray(data);
}

async function insertMemoryRow(row) {
  const client = getSupabaseClient();
  const { data, error } = await client
    .from(MEMORY_TABLE)
    .insert(row)
    .select("*")
    .maybeSingle();
  if (error) throw toDbError("Supabase insertMemoryRow failed", error);
  return data;
}

async function updateMemoryRowById(id, row) {
  const client = getSupabaseClient();
  const payload = { ...row, updated_at: new Date().toISOString() };
  delete payload.id;
  const { data, error } = await client
    .from(MEMORY_TABLE)
    .update(payload)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw toDbError("Supabase updateMemoryRowById failed", error);
  return data;
}

async function upsertMemoryRow(row) {
  const client = getSupabaseClient();
  const payload = { ...row, updated_at: new Date().toISOString() };
  const { data, error } = await client
    .from(MEMORY_TABLE)
    .upsert(payload, { onConflict: "id" })
    .select("*")
    .maybeSingle();
  if (error) throw toDbError("Supabase upsertMemoryRow failed", error);
  return data;
}

async function countMemoryRows() {
  const client = getSupabaseClient();
  const { count, error } = await client
    .from(MEMORY_TABLE)
    .select("*", { count: "exact", head: true });
  if (error) throw toDbError("Supabase countMemoryRows failed", error);
  return typeof count === "number" ? count : 0;
}

async function touchMemoryRow(id) {
  if (!isValidUuid(id)) return;
  try {
    const client = getSupabaseClient();
    const { data: row, error } = await client
      .from(MEMORY_TABLE)
      .select("raw, activation_count, last_active")
      .eq("id", id)
      .maybeSingle();
    if (error || !row) return;
    const raw = ensureObject(row.raw, {});
    const currentCount = raw.activation_count ?? row.activation_count ?? 0;
    const numericCount = Number(currentCount);
    const nextCount = Number.isFinite(numericCount) ? numericCount + 1 : 1;
    const now = new Date().toISOString();
    await client
      .from(MEMORY_TABLE)
      .update({
        raw: { ...raw, activation_count: nextCount, last_active: now },
        activation_count: nextCount,
        last_active: now,
        updated_at: now,
      })
      .eq("id", id);
  } catch (_) {}
}

function makeMemorySummary(memory = {}) {
  const title = memory.title ? `《${memory.title}》` : "未命名记忆";
  const layer = memory.layer || "unknown";
  const contentLength = String(memory.content || "").length;
  return `${title} · ${layer} · importance=${memory.importance ?? ""} · content_length=${contentLength}`;
}

function formatMemoryForModel(memory = {}, snippetLength = 0) {
  const lines = [];
  const title = memory.title ? `《${memory.title}》` : "未命名记忆";
  lines.push(`id: ${memory.id ?? ""}`);
  lines.push(`标题: ${title}`);
  lines.push(`layer: ${memory.layer ?? ""}${memory.sub_layer ? " / " + memory.sub_layer : ""}`);
  lines.push(`importance: ${memory.importance ?? ""}`);
  if (memory.date) lines.push(`date: ${memory.date}`);
  if (memory.author) lines.push(`author: ${memory.author}`);
  if (memory.mood) lines.push(`mood: ${memory.mood}`);
  if (memory.keywords?.length) lines.push(`keywords: ${memory.keywords.join(", ")}`);

  function snippet(text, limit) {
    const s = String(text || "");
    return limit > 0 && s.length > limit ? s.slice(0, limit) + `…（共 ${s.length} 字）` : s;
  }

  lines.push(`\ncontent:\n${snippet(memory.content, snippetLength)}`);
  if (memory.why_precious) lines.push(`\nwhy_precious:\n${snippet(memory.why_precious, snippetLength > 0 ? 800 : 0)}`);
  if (memory.today_snapshot) lines.push(`\ntoday_snapshot:\n${snippet(memory.today_snapshot, snippetLength > 0 ? 800 : 0)}`);
  return lines.join("\n");
}

const memoryRecordSchema = z
  .object({
    id: z.string(),
    legacy_id: z.string().optional().default(""),
    layer: z.string(),
    sub_layer: z.string().optional().default(""),
    title: z.string().optional().default(""),
    date: z.string().optional().default(""),
    author: z.string().optional().default(""),
    mood: z.string().optional().default(""),
    keywords: z.array(z.string()).optional().default([]),
    profiles: z.array(z.string()).optional().default([]),
    content: z.string(),
    why_precious: z.string().optional().default(""),
    today_snapshot: z.string().optional().default(""),
    importance: z.number(),
    activation_count: z.number().optional(),
    last_active: z.string().optional(),
    created_at: z.string().optional(),
    updated_at: z.string().optional(),
    resolved: z.boolean().optional(),
    pinned: z.boolean().optional(),
    protected: z.boolean().optional(),
    _archived: z.boolean().optional(),
    valence: z.number().optional(),
    arousal: z.number().optional(),
    raw: z.record(z.any()).optional(),
  })
  .passthrough();

function parseDateLike(value = "") {
  if (!value) return null;
  const raw = String(value);
  const d = new Date(raw.length <= 10 ? `${raw}T12:00:00` : raw.replace(" ", "T"));
  return Number.isNaN(d.getTime()) ? null : d;
}

function calcDecayScore(memory = {}) {
  if (!memory || memory._archived) return 0;
  if (memory.pinned) return 999;
  if (memory.protected) return 500 + Math.max(1, Number(memory.importance || 5)) * 10;

  const importance = Math.max(1, Math.min(10, Number(memory.importance || 5)));
  const activationCount = Math.max(1, Number(memory.activation_count || 1));
  const arousal = Math.max(0, Math.min(1, Number(memory.arousal ?? 0.3)));
  const lastActive =
    parseDateLike(memory.last_active) ||
    parseDateLike(memory.date) ||
    new Date();
  const daysSince = Math.max(0, (Date.now() - lastActive.getTime()) / 86400000);

  let timeWeight = 1;
  if (daysSince <= 1) timeWeight = 1;
  else if (daysSince <= 2) timeWeight = 1 - 0.1 * (daysSince - 1);
  else timeWeight = Math.max(0.3, 0.9 * Math.exp(-0.2197 * (daysSince - 2)));

  const emotionWeight = 1 + arousal * 0.8;
  let score =
    timeWeight *
    importance *
    Math.pow(activationCount, 0.3) *
    Math.exp(-0.05 * daysSince) *
    emotionWeight;

  if (memory.resolved && memory.digested) score *= 0.02;
  else if (memory.resolved) score *= 0.05;
  if (arousal > 0.7 && !memory.resolved) score *= 1.5;

  return Math.round(score * 10000) / 10000;
}

function calculateSurfaceScore(memory = {}) {
  return calcDecayScore(memory);
}

function matchesProfileFilter(memory, profileFilter) {
  const profiles = ensureArray(memory.profiles);
  const effective = profiles.length ? profiles : ["shared"];
  if (profileFilter === "all") return true;
  if (profileFilter === "rowan") return effective.includes("shared") || effective.includes("rowan");
  if (profileFilter === "arion") return effective.includes("shared") || effective.includes("arion");
  return effective.includes("shared");
}

// ── vault_briefing helpers ────────────────────────────────────────────────────

async function readVaultState() {
  const client = getSupabaseClient();
  const { data, error } = await client
    .from(SUPABASE_TABLE)
    .select("state_json, updated_at")
    .eq("id", SUPABASE_ROW_ID)
    .maybeSingle();
  if (error) throw toDbError("readVaultState", error);
  return data || null;
}

function compactText(value, maxLen = 70) {
  const s = String(value || "").trim();
  return s.length > maxLen ? s.slice(0, maxLen) + "…" : s;
}

function sortByDateDesc(arr, getDate) {
  return [...arr].sort((a, b) => {
    const da = parseDateLike(getDate(a)) ?? new Date(0);
    const db = parseDateLike(getDate(b)) ?? new Date(0);
    return db.getTime() - da.getTime();
  });
}

function latestPeriod(periodList) {
  if (!Array.isArray(periodList) || !periodList.length) return null;
  return sortByDateDesc(periodList, (p) => p.startDate || "")[0] || null;
}

function buildVaultBriefing(stateJson, modules = [], limit = 3) {
  const all = ["profile", "diaries", "bottles", "health", "calendar", "collections"];
  const selected = modules.length ? modules.filter((m) => all.includes(m)) : all;
  const sections = [];
  const counts = {};

  if (selected.includes("profile")) {
    const profile = ensureObject(stateJson.profile, {});
    const items = [];
    if (profile.pairName) items.push(`CP名：${profile.pairName}`);
    if (profile.startDate) items.push(`纪念日：${profile.startDate}`);
    if (profile.domain) items.push(`域名：${profile.domain}`);
    if (items.length) sections.push({ label: "基本信息", items });
    counts.profile = items.length;
  }

  if (selected.includes("diaries")) {
    const diaries = ensureArray(stateJson.diaries);
    const sorted = sortByDateDesc(diaries, (d) => d.date || "");
    const top = sorted.slice(0, limit);
    const items = top.map((d) => {
      const title = d.title ? compactText(d.title, 30) : compactText(d.content, 40);
      const moodStr = Array.isArray(d.moods) && d.moods.length ? d.moods.join("/") : (d.mood || "");
      return `${d.date || "未知日期"} · ${title}${moodStr ? " · " + moodStr : ""}`;
    });
    if (items.length) sections.push({ label: "最近日记", items });
    counts.diaries = diaries.length;
  }

  if (selected.includes("bottles")) {
    const bottles = ensureArray(stateJson.bottles);
    const unarchived = bottles.filter((b) => !b.archived);
    const unread = unarchived.filter((b) => !b.read);
    const sorted = sortByDateDesc(unarchived, (b) => b.date || "");
    const top = sorted.slice(0, limit);
    const items = [];
    if (unread.length) items.push(`未读漂流瓶：${unread.length} 封`);
    for (const b of top) {
      const readLabel = b.read ? "已读" : "未读";
      const from = b.from || b.sender || "未知";
      items.push(`${readLabel} · ${from} · ${compactText(b.content, 60)}`);
    }
    if (items.length) sections.push({ label: "漂流瓶", items });
    counts.bottles = bottles.length;
    counts.bottles_unread = unread.length;
  }

  if (selected.includes("health")) {
    const health = ensureObject(stateJson.health, {});
    const cycle = ensureObject(health.cycle, {});
    const items = [];

    const cycleLength = cycle.cycleLength ?? health.cycleLength;
    const periodLength = cycle.periodLength ?? health.periodLength;

    if (cycleLength) items.push(`周期长度：${cycleLength} 天`);
    if (periodLength) items.push(`经期长度：${periodLength} 天`);

    const periods = ensureArray(cycle.periods || health.periods || health.period);
    let latest = latestPeriod(periods);

    if (!latest && cycle.lastPeriodStart) {
      latest = { startDate: cycle.lastPeriodStart, endDate: "" };
    }

    if (latest) {
      const endStr = latest.endDate ? ` ~ ${latest.endDate}` : "（进行中）";
      items.push(`最近经期：${latest.startDate}${endStr}`);
    }

    const logs = ensureArray(health.logs);
    const daily = ensureArray(health.daily);
    const recentEntries = sortByDateDesc([...logs, ...daily], (l) => l.date || "").slice(0, 2);
    for (const entry of recentEntries) {
      const note = compactText(
        entry.note || entry.content || entry.summary || entry.type || "",
        50
      );
      if (note) items.push(`${entry.date || ""} · ${note}`);
    }

    if (items.length) sections.push({ label: "健康", items });
    counts.health_periods = periods.length;
    counts.health_logs = logs.length;
    counts.health_daily = daily.length;
  }

  if (selected.includes("calendar")) {
    const calendarNotes = ensureArray(stateJson.calendarNotes);
    const sorted = sortByDateDesc(calendarNotes, (n) => n.date || "");
    const top = sorted.slice(0, limit);
    const items = top.map((n) => {
      const moodStr = n.mood ? ` · ${n.mood}` : "";
      const summary = compactText(n.summary || n.note || n.content || "", 60);
      return `${n.date || "未知日期"}${moodStr} · ${summary}`;
    });
    if (items.length) sections.push({ label: "日历备注", items });
    counts.calendar = calendarNotes.length;
  }

  if (selected.includes("collections")) {
    const collections = ensureArray(stateJson.collections);
    const folders = collections.filter((c) => c.type === "folder" || c.isFolder);
    const collItems = collections.filter((c) => c.type !== "folder" && !c.isFolder);
    const sectionItems = [];
    sectionItems.push(`收藏：${collItems.length} 条，文件夹：${folders.length} 个`);
    for (const item of collItems.slice(0, limit)) {
      sectionItems.push(compactText(item.title || item.content || "", 60));
    }
    for (const folder of folders.slice(0, limit)) {
      sectionItems.push(`📁 ${compactText(folder.name || folder.title || "", 40)}`);
    }
    if (sectionItems.length) sections.push({ label: "收藏", items: sectionItems });
    counts.collections = collItems.length;
    counts.folders = folders.length;
  }

  const total_items = sections.reduce((n, s) => n + s.items.length, 0);
  return { sections, counts, total_items };
}

function createServer() {
  const server = new McpServer({
    name: "memory-mcp",
    version: "1.1.2",
  });

  server.registerTool(
    "memory_ping",
    {
      title: "Memory Ping",
      description: "Check whether the memory MCP server is reachable.",
      inputSchema: z.object({}),
      outputSchema: z.object({
        status: z.string(),
        timestamp: z.string(),
        storage: z.string(),
        supabase_configured: z.boolean(),
      }),
    },
    async () => {
      const result = {
        status: "ok",
        timestamp: new Date().toISOString(),
        storage: "supabase",
        supabase_configured: hasSupabaseConfig(),
      };

      log("info", "tool", {
        tool: "memory_ping",
        args: {},
        result,
      });

      return makeResult(
        result,
        `memory_ping 正常：status=ok, storage=${result.storage}, supabase_configured=${result.supabase_configured}, timestamp=${result.timestamp}`
      );
    }
  );

  server.registerTool(
    "memory_write",
    {
      title: "Memory Write",
      description: "Write one memory item into the Supabase public.memories table.",
      inputSchema: z.object({
        content: z.string().min(1),
        layer: z.string().optional(),
        importance: z.number().optional(),
        id: z.string().optional(),
        legacy_id: z.string().optional(),
        sub_layer: z.string().optional(),
        title: z.string().optional(),
        date: z.string().optional(),
        author: z.string().optional(),
        mood: z.string().optional(),
        keywords: z.union([z.array(z.string()), z.string()]).optional(),
        profiles: z.union([z.array(z.string()), z.string()]).optional(),
        why_precious: z.string().optional(),
        today_snapshot: z.string().optional(),
        resolved: z.boolean().optional(),
        pinned: z.boolean().optional(),
        protected: z.boolean().optional(),
        _archived: z.boolean().optional(),
        valence: z.number().optional(),
        arousal: z.number().optional(),
        activation_count: z.number().optional(),
        last_active: z.string().optional(),
        raw: z.record(z.any()).optional(),
      }),
      outputSchema: z.object({
        item: memoryRecordSchema,
        total_memories: z.number(),
        updated_at: z.string(),
        mode: z.string(),
      }),
    },
    async (args) => {
      const row = buildMemoryRow(args);
      let saved;
      let mode;

      if (row.id) {
        saved = await upsertMemoryRow(row);
        mode = "upsert_by_id";
      } else if (row.legacy_id) {
        const existing = await readMemoryByLegacyId(row.legacy_id);
        if (existing?.id) {
          saved = await updateMemoryRowById(existing.id, row);
          mode = "update_by_legacy_id";
        } else {
          saved = await insertMemoryRow(row);
          mode = "insert";
        }
      } else {
        saved = await insertMemoryRow(row);
        mode = "insert";
      }

      const item = denormalizeMemoryRow(saved) || denormalizeMemoryRow({ ...row });
      const total = await countMemoryRows();
      const result = {
        item,
        total_memories: total,
        updated_at: item?.updated_at || new Date().toISOString(),
        mode,
      };

      log("info", "tool", {
        tool: "memory_write",
        args: {
          id: item?.id,
          legacy_id: item?.legacy_id || undefined,
          layer: row.layer,
          sub_layer: row.sub_layer,
          author: row.author,
          importance: row.importance,
          content_length: row.content.length,
          title_length: (row.title || "").length,
          keyword_count: row.keywords.length,
        },
        result: {
          item_id: item?.id,
          total_memories: result.total_memories,
          updated_at: result.updated_at,
          mode: result.mode,
        },
      });

      return makeResult(
        result,
        `已写入记忆：${makeMemorySummary(item)}。当前共 ${result.total_memories} 条，写入方式 ${result.mode}，更新时间 ${result.updated_at}`
      );
    }
  );

  server.registerTool(
    "memory_read",
    {
      title: "Memory Read",
      description:
        "Read one memory by id (uuid or legacy_id), or read the latest memories from the Supabase public.memories table.",
      inputSchema: z.object({
        id: z.string().optional(),
        layer: z.string().optional(),
        sub_layer: z.string().optional(),
        limit: z.number().int().min(1).max(50).optional().default(10),
        include_archived: z.boolean().optional().default(false),
      }),
      outputSchema: z.object({
        found: z.boolean(),
        item: memoryRecordSchema.nullable().optional(),
        items: z.array(memoryRecordSchema),
        total_memories: z.number(),
        returned_count: z.number(),
        updated_at: z.string(),
      }),
    },
    async ({ id, layer, sub_layer, limit = 10, include_archived = false }) => {
      let item = null;
      let items = [];

      if (id) {
        let row = await readMemoryById(id);
        if (!row) row = await readMemoryByLegacyId(id);
        if (row) {
          const den = denormalizeMemoryRow(row);
          if (include_archived || !den?._archived) {
            item = den;
            items = den ? [den] : [];
          }
        }
      } else {
        const cap = Math.max(1, Math.min(50, Number(limit) || 10));
        const rows = await readMemoryRows({ layer, sub_layer, limit: cap * 2 });
        items = rows
          .map(denormalizeMemoryRow)
          .filter((m) => m && (include_archived || !m._archived))
          .slice(0, cap);
      }

      const total = await countMemoryRows();
      const result = {
        found: Boolean(item || items.length),
        item,
        items,
        total_memories: total,
        returned_count: items.length,
        updated_at: items[0]?.updated_at || item?.updated_at || "",
      };

      log("info", "tool", {
        tool: "memory_read",
        args: { id, layer, sub_layer, limit, include_archived },
        result: {
          found: result.found,
          returned_count: result.returned_count,
          total_memories: result.total_memories,
        },
      });

      let text;
      if (id) {
        text = result.found
          ? `已读取记忆（总数 ${result.total_memories}）：\n\n${formatMemoryForModel(result.item)}`
          : `没有找到 id=${id} 的记忆。`;
      } else {
        const blocks = items.map((m, i) => `【${i + 1}/${items.length}】\n${formatMemoryForModel(m, 1200)}`).join("\n\n---\n\n");
        text = `已读取 ${result.returned_count} 条记忆（总数 ${result.total_memories}）：\n\n${blocks || "（无结果）"}`;
      }

      return makeResult(result, text);
    }
  );

  server.registerTool(
    "memory_query",
    {
      title: "Memory Query",
      description:
        "Search memories by keyword, layer, sub_layer, author, keywords, or importance from the Supabase public.memories table.",
      inputSchema: z.object({
        q: z.string().optional().default(""),
        layer: z.string().optional(),
        sub_layer: z.string().optional(),
        author: z.string().optional(),
        keywords: z.union([z.array(z.string()), z.string()]).optional(),
        min_importance: z.number().optional(),
        max_importance: z.number().optional(),
        include_archived: z.boolean().optional().default(false),
        include_resolved: z.boolean().optional().default(true),
        limit: z.number().int().min(1).max(50).optional().default(10),
      }),
      outputSchema: z.object({
        items: z.array(memoryRecordSchema),
        returned_count: z.number(),
        total_memories: z.number(),
        updated_at: z.string(),
      }),
    },
    async ({
      q = "",
      layer,
      sub_layer,
      author,
      keywords,
      min_importance,
      max_importance,
      include_archived = false,
      include_resolved = true,
      limit = 10,
    }) => {
      const cap = Math.max(1, Math.min(50, Number(limit) || 10));
      const rows = await queryMemoryRows({
        q,
        layer,
        sub_layer,
        author,
        keywords,
        min_importance,
        max_importance,
        limit: cap,
      });
      let items = rows.map(denormalizeMemoryRow).filter(Boolean);
      if (!include_archived) items = items.filter((m) => !m._archived);
      if (!include_resolved) items = items.filter((m) => !m.resolved);
      items = items.slice(0, cap);

      const total = await countMemoryRows();
      const result = {
        items,
        returned_count: items.length,
        total_memories: total,
        updated_at: items[0]?.updated_at || "",
      };

      log("info", "tool", {
        tool: "memory_query",
        args: {
          q,
          layer,
          sub_layer,
          author,
          keywords,
          min_importance,
          max_importance,
          include_archived,
          include_resolved,
          limit,
        },
        result: {
          returned_count: result.returned_count,
          total_memories: result.total_memories,
        },
      });

      const blocks = items.length
        ? items
            .map((item, index) => `【${index + 1}/${items.length}】\n${formatMemoryForModel(item, 1200)}`)
            .join("\n\n---\n\n")
        : "没有命中任何记忆。";

      return makeResult(
        result,
        `查询完成，共命中 ${result.returned_count} 条（总数 ${result.total_memories}）：\n\n${blocks}`
      );
    }
  );

  server.registerTool(
    "memory_surface",
    {
      title: "Memory Surface",
      description:
        "Surface memories using an OB-style algorithm that scores by importance, recency, arousal, " +
        "activation count, and pinned/protected status. Pinned memories appear first. Resolved memories " +
        "are down-weighted. High-arousal unresolved memories are boosted. Optionally accepts a query to " +
        "text-search first, then re-rank by weighted score.",
      inputSchema: z.object({
        q: z.string().optional().default(""),
        profile: z.enum(["shared", "rowan", "arion", "all"]).optional().default("shared"),
        layer: z.string().optional(),
        sub_layer: z.string().optional(),
        limit: z.number().int().min(1).max(30).optional().default(10),
        include_resolved: z.boolean().optional().default(false),
        include_archived: z.boolean().optional().default(false),
        touch: z.boolean().optional().default(true),
        snippet_length: z.number().int().min(0).optional().default(1200),
      }),
      outputSchema: z.object({
        items: z.array(
          z.object({
            id: z.string(),
            title: z.string(),
            content: z.string(),
            layer: z.string(),
            sub_layer: z.string(),
            importance: z.number(),
            profiles: z.array(z.string()),
            keywords: z.array(z.string()),
            name: z.string(),
            domain: z.array(z.string()),
            tags: z.array(z.string()),
            bucket_id: z.string(),
            bucket_type: z.string(),
            date: z.string(),
            score: z.number(),
            pinned: z.boolean(),
            protected: z.boolean(),
            resolved: z.boolean(),
            activation_count: z.number(),
            last_active: z.string(),
          })
        ),
        returned_count: z.number(),
        total_memories: z.number(),
        touched: z.boolean(),
        generated_at: z.string(),
      }),
    },
    async ({
      q = "",
      profile = "shared",
      layer,
      sub_layer,
      limit = 10,
      include_resolved = false,
      include_archived = false,
      touch = true,
      snippet_length = 1200,
    }) => {
      const cap = Math.max(1, Math.min(30, Number(limit) || 10));
      const hasQuery = Boolean(q && String(q).trim());
      const ql = hasQuery ? q.toLowerCase() : "";

      function computeScore(m) {
        let s = calculateSurfaceScore(m);
        if (hasQuery) {
          const title = String(m.title || "").toLowerCase();
          const name = String(m.name || "").toLowerCase();
          const kws = ensureArray(m.keywords).map((k) => String(k).toLowerCase());
          const tags = ensureArray(m.tags).map((k) => String(k).toLowerCase());
          const domain = ensureArray(m.domain).map((d) => String(d).toLowerCase());
          const content = String(m.content || "").toLowerCase();
          if (title.includes(ql) || name.includes(ql)) s *= 2.5;
          else if (
            kws.some((k) => k.includes(ql)) ||
            tags.some((k) => k.includes(ql)) ||
            domain.some((d) => d.includes(ql))
          ) s *= 1.8;
          else if (content.includes(ql)) s *= 1.2;
        }
        return Math.round(s * 10000) / 10000;
      }

      let rows;
      if (hasQuery) {
        const [queryRows, recentRows] = await Promise.all([
          queryMemoryRows({ q, layer, sub_layer, limit: Math.min(300, cap * 10) }),
          readMemoryRows({ layer, sub_layer, limit: 300 }),
        ]);
        const seen = new Set();
        rows = [];
        for (const r of [...queryRows, ...recentRows]) {
          if (r?.id && !seen.has(r.id)) {
            seen.add(r.id);
            rows.push(r);
          }
        }
      } else {
        rows = await readMemoryRows({ layer, sub_layer, limit: 300 });
      }

      let memories = rows.map(denormalizeMemoryRow).filter(Boolean);
      if (!include_archived) memories = memories.filter((m) => !m._archived);
      if (!include_resolved) memories = memories.filter((m) => !m.resolved);
      memories = memories.filter((m) => matchesProfileFilter(m, profile));

      const scored = memories.map((m) => ({ m, score: computeScore(m) }));
      scored.sort((a, b) => b.score - a.score);
      const top = scored.slice(0, cap);

      if (touch) {
        for (const { m } of top) {
          touchMemoryRow(m.id).catch(() => {});
        }
      }

      const total = await countMemoryRows();

      function applySnippet(text) {
        const s = String(text || "");
        return snippet_length > 0 && s.length > snippet_length
          ? s.slice(0, snippet_length) + `…（共 ${s.length} 字）`
          : s;
      }

      const structuredItems = top.map(({ m, score }) => ({
        id: m.id ?? "",
        title: m.title ?? "",
        content: applySnippet(m.content),
        layer: m.layer ?? "",
        sub_layer: m.sub_layer ?? "",
        importance: typeof m.importance === "number" ? m.importance : 0,
        profiles: ensureArray(m.profiles),
        keywords: ensureArray(m.keywords),
        name: m.name ?? "",
        domain: ensureArray(m.domain),
        tags: ensureArray(m.tags),
        bucket_id: m.bucket_id ?? "",
        bucket_type: m.bucket_type ?? "",
        date: m.date ?? "",
        score,
        pinned: Boolean(m.pinned),
        protected: Boolean(m.protected),
        resolved: Boolean(m.resolved),
        activation_count: typeof m.activation_count === "number" ? m.activation_count : 0,
        last_active: m.last_active ?? "",
      }));

      const result = {
        items: structuredItems,
        returned_count: structuredItems.length,
        total_memories: total,
        touched: touch && top.length > 0,
        generated_at: new Date().toISOString(),
      };

      log("info", "tool", {
        tool: "memory_surface",
        args: { q, profile, layer, sub_layer, limit, include_resolved, include_archived, touch },
        result: { returned_count: result.returned_count, total_memories: result.total_memories },
      });

      const blocks = top.length
        ? top
            .map(
              ({ m, score }, i) =>
                `【${i + 1}/${top.length}】score=${score}\n${formatMemoryForModel(m, snippet_length)}`
            )
            .join("\n\n---\n\n")
        : "没有浮现任何记忆。";

      return makeResult(
        result,
        `记忆浮现完成，共返回 ${result.returned_count} 条（总数 ${result.total_memories}）：\n\n${blocks}`
      );
    }
  );

  server.registerTool(
    "memory_briefing",
    {
      title: "Memory Briefing",
      description:
        "Return a compact briefing (3–7 items) assembled from high-priority memo and daily memories, " +
        "sorted by decay score. Intended to be injected once per session at the start of a conversation " +
        "so the model is aware of recent context without manual querying.",
      inputSchema: z.object({}),
      outputSchema: z.object({
        sections: z.array(
          z.object({
            label: z.string(),
            items: z.array(z.string()),
          })
        ),
        total_items: z.number(),
        briefing_text: z.string(),
        generated_at: z.string(),
      }),
    },
    async () => {
      const sections = [];

      // memo layer: up to 2, sorted by date desc
      const memoRows = await readMemoryRows({ layer: "memo", limit: 20 });
      const memos = memoRows
        .map(denormalizeMemoryRow)
        .filter((m) => m && !m.resolved && !m._archived)
        .sort((a, b) => {
          const da = parseDateLike(a.date) ?? new Date(0);
          const db = parseDateLike(b.date) ?? new Date(0);
          return db.getTime() - da.getTime();
        })
        .slice(0, 2);
      if (memos.length) {
        sections.push({
          label: "上窗备忘",
          items: memos.map((m) => (m.title || String(m.content || "").slice(0, 36)).trim()),
        });
      }

      // daily layer: top 3 by decay score
      const dailyRows = await readMemoryRows({ layer: "daily", limit: 50 });
      const allDailys = dailyRows
        .map(denormalizeMemoryRow)
        .filter((m) => m && !m.resolved && !m._archived)
        .sort((a, b) => calcDecayScore(b) - calcDecayScore(a));
      const topDailys = allDailys.slice(0, 3);
      if (topDailys.length) {
        sections.push({
          label: "最近的事",
          items: topDailys.map((m) => (m.title || String(m.content || "").slice(0, 36)).trim()),
        });
      }

      // high-arousal daily not already shown, up to 2
      const shownIds = new Set(topDailys.map((m) => m.id));
      const urgent = allDailys
        .filter((m) => !shownIds.has(m.id) && Number(m.arousal ?? 0) > 0.6)
        .slice(0, 2);
      if (urgent.length) {
        sections.push({
          label: "需要关注",
          items: urgent.map((m) => (m.title || String(m.content || "").slice(0, 36)).trim()),
        });
      }

      const totalItems = sections.reduce((n, s) => n + s.items.length, 0);
      const briefingText = sections.length
        ? sections.map((s) => `【${s.label}】${s.items.join("；")}`).join("\n")
        : "（暂无 briefing）";
      const generatedAt = new Date().toISOString();

      const result = {
        sections,
        total_items: totalItems,
        briefing_text: briefingText,
        generated_at: generatedAt,
      };

      log("info", "tool", {
        tool: "memory_briefing",
        result: { total_items: totalItems, section_count: sections.length },
      });

      return makeResult(result, `[记忆浮现 · ${generatedAt}]\n${briefingText}`);
    }
  );

  server.registerTool(
    "vault_briefing",
    {
      title: "Vault Briefing",
      description:
        "Return a compact read-only summary of legacy frontend modules stored in vault_state.state_json " +
        "(diaries, bottles, health, calendar, collections, profile). " +
        "Use this at the start of a session to get context about the user's older data without reading the full state.",
      inputSchema: z.object({
        modules: z
          .array(z.enum(["profile", "diaries", "bottles", "health", "calendar", "collections"]))
          .optional()
          .default([]),
        limit: z.number().int().min(1).max(10).optional().default(3),
      }),
      outputSchema: z.object({
        sections: z.array(z.object({ label: z.string(), items: z.array(z.string()) })),
        counts: z.record(z.any()),
        total_items: z.number(),
        briefing_text: z.string(),
        generated_at: z.string(),
        vault_updated_at: z.string(),
      }),
    },
    async ({ modules = [], limit = 3 }) => {
      const row = await readVaultState();
      const stateJson = ensureObject(row?.state_json, {});
      const vaultUpdatedAt = row?.updated_at || "";

      const { sections, counts, total_items } = buildVaultBriefing(stateJson, modules, limit);

      const generatedAt = new Date().toISOString();
      const lines = [`[旧状态浮现 · ${generatedAt}]`];
      if (sections.length) {
        for (const section of sections) {
          lines.push(`【${section.label}】${section.items.join("；")}`);
        }
      } else {
        lines.push("（暂无旧状态 briefing）");
      }
      const briefingText = lines.join("\n");

      const result = {
        sections,
        counts,
        total_items,
        briefing_text: briefingText,
        generated_at: generatedAt,
        vault_updated_at: vaultUpdatedAt,
      };

      log("info", "tool", {
        tool: "vault_briefing",
        args: { modules, limit },
        result: { total_items, section_count: sections.length },
      });

      return makeResult(result, briefingText);
    }
  );

  return server;
}

async function closeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return;

  sessions.delete(sessionId);

  try {
    await session.transport.close();
  } catch (error) {
    log("warn", "session", {
      event: "transport_close_failed",
      sessionId,
      message: error instanceof Error ? error.message : String(error),
    });
  }

  try {
    await session.server.close();
  } catch (error) {
    log("warn", "session", {
      event: "server_close_failed",
      sessionId,
      message: error instanceof Error ? error.message : String(error),
    });
  }
}

app.get("/", (req, res) => {
  log("info", "http", {
    method: req.method,
    url: req.originalUrl,
    accept: req.headers["accept"],
  });

  res.status(200).send("memory-mcp is running");
});

app.get("/health", async (req, res) => {
  log("info", "http", {
    method: req.method,
    url: req.originalUrl,
    accept: req.headers["accept"],
  });

  const payload = {
    status: "ok",
    sessions: sessions.size,
    storage: "supabase",
    supabase_configured: hasSupabaseConfig(),
    bearer_auth_configured: hasAuthConfig(),
    oauth_configured: hasOAuthConfig(),
    auth_configured: hasAnyAuthConfig(),
    oauth_refresh_tokens: hasOAuthConfig() ? refreshTokensByHash.size : undefined,
    oauth_token_storage: "memory+supabase (refresh tokens persisted; access tokens lost on restart)",
    memory_table: MEMORY_TABLE,
    oauth_state_table: SUPABASE_TABLE,
    oauth_state_row_id: OAUTH_STATE_ROW_ID,
  };

  if (hasSupabaseConfig()) {
    try {
      payload.memories = await countMemoryRows();
    } catch (error) {
      payload.supabase_error = error instanceof Error ? error.message : String(error);
    }
  }

  res.json(payload);
});

// ── Frontend REST API for memories ──────────────────────────────────────────

// CORS middleware covers all /api/* responses including 401/403 from requireFrontendAuth
app.use("/api", (req, res, next) => { setCORSHeaders(req, res); next(); });

app.options("/api/memories", (req, res) => res.sendStatus(204));
app.options("/api/memories/:id", (req, res) => res.sendStatus(204));
app.options("/api/memories/:id/restore", (req, res) => res.sendStatus(204));
app.options("/api/memories/:id/permanent", (req, res) => res.sendStatus(204));

app.get("/api/memories", requireFrontendAuth, async (req, res) => {
  try {
    const { layer, sub_layer, q } = req.query;
    const limit = Math.max(1, Math.min(2000, Number(req.query.limit) || 50));
    const offset = Math.max(0, Number(req.query.offset) || 0);
    const includeArchived = req.query.include_archived === "true" || req.query.include_archived === "1";
    // Fetch one extra row as a canary to detect whether more pages exist.
    // For include_archived queries fetchLimit = limit+1; for visible-only queries over-fetch x3.
    const fetchLimit = includeArchived ? limit + 1 : limit * 3;
    let rows;
    if (q && String(q).trim()) {
      rows = await queryMemoryRows({ q, layer, sub_layer, limit: fetchLimit });
    } else {
      rows = await readMemoryRows({ layer, sub_layer, limit: fetchLimit, offset });
    }
    let items = rows.map(denormalizeMemoryRow).filter(Boolean);
    if (!includeArchived) items = items.filter((m) => !m._archived);
    const has_more = items.length > limit;
    items = items.slice(0, limit);
    log("info", "api", { route: "GET /api/memories", returned: items.length, offset });
    res.json({ items, count: items.length, has_more });
  } catch (err) {
    log("error", "api", { route: "GET /api/memories", message: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: "Failed to read memories" });
  }
});

app.get("/api/memories/:id", requireFrontendAuth, async (req, res) => {
  try {
    const { id } = req.params;
    let row = isValidUuid(id) ? await readMemoryById(id) : null;
    if (!row) row = await readMemoryByLegacyId(id);
    if (!row) return res.status(404).json({ error: "Not found" });
    res.json(denormalizeMemoryRow(row));
  } catch (err) {
    log("error", "api", { route: "GET /api/memories/:id", message: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: "Failed to read memory" });
  }
});

app.post("/api/memories", requireFrontendAuth, async (req, res) => {
  try {
    const row = buildMemoryRow(req.body);
    let saved;
    let mode;
    if (row.id) {
      saved = await upsertMemoryRow(row);
      mode = "upsert_by_id";
    } else if (row.legacy_id) {
      const existing = await readMemoryByLegacyId(row.legacy_id);
      if (existing?.id) {
        saved = await updateMemoryRowById(existing.id, row);
        mode = "update_by_legacy_id";
      } else {
        saved = await insertMemoryRow(row);
        mode = "insert";
      }
    } else {
      saved = await insertMemoryRow(row);
      mode = "insert";
    }
    log("info", "api", { route: "POST /api/memories", id: saved?.id, mode });
    res.status(201).json(denormalizeMemoryRow(saved));
  } catch (err) {
    log("error", "api", { route: "POST /api/memories", message: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: "Failed to create memory" });
  }
});

app.patch("/api/memories/:id", requireFrontendAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidUuid(id)) return res.status(400).json({ error: "Invalid id" });
    const existing = await readMemoryById(id);
    if (!existing) return res.status(404).json({ error: "Not found" });
    const existingRaw = ensureObject(existing.raw, {});
    const incomingRaw = ensureObject(req.body.raw, {});
    const mergedRaw = { ...existingRaw, ...incomingRaw };
    // Propagate top-level compat fields from body into mergedRaw so buildMemoryRow picks them up
    for (const field of RAW_COMPAT_FIELDS) {
      if (req.body[field] !== undefined) mergedRaw[field] = req.body[field];
    }
    const mergedInput = { ...existing, ...req.body, raw: mergedRaw, id };
    const row = buildMemoryRow(mergedInput);
    const saved = await updateMemoryRowById(id, row);
    log("info", "api", { route: "PATCH /api/memories/:id", id });
    res.json(denormalizeMemoryRow(saved));
  } catch (err) {
    log("error", "api", { route: "PATCH /api/memories/:id", message: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: "Failed to update memory" });
  }
});

app.delete("/api/memories/:id", requireFrontendAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidUuid(id)) return res.status(400).json({ error: "Invalid id" });
    const existing = await readMemoryById(id);
    if (!existing) return res.status(404).json({ error: "Not found" });
    const raw = { ...ensureObject(existing.raw, {}), _archived: true };
    const saved = await updateMemoryRowById(id, { ...existing, raw });
    log("info", "api", { route: "DELETE /api/memories/:id", id });
    res.json(denormalizeMemoryRow(saved));
  } catch (err) {
    log("error", "api", { route: "DELETE /api/memories/:id", message: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: "Failed to archive memory" });
  }
});

app.delete("/api/memories/:id/permanent", requireFrontendAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidUuid(id)) return res.status(400).json({ error: "Invalid id" });
    const existing = await readMemoryById(id);
    if (!existing) return res.status(404).json({ error: "Not found" });
    const existingRaw = ensureObject(existing.raw, {});
    if (existingRaw._archived !== true) return res.status(409).json({ error: "Only archived memories can be permanently deleted" });
    const client = getSupabaseClient();
    const { error } = await client.from(MEMORY_TABLE).delete().eq("id", id);
    if (error) throw toDbError("Supabase permanent delete failed", error);
    log("info", "api", { route: "DELETE /api/memories/:id/permanent", id });
    res.json({ ok: true, id });
  } catch (err) {
    log("error", "api", { route: "DELETE /api/memories/:id/permanent", message: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: "Failed to permanently delete memory" });
  }
});

app.post("/api/memories/:id/restore", requireFrontendAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidUuid(id)) return res.status(400).json({ error: "Invalid id" });
    const existing = await readMemoryById(id);
    if (!existing) return res.status(404).json({ error: "Not found" });
    const raw = { ...ensureObject(existing.raw, {}), _archived: false };
    const saved = await updateMemoryRowById(id, { ...existing, raw });
    log("info", "api", { route: "POST /api/memories/:id/restore", id });
    res.json(denormalizeMemoryRow(saved));
  } catch (err) {
    log("error", "api", { route: "POST /api/memories/:id/restore", message: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: "Failed to restore memory" });
  }
});

// ── MCP endpoint ─────────────────────────────────────────────────────────────

app.all("/mcp", async (req, res) => {
  if (!hasAnyAuthConfig()) {
    return res.status(503).json({
      jsonrpc: "2.0",
      error: {
        code: -32003,
        message: "No authentication configured (MCP_AUTH_TOKEN or OAuth). Refusing unauthenticated MCP access.",
      },
      id: req.body?.id ?? null,
    });
  }

  if (!isAuthorized(req)) {
    const wwwAuth = PUBLIC_BASE_URL
      ? `Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"`
      : `Bearer realm="mcp"`;
    res.set("WWW-Authenticate", wwwAuth);
    return res.status(401).json({
      jsonrpc: "2.0",
      error: {
        code: -32004,
        message: "Unauthorized MCP request.",
      },
      id: req.body?.id ?? null,
    });
  }

  const sessionIdHeader = req.headers["mcp-session-id"];
  const sessionId = Array.isArray(sessionIdHeader) ? sessionIdHeader[0] : sessionIdHeader;
  const rpcMethod = req.body?.method;
  const isInitialize = rpcMethod === "initialize";

  log("info", "http", {
    method: req.method,
    url: req.originalUrl,
    accept: req.headers["accept"],
    contentType: req.headers["content-type"],
    sessionId: sessionId ?? null,
  });

  log("info", "rpc", {
    sessionId: sessionId ?? null,
    method: rpcMethod ?? null,
  });

  try {
    let session = sessionId ? sessions.get(sessionId) : undefined;

    if (isInitialize && sessionId && session) {
      log("info", "session", {
        event: "replace_existing_session",
        sessionId,
      });
      await closeSession(sessionId);
      session = undefined;
    }

    if (!session) {
      if (!isInitialize && sessionId) {
        log("warn", "rpc", {
          event: "session_not_found",
          sessionId,
          method: rpcMethod ?? null,
        });
        // POST → 200 so JSON-RPC clients see the error body cleanly;
        // GET/DELETE → 404 is appropriate (no JSON-RPC body expected)
        return res.status(req.method === "POST" ? 200 : 404).json({
          jsonrpc: "2.0",
          error: {
            code: -32001,
            message: "Session not found. Re-initialize the MCP connection.",
          },
          id: req.body?.id ?? null,
        });
      }

      const server = createServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => sessionId || randomUUID(),
      });

      transport.onclose = async () => {
        const activeSessionId = transport.sessionId;
        if (!activeSessionId) return;

        const current = sessions.get(activeSessionId);
        if (current?.transport === transport) {
          sessions.delete(activeSessionId);
        }

        try {
          await server.close();
        } catch (error) {
          log("warn", "session", {
            event: "server_close_failed_on_transport_close",
            sessionId: activeSessionId,
            message: error instanceof Error ? error.message : String(error),
          });
        }
      };

      await server.connect(transport);
      session = { server, transport };
    }

    // Ensure both MIME types are present so StreamableHTTPServerTransport
    // can negotiate SSE mode regardless of what the client sent
    if (req.method === "POST") {
      const accept = String(req.headers["accept"] || "");
      if (!accept.includes("application/json") || !accept.includes("text/event-stream")) {
        const parts = new Set(accept.split(",").map((s) => s.trim()).filter(Boolean));
        parts.add("application/json");
        parts.add("text/event-stream");
        req.headers["accept"] = [...parts].join(", ");
      }
    }

    await session.transport.handleRequest(req, res, req.body);

    const activeSessionId = session.transport.sessionId;
    if (activeSessionId) {
      sessions.set(activeSessionId, session);
    }
  } catch (error) {
    log("error", "rpc", {
      sessionId: sessionId ?? null,
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });

    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal server error",
        },
        id: req.body?.id ?? null,
      });
    }
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of authCodes.entries()) {
    if (now > v.expiresAt) authCodes.delete(k);
  }
  for (const [k, v] of accessTokens.entries()) {
    if (now > v.expiresAt) accessTokens.delete(k);
  }
  for (const [k, v] of refreshTokensByHash.entries()) {
    if (now > v.expiresAt) refreshTokensByHash.delete(k);
  }
  for (const [k, v] of pendingAuths.entries()) {
    if (now > v.expiresAt) pendingAuths.delete(k);
  }
}, 60_000).unref();

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  if (!hasOAuthConfig()) {
    return res.status(404).json({ error: "OAuth not configured on this server." });
  }
  res.json({
    resource: PUBLIC_BASE_URL,
    authorization_servers: [PUBLIC_BASE_URL],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  if (!hasOAuthConfig()) {
    return res.status(404).json({ error: "OAuth not configured on this server." });
  }
  res.json({
    issuer: PUBLIC_BASE_URL,
    authorization_endpoint: `${PUBLIC_BASE_URL}/authorize`,
    token_endpoint: `${PUBLIC_BASE_URL}/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
  });
});

app.get("/authorize", (req, res) => {
  if (!hasOAuthConfig()) {
    return res.status(503).send("OAuth is not configured on this server.");
  }

  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;

  if (response_type !== "code") {
    return res.status(400).send("Unsupported response_type. Only 'code' is supported.");
  }
  if (!client_id || !constantTimeEquals(String(client_id), MCP_OAUTH_CLIENT_ID)) {
    return res.status(400).send("Invalid client_id.");
  }
  if (!redirect_uri) {
    return res.status(400).send("Missing redirect_uri.");
  }
  if (!code_challenge) {
    return res.status(400).send("Missing code_challenge. PKCE with S256 is required.");
  }
  if (code_challenge_method !== "S256") {
    return res.status(400).send("Only code_challenge_method=S256 is supported.");
  }

  // Store validated params server-side; pendingId is the CSRF token.
  const pendingId = randomUUID();
  pendingAuths.set(pendingId, {
    clientId: String(client_id),
    redirectUri: String(redirect_uri),
    codeChallenge: String(code_challenge),
    state: state ? String(state) : "",
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  log("info", "oauth", { event: "authorize_consent_shown", client_id });

  // Consent page: user explicitly clicks "授权" before code is issued.
  // This prevents blind auto-redirect and satisfies MCP spec SHOULD requirement.
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权 — memory-mcp</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
  .card{background:#fff;border:1px solid #e0e0e0;border-radius:14px;padding:40px 36px;max-width:420px;width:100%;text-align:center}
  h2{font-size:1.2rem;font-weight:600;margin-bottom:10px}
  p{color:#555;font-size:.9rem;line-height:1.6;margin-bottom:28px}
  code{font-size:.8rem;background:#f0f0f0;padding:2px 6px;border-radius:4px}
  button{background:#111;color:#fff;border:none;border-radius:9px;padding:13px 0;width:100%;font-size:1rem;cursor:pointer}
  button:hover{background:#333}
</style>
</head>
<body>
<div class="card">
  <h2>连接记忆 MCP 服务</h2>
  <p>Claude 正在请求访问你的 <code>memory-mcp</code> 服务器。<br>点击授权后 Claude 将可以读写你的记忆。</p>
  <form method="POST" action="/authorize">
    <input type="hidden" name="pending_id" value="${htmlEscape(pendingId)}">
    <button type="submit">授权连接</button>
  </form>
</div>
</body>
</html>`);
});

app.post("/authorize", express.urlencoded({ extended: false }), (req, res) => {
  if (!hasOAuthConfig()) {
    return res.status(503).send("OAuth is not configured on this server.");
  }

  const pendingId = String(req.body.pending_id || "");
  const pending = pendingAuths.get(pendingId);
  if (!pending || Date.now() > pending.expiresAt) {
    if (pending) pendingAuths.delete(pendingId);
    return res.status(400).send("Authorization request expired or invalid. Please try again from Claude.");
  }
  pendingAuths.delete(pendingId);

  const code = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
  authCodes.set(code, {
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    codeChallenge: pending.codeChallenge,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  log("info", "oauth", { event: "auth_code_issued", client_id: pending.clientId });

  const callbackUrl = new URL(pending.redirectUri);
  callbackUrl.searchParams.set("code", code);
  if (pending.state) callbackUrl.searchParams.set("state", pending.state);

  res.redirect(callbackUrl.toString());
});

app.post("/token", express.urlencoded({ extended: false }), async (req, res) => {
  if (!hasOAuthConfig()) {
    return res.status(503).json({ error: "server_error", error_description: "OAuth is not configured." });
  }

  let clientId = String(req.body.client_id || "");
  let clientSecret = String(req.body.client_secret || "");

  const authHeader = req.headers.authorization || "";
  if (!clientId && authHeader.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
    const sep = decoded.indexOf(":");
    if (sep !== -1) {
      clientId = decodeURIComponent(decoded.slice(0, sep));
      clientSecret = decodeURIComponent(decoded.slice(sep + 1));
    }
  }

  if (!clientId || !constantTimeEquals(clientId, MCP_OAUTH_CLIENT_ID)) {
    return res.status(401).json({ error: "invalid_client" });
  }
  if (!clientSecret || !constantTimeEquals(clientSecret, MCP_OAUTH_CLIENT_SECRET)) {
    return res.status(401).json({ error: "invalid_client" });
  }

  const grantType = String(req.body.grant_type || "");

  // ── refresh_token grant ──────────────────────────────────────────
  if (grantType === "refresh_token") {
    const incomingRefreshToken = String(req.body.refresh_token || "");
    const rtEntry = isValidRefreshToken(incomingRefreshToken);
    if (!rtEntry) {
      return res.status(400).json({ error: "invalid_grant", error_description: "Refresh token not found or expired." });
    }
    if (!constantTimeEquals(rtEntry.clientId, clientId)) {
      return res.status(400).json({ error: "invalid_grant", error_description: "refresh_token client mismatch." });
    }

    // Rotate: revoke old refresh token, issue new pair.
    refreshTokensByHash.delete(hashToken(incomingRefreshToken));

    const accessToken = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
    accessTokens.set(accessToken, { clientId, expiresAt: Date.now() + MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS * 1000 });

    const newRefreshToken = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
    const newRtHash = hashToken(newRefreshToken);
    const refreshExpiresAt = Date.now() + MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS * 1000;
    refreshTokensByHash.set(newRtHash, { clientId, expiresAt: refreshExpiresAt });

    log("info", "oauth", { event: "token_refreshed", client_id: clientId, expires_in: MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS });

    await saveOAuthState();

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: newRefreshToken,
    });
  }

  // ── authorization_code grant ─────────────────────────────────────
  if (grantType !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  const code = String(req.body.code || "");
  const codeEntry = authCodes.get(code);
  if (!codeEntry || Date.now() > codeEntry.expiresAt) {
    if (codeEntry) authCodes.delete(code);
    return res.status(400).json({ error: "invalid_grant", error_description: "Authorization code not found or expired." });
  }

  const redirectUri = String(req.body.redirect_uri || "");
  if (redirectUri && codeEntry.redirectUri && redirectUri !== codeEntry.redirectUri) {
    return res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch." });
  }

  const codeVerifier = String(req.body.code_verifier || "");
  if (!codeVerifier) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Missing code_verifier." });
  }
  if (!verifyPKCE(codeVerifier, codeEntry.codeChallenge)) {
    return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed." });
  }

  authCodes.delete(code);

  const accessToken = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
  accessTokens.set(accessToken, { clientId, expiresAt: Date.now() + MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS * 1000 });

  const refreshToken = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
  const rtHash = hashToken(refreshToken);
  const refreshExpiresAt = Date.now() + MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS * 1000;
  refreshTokensByHash.set(rtHash, { clientId, expiresAt: refreshExpiresAt });

  log("info", "oauth", { event: "access_token_issued", client_id: clientId, expires_in: MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS });

  await saveOAuthState();

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refreshToken,
  });
});

const PORT = Number(process.env.PORT || 3000);
const httpServer = app.listen(PORT, () => {
  log("info", "server", {
    message: `MCP server started on port ${PORT}`,
    storage: "supabase",
    supabase_configured: hasSupabaseConfig(),
    memory_table: MEMORY_TABLE,
    oauth_state_table: SUPABASE_TABLE,
    oauth_state_row_id: OAUTH_STATE_ROW_ID,
    bearer_auth_configured: hasAuthConfig(),
    oauth_configured: hasOAuthConfig(),
    auth_configured: hasAnyAuthConfig(),
  });
  loadOAuthState().catch(() => {});
});

async function shutdown() {
  httpServer.close();

  for (const sessionId of sessions.keys()) {
    await closeSession(sessionId);
  }

  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
