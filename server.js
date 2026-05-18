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

function effectiveProfiles(value) {
  const profiles = ensureArray(value).map((v) => String(v).trim()).filter(Boolean);
  return profiles.length ? profiles : ["shared"];
}

function normalizeProfiles(value) {
  if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
  if (typeof value === "string") {
    return value.split(/[，,、;；\n]/).map((v) => v.trim()).filter(Boolean);
  }
  return [];
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

function flattenKeywordTokens(tokens) {
  return [...new Set(
    tokens
      .slice(0, KEYWORDS_MAX)
      .map((t) => safeString(String(t ?? "").trim(), STR_LIMITS.keyword).trim())
      .filter(Boolean)
  )];
}

function splitKeywords(value) {
  if (Array.isArray(value)) {
    const expanded = [];
    for (const item of value) {
      const s = String(item ?? "").trim();
      if (s.startsWith("[")) {
        try {
          const parsed = JSON.parse(s);
          if (Array.isArray(parsed)) {
            for (const inner of parsed) {
              const t = String(inner ?? "").trim();
              if (t) expanded.push(t);
            }
            continue;
          }
        } catch (_) {}
      }
      if (s) expanded.push(s);
    }
    return flattenKeywordTokens(expanded);
  }
  if (typeof value === "string") {
    const s = value.trim();
    // Top-level JSON-stringified array: "[\"大同\",\"五一\"]"
    if (s.startsWith("[")) {
      try {
        const parsed = JSON.parse(s);
        if (Array.isArray(parsed)) {
          return flattenKeywordTokens(parsed.map((v) => String(v ?? "").trim()));
        }
      } catch (_) {}
    }
    return flattenKeywordTokens(
      s.split(/[，,、;；\n]/).map((t) => t.trim())
    );
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

function buildMemoryRow(input = {}, { isUpdate = false } = {}) {
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

  // Shallow-copy so we never mutate the caller's raw object (which may still be
  // referenced after this call returns).
  const raw = { ...ensureObject(input.raw, {}) };
  for (const field of RAW_COMPAT_FIELDS) {
    if (input[field] !== undefined) raw[field] = input[field];
  }
  // Auto-protect core/treasure/diary only when inserting a new row. On updates we
  // must preserve whatever the existing record had, otherwise an unprotect can be
  // silently reverted on the next edit.
  if (
    !isUpdate &&
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

const RAW_COLUMN_SYNC = ["resolved", "pinned", "protected", "digested", "activation_count", "last_active", "valence", "arousal"];

function syncRawToColumns(row) {
  const raw = row.raw;
  if (!raw) return;
  for (const field of RAW_COLUMN_SYNC) {
    if (raw[field] !== undefined) row[field] = raw[field];
  }
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
    profiles: effectiveProfiles(row.profiles),
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
  return String(value).replace(/[(),%*_.\\'"]/g, " ").trim();
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
    log("info", "memory", { event: "touch_memory_row", id, current_count: numericCount, next_count: nextCount });
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

async function readMemoryRowsByBucketId(bucketId, { limit = 500 } = {}) {
  if (!bucketId) return [];
  const client = getSupabaseClient();
  const cap = Math.max(1, Math.min(2000, Number(limit) || 500));
  const { data, error } = await client
    .from(MEMORY_TABLE)
    .select("*")
    .eq("bucket_id", bucketId)
    .order("updated_at", { ascending: false, nullsFirst: false })
    .limit(cap);
  if (error) throw toDbError("readMemoryRowsByBucketId failed", error);
  return ensureArray(data);
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
  if (memory.bucket_id) {
    const bucketParts = [`bucket_id: ${memory.bucket_id}`, `bucket_type: ${memory.bucket_type || "topic"}`];
    if (memory.name) bucketParts.push(`name: ${memory.name}`);
    if (memory.domain?.length) bucketParts.push(`domain: ${memory.domain.join(", ")}`);
    if (memory.tags?.length) bucketParts.push(`tags: ${memory.tags.join(", ")}`);
    lines.push(bucketParts.join(" | "));
  }
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
  const effective = effectiveProfiles(memory.profiles);
  if (profileFilter === "all") return true;
  if (profileFilter === "rowan") return effective.includes("shared") || effective.includes("rowan");
  if (profileFilter === "arion") return effective.includes("shared") || effective.includes("arion");
  return effective.includes("shared");
}

function memoryTextMatch(memory, q) {
  const ql = String(q || "").trim().toLowerCase();
  if (!ql) return true;
  const raw = ensureObject(memory.raw, {});
  const title = String(memory.title || "").toLowerCase();
  const name = String(memory.name || "").toLowerCase();
  const author = String(memory.author || "").toLowerCase();
  const mood = String(memory.mood || "").toLowerCase();
  const keywords = ensureArray(memory.keywords).map((v) => String(v).toLowerCase());
  const tags = ensureArray(memory.tags).map((v) => String(v).toLowerCase());
  const domain = ensureArray(memory.domain).map((v) => String(v).toLowerCase());
  const content = String(memory.content || "").toLowerCase();
  const whyPrecious = String(memory.why_precious || raw.why_precious || "").toLowerCase();
  const todaySnapshot = String(memory.today_snapshot || raw.today_snapshot || "").toLowerCase();
  const rawSummary = [raw.digest_text, raw.summary, raw.memo, raw.note]
    .filter(Boolean).map((v) => String(v).toLowerCase()).join(" ");
  return (
    title.includes(ql) ||
    name.includes(ql) ||
    author.includes(ql) ||
    mood.includes(ql) ||
    keywords.some((v) => v.includes(ql)) ||
    tags.some((v) => v.includes(ql)) ||
    domain.some((v) => v.includes(ql)) ||
    content.includes(ql) ||
    whyPrecious.includes(ql) ||
    todaySnapshot.includes(ql) ||
    Boolean(rawSummary && rawSummary.includes(ql))
  );
}

// Returns { score, reason } for search_memories_surface.
// Scoring is purely additive post-filter — pinned/protected never bypass q/kw gates.
function scoreSearchResult(m, ql, kwList) {
  const reasons = [];
  const imp = Math.max(1, Math.min(10, Number(m.importance) || 5));
  // Importance + capped decay as baseline (decay kept small so it doesn't bury keyword hits)
  let score = imp * 0.5 + Math.min(calcDecayScore(m), 20) * 0.05;

  if (ql) {
    const q = ql.toLowerCase();
    const title = String(m.title || "").toLowerCase();
    const name = String(m.name || "").toLowerCase();
    const kws = ensureArray(m.keywords).map((k) => String(k).toLowerCase());
    const tags = ensureArray(m.tags).map((t) => String(t).toLowerCase());
    const domain = ensureArray(m.domain).map((d) => String(d).toLowerCase());
    const content = String(m.content || "").toLowerCase();
    const whyPrecious = String(m.why_precious || "").toLowerCase();
    const todaySnapshot = String(m.today_snapshot || "").toLowerCase();

    if (title.includes(q) || name.includes(q)) {
      score += imp * 3.0;
      reasons.push("title/name");
    } else if (
      kws.some((k) => k.includes(q)) ||
      tags.some((t) => t.includes(q)) ||
      domain.some((d) => d.includes(q))
    ) {
      score += imp * 1.8;
      reasons.push("kw/tag/domain");
    } else if (content.includes(q) || whyPrecious.includes(q) || todaySnapshot.includes(q)) {
      score += imp * 1.2;
      reasons.push("content");
    }
  }

  if (kwList.length) {
    const memKws = new Set(ensureArray(m.keywords).map((k) => String(k).toLowerCase()));
    const hits = kwList.filter((k) => memKws.has(String(k).toLowerCase()));
    if (hits.length) {
      const ratio = hits.length / kwList.length;
      score += imp * ratio * 2.0;
      reasons.push(`kw_overlap=${hits.length}/${kwList.length}`);
    }
  }

  if (m.pinned) { score += 5; reasons.push("pinned"); }
  else if (m.protected) { score += 2; reasons.push("protected"); }

  // resolved/digested downweight (only reached when include_* flags are true)
  if (m.resolved && m.digested) score *= 0.1;
  else if (m.resolved) score *= 0.2;
  else if (m.digested) score *= 0.3;

  return {
    score: Math.round(score * 10000) / 10000,
    reason: reasons.join(", ") || "recency",
  };
}

function calcHoldSimilarity(inputRow, candidate) {
  let score = 0;

  // Keywords: input coverage rate — weight 0.40
  const inputKws = new Set(ensureArray(inputRow.keywords).map((k) => String(k).toLowerCase()));
  const candKws = new Set(ensureArray(candidate.keywords).map((k) => String(k).toLowerCase()));
  if (inputKws.size > 0) {
    const intersection = [...inputKws].filter((k) => candKws.has(k)).length;
    score += 0.40 * (intersection / inputKws.size);
  }

  // Layer match — weight 0.15
  const il = String(inputRow.layer || "").toLowerCase();
  const cl = String(candidate.layer || "").toLowerCase();
  if (il && cl && il === cl) score += 0.15;

  // Sub_layer match — weight 0.10
  const isl = String(inputRow.sub_layer || "").toLowerCase();
  const csl = String(candidate.sub_layer || "").toLowerCase();
  if (isl && csl) {
    if (isl === csl) score += 0.10;
  }

  // Title similarity — weight up to 0.20
  const it = String(inputRow.title || "").toLowerCase().trim();
  const ct = String(candidate.title || "").toLowerCase().trim();
  if (it && ct) {
    if (it === ct) {
      score += 0.20;
    } else if (it.length > 3 && ct.includes(it)) {
      score += 0.15;
    } else if (ct.length > 3 && it.includes(ct)) {
      score += 0.15;
    } else {
      // CJK-friendly character-level overlap
      const itChars = new Set([...it].filter((c) => c.trim()));
      const ctCharsArr = [...ct].filter((c) => c.trim());
      const overlap = ctCharsArr.filter((c) => itChars.has(c)).length;
      score += 0.08 * Math.min(overlap / Math.max(itChars.size, ctCharsArr.length, 1), 1);
    }
  }

  // Content snippet match — weight up to 0.10
  const ic = String(inputRow.content || "").toLowerCase();
  const cc = String(candidate.content || "").toLowerCase();
  if (ic.length >= 8 && cc.length >= 8) {
    const snippet = ic.slice(0, 30);
    if (cc.includes(snippet)) {
      score += 0.10;
    } else {
      const icSample = new Set([...ic.slice(0, 120)].filter((c) => c.trim()));
      const ccSample = [...cc.slice(0, 120)].filter((c) => c.trim());
      const overlap = ccSample.filter((c) => icSample.has(c)).length;
      score += 0.05 * Math.min(overlap / Math.max(icSample.size, ccSample.length, 1), 1);
    }
  }

  // Author match — weight 0.03
  const ia = String(inputRow.author || "").toLowerCase().trim();
  const ca = String(candidate.author || "").toLowerCase().trim();
  if (ia && ca && ia === ca) score += 0.03;

  // Mood match — weight 0.02
  const im = String(inputRow.mood || "").toLowerCase().trim();
  const cm = String(candidate.mood || "").toLowerCase().trim();
  if (im && cm && im === cm) score += 0.02;

  return Math.round(Math.min(score, 1) * 10000) / 10000;
}

// ── Bucket clustering helpers ─────────────────────────────────────────────────

const BUCKET_TAGS_MAX = 10;
const BUCKET_DOMAIN_MAX = 5;
const BUCKET_MATCH_THRESHOLD = 0.28;

function normalizeBucketText(text) {
  return String(text || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^\w一-鿿]/g, "");
}

function makeStableBucketId(seed) {
  const hash = createHash("sha256").update(String(seed)).digest("hex").slice(0, 8);
  return `bucket_${hash}`;
}

function inferBucketSeed(memory) {
  const layer = String(memory.layer || "daily");
  const subLayer = String(memory.sub_layer || "").trim();
  const keywords = ensureArray(memory.keywords);
  const title = String(memory.title || "").trim();
  if (subLayer) {
    const topKw = keywords[0] ? normalizeBucketText(keywords[0]) : "";
    return `${layer}/${subLayer}/${topKw}`.replace(/\/+$/, "");
  }
  if (keywords.length > 0) {
    const topKw = normalizeBucketText(keywords[0]);
    if (topKw) return `${layer}/${topKw}`;
  }
  if (title) {
    const titleKey = normalizeBucketText(title.slice(0, 20));
    if (titleKey) return `${layer}/${titleKey}`;
  }
  return layer;
}

function scoreBucketMatch(memory, bucketCandidate) {
  let score = 0;
  let hasSubjectHit = false;

  // layer/sub_layer: bonus only, cannot trigger a match on their own
  const ml = String(memory.layer || "").toLowerCase();
  const bl = String(bucketCandidate.layer || "").toLowerCase();
  if (ml && bl && ml === bl) score += 0.20;

  const ms = String(memory.sub_layer || "").toLowerCase().trim();
  const bs = String(bucketCandidate.sub_layer || "").toLowerCase().trim();
  if (ms && bs && ms === bs) score += 0.15;

  // Subject hit 1: keywords intersection
  const mKws = new Set(ensureArray(memory.keywords).map((k) => String(k).toLowerCase()));
  const bKws = new Set(ensureArray(bucketCandidate.keywords).map((k) => String(k).toLowerCase()));
  if (mKws.size > 0 && bKws.size > 0) {
    const intersection = [...mKws].filter((k) => bKws.has(k)).length;
    if (intersection > 0) {
      hasSubjectHit = true;
      const union = new Set([...mKws, ...bKws]).size;
      score += 0.40 * (intersection / union);
    }
  }

  // Subject hit 2: title ↔ bucket name containment
  const mt = String(memory.title || "").toLowerCase().trim();
  const bn = String(bucketCandidate.name || "").toLowerCase().trim();
  if (mt && bn && mt.length > 1 && bn.length > 1) {
    if (mt.includes(bn) || bn.includes(mt)) {
      hasSubjectHit = true;
      score += 0.10;
    }
  }

  // Subject hit 3: domain/tags intersection
  const mDomain = new Set(ensureArray(memory.domain).map((d) => String(d).toLowerCase()));
  const mTags = new Set(ensureArray(memory.tags).map((t) => String(t).toLowerCase()));
  const bDomain = ensureArray(bucketCandidate.domain).map((d) => String(d).toLowerCase());
  const bTags = ensureArray(bucketCandidate.tags).map((t) => String(t).toLowerCase());
  const domainHits = bDomain.filter((d) => mDomain.has(d)).length;
  const tagHits = bTags.filter((t) => mTags.has(t)).length;
  if (domainHits + tagHits > 0) {
    hasSubjectHit = true;
    const dtDenom = Math.max(bDomain.length + bTags.length, 1);
    score += 0.10 * ((domainHits + tagHits) / dtDenom);
  }

  // Gate: no subject hit → no match
  if (!hasSubjectHit) return 0;

  // Recency bonus (cannot solo-trigger match)
  const la = parseDateLike(bucketCandidate.last_active);
  if (la) {
    const days = Math.max(0, (Date.now() - la.getTime()) / 86400000);
    if (days <= 1) score += 0.05;
    else if (days <= 7) score += 0.03;
    else if (days <= 30) score += 0.01;
  }

  return Math.round(Math.min(score, 1) * 10000) / 10000;
}

async function findBestBucketForMemory(memory) {
  try {
    const client = getSupabaseClient();
    const { data, error } = await client
      .from(MEMORY_TABLE)
      .select("bucket_id, bucket_type, name, domain, tags, keywords, layer, sub_layer, last_active, raw")
      .not("bucket_id", "is", null)
      .neq("bucket_id", "")
      .order("updated_at", { ascending: false, nullsFirst: false })
      .limit(300);
    if (error || !data) return null;

    const bucketMap = new Map();
    for (const row of data) {
      const bid = String(row.bucket_id || "");
      if (!bid || bucketMap.has(bid)) continue;
      const raw = ensureObject(row.raw, {});
      bucketMap.set(bid, {
        bucket_id: bid,
        bucket_type: row.bucket_type || raw.bucket_type || "topic",
        name: row.name || raw.name || "",
        domain: ensureArray(row.domain ?? raw.domain),
        tags: ensureArray(row.tags ?? raw.tags),
        keywords: ensureArray(row.keywords),
        layer: row.layer || "",
        sub_layer: row.sub_layer || "",
        last_active: row.last_active || raw.last_active || "",
      });
    }

    if (!bucketMap.size) return null;

    let best = null;
    let bestScore = BUCKET_MATCH_THRESHOLD;
    for (const candidate of bucketMap.values()) {
      const s = scoreBucketMatch(memory, candidate);
      if (s > bestScore) { bestScore = s; best = candidate; }
    }
    return best;
  } catch (_) {
    return null;
  }
}

function inferBucketType(layer) {
  if (layer === "diary") return "diary";
  if (layer === "core" || layer === "treasure") return "core";
  return "topic";
}

function buildBucketForMemory(memory) {
  const seed = inferBucketSeed(memory);
  const bucket_id = makeStableBucketId(seed);
  const bucket_type = inferBucketType(String(memory.layer || "daily"));
  const keywords = ensureArray(memory.keywords);
  const title = String(memory.title || "").trim();
  const subLayer = String(memory.sub_layer || "").trim();
  const name = safeString(title || (keywords[0] ? String(keywords[0]) : "") || subLayer || seed, 100);
  const domain = ensureArray(memory.domain).slice(0, BUCKET_DOMAIN_MAX);
  const tags = [...new Set([...keywords, ...ensureArray(memory.tags), ...ensureArray(memory.domain)])].slice(0, BUCKET_TAGS_MAX);
  return { bucket_id, bucket_type, name, domain, tags };
}

function applyBucketFields(row, bucket) {
  if (!bucket) return row;
  if (bucket.bucket_id) row.bucket_id = bucket.bucket_id;
  if (bucket.bucket_type) row.bucket_type = bucket.bucket_type;
  if (bucket.name) row.name = bucket.name;
  if (Array.isArray(bucket.domain)) row.domain = bucket.domain;
  if (Array.isArray(bucket.tags)) row.tags = bucket.tags;
  return row;
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

async function buildRecallContext({
  q,
  profile = "shared",
  layer,
  sub_layer,
  budget_chars = 4000,
  max_items = 20,
  include_resolved = false,
  include_digested = false,
  include_archived = false,
  touch = false,
  include_buckets = true,
} = {}) {
  const ql = q ? String(q).trim() : "";
  const hasQ = Boolean(ql);
  const SNIPPET_CAP = 600;
  const BUCKET_SNIPPET_CAP = 200;
  const MAX_TIER3 = 3;
  const MAX_BUCKETS = 5;

  function makeSnippet(m) {
    const content = String(m.content || "");
    return content.length > SNIPPET_CAP ? content.slice(0, SNIPPET_CAP) + "…" : content;
  }

  function filterClosed(arr) {
    let out = arr;
    if (!include_archived) out = out.filter((m) => !m._archived);
    if (!include_resolved) out = out.filter((m) => !m.resolved);
    if (!include_digested) out = out.filter((m) => !m.digested);
    return out;
  }

  // ─── Tier 1: Precise Search ─────────────────────────────────────────────
  let rows = [];
  if (hasQ) {
    const batchLimit = Math.min(600, max_items * 15);
    const batches = await Promise.all([
      queryMemoryRows({ q: ql, layer, sub_layer, limit: batchLimit }),
      queryMemoryRows({ keywords: ql, layer, sub_layer, limit: batchLimit }),
    ]);
    const seen = new Set();
    for (const batch of batches) {
      for (const r of ensureArray(batch)) {
        if (r?.id && !seen.has(r.id)) {
          seen.add(r.id);
          rows.push(r);
        }
      }
    }
  } else {
    rows = await readMemoryRows({ layer, sub_layer, limit: 500 });
  }

  let memories = filterClosed(rows.map(denormalizeMemoryRow).filter(Boolean));
  memories = memories.filter((m) => matchesProfileFilter(m, profile));
  if (hasQ) memories = memories.filter((m) => memoryTextMatch(m, ql));

  const t1Scored = memories.map((m) => {
    const { score, reason } = scoreSearchResult(m, ql, []);
    return { m, score, reason, tier: 1 };
  });
  t1Scored.sort((a, b) => {
    if (a.m.pinned !== b.m.pinned) return a.m.pinned ? -1 : 1;
    return b.score - a.score;
  });
  const t1Candidates = t1Scored.slice(0, Math.min(max_items, 15));

  // No Tier 1 hits → return empty; Tier 3 not supplemented
  if (t1Candidates.length === 0) {
    return {
      context_text: "未找到相关记忆。",
      selected_memories: [],
      selected_buckets: [],
      omitted_count: 0,
      omitted_reason: [],
      generated_at: new Date().toISOString(),
      touch_applied: false,
      touched_ids: [],
      touched_count: 0,
    };
  }

  // ─── Tier 3: Core/Treasure (only when Tier 1 has hits) ──────────────────
  const t1Ids = new Set(t1Candidates.map(({ m }) => m.id));
  const [coreRows, treasureRows] = await Promise.all([
    readMemoryRows({ layer: "core", limit: 100 }),
    readMemoryRows({ layer: "treasure", limit: 100 }),
  ]);
  let t3Mems = filterClosed([...coreRows, ...treasureRows].map(denormalizeMemoryRow).filter(Boolean));
  t3Mems = t3Mems.filter((m) => matchesProfileFilter(m, profile));
  t3Mems = t3Mems.filter((m) => !t1Ids.has(m.id));
  t3Mems.sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    if (a.protected !== b.protected) return a.protected ? -1 : 1;
    const ai = Number(a.importance) || 0;
    const bi = Number(b.importance) || 0;
    if (ai !== bi) return bi - ai;
    const ada = parseDateLike(a.last_active || a.updated_at) ?? new Date(0);
    const bda = parseDateLike(b.last_active || b.updated_at) ?? new Date(0);
    return bda.getTime() - ada.getTime();
  });
  const t3Candidates = t3Mems.slice(0, MAX_TIER3).map((m) => ({
    m,
    score: Number(m.importance) || 0,
    reason: `layer=${m.layer} importance=${m.importance}`,
    tier: 3,
  }));

  // ─── Apply max_items cap ─────────────────────────────────────────────────
  const allCandidates = [...t1Candidates, ...t3Candidates];
  const omittedByMaxItems = Math.max(0, allCandidates.length - max_items);
  // Working arrays — mutated during budget enforcement
  let t1Items = t1Candidates.slice(0, max_items);
  let t3Items = t3Candidates.slice(0, Math.max(0, max_items - t1Items.length));

  // ─── Tier 2: Bucket Context ──────────────────────────────────────────────
  let buckets = [];
  if (include_buckets) {
    const bucketIds = [
      ...new Set([...t1Items, ...t3Items].map(({ m }) => m.bucket_id).filter(Boolean)),
    ].slice(0, MAX_BUCKETS);
    const bucketResults = await Promise.all(
      bucketIds.map(async (bid) => {
        const bRows = await readMemoryRowsByBucketId(bid, { limit: 50 });
        let bMems = filterClosed(bRows.map(denormalizeMemoryRow).filter(Boolean));
        bMems = bMems.filter((m) => matchesProfileFilter(m, profile));
        if (!bMems.length) return null;
        const topMem = [...bMems].sort((a, b) => (Number(b.importance) || 0) - (Number(a.importance) || 0))[0];
        const raw = String(topMem.content || topMem.title || "");
        return {
          bucket_id: bid,
          name: topMem.name || "",
          bucket_type: topMem.bucket_type || "topic",
          memory_count: bMems.length,
          summary_snippet: raw.slice(0, BUCKET_SNIPPET_CAP),
        };
      })
    );
    buckets = bucketResults.filter(Boolean);
  }

  // ─── Build context_text (shared logic, called after each budget trim) ────
  const generatedAt = new Date().toISOString();

  function buildContextText(t1, t3, bkts, omittedMemories, omittedReasons) {
    const ls = [`[RECALL — ${generatedAt}]`, `Query: ${ql || "(无)"}`];
    if (t1.length) {
      ls.push(`\n── 精确命中（${t1.length} 条）${"─".repeat(20)}`);
      t1.forEach(({ m, score }, i) => {
        ls.push(`${i + 1}. [${m.layer ?? ""}${m.sub_layer ? "/" + m.sub_layer : ""}] ${m.title || "未命名"}  score=${score}`);
        ls.push(`   ${makeSnippet(m)}`);
      });
    }
    if (bkts.length) {
      ls.push(`\n── Bucket 上下文（${bkts.length} 个）${"─".repeat(16)}`);
      for (const b of bkts) {
        ls.push(`• ${b.name || b.bucket_id}（${b.bucket_type}，${b.memory_count} 条）: ${b.summary_snippet}`);
      }
    }
    if (t3.length) {
      ls.push(`\n── 常驻记忆（core/treasure，${t3.length} 条）${"─".repeat(10)}`);
      t3.forEach(({ m }) => {
        ls.push(`${m.title || "未命名"}: ${makeSnippet(m)}`);
      });
    }
    if (omittedMemories > 0) {
      ls.push(`\n── 已省略 ${omittedMemories} 条（${omittedReasons.join("、")}）${"─".repeat(12)}`);
    }
    return ls.join("\n");
  }

  // ─── Budget Enforcement (post-build, hard guarantee) ────────────────────
  let omittedByBudget = 0;
  let budgetConstrained = false;
  let contextText = buildContextText(t1Items, t3Items, buckets, omittedByMaxItems, omittedByMaxItems > 0 ? ["max_items"] : []);

  while (contextText.length > budget_chars) {
    budgetConstrained = true;
    if (buckets.length > 0) {
      // Priority 1: remove least-important bucket (last); not a memory, not counted in omittedByBudget
      buckets.pop();
    } else if (t3Items.length > 0) {
      // Priority 2: remove last Tier 3 (already sorted lowest-priority last)
      t3Items.pop();
      omittedByBudget++;
    } else if (t1Items.length > 1) {
      // Priority 3: remove last Tier 1 (lowest score last)
      t1Items.pop();
      omittedByBudget++;
    } else {
      // Last resort: hard truncate — no more items to drop
      contextText = contextText.slice(0, budget_chars);
      break;
    }
    const totalOmitted = omittedByMaxItems + omittedByBudget;
    const reasons = [];
    if (omittedByMaxItems > 0) reasons.push("max_items");
    if (budgetConstrained) reasons.push("budget");
    contextText = buildContextText(t1Items, t3Items, buckets, totalOmitted, reasons);
  }

  const omittedCount = omittedByMaxItems + omittedByBudget;
  const omittedReason = [];
  if (omittedByMaxItems > 0) omittedReason.push("max_items");
  if (budgetConstrained) omittedReason.push("budget");

  // ─── Build selected_memories from final t1Items + t3Items ────────────────
  const selectedMemories = [...t1Items, ...t3Items].map(({ m, score, reason, tier }) => ({
    id: m.id ?? "",
    title: m.title ?? "",
    layer: m.layer ?? "",
    sub_layer: m.sub_layer ?? "",
    score,
    reason,
    content_snippet: makeSnippet(m),
    bucket_id: m.bucket_id ?? "",
    importance: typeof m.importance === "number" ? m.importance : 0,
    tier,
    pinned: Boolean(m.pinned),
    protected: Boolean(m.protected),
    resolved: Boolean(m.resolved),
    digested: Boolean(m.digested),
  }));

  // ─── Touch ───────────────────────────────────────────────────────────────
  const touchIds = touch
    ? [...new Set(selectedMemories.map((item) => item.id).filter(isValidUuid))]
    : [];
  if (touch && touchIds.length) {
    log("info", "tool", { tool: "recall_context_touch", touch_ids: touchIds, touch_count: touchIds.length });
    await Promise.allSettled(touchIds.map((id) => touchMemoryRow(id)));
  }

  return {
    context_text: contextText,
    selected_memories: selectedMemories,
    selected_buckets: buckets,
    omitted_count: omittedCount,
    omitted_reason: omittedReason,
    generated_at: generatedAt,
    touch_applied: touch && touchIds.length > 0,
    touched_ids: touchIds,
    touched_count: touchIds.length,
  };
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
        hint: z.string().optional(),
      }),
    },
    async (args) => {
      const row = buildMemoryRow(args);
      let saved;
      let mode;

      if (row.id) {
        // Merge semantics: fetch existing so unspecified fields are preserved
        const existing = await readMemoryById(row.id);
        if (existing) {
          const existingRaw = ensureObject(existing.raw, {});
          // Base = existing DB fields; overlay only fields explicitly provided in args
          const mergedArgs = {
            layer: existing.layer,
            sub_layer: existing.sub_layer,
            title: existing.title,
            content: existing.content,
            importance: existing.importance,
            date: existing.date,
            author: existing.author,
            mood: existing.mood,
            keywords: existing.keywords,
            profiles: existing.profiles,
            legacy_id: existing.legacy_id,
          };
          for (const [k, v] of Object.entries(args)) {
            if (v !== undefined && k !== "raw") mergedArgs[k] = v;
          }
          // Deep-merge raw: existing raw + args.raw, then overlay RAW_COMPAT_FIELDS from args
          mergedArgs.raw = { ...existingRaw, ...ensureObject(args.raw, {}) };
          for (const field of RAW_COMPAT_FIELDS) {
            if (args[field] !== undefined) mergedArgs.raw[field] = args[field];
          }
          mergedArgs.id = row.id;
          const mergedRow = buildMemoryRow(mergedArgs, { isUpdate: true });
          saved = await updateMemoryRowById(row.id, mergedRow);
        } else {
          saved = await upsertMemoryRow(row);
        }
        mode = "upsert_by_id";
      } else if (row.legacy_id) {
        const existing = await readMemoryByLegacyId(row.legacy_id);
        if (existing?.id) {
          // Same merge-preserve logic as the id path: base = existing, overlay args
          const existingRaw = ensureObject(existing.raw, {});
          const mergedArgs = {
            layer: existing.layer,
            sub_layer: existing.sub_layer,
            title: existing.title,
            content: existing.content,
            importance: existing.importance,
            date: existing.date,
            author: existing.author,
            mood: existing.mood,
            keywords: existing.keywords,
            profiles: existing.profiles,
            legacy_id: existing.legacy_id,
          };
          for (const [k, v] of Object.entries(args)) {
            if (v !== undefined && k !== "raw") mergedArgs[k] = v;
          }
          mergedArgs.raw = { ...existingRaw, ...ensureObject(args.raw, {}) };
          for (const field of RAW_COMPAT_FIELDS) {
            if (args[field] !== undefined) mergedArgs.raw[field] = args[field];
          }
          mergedArgs.id = existing.id;
          const mergedRow = buildMemoryRow(mergedArgs, { isUpdate: true });
          saved = await updateMemoryRowById(existing.id, mergedRow);
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
      if (row.layer === "diary" && !row.raw?.chord_tag) {
        result.hint = "chord_tag 未填写——今天的情绪是什么调？";
      }

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
        strict_q: z.boolean().optional().default(false),
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
        mode: z.string(),
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
      strict_q = false,
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
        const batchLimit = Math.min(300, cap * 10);
        const [textRows, kwRows] = await Promise.all([
          queryMemoryRows({ q, layer, sub_layer, limit: batchLimit }),
          queryMemoryRows({ keywords: q, layer, sub_layer, limit: batchLimit }),
        ]);
        const seen = new Set();
        rows = [];
        for (const r of [...textRows, ...kwRows]) {
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
      if (hasQuery && strict_q) {
        memories = memories.filter((m) => memoryTextMatch(m, q));
      }

      const scored = memories.map((m) => ({
        m,
        score: computeScore(m),
        isHit: hasQuery ? memoryTextMatch(m, q) : true,
      }));
      scored.sort((a, b) => b.score - a.score);

      let top;
      if (hasQuery && !strict_q) {
        const hits = scored.filter((s) => s.isHit);
        const nonHits = scored.filter((s) => !s.isHit);
        top = [...hits, ...nonHits].slice(0, cap);
      } else {
        top = scored.slice(0, cap);
      }

      if (touch) {
        await Promise.allSettled(top.map(({ m }) => touchMemoryRow(m.id)));
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
        profiles: effectiveProfiles(m.profiles),
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

      const mode = hasQuery && strict_q ? "query_strict" : (hasQuery ? "query_biased" : "surface");

      const result = {
        items: structuredItems,
        returned_count: structuredItems.length,
        total_memories: total,
        touched: touch && top.length > 0,
        mode,
        generated_at: new Date().toISOString(),
      };

      log("info", "tool", {
        tool: "memory_surface",
        args: { q, profile, layer, sub_layer, limit, include_resolved, include_archived, touch, strict_q },
        result: { returned_count: result.returned_count, total_memories: result.total_memories, mode },
      });

      const blocks = top.length
        ? top
            .map(
              ({ m, score }, i) =>
                `【${i + 1}/${top.length}】score=${score}\n${formatMemoryForModel(m, snippet_length)}`
            )
            .join("\n\n---\n\n")
        : hasQuery && strict_q ? `没有找到匹配 "${q}" 的记忆。` : "没有浮现任何记忆。";

      return makeResult(
        result,
        `记忆浮现完成（mode=${mode}），共返回 ${result.returned_count} 条（总数 ${result.total_memories}）：\n\n${blocks}`
      );
    }
  );

  server.registerTool(
    "memory_hold",
    {
      title: "Memory Hold",
      description:
        "Write a new memory or merge into an existing similar one. " +
        "Uses lightweight keyword/title/content similarity scoring (no embeddings). " +
        "If the best candidate scores >= threshold the new content is appended to that memory; " +
        "otherwise a new memory is created.",
      inputSchema: z.object({
        content: z.string().min(1),
        title: z.string().optional(),
        layer: z.string().optional(),
        sub_layer: z.string().optional(),
        author: z.string().optional(),
        mood: z.string().optional(),
        keywords: z.union([z.array(z.string()), z.string()]).optional(),
        profiles: z.union([z.array(z.string()), z.string()]).optional(),
        pinned: z.boolean().optional(),
        protected: z.boolean().optional(),
        importance: z.number().int().min(1).max(10).optional().default(2),
        date: z.string().optional(),
        today_snapshot: z.string().optional(),
        merge: z.boolean().optional().default(true),
        threshold: z.number().min(0).max(1).optional().default(0.55),
        limit: z.number().int().min(1).max(100).optional().default(20),
      }),
      outputSchema: z.object({
        mode: z.enum(["created", "merged"]),
        item: memoryRecordSchema,
        matched_id: z.string().optional(),
        similarity: z.number(),
        considered_count: z.number(),
      }),
    },
    async ({
      content,
      title,
      layer = "daily",
      sub_layer,
      author,
      mood,
      keywords,
      profiles,
      pinned,
      protected: protectedFlag,
      importance = 2,
      date,
      today_snapshot,
      merge = true,
      threshold = 0.55,
      limit = 20,
    }) => {
      const inputRow = buildMemoryRow({ content, title, layer, sub_layer, author, mood, keywords, profiles, importance, date, today_snapshot });

      // Apply pinned/protected to inputRow (only-raise; pinned forces protected)
      if (pinned) { inputRow.raw.pinned = true; inputRow.raw.protected = true; }
      else if (protectedFlag) { inputRow.raw.protected = true; }

      if (!merge) {
        if (!inputRow.bucket_id) {
          try {
            const bucket = await findBestBucketForMemory(inputRow) || buildBucketForMemory(inputRow);
            applyBucketFields(inputRow, bucket);
          } catch (_) {}
        }
        syncRawToColumns(inputRow);
        const saved = await insertMemoryRow(inputRow);
        const item = denormalizeMemoryRow(saved);
        log("info", "tool", {
          tool: "memory_hold",
          mode: "created",
          args: { layer, title, keyword_count: inputRow.keywords.length },
          result: { item_id: item?.id },
        });
        return makeResult(
          { mode: "created", item, similarity: 0, considered_count: 0 },
          `[created] id=${item?.id} | title=${item?.title || "(无)"} | similarity=0 | pinned=${item?.pinned} protected=${item?.protected} resolved=${item?.resolved} _archived=${item?._archived}`
        );
      }

      // Build candidate pool
      const [kwRows, titleRows, recentRows] = await Promise.all([
        inputRow.keywords.length
          ? queryMemoryRows({ keywords: inputRow.keywords, layer, sub_layer, limit: limit * 5 })
          : Promise.resolve([]),
        title
          ? queryMemoryRows({ q: title, layer, sub_layer, limit: limit * 3 })
          : Promise.resolve([]),
        readMemoryRows({ layer, sub_layer, limit: limit * 3 }),
      ]);

      const seen = new Set();
      const candidates = [];
      for (const r of [...kwRows, ...titleRows, ...recentRows]) {
        if (r?.id && !seen.has(r.id)) {
          seen.add(r.id);
          const den = denormalizeMemoryRow(r);
          if (den) candidates.push(den);
        }
      }

      // Filter: no archived, no resolved
      const eligible = candidates.filter((m) => !m._archived && !m.resolved);

      // Score each candidate
      const scored = eligible
        .map((m) => ({ m, score: calcHoldSimilarity(inputRow, m) }))
        .sort((a, b) => b.score - a.score);

      const best = scored[0];

      if (!best || best.score < threshold) {
        if (!inputRow.bucket_id) {
          try {
            const bucket = await findBestBucketForMemory(inputRow) || buildBucketForMemory(inputRow);
            applyBucketFields(inputRow, bucket);
          } catch (_) {}
        }
        syncRawToColumns(inputRow);
        const saved = await insertMemoryRow(inputRow);
        const item = denormalizeMemoryRow(saved);
        log("info", "tool", {
          tool: "memory_hold",
          mode: "created",
          args: { layer, title, threshold },
          result: { item_id: item?.id, best_score: best?.score ?? 0, considered_count: eligible.length },
        });
        return makeResult(
          { mode: "created", item, similarity: best?.score ?? 0, considered_count: eligible.length },
          `[created] id=${item?.id} | title=${item?.title || "(无)"} | similarity=${best?.score ?? 0} | pinned=${item?.pinned} protected=${item?.protected} resolved=${item?.resolved} _archived=${item?._archived}`
        );
      }

      // Merge into best match
      const existing = best.m;
      const existingRaw = ensureObject(existing.raw, {});

      const appendDate = (date || new Date().toISOString()).slice(0, 10);
      const mergedContent =
        String(existing.content || "") +
        `\n\n---\n补充于 ${appendDate}：\n${inputRow.content}`;

      const mergedKeywords = [
        ...new Set([...ensureArray(existing.keywords), ...inputRow.keywords]),
      ];
      const mergedProfiles = [
        ...new Set([...effectiveProfiles(existing.profiles), ...inputRow.profiles]),
      ];
      const mergedImportance = Math.max(
        Number(existing.importance) || 0,
        inputRow.importance
      );

      const now = new Date().toISOString();
      const newRaw = {
        ...existingRaw,
        activation_count:
          (Number(existingRaw.activation_count ?? existing.activation_count) || 0) + 1,
        last_active: now,
      };
      // Preserve existing pinned/protected — never lower them on merge
      if (existing.pinned) newRaw.pinned = true;
      if (existing.protected) newRaw.protected = true;
      // Apply incoming pinned/protected — only raise, never lower
      if (pinned) { newRaw.pinned = true; newRaw.protected = true; }
      else if (protectedFlag) { newRaw.protected = true; }
      // today_snapshot: new value overrides existing when provided
      if (today_snapshot !== undefined) newRaw.today_snapshot = today_snapshot;

      const mergeInput = { ...existing };
      // Strip top-level compat fields before buildMemoryRow to prevent override
      for (const field of RAW_COMPAT_FIELDS) delete mergeInput[field];
      delete mergeInput.digested;

      mergeInput.content = mergedContent;
      mergeInput.keywords = mergedKeywords;
      mergeInput.profiles = mergedProfiles;
      mergeInput.importance = mergedImportance;
      if (mood) mergeInput.mood = mood;
      if (author) mergeInput.author = author;
      mergeInput.raw = newRaw;
      mergeInput.id = existing.id;

      const row = buildMemoryRow(mergeInput, { isUpdate: true });
      // Force-preserve values that buildMemoryRow might not carry
      if (newRaw.pinned) row.raw.pinned = true;
      if (newRaw.protected) row.raw.protected = true;
      if (existingRaw.digested !== undefined) row.raw.digested = existingRaw.digested;
      row.raw.activation_count = newRaw.activation_count;
      row.raw.last_active = now;

      // Bucket: prefer existing bucket; only auto-assign if existing has none
      if (existing.bucket_id) {
        row.bucket_id = existing.bucket_id;
        row.bucket_type = existing.bucket_type || inferBucketType(existing.layer || "daily");
        row.name = existing.name || "";
        row.domain = ensureArray(existing.domain);
        row.tags = [...new Set([...ensureArray(existing.tags), ...ensureArray(inputRow.tags)])].slice(0, BUCKET_TAGS_MAX);
      } else {
        try {
          const bucket = await findBestBucketForMemory(row) || buildBucketForMemory(row);
          applyBucketFields(row, bucket);
        } catch (_) {}
      }

      syncRawToColumns(row);
      const saved = await updateMemoryRowById(existing.id, row);
      const item =
        denormalizeMemoryRow(saved) ??
        denormalizeMemoryRow({ ...row, id: existing.id });

      log("info", "tool", {
        tool: "memory_hold",
        mode: "merged",
        args: { layer, title, threshold },
        result: {
          matched_id: existing.id,
          similarity: best.score,
          considered_count: eligible.length,
          appended_length: inputRow.content.length,
        },
      });

      return makeResult(
        {
          mode: "merged",
          item,
          matched_id: existing.id,
          similarity: best.score,
          considered_count: eligible.length,
        },
        `[merged] id=${item?.id} | matched_id=${existing.id} | similarity=${best.score} threshold=${threshold} | appended=${inputRow.content.length}chars | pinned=${item?.pinned} protected=${item?.protected} resolved=${item?.resolved} _archived=${item?._archived}`
      );
    }
  );

  server.registerTool(
    "memory_trace",
    {
      title: "Memory Trace",
      description:
        "Update memory state after memory_surface surfacing. " +
        "Supports marking resolved / digested / pinned, archiving / restoring, " +
        "and patching importance, content, keywords, profiles, and title.",
      inputSchema: z.object({
        id: z.string(),
        resolved: z.boolean().optional(),
        pinned: z.boolean().optional(),
        protected: z.boolean().optional(),
        digested: z.boolean().optional(),
        importance: z.number().int().min(1).max(10).optional(),
        profiles: z.union([z.array(z.string()), z.string()]).optional(),
        title: z.string().optional(),
        content: z.string().optional(),
        keywords: z.union([z.array(z.string()), z.string()]).optional(),
        action: z.enum(["archive", "restore", "patch"]).optional().default("patch"),
      }),
      outputSchema: z.object({
        item: memoryRecordSchema.nullable(),
        updated_fields: z.array(z.string()),
        updated_at: z.string(),
      }),
    },
    async ({
      id,
      resolved,
      pinned,
      protected: protectedFlag,
      digested,
      importance,
      profiles,
      title,
      content,
      keywords,
      action = "patch",
    }) => {
      let existing = isValidUuid(id) ? await readMemoryById(id) : null;
      if (!existing) existing = await readMemoryByLegacyId(id);
      if (!existing) {
        return makeResult(
          { item: null, updated_fields: [], updated_at: "" },
          `没有找到 id=${id} 的记忆。`
        );
      }

      const existingRaw = ensureObject(existing.raw, {});
      const newRaw = { ...existingRaw };
      const updatedFields = [];

      // action: archive / restore
      if (action === "archive") {
        newRaw._archived = true;
        updatedFields.push("_archived");
      } else if (action === "restore") {
        newRaw._archived = false;
        updatedFields.push("_archived");
      }

      // state flags → raw
      if (resolved !== undefined) { newRaw.resolved = resolved; updatedFields.push("resolved"); }
      if (protectedFlag !== undefined) { newRaw.protected = protectedFlag; updatedFields.push("protected"); }
      if (pinned !== undefined) {
        newRaw.pinned = pinned;
        // pinned=true overrides protected regardless of what protectedFlag says
        if (pinned) {
          newRaw.protected = true;
          if (!updatedFields.includes("protected")) updatedFields.push("protected");
        }
        updatedFields.push("pinned");
      }
      // digested is not in RAW_COMPAT_FIELDS — handle explicitly
      if (digested !== undefined) { newRaw.digested = digested; updatedFields.push("digested"); }

      // Build a clean input for buildMemoryRow: strip existing top-level compat fields
      // so they don't override newRaw via buildMemoryRow's RAW_COMPAT_FIELDS loop.
      const cleanInput = { ...existing };
      for (const field of RAW_COMPAT_FIELDS) delete cleanInput[field];
      delete cleanInput.digested;

      // Apply non-compat patches
      if (title !== undefined) { cleanInput.title = title; updatedFields.push("title"); }
      if (content !== undefined) { cleanInput.content = content; updatedFields.push("content"); }
      if (importance !== undefined) { cleanInput.importance = importance; updatedFields.push("importance"); }
      if (keywords !== undefined) { cleanInput.keywords = keywords; updatedFields.push("keywords"); }
      if (profiles !== undefined) { cleanInput.profiles = profiles; updatedFields.push("profiles"); }

      // Defensive: ensure newRaw carries existing protected/pinned state so the
      // update path never resurrects a previously cleared flag, even if some
      // future code path drops `!isUpdate` from buildMemoryRow's auto-inject guard.
      if (newRaw.protected === undefined && existingRaw.protected !== undefined) {
        newRaw.protected = existingRaw.protected;
      }
      if (newRaw.pinned === undefined && existingRaw.pinned !== undefined) {
        newRaw.pinned = existingRaw.pinned;
      }

      cleanInput.raw = newRaw;
      cleanInput.id = existing.id;

      const row = buildMemoryRow(cleanInput, { isUpdate: true });
      // newRaw is used as the raw base, so digested / _archived are already preserved
      // there. Re-assert here so this code remains correct even if buildMemoryRow's
      // raw handling changes (cheap, idempotent).
      if (digested !== undefined) row.raw.digested = digested;
      if (action === "archive") row.raw._archived = true;
      if (action === "restore") row.raw._archived = false;
      // pinned=true wins over any explicit protectedFlag
      if (pinned === true) row.raw.protected = true;
      else if (protectedFlag !== undefined) row.raw.protected = protectedFlag;

      // Sync top-level status columns in the SAME update so raw and columns can't
      // diverge. (_archived is raw-only — no top-level column on public.memories.)
      if (resolved !== undefined) row.resolved = resolved;
      if (digested !== undefined) row.digested = digested;
      if (pinned !== undefined) {
        row.pinned = pinned;
        if (pinned) row.protected = true;
        else if (protectedFlag !== undefined) row.protected = protectedFlag;
      } else if (protectedFlag !== undefined) {
        row.protected = protectedFlag;
      }

      const saved = await updateMemoryRowById(existing.id, row);
      const item = denormalizeMemoryRow(saved) ?? denormalizeMemoryRow({ ...row, id: existing.id });

      log("info", "tool", {
        tool: "memory_trace",
        args: { id: existing.id, action, resolved, pinned, protected: protectedFlag, digested, importance, updated_fields: updatedFields },
        result: { item_id: item?.id, updated_at: item?.updated_at },
      });

      const statusParts = [];
      if (item?.pinned) statusParts.push("pinned");
      if (item?.resolved) statusParts.push("resolved");
      if (item?.digested) statusParts.push("digested");
      if (item?._archived) statusParts.push("archived");
      const statusStr = statusParts.length ? ` [${statusParts.join(", ")}]` : "";

      return makeResult(
        { item, updated_fields: updatedFields, updated_at: item?.updated_at || "" },
        `已更新记忆${item?.title ? `《${item.title}》` : ""}${statusStr}，` +
          `已修改字段：${updatedFields.join(", ") || "（无变化）"}。updated_at=${item?.updated_at || ""}`
      );
    }
  );

  server.registerTool(
    "memory_briefing",
    {
      title: "Memory Briefing",
      description:
        "Return a compact briefing assembled from memo, diary, and daily memories. " +
        "diary = 每日主记录（叙事/情绪/生活片段），briefing 优先显示其 today_snapshot；" +
        "daily = 短期事项/临时上下文/提醒，不再作为每日自动记录与 diary 重复。" +
        "Intended to be injected once per session at the start of a conversation " +
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

      // diary layer: recent entries, prefer today_snapshot > title > content prefix
      const diaryRows = await readMemoryRows({ layer: "diary", limit: 20 });
      const recentDiaries = diaryRows
        .map(denormalizeMemoryRow)
        .filter((m) => m && !m._archived)
        .sort((a, b) => {
          const da = parseDateLike(a.date) ?? new Date(0);
          const db = parseDateLike(b.date) ?? new Date(0);
          return db.getTime() - da.getTime();
        })
        .slice(0, 3);
      if (recentDiaries.length) {
        sections.push({
          label: "近期日记",
          items: recentDiaries.map((m) => {
            const snap = m.today_snapshot || m.title || String(m.content || "").slice(0, 40);
            const datePrefix = m.date ? String(m.date).slice(0, 10) + " · " : "";
            return (datePrefix + snap.trim()).trim();
          }),
        });
      }

      // daily layer: short-term items / reminders / temporary context (top 3 by decay score)
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
    "memory_digest",
    {
      title: "Memory Digest",
      description:
        "Consolidate a batch of fragmented memories into one long-term condensed memory, " +
        "then mark sources as resolved+digested to keep the pool clean. " +
        "Use dry_run=true (default) to preview candidates before committing.",
      inputSchema: z.object({
        source_ids: z.array(z.string()).optional(),
        q: z.string().optional(),
        layer: z.string().optional(),
        sub_layer: z.string().optional(),
        profile: z.enum(["shared", "rowan", "arion", "all"]).optional().default("shared"),
        limit: z.number().int().min(1).max(30).optional().default(10),
        title: z.string().optional(),
        content: z.string().optional(),
        keywords: z.union([z.array(z.string()), z.string()]).optional(),
        profiles: z.union([z.array(z.string()), z.string()]).optional(),
        importance: z.number().int().min(1).max(10).optional(),
        dry_run: z.boolean().optional().default(true),
        mark_sources: z.boolean().optional().default(true),
      }),
      outputSchema: z.object({
        mode: z.enum(["preview", "digested"]),
        item: memoryRecordSchema.nullable().optional(),
        sources: z.array(memoryRecordSchema),
        source_ids: z.array(z.string()),
        digested_count: z.number(),
        skipped_count: z.number(),
        skipped_reasons: z.array(z.string()),
      }),
    },
    async ({
      source_ids,
      q,
      layer = "daily",
      sub_layer,
      profile = "shared",
      limit = 10,
      title,
      content,
      keywords,
      profiles,
      importance,
      dry_run = true,
      mark_sources = true,
    }) => {
      // 1. Gather candidates
      let rawCandidates = [];

      if (source_ids && source_ids.length > 0) {
        // Explicit IDs — fetch exactly those
        const fetched = await Promise.all(
          source_ids.map((id) => isValidUuid(id) ? readMemoryById(id) : Promise.resolve(null))
        );
        rawCandidates = fetched.filter(Boolean).map(denormalizeMemoryRow).filter(Boolean);
      } else if (q && String(q).trim()) {
        // Query-only — no recent fallback; q miss means sources=[]
        const queryRows = await queryMemoryRows({ q, layer, sub_layer, limit: limit * 3 });
        const seen = new Set();
        for (const r of queryRows) {
          if (r?.id && !seen.has(r.id)) {
            seen.add(r.id);
            const den = denormalizeMemoryRow(r);
            if (den) rawCandidates.push(den);
          }
        }
        rawCandidates = rawCandidates.filter((m) => matchesProfileFilter(m, profile)).slice(0, limit * 2);
      } else {
        // No source_ids, no q — browse recent rows
        const recentRows = await readMemoryRows({ layer, sub_layer, limit: limit * 3 });
        const seen = new Set();
        for (const r of recentRows) {
          if (r?.id && !seen.has(r.id)) {
            seen.add(r.id);
            const den = denormalizeMemoryRow(r);
            if (den) rawCandidates.push(den);
          }
        }
        rawCandidates = rawCandidates.filter((m) => matchesProfileFilter(m, profile)).slice(0, limit * 2);
      }

      // 2. Filter: skip archived, resolved, pinned, protected
      const eligible = [];
      const skipped = [];
      for (const m of rawCandidates) {
        if (m._archived)  { skipped.push(`${m.id}: _archived=true`);  continue; }
        if (m.resolved)   { skipped.push(`${m.id}: resolved=true`);   continue; }
        if (m.pinned)     { skipped.push(`${m.id}: pinned=true`);     continue; }
        if (m.protected)  { skipped.push(`${m.id}: protected=true`);  continue; }
        eligible.push(m);
      }
      const sources = eligible.slice(0, limit);
      const resultSourceIds = sources.map((m) => m.id);

      if (dry_run) {
        log("info", "tool", {
          tool: "memory_digest",
          mode: "preview",
          args: { source_ids, q, layer, sub_layer, profile, limit, dry_run },
          result: { eligible: sources.length, skipped: skipped.length },
        });
        return makeResult(
          {
            mode: "preview",
            sources,
            source_ids: resultSourceIds,
            digested_count: 0,
            skipped_count: skipped.length,
            skipped_reasons: skipped,
          },
          `[preview] ${sources.length} 条来源候选，${skipped.length} 条跳过。dry_run=true，未写入。source_ids=${resultSourceIds.join(", ") || "(无)"}`
        );
      }

      // Apply safety gate: dry_run=false requires explicit source_ids
      if (!source_ids || source_ids.length === 0) {
        return makeResult(
          {
            mode: "preview",
            sources,
            source_ids: resultSourceIds,
            digested_count: 0,
            skipped_count: skipped.length,
            skipped_reasons: skipped,
          },
          "dry_run=false requires explicit source_ids. Please run dry_run=true first and pass confirmed source_ids."
        );
      }

      // Guard: no eligible sources → abort without writing
      if (sources.length === 0) {
        return makeResult(
          {
            mode: "preview",
            sources: [],
            source_ids: [],
            digested_count: 0,
            skipped_count: skipped.length,
            skipped_reasons: skipped,
          },
          `[digest 中止] 没有符合条件的来源记忆（${skipped.length} 条被跳过），未写入。`
        );
      }

      // Guard: content required — no auto-generated snippets
      if (!content || !String(content).trim()) {
        return makeResult(
          {
            mode: "preview",
            sources,
            source_ids: resultSourceIds,
            digested_count: 0,
            skipped_count: skipped.length,
            skipped_reasons: skipped,
          },
          `[digest 中止] dry_run=false 时必须提供 content（调用方整理好的长期记忆内容），未写入。候选 ${sources.length} 条，请先 dry_run=true 确认来源再传入 content。`
        );
      }

      // 3. Build condensed memory
      const mergedKeywords = [
        ...new Set([
          ...sources.flatMap((m) => ensureArray(m.keywords)),
          ...splitKeywords(keywords),
        ]),
      ];
      const rawMergedProfiles = [
        ...new Set([
          ...sources.flatMap((m) => effectiveProfiles(m.profiles)),
          ...normalizeProfiles(profiles),
        ]),
      ];
      const mergedProfiles = rawMergedProfiles.length ? rawMergedProfiles : ["shared"];
      const sourceMaxImportance = sources.reduce(
        (max, m) => Math.max(max, Number(m.importance) || 0),
        0
      );
      const condensedImportance = importance ?? Math.max(sourceMaxImportance, 3);
      const now = new Date().toISOString();

      const condensedRow = buildMemoryRow({
        title: title || `消化摘要 ${now.slice(0, 10)}`,
        content: String(content).trim(),
        layer: "memo",
        sub_layer,
        keywords: mergedKeywords,
        profiles: mergedProfiles,
        importance: condensedImportance,
      });
      condensedRow.raw.source_ids = resultSourceIds;
      condensedRow.raw.digested_from_count = sources.length;
      condensedRow.raw.digest_generated_at = now;

      // Inherit bucket from sources — pick the most-frequent bucket_id
      const sourceBucketIds = [...new Set(sources.map((m) => m.bucket_id).filter(Boolean))];
      condensedRow.raw.source_bucket_ids = sourceBucketIds;
      if (sourceBucketIds.length > 0) {
        const bucketFreq = {};
        for (const m of sources) { if (m.bucket_id) bucketFreq[m.bucket_id] = (bucketFreq[m.bucket_id] || 0) + 1; }
        const dominantBid = Object.entries(bucketFreq).sort((a, b) => b[1] - a[1])[0][0];
        const rep = sources.find((m) => m.bucket_id === dominantBid);
        if (rep) {
          condensedRow.bucket_id = dominantBid;
          condensedRow.bucket_type = rep.bucket_type || "topic";
          condensedRow.name = rep.name || "";
          condensedRow.domain = ensureArray(rep.domain).slice(0, BUCKET_DOMAIN_MAX);
          condensedRow.tags = [...new Set(sources.flatMap((m) => ensureArray(m.tags)))].slice(0, BUCKET_TAGS_MAX);
        }
      } else {
        try {
          const bucket = await findBestBucketForMemory(condensedRow) || buildBucketForMemory(condensedRow);
          applyBucketFields(condensedRow, bucket);
        } catch (_) {}
      }

      const savedCondensed = await insertMemoryRow(condensedRow);
      const item = denormalizeMemoryRow(savedCondensed);

      // 4. Mark sources resolved + digested
      let markedCount = 0;
      if (mark_sources && sources.length > 0) {
        await Promise.all(
          sources.map(async (src) => {
            try {
              const existingRaw = ensureObject(src.raw, {});
              const newRaw = { ...existingRaw, resolved: true, digested: true };
              const cleanInput = { ...src };
              for (const field of RAW_COMPAT_FIELDS) delete cleanInput[field];
              delete cleanInput.digested;
              cleanInput.raw = newRaw;
              cleanInput.id = src.id;
              const row = buildMemoryRow(cleanInput, { isUpdate: true });
              row.raw.resolved = true;
              row.raw.digested = true;
              syncRawToColumns(row);
              await updateMemoryRowById(src.id, row);
              markedCount++;
            } catch (_) {}
          })
        );
      }

      log("info", "tool", {
        tool: "memory_digest",
        mode: "digested",
        args: { source_ids, q, layer, sub_layer, profile, limit, dry_run, mark_sources },
        result: { condensed_id: item?.id, digested_count: markedCount, skipped: skipped.length },
      });

      return makeResult(
        {
          mode: "digested",
          item,
          sources,
          source_ids: resultSourceIds,
          digested_count: markedCount,
          skipped_count: skipped.length,
          skipped_reasons: skipped,
        },
        `[digested] condensed_id=${item?.id} | title=${item?.title || "(无)"} | sources=${sources.length} digested=${markedCount} skipped=${skipped.length}`
      );
    }
  );

  server.registerTool(
    "memory_debug_read",
    {
      title: "Memory Debug Read",
      description:
        "Read-only diagnostic tool. Returns full state of one memory row including " +
        "resolved/digested/pinned/protected/_archived flags and digest-related raw fields. " +
        "Does not write, touch, or update activation_count.",
      inputSchema: z.object({
        id: z.string(),
      }),
      outputSchema: z.object({
        found: z.boolean(),
        item: memoryRecordSchema.nullable(),
        debug: z.object({
          id: z.string(),
          legacy_id: z.string(),
          title: z.string(),
          layer: z.string(),
          sub_layer: z.string(),
          bucket_id: z.string(),
          bucket_type: z.string(),
          name: z.string(),
          keywords: z.array(z.string()),
          profiles: z.array(z.string()),
          resolved: z.boolean(),
          digested: z.boolean(),
          pinned: z.boolean(),
          protected: z.boolean(),
          _archived: z.boolean(),
          activation_count: z.number(),
          last_active: z.string(),
          updated_at: z.string(),
          raw_source_ids: z.array(z.string()),
          raw_digested_from_count: z.number().nullable(),
          raw_digest_generated_at: z.string(),
        }).nullable(),
      }),
    },
    async ({ id }) => {
      let row = isValidUuid(id) ? await readMemoryById(id) : null;
      if (!row) row = await readMemoryByLegacyId(id);

      if (!row) {
        return makeResult(
          { found: false, item: null, debug: null },
          `[debug] 未找到 id=${id}`
        );
      }

      const item = denormalizeMemoryRow(row);
      if (item) delete item.raw;
      const raw = ensureObject(row.raw, {});
      const {
        resolved: _r, pinned: _p, protected: protectedFlag,
        digested: _d, _archived: _a,
      } = item ?? {};

      const debug = {
        id: item?.id ?? "",
        legacy_id: String(row.legacy_id ?? ""),
        title: item?.title ?? "",
        layer: item?.layer ?? "",
        sub_layer: item?.sub_layer ?? "",
        bucket_id: item?.bucket_id ?? "",
        bucket_type: item?.bucket_type ?? "",
        name: item?.name ?? "",
        keywords: ensureArray(item?.keywords),
        profiles: effectiveProfiles(item?.profiles),
        resolved: Boolean(_r),
        digested: Boolean(_d),
        pinned: Boolean(_p),
        protected: Boolean(protectedFlag),
        _archived: Boolean(_a),
        activation_count: Number(item?.activation_count ?? 0),
        last_active: String(item?.last_active ?? ""),
        updated_at: String(item?.updated_at ?? ""),
        raw_source_ids: ensureArray(raw.source_ids).map(String),
        raw_digested_from_count: raw.digested_from_count != null ? Number(raw.digested_from_count) : null,
        raw_digest_generated_at: String(raw.digest_generated_at ?? ""),
      };

      const lines = [
        `[debug] id=${debug.id}`,
        `title=${debug.title || "(无)"}  layer=${debug.layer}${debug.sub_layer ? "/" + debug.sub_layer : ""}`,
        `bucket_id=${debug.bucket_id || "(无)"}  bucket_type=${debug.bucket_type || "(无)"}  name=${debug.name || "(无)"}`,
        `resolved=${debug.resolved}  digested=${debug.digested}  pinned=${debug.pinned}  protected=${debug.protected}  _archived=${debug._archived}`,
        `activation_count=${debug.activation_count}  last_active=${debug.last_active}`,
        `keywords=[${debug.keywords.join(", ")}]`,
        `profiles=[${debug.profiles.join(", ")}]`,
        `raw_source_ids=[${debug.raw_source_ids.join(", ") || "(无)"}]`,
        `raw_digested_from_count=${debug.raw_digested_from_count ?? "(无)"}`,
        `raw_digest_generated_at=${debug.raw_digest_generated_at || "(无)"}`,
        `updated_at=${debug.updated_at}`,
      ];

      return makeResult({ found: true, item, debug }, lines.join("\n"));
    }
  );

  server.registerTool(
    "memory_bucket_surface",
    {
      title: "Memory Bucket Surface",
      description:
        "Read-only. Aggregate memories by bucket and return cluster statistics " +
        "(memory_count, open_count, resolved_count, pinned_count, protected_count, " +
        "max_importance, last_active, score, sample_ids, sample_titles). " +
        "Useful for discovering active topic clusters without reading every memory.",
      inputSchema: z.object({
        q: z.string().optional(),
        profile: z.enum(["shared", "rowan", "arion", "all"]).optional().default("shared"),
        include_resolved: z.boolean().optional().default(false),
        include_archived: z.boolean().optional().default(false),
        limit: z.number().int().min(1).max(50).optional().default(10),
      }),
      outputSchema: z.object({
        buckets: z.array(z.object({
          bucket_id: z.string(),
          bucket_type: z.string(),
          name: z.string(),
          domain: z.array(z.string()),
          tags: z.array(z.string()),
          memory_count: z.number(),
          open_count: z.number(),
          resolved_count: z.number(),
          pinned_count: z.number(),
          protected_count: z.number(),
          max_importance: z.number(),
          last_active: z.string(),
          score: z.number(),
          sample_ids: z.array(z.string()),
          sample_titles: z.array(z.string()),
        })),
        returned_count: z.number(),
        generated_at: z.string(),
      }),
    },
    async ({ q, profile = "shared", include_resolved = false, include_archived = false, limit = 10 }) => {
      const client = getSupabaseClient();
      const { data: rows, error } = await client
        .from(MEMORY_TABLE)
        .select("id, title, layer, sub_layer, bucket_id, bucket_type, name, domain, tags, importance, profiles, resolved, digested, pinned, protected, last_active, updated_at, raw")
        .not("bucket_id", "is", null)
        .neq("bucket_id", "")
        .order("updated_at", { ascending: false, nullsFirst: false })
        .limit(2000);
      if (error) throw toDbError("memory_bucket_surface fetch failed", error);

      let memories = ensureArray(rows).map(denormalizeMemoryRow).filter(Boolean);
      // Step 1: filter only by archived / profile / q — keep resolved for stats
      if (!include_archived) memories = memories.filter((m) => !m._archived);
      memories = memories.filter((m) => matchesProfileFilter(m, profile));
      if (q && String(q).trim()) memories = memories.filter((m) => memoryTextMatch(m, q));

      // Group by bucket_id
      const bucketMap = new Map();
      for (const m of memories) {
        const bid = m.bucket_id;
        if (!bid) continue;
        if (!bucketMap.has(bid)) {
          bucketMap.set(bid, {
            bucket_id: bid,
            bucket_type: m.bucket_type || "topic",
            name: m.name || "",
            domain: ensureArray(m.domain),
            tags: ensureArray(m.tags),
            all: [],
          });
        }
        bucketMap.get(bid).all.push(m);
      }

      const results = [];
      for (const info of bucketMap.values()) {
        const all = info.all;
        // open: not resolved, not digested, not archived
        const open = all.filter((m) => !m.resolved && !m.digested && !m._archived);
        // resolved: resolved OR digested
        const resolvedArr = all.filter((m) => m.resolved || m.digested);
        const pinnedArr = all.filter((m) => m.pinned);
        const protectedArr = all.filter((m) => m.protected);
        const maxImportance = Math.max(...all.map((m) => Number(m.importance) || 0), 0);
        const lastActive = all.reduce((best, m) => {
          const d = parseDateLike(m.last_active || m.updated_at);
          if (!d) return best;
          return (!best || d > best) ? d : best;
        }, null);

        // Score: always driven by open items; resolved get 0.1x weight only when include_resolved=true
        const openScores = open.map((m) => calcDecayScore(m)).sort((a, b) => b - a);
        let bucketScore = openScores.slice(0, 3).reduce((s, v) => s + v, 0);
        if (include_resolved && resolvedArr.length > 0) {
          const resolvedBonus = resolvedArr
            .map((m) => calcDecayScore(m) * 0.1)
            .sort((a, b) => b - a)
            .slice(0, 3)
            .reduce((s, v) => s + v, 0);
          bucketScore += resolvedBonus;
        }

        // Samples: open first; resolved only allowed when include_resolved=true
        const openSorted = [...open].sort((a, b) => (Number(b.importance) || 0) - (Number(a.importance) || 0));
        let samplePool;
        if (include_resolved) {
          const resolvedSorted = [...resolvedArr].sort((a, b) => (Number(b.importance) || 0) - (Number(a.importance) || 0));
          samplePool = [...openSorted, ...resolvedSorted];
        } else {
          samplePool = openSorted;
        }
        const sortedSamples = samplePool.slice(0, 3);

        results.push({
          bucket_id: info.bucket_id,
          bucket_type: info.bucket_type,
          name: info.name,
          domain: info.domain,
          tags: info.tags,
          memory_count: all.length,
          open_count: open.length,
          resolved_count: resolvedArr.length,
          pinned_count: pinnedArr.length,
          protected_count: protectedArr.length,
          max_importance: maxImportance,
          last_active: lastActive ? lastActive.toISOString() : "",
          score: Math.round(bucketScore * 10000) / 10000,
          sample_ids: sortedSamples.map((m) => m.id),
          sample_titles: sortedSamples.map((m) => m.title || ""),
        });
      }
      results.sort((a, b) => b.score - a.score);
      const cap = Math.max(1, Math.min(50, Number(limit) || 10));
      const topResults = results.slice(0, cap);

      log("info", "tool", {
        tool: "memory_bucket_surface",
        args: { q, profile, include_resolved, include_archived, limit },
        result: { bucket_count: topResults.length },
      });

      const lines = topResults.map((b, i) =>
        `【${i + 1}】${b.name || b.bucket_id} (${b.bucket_type}) · 记忆数=${b.memory_count} open=${b.open_count} resolved=${b.resolved_count} score=${b.score} · tags=[${b.tags.slice(0, 4).join(",")}]`
      );
      return makeResult(
        { buckets: topResults, returned_count: topResults.length, generated_at: new Date().toISOString() },
        `共找到 ${topResults.length} 个 bucket：\n${lines.join("\n") || "（无）"}`
      );
    }
  );

  server.registerTool(
    "memory_bucket_read",
    {
      title: "Memory Bucket Read",
      description:
        "Read-only. List memories belonging to a specific bucket_id, " +
        "sorted by pinned > protected > importance > last_active. Does not touch/update records.",
      inputSchema: z.object({
        bucket_id: z.string().min(1),
        include_resolved: z.boolean().optional().default(true),
        include_archived: z.boolean().optional().default(false),
        limit: z.number().int().min(1).max(100).optional().default(30),
      }),
      outputSchema: z.object({
        bucket_id: z.string(),
        items: z.array(memoryRecordSchema),
        returned_count: z.number(),
      }),
    },
    async ({ bucket_id, include_resolved = true, include_archived = false, limit = 30 }) => {
      const rows = await readMemoryRowsByBucketId(bucket_id, { limit: 1000 });
      let memories = rows.map(denormalizeMemoryRow).filter(Boolean);
      if (!include_archived) memories = memories.filter((m) => !m._archived);
      if (!include_resolved) memories = memories.filter((m) => !m.resolved);

      memories.sort((a, b) => {
        if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
        if (a.protected !== b.protected) return a.protected ? -1 : 1;
        const ai = Number(a.importance) || 0;
        const bi_ = Number(b.importance) || 0;
        if (ai !== bi_) return bi_ - ai;
        const ala = parseDateLike(a.last_active || a.updated_at) ?? new Date(0);
        const bla = parseDateLike(b.last_active || b.updated_at) ?? new Date(0);
        return bla.getTime() - ala.getTime();
      });

      const cap = Math.max(1, Math.min(100, Number(limit) || 30));
      memories = memories.slice(0, cap);

      log("info", "tool", {
        tool: "memory_bucket_read",
        args: { bucket_id, include_resolved, include_archived, limit },
        result: { returned_count: memories.length },
      });

      const blocks = memories.length
        ? memories.map((m, i) => `【${i + 1}/${memories.length}】\n${formatMemoryForModel(m, 800)}`).join("\n\n---\n\n")
        : "（该 bucket 下无记忆）";
      return makeResult(
        { bucket_id, items: memories, returned_count: memories.length },
        `bucket=${bucket_id}，共 ${memories.length} 条：\n\n${blocks}`
      );
    }
  );

  server.registerTool(
    "memory_bucket_trace",
    {
      title: "Memory Bucket Trace",
      description:
        "Write tool for bucket management. " +
        "rename: update the name field on all non-archived memories in the bucket. " +
        "retag: merge new tags into all non-archived memories in the bucket. " +
        "merge: reassign all non-archived memories from source bucket to target_bucket_id. " +
        "Never deletes records or changes content/resolved/digested/_archived status.",
      inputSchema: z.object({
        bucket_id: z.string().min(1),
        action: z.enum(["rename", "retag", "merge"]),
        name: z.string().optional(),
        tags: z.union([z.array(z.string()), z.string()]).optional(),
        target_bucket_id: z.string().optional(),
      }),
      outputSchema: z.object({
        action: z.string(),
        bucket_id: z.string(),
        updated_count: z.number(),
        target_bucket_id: z.string().optional(),
      }),
    },
    async ({ bucket_id, action, name, tags, target_bucket_id }) => {
      const client = getSupabaseClient();
      const now = new Date().toISOString();
      const rows = await readMemoryRowsByBucketId(bucket_id, { limit: 2000 });
      // Filter: not archived (check both top-level and raw)
      const eligible = rows.filter((r) => {
        const raw = ensureObject(r.raw, {});
        return !(raw._archived || r._archived);
      });

      let updatedCount = 0;

      if (action === "rename") {
        if (!name || !String(name).trim()) throw new Error("name is required for rename");
        const newName = safeString(String(name).trim(), STR_LIMITS.title);
        await Promise.all(eligible.map(async (r) => {
          try {
            const raw = { ...ensureObject(r.raw, {}), name: newName };
            await client.from(MEMORY_TABLE).update({ name: newName, raw, updated_at: now }).eq("id", r.id);
            updatedCount++;
          } catch (_) {}
        }));

      } else if (action === "retag") {
        const newTags = splitKeywords(tags).slice(0, BUCKET_TAGS_MAX);
        await Promise.all(eligible.map(async (r) => {
          try {
            const merged = [...new Set([...ensureArray(r.tags), ...newTags])].slice(0, BUCKET_TAGS_MAX);
            const raw = { ...ensureObject(r.raw, {}), tags: merged };
            await client.from(MEMORY_TABLE).update({ tags: merged, raw, updated_at: now }).eq("id", r.id);
            updatedCount++;
          } catch (_) {}
        }));

      } else if (action === "merge") {
        if (!target_bucket_id || !String(target_bucket_id).trim()) throw new Error("target_bucket_id is required for merge");
        // Fetch target bucket representative to inherit name/type
        const { data: targetRows } = await client
          .from(MEMORY_TABLE)
          .select("bucket_type, name, domain, tags, raw")
          .eq("bucket_id", target_bucket_id)
          .limit(1);
        const targetRow = targetRows?.[0];
        const targetRaw = ensureObject(targetRow?.raw, {});
        const targetBucketType = targetRow?.bucket_type || targetRaw.bucket_type || "topic";
        const targetName = targetRow?.name || targetRaw.name || "";

        await Promise.all(eligible.map(async (r) => {
          try {
            const raw = { ...ensureObject(r.raw, {}), bucket_id: target_bucket_id };
            const payload = { bucket_id: target_bucket_id, bucket_type: targetBucketType, raw, updated_at: now };
            if (targetName) payload.name = targetName;
            await client.from(MEMORY_TABLE).update(payload).eq("id", r.id);
            updatedCount++;
          } catch (_) {}
        }));
      }

      log("info", "tool", {
        tool: "memory_bucket_trace",
        args: { bucket_id, action, name, target_bucket_id },
        result: { updated_count: updatedCount },
      });

      const result = { action, bucket_id, updated_count: updatedCount };
      if (target_bucket_id) result.target_bucket_id = target_bucket_id;
      return makeResult(
        result,
        `[bucket_trace] action=${action} bucket_id=${bucket_id} updated=${updatedCount}${target_bucket_id ? " → " + target_bucket_id : ""}`
      );
    }
  );

  server.registerTool(
    "search_memories_surface",
    {
      title: "Search Memories Surface",
      description:
        "Read-only search tool. Score and rank memories by text match (q), keyword overlap, " +
        "importance, and recency. Returns structured results with score/reason/content_snippet. " +
        "Defaults: excludes archived/resolved/digested. strict_q=true returns empty when q has no hits. " +
        "touch=false (default) — does NOT update activation_count or last_active.",
      inputSchema: z.object({
        q: z.string().optional(),
        keywords: z.union([z.array(z.string()), z.string()]).optional(),
        profile: z.enum(["shared", "rowan", "arion", "all"]).optional().default("shared"),
        layer: z.string().optional(),
        sub_layer: z.string().optional(),
        limit: z.number().int().min(1).max(50).optional().default(10),
        include_resolved: z.boolean().optional().default(false),
        include_digested: z.boolean().optional().default(false),
        include_archived: z.boolean().optional().default(false),
        strict_q: z.boolean().optional().default(false),
        touch: z.boolean().optional().default(false),
      }),
      outputSchema: z.object({
        items: z.array(
          z.object({
            id: z.string(),
            title: z.string(),
            layer: z.string(),
            sub_layer: z.string(),
            content_snippet: z.string(),
            keywords: z.array(z.string()),
            profiles: z.array(z.string()),
            bucket_id: z.string(),
            bucket_type: z.string(),
            name: z.string(),
            importance: z.number(),
            resolved: z.boolean(),
            digested: z.boolean(),
            pinned: z.boolean(),
            protected: z.boolean(),
            _archived: z.boolean(),
            score: z.number(),
            reason: z.string(),
            updated_at: z.string(),
            last_active: z.string(),
          })
        ),
        returned_count: z.number(),
        mode: z.string(),
        generated_at: z.string(),
        touched: z.boolean(),
        touched_ids: z.array(z.string()),
        touched_count: z.number(),
      }),
    },
    async ({
      q,
      keywords,
      profile = "shared",
      layer,
      sub_layer,
      limit = 10,
      include_resolved = false,
      include_digested = false,
      include_archived = false,
      strict_q = false,
      touch = false,
    }) => {
      const cap = Math.max(1, Math.min(50, Number(limit) || 10));
      const ql = q ? String(q).trim() : "";
      const hasQ = Boolean(ql);
      const kwList = splitKeywords(keywords);
      const hasKw = kwList.length > 0;
      const hasSearch = hasQ || hasKw;

      // Fetch: DB-side pre-filter by search terms only; recent/surface rows are
      // surface-mode only (q/keywords empty). Recency/importance only rank gated results.
      let rows;
      if (hasSearch) {
        const batchLimit = Math.min(600, cap * 15);
        const fetches = [];
        if (hasQ) {
          fetches.push(queryMemoryRows({ q: ql, layer, sub_layer, limit: batchLimit }));
          fetches.push(queryMemoryRows({ keywords: ql, layer, sub_layer, limit: batchLimit }));
        }
        if (hasKw) {
          fetches.push(queryMemoryRows({ keywords, layer, sub_layer, limit: batchLimit }));
        }
        const batches = await Promise.all(fetches);
        const seen = new Set();
        rows = [];
        for (const batch of batches) {
          for (const r of ensureArray(batch)) {
            if (r?.id && !seen.has(r.id)) {
              seen.add(r.id);
              rows.push(r);
            }
          }
        }
      } else {
        rows = await readMemoryRows({ layer, sub_layer, limit: 500 });
      }

      // Denormalize and filter
      let memories = rows.map(denormalizeMemoryRow).filter(Boolean);
      if (!include_archived) memories = memories.filter((m) => !m._archived);
      if (!include_resolved) memories = memories.filter((m) => !m.resolved);
      if (!include_digested) memories = memories.filter((m) => !m.digested);
      memories = memories.filter((m) => matchesProfileFilter(m, profile));

      // Search gate: every result must have at least one hit when search terms are present.
      // q and keywords are OR-combined. pinned/protected/importance only affect ranking
      // of already-gated items — they cannot make a non-hit item enter the results.
      if (hasSearch) {
        memories = memories.filter((m) => {
          const qHit = hasQ && memoryTextMatch(m, ql);
          const kwHit = hasKw && (() => {
            const memTerms = new Set([
              ...ensureArray(m.keywords),
              ...ensureArray(m.tags),
              ...ensureArray(m.domain),
            ].map((k) => String(k).toLowerCase()));
            return kwList.some((kw) => memTerms.has(String(kw).toLowerCase()));
          })();
          return qHit || kwHit;
        });
      }
      // strict_q: q must hit; kw-only hits do not satisfy this (returns 0 when q misses)
      if (hasQ && strict_q) {
        memories = memories.filter((m) => memoryTextMatch(m, ql));
      }

      // Score, build snippet, sort
      const SNIPPET_LEN = 200;
      const scored = memories.map((m) => {
        const { score, reason } = scoreSearchResult(m, ql, kwList);

        const content = String(m.content || "");
        let snippet;
        if (!content) {
          snippet = "";
        } else if (hasQ) {
          const idx = content.toLowerCase().indexOf(ql.toLowerCase());
          if (idx < 0) {
            snippet = content.slice(0, SNIPPET_LEN) + (content.length > SNIPPET_LEN ? "…" : "");
          } else {
            const start = Math.max(0, idx - 40);
            const end = Math.min(content.length, idx + SNIPPET_LEN);
            snippet =
              (start > 0 ? "…" : "") +
              content.slice(start, end) +
              (end < content.length ? "…" : "");
          }
        } else {
          snippet = content.slice(0, SNIPPET_LEN) + (content.length > SNIPPET_LEN ? "…" : "");
        }

        return { m, score, reason, snippet };
      });

      scored.sort((a, b) => b.score - a.score);
      const top = scored.slice(0, cap);

      // touch=true: deduplicate ids before touch to guard against duplicate rows in top
      const touchIds = touch
        ? [...new Set(top.map(({ m }) => m.id).filter(isValidUuid))]
        : [];
      if (touch && touchIds.length) {
        log("info", "tool", {
          tool: "search_memories_surface_touch",
          touch_ids: touchIds,
          touch_count: touchIds.length,
        });
        await Promise.allSettled(touchIds.map((id) => touchMemoryRow(id)));
      }

      const mode = hasQ && strict_q ? "strict" : hasSearch ? "search" : "surface";

      const items = top.map(({ m, score, reason, snippet }) => ({
        id: m.id ?? "",
        title: m.title ?? "",
        layer: m.layer ?? "",
        sub_layer: m.sub_layer ?? "",
        content_snippet: snippet,
        keywords: ensureArray(m.keywords),
        profiles: effectiveProfiles(m.profiles),
        bucket_id: m.bucket_id ?? "",
        bucket_type: m.bucket_type ?? "",
        name: m.name ?? "",
        importance: typeof m.importance === "number" ? m.importance : 0,
        resolved: Boolean(m.resolved),
        digested: Boolean(m.digested),
        pinned: Boolean(m.pinned),
        protected: Boolean(m.protected),
        _archived: Boolean(m._archived),
        score,
        reason,
        updated_at: m.updated_at ?? "",
        last_active: m.last_active ?? "",
      }));

      log("info", "tool", {
        tool: "search_memories_surface",
        args: { q, keywords, profile, layer, sub_layer, limit, include_resolved, include_digested, include_archived, strict_q, touch },
        result: { returned_count: items.length, mode },
      });

      const emptyMsg = hasQ && strict_q
        ? `没有找到匹配 "${ql}" 的记忆。`
        : "没有找到记忆。";

      const blocks = top.length
        ? top
            .map(({ m, score, reason, snippet }, i) => {
              const parts = [
                `【${i + 1}/${top.length}】score=${score}  reason=${reason}`,
                `标题: ${m.title || "未命名"}`,
                `layer: ${m.layer ?? ""}${m.sub_layer ? "/" + m.sub_layer : ""}`,
              ];
              if (m.bucket_id) parts.push(`bucket: ${m.name || m.bucket_id} (${m.bucket_type || "topic"})`);
              if (ensureArray(m.keywords).length) parts.push(`keywords: ${ensureArray(m.keywords).join(", ")}`);
              if (snippet) parts.push(`snippet: ${snippet}`);
              return parts.join("\n");
            })
            .join("\n\n---\n\n")
        : emptyMsg;

      return makeResult(
        {
          items,
          returned_count: items.length,
          mode,
          generated_at: new Date().toISOString(),
          touched: touch && touchIds.length > 0,
          touched_ids: touchIds,
          touched_count: touchIds.length,
        },
        `search_memories_surface（mode=${mode}），共返回 ${items.length} 条：\n\n${blocks}`
      );
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

  server.registerTool(
    "recall_context",
    {
      title: "Recall Context",
      description:
        "Build a compact recall context for the model from memories. " +
        "Tier 1: precise text search (q-gated). " +
        "Tier 2: bucket summaries for matched memories (include_buckets=true). " +
        "Tier 3: core/treasure permanent memories — only appended when Tier 1 has hits. " +
        "Returns context_text (Chinese-framed, ready-to-use), selected_memories, selected_buckets. " +
        "touch=false by default (read-only). touch=true writes activation_count for final selected ids only.",
      inputSchema: z.object({
        q: z.string().min(1),
        profile: z.enum(["shared", "rowan", "arion", "all"]).optional().default("shared"),
        layer: z.string().optional(),
        sub_layer: z.string().optional(),
        budget_chars: z.number().int().min(500).max(20000).optional().default(4000),
        max_items: z.number().int().min(1).max(50).optional().default(20),
        include_resolved: z.boolean().optional().default(false),
        include_digested: z.boolean().optional().default(false),
        include_archived: z.boolean().optional().default(false),
        touch: z.boolean().optional().default(false),
        include_buckets: z.boolean().optional().default(true),
      }),
      outputSchema: z.object({
        context_text: z.string(),
        selected_memories: z.array(
          z.object({
            id: z.string(),
            title: z.string(),
            layer: z.string(),
            sub_layer: z.string(),
            score: z.number(),
            reason: z.string(),
            content_snippet: z.string(),
            bucket_id: z.string(),
            importance: z.number(),
            tier: z.number(),
            pinned: z.boolean(),
            protected: z.boolean(),
            resolved: z.boolean(),
            digested: z.boolean(),
          })
        ),
        selected_buckets: z.array(
          z.object({
            bucket_id: z.string(),
            name: z.string(),
            bucket_type: z.string(),
            memory_count: z.number(),
            summary_snippet: z.string(),
          })
        ),
        omitted_count: z.number(),
        omitted_reason: z.array(z.string()),
        generated_at: z.string(),
        touch_applied: z.boolean(),
        touched_ids: z.array(z.string()),
        touched_count: z.number(),
      }),
    },
    async ({
      q,
      profile = "shared",
      layer,
      sub_layer,
      budget_chars = 4000,
      max_items = 20,
      include_resolved = false,
      include_digested = false,
      include_archived = false,
      touch = false,
      include_buckets = true,
    }) => {
      const result = await buildRecallContext({
        q,
        profile,
        layer,
        sub_layer,
        budget_chars,
        max_items,
        include_resolved,
        include_digested,
        include_archived,
        touch,
        include_buckets,
      });

      log("info", "tool", {
        tool: "recall_context",
        args: { q, profile, layer, sub_layer, budget_chars, max_items, include_resolved, include_digested, include_archived, touch, include_buckets },
        result: {
          selected_count: result.selected_memories.length,
          bucket_count: result.selected_buckets.length,
          omitted_count: result.omitted_count,
          touch_applied: result.touch_applied,
          context_chars: result.context_text.length,
        },
      });

      return makeResult(result, result.context_text);
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
      const existing = await readMemoryById(row.id);
      if (existing) {
        const existingRaw = ensureObject(existing.raw, {});
        const mergedArgs = {
          layer: existing.layer,
          sub_layer: existing.sub_layer,
          title: existing.title,
          content: existing.content,
          importance: existing.importance,
          date: existing.date,
          author: existing.author,
          mood: existing.mood,
          keywords: existing.keywords,
          profiles: existing.profiles,
          legacy_id: existing.legacy_id,
        };
        for (const [k, v] of Object.entries(req.body)) {
          if (v !== undefined && k !== "raw") mergedArgs[k] = v;
        }
        mergedArgs.raw = { ...existingRaw, ...ensureObject(req.body.raw, {}) };
        for (const field of RAW_COMPAT_FIELDS) {
          if (req.body[field] !== undefined) mergedArgs.raw[field] = req.body[field];
        }
        mergedArgs.id = existing.id;
        const mergedRow = buildMemoryRow(mergedArgs, { isUpdate: true });
        syncRawToColumns(mergedRow);
        saved = await updateMemoryRowById(existing.id, mergedRow);
        mode = "update_by_id";
      } else {
        syncRawToColumns(row);
        saved = await upsertMemoryRow(row);
        mode = "upsert_by_id";
      }
    } else if (row.legacy_id) {
      const existing = await readMemoryByLegacyId(row.legacy_id);
      if (existing?.id) {
        const existingRaw = ensureObject(existing.raw, {});
        const mergedArgs = {
          layer: existing.layer,
          sub_layer: existing.sub_layer,
          title: existing.title,
          content: existing.content,
          importance: existing.importance,
          date: existing.date,
          author: existing.author,
          mood: existing.mood,
          keywords: existing.keywords,
          profiles: existing.profiles,
          legacy_id: existing.legacy_id,
        };
        for (const [k, v] of Object.entries(req.body)) {
          if (v !== undefined && k !== "raw") mergedArgs[k] = v;
        }
        mergedArgs.raw = { ...existingRaw, ...ensureObject(req.body.raw, {}) };
        for (const field of RAW_COMPAT_FIELDS) {
          if (req.body[field] !== undefined) mergedArgs.raw[field] = req.body[field];
        }
        mergedArgs.id = existing.id;
        const mergedRow = buildMemoryRow(mergedArgs, { isUpdate: true });
        saved = await updateMemoryRowById(existing.id, mergedRow);
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
    const row = buildMemoryRow(mergedInput, { isUpdate: true });
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
    const client = getSupabaseClient();
    const { data: saved, error } = await client
      .from(MEMORY_TABLE)
      .update({ raw, _archived: true, updated_at: new Date().toISOString() })
      .eq("id", id)
      .select("*")
      .maybeSingle();
    if (error) throw toDbError("archive failed", error);
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
    const client = getSupabaseClient();
    const { data: saved, error } = await client
      .from(MEMORY_TABLE)
      .update({ raw, _archived: false, updated_at: new Date().toISOString() })
      .eq("id", id)
      .select("*")
      .maybeSingle();
    if (error) throw toDbError("restore failed", error);
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
