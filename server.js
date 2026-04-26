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
const SUPABASE_TABLE = process.env.SUPABASE_TABLE || "vault_state";
const SUPABASE_ROW_ID = process.env.SUPABASE_ROW_ID || "main";
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || "";
const MCP_OAUTH_CLIENT_ID = process.env.MCP_OAUTH_CLIENT_ID || "";
const MCP_OAUTH_CLIENT_SECRET = process.env.MCP_OAUTH_CLIENT_SECRET || "";
const PUBLIC_BASE_URL = (process.env.MCP_OAUTH_ISSUER || process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
const MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS = Number(process.env.MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS) || 3600;
const MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS = Number(process.env.MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS) || 30 * 24 * 3600;
const OAUTH_STATE_ROW_ID = process.env.OAUTH_STATE_ROW_ID || "oauth_state";
const ID_PATTERN = /^[A-Za-z0-9_-]{1,80}$/;
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

async function loadOAuthState() {
  if (!hasSupabaseConfig() || !hasOAuthConfig()) return;
  try {
    const client = getSupabaseClient();
    const { data } = await client
      .from(SUPABASE_TABLE)
      .select("state_json")
      .eq("id", OAUTH_STATE_ROW_ID)
      .maybeSingle();
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
    log("warn", "oauth", { event: "oauth_state_load_failed", message: err instanceof Error ? err.message : String(err) });
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
    await client.from(SUPABASE_TABLE).upsert({
      id: OAUTH_STATE_ROW_ID,
      state_json: { refresh_tokens },
      updated_at: new Date().toISOString(),
    });
  } catch (err) {
    log("warn", "oauth", { event: "oauth_state_save_failed", message: err instanceof Error ? err.message : String(err) });
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

function safeId(value) {
  const text = typeof value === "string" ? value : "";
  return ID_PATTERN.test(text) ? text : randomUUID();
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

function normalizeMemoryRecord(input = {}) {
  const layer = safeString(input.layer || "daily", STR_LIMITS.type).trim() || "daily";
  const content = safeString(input.content || "", STR_LIMITS.content).trim();
  const keywords = splitKeywords(input.keywords);
  const importance = clampNumber(input.importance, 1, 10, layer === "core" ? 5 : 2);

  const base = {
    id: safeId(input.id),
    layer,
    sub_layer: safeString(input.sub_layer || "", STR_LIMITS.type),
    title: safeString(input.title || "", STR_LIMITS.title),
    date: safeString(input.date || new Date().toISOString(), STR_LIMITS.short),
    author: safeString(input.author || "", STR_LIMITS.short),
    mood: safeString(input.mood || "", STR_LIMITS.short),
    keywords,
    content,
    why_precious: safeString(input.why_precious || "", STR_LIMITS.summary),
    today_snapshot: safeString(input.today_snapshot || "", STR_LIMITS.summary),
    importance,
    activation_count: clampNumber(input.activation_count, 1, 1e9, 1),
    last_active: safeString(input.last_active || new Date().toISOString(), STR_LIMITS.short),
    created_at: safeString(input.created_at || new Date().toISOString(), STR_LIMITS.short),
    updated_at: new Date().toISOString(),
    resolved: Boolean(input.resolved),
    pinned: Boolean(input.pinned),
    protected:
      input.protected !== undefined
        ? Boolean(input.protected)
        : ["core", "treasure", "diary"].includes(layer),
    _archived: Boolean(input._archived),
  };

  if (input.valence !== undefined) {
    base.valence = clampNumber(input.valence, 0, 1, 0.5);
  }
  if (input.arousal !== undefined) {
    base.arousal = clampNumber(input.arousal, 0, 1, 0.3);
  }

  return base;
}

function normalizeStateShape(rawState = {}) {
  const state = ensureObject(rawState, {});
  return {
    ...state,
    memories: ensureArray(state.memories),
  };
}

async function readVaultRow() {
  const client = getSupabaseClient();
  const { data, error } = await client
    .from(SUPABASE_TABLE)
    .select("state_json, updated_at")
    .eq("id", SUPABASE_ROW_ID)
    .maybeSingle();

  if (error) throw error;

  const state = normalizeStateShape(data?.state_json || {});
  return {
    state,
    updatedAt: data?.updated_at || "",
    exists: Boolean(data),
  };
}

class WriteConflictError extends Error {
  constructor(message = "Vault state changed before write completed.") {
    super(message);
    this.name = "WriteConflictError";
    this.code = "write_conflict";
  }
}

async function writeVaultState(nextState, { expectedUpdatedAt = "", rowExists = true } = {}) {
  const client = getSupabaseClient();
  const state = normalizeStateShape(nextState);
  const updatedAt = new Date().toISOString();

  if (rowExists) {
    let query = client
      .from(SUPABASE_TABLE)
      .update({ state_json: state, updated_at: updatedAt })
      .eq("id", SUPABASE_ROW_ID);

    if (expectedUpdatedAt) {
      query = query.eq("updated_at", expectedUpdatedAt);
    }

    const { error: updateError, data: updateData } = await query.select("id");

    if (updateError) throw updateError;
    if (!Array.isArray(updateData) || updateData.length === 0) {
      throw new WriteConflictError();
    }
    return { updatedAt, mode: expectedUpdatedAt ? "update_checked" : "update" };
  }

  const { error: upsertError } = await client
    .from(SUPABASE_TABLE)
    .upsert({ id: SUPABASE_ROW_ID, state_json: state, updated_at: updatedAt });

  if (upsertError) throw upsertError;

  return { updatedAt, mode: "upsert" };
}

function makeMemorySummary(memory = {}) {
  const title = memory.title ? `《${memory.title}》` : "未命名记忆";
  const layer = memory.layer || "unknown";
  const contentLength = String(memory.content || "").length;
  return `${title} · ${layer} · importance=${memory.importance ?? ""} · content_length=${contentLength}`;
}

function safeIncludes(haystack, needle) {
  return String(haystack || "").toLowerCase().includes(String(needle || "").toLowerCase());
}

function byNewest(a, b) {
  const ad = Date.parse(String(a.updated_at || a.last_active || a.created_at || a.date || 0));
  const bd = Date.parse(String(b.updated_at || b.last_active || b.created_at || b.date || 0));
  return (Number.isFinite(bd) ? bd : 0) - (Number.isFinite(ad) ? ad : 0);
}

function queryMemories(memories, options = {}) {
  const {
    q = "",
    layer,
    sub_layer,
    author,
    keywords = [],
    min_importance,
    max_importance,
    include_archived = false,
    include_resolved = true,
    limit = 10,
  } = options;

  const qText = String(q || "").trim().toLowerCase();
  const keywordList = splitKeywords(keywords);

  let list = ensureArray(memories).filter((item) => item && typeof item === "object");

  if (!include_archived) list = list.filter((item) => !item._archived);
  if (!include_resolved) list = list.filter((item) => !item.resolved);
  if (layer) list = list.filter((item) => item.layer === layer);
  if (sub_layer) list = list.filter((item) => item.sub_layer === sub_layer);
  if (author) list = list.filter((item) => safeIncludes(item.author, author));
  if (min_importance !== undefined) {
    const min = Number(min_importance);
    if (Number.isFinite(min)) list = list.filter((item) => Number(item.importance || 0) >= min);
  }
  if (max_importance !== undefined) {
    const max = Number(max_importance);
    if (Number.isFinite(max)) list = list.filter((item) => Number(item.importance || 0) <= max);
  }
  if (keywordList.length) {
    list = list.filter((item) => {
      const itemKeywords = splitKeywords(item.keywords);
      return keywordList.every((keyword) =>
        itemKeywords.some((entry) => entry.toLowerCase().includes(keyword.toLowerCase()))
      );
    });
  }
  if (qText) {
    list = list.filter((item) => {
      const searchable = [
        item.id,
        item.title,
        item.content,
        item.why_precious,
        item.today_snapshot,
        item.layer,
        item.sub_layer,
        item.author,
        ...splitKeywords(item.keywords),
      ]
        .map((value) => String(value || "").toLowerCase())
        .join(" \n ");
      return searchable.includes(qText);
    });
  }

  return list.sort(byNewest).slice(0, Math.max(1, Math.min(50, Number(limit) || 10)));
}

const memoryRecordSchema = z
  .object({
    id: z.string(),
    layer: z.string(),
    sub_layer: z.string().optional().default(""),
    title: z.string().optional().default(""),
    date: z.string(),
    author: z.string().optional().default(""),
    mood: z.string().optional().default(""),
    keywords: z.array(z.string()).optional().default([]),
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
  })
  .passthrough();

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
      description: "Write one memory item into Supabase vault_state.state_json.memories.",
      inputSchema: z.object({
        layer: z.string().min(1),
        content: z.string().min(1),
        importance: z.number().min(1).max(10),
        id: z.string().optional(),
        sub_layer: z.string().optional(),
        title: z.string().optional(),
        date: z.string().optional(),
        author: z.string().optional(),
        mood: z.string().optional(),
        keywords: z.union([z.array(z.string()), z.string()]).optional(),
        why_precious: z.string().optional(),
        today_snapshot: z.string().optional(),
        resolved: z.boolean().optional(),
        pinned: z.boolean().optional(),
        protected: z.boolean().optional(),
        valence: z.number().optional(),
        arousal: z.number().optional(),
      }),
      outputSchema: z.object({
        item: memoryRecordSchema,
        total_memories: z.number(),
        updated_at: z.string(),
        mode: z.string(),
      }),
    },
    async (args) => {
      const entry = normalizeMemoryRecord(args);
      const { state, updatedAt, exists } = await readVaultRow();
      const nextState = normalizeStateShape(state);
      const memories = ensureArray(nextState.memories);

      const index = memories.findIndex((item) => item?.id === entry.id);
      if (index >= 0) {
        memories[index] = {
          ...memories[index],
          ...entry,
          created_at: memories[index].created_at || entry.created_at,
          updated_at: new Date().toISOString(),
        };
      } else {
        memories.unshift(entry);
      }
      nextState.memories = memories;

      const writeMeta = await writeVaultState(nextState, {
        expectedUpdatedAt: updatedAt,
        rowExists: exists,
      });
      const saved = index >= 0 ? memories[index] : entry;
      const result = {
        item: saved,
        total_memories: memories.length,
        updated_at: writeMeta.updatedAt,
        mode: writeMeta.mode,
      };

      log("info", "tool", {
        tool: "memory_write",
        args: {
          id: entry.id,
          layer: entry.layer,
          sub_layer: entry.sub_layer,
          author: entry.author,
          importance: entry.importance,
          content_length: entry.content.length,
          title_length: entry.title.length,
          keyword_count: entry.keywords.length,
        },
        result: {
          item_id: saved.id,
          total_memories: result.total_memories,
          updated_at: result.updated_at,
          mode: result.mode,
        },
      });

      return makeResult(
        result,
        `已写入记忆：${makeMemorySummary(saved)}。当前共 ${result.total_memories} 条，写入方式 ${result.mode}，更新时间 ${result.updated_at}`
      );
    }
  );

  server.registerTool(
    "memory_read",
    {
      title: "Memory Read",
      description:
        "Read one memory by id, or read the latest memories from Supabase vault_state.state_json.memories.",
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
      const { state, updatedAt } = await readVaultRow();
      const memories = ensureArray(state.memories);

      let item = null;
      let items = [];
      if (id) {
        item =
          memories.find((memory) => memory?.id === id && (include_archived || !memory?._archived)) || null;
        items = item ? [item] : [];
      } else {
        items = queryMemories(memories, {
          layer,
          sub_layer,
          include_archived,
          include_resolved: true,
          limit,
        });
      }

      const result = {
        found: Boolean(item || items.length),
        item,
        items,
        total_memories: memories.length,
        returned_count: items.length,
        updated_at: updatedAt,
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

      const text = id
        ? result.found
          ? `已读取记忆：${makeMemorySummary(result.item)}。`
          : `没有找到 id=${id} 的记忆。`
        : `已读取 ${result.returned_count} 条记忆（总数 ${result.total_memories}）。`;

      return makeResult(result, text);
    }
  );

  server.registerTool(
    "memory_query",
    {
      title: "Memory Query",
      description:
        "Search memories by keyword, layer, sub_layer, author, keywords, or importance from Supabase vault_state.state_json.memories.",
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
      const { state, updatedAt } = await readVaultRow();
      const memories = ensureArray(state.memories);
      const items = queryMemories(memories, {
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
      });

      const result = {
        items,
        returned_count: items.length,
        total_memories: memories.length,
        updated_at: updatedAt,
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

      const summary = items.length
        ? items
            .slice(0, 5)
            .map((item, index) => `${index + 1}. ${makeMemorySummary(item)}`)
            .join("\n")
        : "没有命中任何记忆。";

      return makeResult(
        result,
        `查询完成，共命中 ${result.returned_count} 条（总数 ${result.total_memories}）。\n${summary}`
      );
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
    table: SUPABASE_TABLE,
    row_id: SUPABASE_ROW_ID,
  };

  if (hasSupabaseConfig()) {
    try {
      const { state, updatedAt } = await readVaultRow();
      payload.memories = ensureArray(state.memories).length;
      payload.updated_at = updatedAt;
    } catch (error) {
      payload.supabase_error = error instanceof Error ? error.message : String(error);
    }
  }

  res.json(payload);
});

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
          message: "session not found",
          sessionId,
        });
        return res.status(404).json({
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
    table: SUPABASE_TABLE,
    row_id: SUPABASE_ROW_ID,
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
