import { randomUUID, timingSafeEqual } from "node:crypto";
import express from "express";
import { createClient } from "@supabase/supabase-js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as z from "zod";

const app = express();
app.use(express.json({ limit: "1mb" }));

const sessions = new Map();
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  "";
const SUPABASE_TABLE = process.env.SUPABASE_TABLE || "vault_state";
const SUPABASE_ROW_ID = process.env.SUPABASE_ROW_ID || "main";
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || "";
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
  return hasAuthConfig() && constantTimeEquals(getBearerToken(req), MCP_AUTH_TOKEN);
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
    auth_configured: hasAuthConfig(),
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
  if (!hasAuthConfig()) {
    return res.status(503).json({
      jsonrpc: "2.0",
      error: {
        code: -32003,
        message: "MCP_AUTH_TOKEN is not configured. Refusing unauthenticated MCP access.",
      },
      id: req.body?.id ?? null,
    });
  }

  if (!isAuthorized(req)) {
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

const PORT = Number(process.env.PORT || 3000);
const httpServer = app.listen(PORT, () => {
  log("info", "server", {
    message: `MCP server started on port ${PORT}`,
    storage: "supabase",
    supabase_configured: hasSupabaseConfig(),
    table: SUPABASE_TABLE,
    row_id: SUPABASE_ROW_ID,
    auth_configured: hasAuthConfig(),
  });
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
