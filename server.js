import { randomUUID } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as z from "zod";

const app = express();
app.use(express.json({ limit: "1mb" }));

const sessions = new Map();
const memories = [];

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

function createServer() {
  const server = new McpServer({
    name: "memory-mcp",
    version: "1.0.1",
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
      }),
    },
    async () => {
      const result = {
        status: "ok",
        timestamp: new Date().toISOString(),
      };

      log("info", "tool", {
        tool: "memory_ping",
        args: {},
        result,
      });

      return makeResult(result, `memory_ping 正常：status=ok, timestamp=${result.timestamp}`);
    }
  );

  server.registerTool(
    "memory_write",
    {
      title: "Memory Write",
      description: "Write one memory item into temporary in-memory storage.",
      inputSchema: z.object({
        layer: z.string().min(1),
        content: z.string().min(1),
        importance: z.number().min(1).max(5),
      }),
      outputSchema: z.object({
        id: z.string(),
        layer: z.string(),
        content: z.string(),
        importance: z.number(),
        created_at: z.string(),
      }),
    },
    async ({ layer, content, importance }) => {
      const entry = {
        id: randomUUID(),
        layer,
        content,
        importance,
        created_at: new Date().toISOString(),
      };

      memories.push(entry);

      log("info", "tool", {
        tool: "memory_write",
        args: { layer, content, importance },
        result: entry,
      });

      return makeResult(
        entry,
        `已写入 ${layer} 层记忆：${content}（importance: ${importance}）`
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

app.get("/health", (req, res) => {
  log("info", "http", {
    method: req.method,
    url: req.originalUrl,
    accept: req.headers["accept"],
  });

  res.json({ status: "ok", memories: memories.length, sessions: sessions.size });
});

app.all("/mcp", async (req, res) => {
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
  log("info", "server", { message: `MCP server started on port ${PORT}` });
});

process.on("SIGINT", async () => {
  httpServer.close();

  for (const sessionId of sessions.keys()) {
    await closeSession(sessionId);
  }

  process.exit(0);
});
