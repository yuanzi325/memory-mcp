import test from "node:test";
import assert from "node:assert/strict";
import {
  planCandidate,
  planCommit,
  commitImportCandidates,
  DEFAULT_LAYER_BY_KIND,
} from "../commitCandidates.js";

const UUID = "11111111-1111-1111-1111-111111111111";

// 计数型 mock writer：默认成功，记录被调用次数与入参。
function makeWriters(overrides = {}) {
  const calls = { hold: [], comment: [] };
  const holdMemory = overrides.holdMemory
    ? (args) => { calls.hold.push(args); return overrides.holdMemory(args); }
    : (args) => { calls.hold.push(args); return { mode: "created", item: { id: "new-" + calls.hold.length } }; };
  const addRingComment = overrides.addRingComment
    ? (args) => { calls.comment.push(args); return overrides.addRingComment(args); }
    : (args) => { calls.comment.push(args); return { comment: { id: "c-" + calls.comment.length }, comment_count: calls.comment.length }; };
  return { calls, holdMemory, addRingComment };
}

test("dry_run 计划：preference 默认 layer=core", () => {
  const p = planCandidate({ kind: "preference", content: "我讨厌被催" });
  assert.equal(p.action, "hold");
  assert.equal(p.status, "would_create");
  assert.equal(p.layer, "core");
});

test("dry_run 计划：project 默认 layer=memo", () => {
  const p = planCandidate({ kind: "project", content: "MCP bridge 重写" });
  assert.equal(p.layer, "memo");
  assert.equal(p.status, "would_create");
});

test("dry_run 计划：memory 默认 layer=treasure", () => {
  const p = planCandidate({ kind: "memory", content: "我们的约定" });
  assert.equal(p.layer, "treasure");
});

test("dry_run 计划：diary 默认 layer=diary", () => {
  const p = planCandidate({ kind: "diary", content: "今天我..." });
  assert.equal(p.layer, "diary");
});

test("suggested_layer 覆盖默认 layer", () => {
  const p = planCandidate({ kind: "preference", content: "x", suggested_layer: "health" });
  assert.equal(p.layer, "health");
});

test("comment 有 target_memory_id → would_comment", () => {
  const p = planCandidate({ kind: "comment", content: "重新理解了", target_memory_id: UUID });
  assert.equal(p.action, "comment");
  assert.equal(p.status, "would_comment");
  assert.equal(p.comment.memory_id, UUID);
});

test("comment 缺 target_memory_id → needs_target", () => {
  const p = planCandidate({ kind: "comment", content: "重新理解了" });
  assert.equal(p.action, "skip");
  assert.equal(p.status, "needs_target");
});

test("comment 的 target_memory_id 非法 UUID → needs_target", () => {
  const p = planCandidate({ kind: "comment", content: "x", target_memory_id: "not-a-uuid" });
  assert.equal(p.status, "needs_target");
});

test("content 为空 → invalid", () => {
  assert.equal(planCandidate({ kind: "preference", content: "   " }).status, "invalid");
  assert.equal(planCandidate({ kind: "memory", content: undefined }).status, "invalid");
});

test("kind=ignore 不支持提交 → invalid", () => {
  assert.equal(planCandidate({ kind: "ignore", content: "x" }).status, "invalid");
});

test("未知 kind → invalid", () => {
  assert.equal(planCandidate({ kind: "whatever", content: "x" }).status, "invalid");
});

test("importance clamp 到 1-10", () => {
  assert.equal(planCandidate({ kind: "preference", content: "x", importance: 99 }).importance, 10);
  assert.equal(planCandidate({ kind: "preference", content: "x", importance: 0 }).importance, 1);
  assert.equal(planCandidate({ kind: "preference", content: "x", importance: -5 }).importance, 1);
});

test("importance 缺省时按 kind 兜底（在 1-10 内）", () => {
  const p = planCandidate({ kind: "memory", content: "x" });
  assert.ok(p.importance >= 1 && p.importance <= 10);
});

test("planCommit 带 index 且与输入顺序一致", () => {
  const plans = planCommit([
    { kind: "preference", content: "a" },
    { kind: "comment", content: "b" }, // needs_target
    { kind: "project", content: "c" },
  ]);
  assert.deepEqual(plans.map((p) => p.index), [0, 1, 2]);
  assert.deepEqual(plans.map((p) => p.status), ["would_create", "needs_target", "would_create"]);
});

test("planCommit 非数组输入返回 []", () => {
  assert.deepEqual(planCommit(undefined), []);
  assert.deepEqual(planCommit(null), []);
});

test("hold 计划带上 holdMemory 所需参数", () => {
  const p = planCandidate({
    kind: "project",
    content: "重写 bridge",
    title: "bridge 重写",
    keywords: ["bridge", "mcp"],
    importance: 7,
    date: "2026-06-08",
    author: "沅沅",
  });
  assert.deepEqual(p.hold, {
    content: "重写 bridge",
    title: "bridge 重写",
    layer: "memo",
    keywords: ["bridge", "mcp"],
    importance: 7,
    date: "2026-06-08",
    author: "沅沅",
  });
});

test("DEFAULT_LAYER_BY_KIND 映射正确", () => {
  assert.deepEqual(DEFAULT_LAYER_BY_KIND, {
    preference: "core",
    project: "memo",
    memory: "treasure",
    diary: "diary",
  });
});

// ── commitImportCandidates：MCP tool 与 REST endpoint 共用的编排 helper ──────────

test("commitImportCandidates dry_run 绝不调用写库", async () => {
  const { calls, holdMemory, addRingComment } = makeWriters();
  const out = await commitImportCandidates(
    {
      candidates: [
        { kind: "preference", content: "我讨厌被催" },
        { kind: "comment", content: "重新理解了", target_memory_id: UUID },
      ],
      dry_run: true,
    },
    { holdMemory, addRingComment }
  );
  assert.equal(calls.hold.length, 0);
  assert.equal(calls.comment.length, 0);
  assert.equal(out.dry_run, true);
  assert.equal(out.committed_count, 0);
  assert.deepEqual(out.results.map((r) => r.status), ["would_create", "would_comment"]);
});

test("commitImportCandidates: kind=ignore → invalid，即便 dry_run=false 也不写库", async () => {
  const { calls, holdMemory, addRingComment } = makeWriters();
  const out = await commitImportCandidates(
    { candidates: [{ kind: "ignore", content: "随便说说" }], dry_run: false },
    { holdMemory, addRingComment }
  );
  assert.equal(out.results[0].status, "invalid");
  assert.equal(out.committed_count, 0);
  assert.equal(out.skipped_count, 1);
  assert.equal(calls.hold.length, 0);
  assert.equal(calls.comment.length, 0);
});

test("commitImportCandidates: comment 缺 target_memory_id → needs_target，不写库", async () => {
  const { calls, holdMemory, addRingComment } = makeWriters();
  const out = await commitImportCandidates(
    { candidates: [{ kind: "comment", content: "重新理解了" }], dry_run: false },
    { holdMemory, addRingComment }
  );
  assert.equal(out.results[0].status, "needs_target");
  assert.equal(calls.comment.length, 0);
});

test("commitImportCandidates: result.index 按输入候选位置返回", async () => {
  const { holdMemory, addRingComment } = makeWriters();
  const out = await commitImportCandidates(
    {
      candidates: [
        { kind: "comment", content: "a" }, // needs_target
        { kind: "preference", content: "b" }, // would_create
        { kind: "ignore", content: "c" }, // invalid
      ],
      dry_run: true,
    },
    { holdMemory, addRingComment }
  );
  assert.deepEqual(out.results.map((r) => r.index), [0, 1, 2]);
  assert.deepEqual(out.results.map((r) => r.status), ["needs_target", "would_create", "invalid"]);
});

test("commitImportCandidates: 单条写入失败不影响后续候选", async () => {
  let n = 0;
  const { calls, holdMemory, addRingComment } = makeWriters({
    holdMemory: () => {
      n++;
      if (n === 1) throw new Error("boom");
      return { mode: "created", item: { id: "ok-" + n } };
    },
  });
  const out = await commitImportCandidates(
    {
      candidates: [
        { kind: "preference", content: "第一条会炸" },
        { kind: "preference", content: "第二条要成功" },
      ],
      dry_run: false,
    },
    { holdMemory, addRingComment }
  );
  assert.equal(out.results[0].status, "error");
  assert.equal(out.results[0].message, "boom");
  assert.equal(out.results[1].status, "created");
  assert.equal(out.committed_count, 1);
  assert.equal(out.skipped_count, 1);
  assert.equal(calls.hold.length, 2); // 第二条仍被尝试
});

test("commitImportCandidates: dry_run=false 真正写入（created / commented）", async () => {
  const { calls, holdMemory, addRingComment } = makeWriters();
  const out = await commitImportCandidates(
    {
      candidates: [
        { kind: "memory", content: "我们的约定", source: "chat-2026" },
        { kind: "comment", content: "重新理解了", target_memory_id: UUID },
      ],
      dry_run: false,
    },
    { holdMemory, addRingComment }
  );
  assert.deepEqual(out.results.map((r) => r.status), ["created", "commented"]);
  assert.equal(out.committed_count, 2);
  assert.equal(out.skipped_count, 0);
  // hold 写入带上导入溯源 raw。
  assert.equal(calls.hold[0].raw.import_kind, "memory");
  assert.equal(calls.hold[0].raw.import_source, "chat-2026");
  // comment 落到正确目标记忆。
  assert.equal(calls.comment[0].memory_id, UUID);
  assert.equal(out.results[1].comment_id, "c-1");
});
