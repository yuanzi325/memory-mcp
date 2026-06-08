import test from "node:test";
import assert from "node:assert/strict";
import { planCandidate, planCommit, DEFAULT_LAYER_BY_KIND } from "../commitCandidates.js";

const UUID = "11111111-1111-1111-1111-111111111111";

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
