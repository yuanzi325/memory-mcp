import test from "node:test";
import assert from "node:assert/strict";
import { evaluateSentinel } from "../sentinel.js";

test("普通寒暄返回 need_recall=false", () => {
  for (const message of ["早安宝宝", "你好呀", "哈喽，在吗", "晚安，么么"]) {
    const r = evaluateSentinel({ message });
    assert.equal(r.need_recall, false, `expected false for: ${message}`);
    assert.equal(r.depth, "none");
    assert.equal(r.q, "");
    assert.deepEqual(r.layers, []);
    assert.equal(r.touch_recommended, false);
  }
});

test("简单情绪句「抱抱我」返回 need_recall=false", () => {
  const r = evaluateSentinel({ message: "抱抱我" });
  assert.equal(r.need_recall, false);
  assert.equal(r.depth, "none");
  assert.equal(r.touch_recommended, false);
});

test("「还记得上次那个 MCP bridge 掉线吗」返回 need_recall=true，q 具体", () => {
  const r = evaluateSentinel({ message: "还记得上次那个 MCP bridge 掉线吗" });
  assert.equal(r.need_recall, true);
  // q 不应只是泛词，应包含具体主题，且不含触发短语 / 泛词
  assert.match(r.q, /bridge/i);
  assert.ok(r.q.includes("掉线"), `q should mention 掉线, got: ${r.q}`);
  assert.ok(!r.q.includes("还记得"), `q should not contain trigger word, got: ${r.q}`);
  assert.ok(!r.q.includes("上次"), `q should not contain trigger word, got: ${r.q}`);
  assert.ok(!r.q.includes("那个"), `q should not contain filler, got: ${r.q}`);
  assert.ok(!/沅沅|用户|今天/.test(r.q), `q should not be a generic term, got: ${r.q}`);
});

test("「继续 status 仪表盘 usage 那个」返回 need_recall=true", () => {
  const r = evaluateSentinel({ message: "继续 status 仪表盘 usage 那个" });
  assert.equal(r.need_recall, true);
  assert.ok(r.q.length > 0);
  assert.ok(r.q.toLowerCase().includes("status"), `q should mention status, got: ${r.q}`);
  assert.ok(r.q.includes("仪表盘"), `q should mention 仪表盘, got: ${r.q}`);
  assert.ok(!r.q.includes("继续"), `q should not contain trigger word, got: ${r.q}`);
  assert.ok(!r.q.includes("那个"), `q should not contain filler, got: ${r.q}`);
});

test("核心设定类返回 depth=deep", () => {
  const r = evaluateSentinel({ message: "还记得我们的核心设定吗" });
  assert.equal(r.need_recall, true);
  assert.equal(r.depth, "deep");
  assert.ok(r.layers.includes("core"), `layers should include core, got: ${JSON.stringify(r.layers)}`);
  assert.ok(r.q.length > 0 && !/^沅沅$|^用户$|^今天$/.test(r.q));
});

test("身份设定类也返回 deep", () => {
  const r = evaluateSentinel({ message: "你是谁，我们之前定下的身份设定还记得吗" });
  assert.equal(r.need_recall, true);
  assert.equal(r.depth, "deep");
  assert.ok(r.layers.includes("core"));
});

test("项目类召回返回 normal 且建议 memo layer", () => {
  const r = evaluateSentinel({ message: "接着上次那个部署的项目继续弄" });
  assert.equal(r.need_recall, true);
  assert.equal(r.depth, "normal");
  assert.ok(r.layers.includes("memo"));
});

test("无副作用：返回结构稳定且字段齐全", () => {
  const r = evaluateSentinel({ message: "上次那个 bug" });
  assert.equal(typeof r.need_recall, "boolean");
  assert.ok(["none", "shallow", "normal", "deep"].includes(r.depth));
  assert.equal(typeof r.q, "string");
  assert.ok(Array.isArray(r.layers));
  assert.equal(typeof r.reason, "string");
  assert.equal(typeof r.touch_recommended, "boolean");
  // 同样输入两次应得到完全一致的结果（纯函数）
  const r2 = evaluateSentinel({ message: "上次那个 bug" });
  assert.deepEqual(r, r2);
});

test("具体技术主题+故障词（无「上次/还记得」）也应 need_recall=true", () => {
  for (const message of ["记忆库 MCP 又断联了", "memory-mcp bridge 又挂了"]) {
    const r = evaluateSentinel({ message });
    assert.equal(r.need_recall, true, `expected true for: ${message}`);
    assert.ok(r.q.length > 0, `q should be non-empty for: ${message}`);
    assert.ok(/mcp|bridge/i.test(r.q), `q should keep the technical topic, got: ${r.q}`);
    assert.ok(r.layers.includes("memo"), `layers should include memo, got: ${JSON.stringify(r.layers)}`);
  }
});

test("「继续讲这个」太宽且 q 空洞，应 need_recall=false", () => {
  const r = evaluateSentinel({ message: "继续讲这个" });
  assert.equal(r.need_recall, false, `expected false, got: ${JSON.stringify(r)}`);
  assert.equal(r.depth, "none");
  assert.equal(r.q, "");
  assert.deepEqual(r.layers, []);
  assert.equal(r.touch_recommended, false);
});

test("「继续」配具体主题仍 need_recall=true（不被弱 q 误降级）", () => {
  const r = evaluateSentinel({ message: "继续 status 仪表盘 usage 那个" });
  assert.equal(r.need_recall, true);
  assert.ok(r.q.toLowerCase().includes("status"));
});

test("空消息返回 need_recall=false", () => {
  const r = evaluateSentinel({ message: "   " });
  assert.equal(r.need_recall, false);
  assert.equal(r.depth, "none");
});
