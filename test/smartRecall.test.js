import test from "node:test";
import assert from "node:assert/strict";
import { planSmartRecall } from "../smartRecall.js";
import { evaluateSentinel } from "../sentinel.js";

// 用真实 sentinel 判断 + 编排,贴近 smart_recall_context 工具内部流程
// (只到决定层,不触发 buildRecallContext / DB)。
function planFor(message, opts = {}) {
  const sentinel = evaluateSentinel({ message, profile: opts.profile, recent_context: opts.recent_context });
  const decision = planSmartRecall({ message, sentinel, force: opts.force, touch: opts.touch });
  return { sentinel, decision };
}

test("普通寒暄不调用 recall,recall_args=null", () => {
  const { sentinel, decision } = planFor("早安宝宝");
  assert.equal(sentinel.need_recall, false);
  assert.equal(decision.should_recall, false);
  assert.equal(decision.recall_args, null);
  assert.equal(decision.skipped_reason, sentinel.reason);
});

test("「记忆库 MCP 又断联了」会召回,depth=shallow / layers=['memo']", () => {
  const { sentinel, decision } = planFor("记忆库 MCP 又断联了");
  assert.equal(sentinel.need_recall, true);
  assert.equal(decision.should_recall, true);
  assert.equal(decision.recall_args.depth, "shallow");
  assert.deepEqual(decision.recall_args.layers, ["memo"]);
  assert.ok(decision.recall_args.q.length > 0);
});

test("「继续 status 仪表盘 usage 那个」会召回,带 sentinel 的 q/depth/layers", () => {
  const { sentinel, decision } = planFor("继续 status 仪表盘 usage 那个");
  assert.equal(decision.should_recall, true);
  assert.equal(decision.recall_args.q, sentinel.q);
  assert.equal(decision.recall_args.depth, sentinel.depth);
  assert.deepEqual(decision.recall_args.layers, sentinel.layers);
  assert.ok(decision.recall_args.q.toLowerCase().includes("status"));
});

test("force=true 时即使「抱抱我」也进入 recall", () => {
  const { sentinel, decision } = planFor("抱抱我", { force: true });
  assert.equal(sentinel.need_recall, false);
  assert.equal(decision.should_recall, true);
  // q 兜底原始 message,depth=none→normal
  assert.equal(decision.recall_args.q, "抱抱我");
  assert.equal(decision.recall_args.depth, "normal");
});

test("显式 touch 优先于 sentinel.touch_recommended", () => {
  // 构造一个 touch_recommended=true 的 sentinel
  const sTrue = { need_recall: true, depth: "deep", q: "核心设定", layers: ["core"], reason: "", touch_recommended: true };
  // 显式 false 覆盖
  const dFalse = planSmartRecall({ message: "x", sentinel: sTrue, touch: false });
  assert.equal(dFalse.recall_args.touch, false);
  // 显式 true 覆盖一个建议 false 的 sentinel
  const sFalse = { need_recall: true, depth: "shallow", q: "bug", layers: [], reason: "", touch_recommended: false };
  const dTrue = planSmartRecall({ message: "x", sentinel: sFalse, touch: true });
  assert.equal(dTrue.recall_args.touch, true);
  // 不传 touch → 跟随 sentinel
  const dFollow = planSmartRecall({ message: "x", sentinel: sTrue });
  assert.equal(dFollow.recall_args.touch, true);
});

test("depth=none 在召回时归一化为 normal", () => {
  const s = { need_recall: false, depth: "none", q: "", layers: [], reason: "r", touch_recommended: false };
  const d = planSmartRecall({ message: "查一下记忆", sentinel: s, force: true });
  assert.equal(d.should_recall, true);
  assert.equal(d.recall_args.depth, "normal");
  assert.equal(d.recall_args.q, "查一下记忆"); // q 空 → 兜底 message
});

test("layers 为空数组时 recall_args.layers=undefined（不限制）", () => {
  const s = { need_recall: true, depth: "normal", q: "x", layers: [], reason: "", touch_recommended: false };
  const d = planSmartRecall({ message: "x", sentinel: s });
  assert.equal(d.recall_args.layers, undefined);
});

test("planSmartRecall 不召回时给出 skipped_reason 兜底", () => {
  const d = planSmartRecall({ message: "hi", sentinel: { need_recall: false } });
  assert.equal(d.should_recall, false);
  assert.ok(d.skipped_reason.length > 0);
});
