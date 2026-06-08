import test from "node:test";
import assert from "node:assert/strict";
import { resolveRecallPlan, layerAllowed, DEPTH_PRESETS } from "../recallPlan.js";

test("depth=shallow 不追加 Tier 3 背景且数量/预算更小", () => {
  const p = resolveRecallPlan({ depth: "shallow" });
  assert.equal(p.depth, "shallow");
  assert.equal(p.max_tier3, 0, "shallow 不应追加 core/treasure 背景");
  assert.equal(p.wantTier3, false);
  assert.ok(p.max_items < DEPTH_PRESETS.normal.max_items, "shallow max_items 应更小");
  assert.ok(p.budget_chars < DEPTH_PRESETS.normal.budget_chars, "shallow budget 应更小");
  assert.ok(p.max_buckets < DEPTH_PRESETS.normal.max_buckets, "shallow bucket 应更少");
  assert.equal(p.anchorBoost, false);
});

test("depth=normal 保持现有默认行为", () => {
  const p = resolveRecallPlan({ depth: "normal" });
  assert.equal(p.depth, "normal");
  assert.equal(p.max_items, 20);
  assert.equal(p.budget_chars, 4000);
  assert.equal(p.max_tier3, 3);
  assert.equal(p.max_buckets, 5);
  assert.equal(p.wantTier3, true);
  assert.equal(p.anchorBoost, false);
});

test("不传 depth 等同 normal（向后兼容）", () => {
  const p = resolveRecallPlan({});
  assert.deepEqual(
    { d: p.depth, mi: p.max_items, bc: p.budget_chars, t3: p.max_tier3, mb: p.max_buckets },
    { d: "normal", mi: 20, bc: 4000, t3: 3, mb: 5 }
  );
  assert.equal(p.layers, null, "不传 layers 时不限制 layer");
});

test("非法 depth 回落到 normal", () => {
  const p = resolveRecallPlan({ depth: "ultra" });
  assert.equal(p.depth, "normal");
  assert.equal(p.max_items, 20);
});

test("depth=deep 更大且增强 core/treasure/anchor", () => {
  const p = resolveRecallPlan({ depth: "deep" });
  assert.equal(p.depth, "deep");
  assert.ok(p.max_items > DEPTH_PRESETS.normal.max_items, "deep max_items 应更大");
  assert.ok(p.budget_chars > DEPTH_PRESETS.normal.budget_chars, "deep budget 应更大");
  assert.ok(p.max_tier3 > DEPTH_PRESETS.normal.max_tier3, "deep 应带更多常驻背景");
  assert.equal(p.wantTier3, true);
  assert.equal(p.anchorBoost, true, "deep 应增强 anchor 召回");
});

test("显式 budget_chars / max_items 覆盖 depth 默认值", () => {
  const p = resolveRecallPlan({ depth: "deep", budget_chars: 2000, max_items: 5 });
  assert.equal(p.budget_chars, 2000);
  assert.equal(p.max_items, 5);
  // depth 派生的其它参数仍保留
  assert.equal(p.max_tier3, DEPTH_PRESETS.deep.max_tier3);
  assert.equal(p.anchorBoost, true);
});

test("layers=['memo'] 只允许 memo，不混入 diary/treasure", () => {
  const p = resolveRecallPlan({ depth: "normal", layers: ["memo"] });
  assert.deepEqual(p.layers, ["memo"]);
  assert.equal(layerAllowed(p, "memo"), true);
  assert.equal(layerAllowed(p, "diary"), false);
  assert.equal(layerAllowed(p, "treasure"), false);
  assert.equal(layerAllowed(p, "core"), false);
});

test("layers 为空数组 / 不传时不限制 layer", () => {
  const pEmpty = resolveRecallPlan({ layers: [] });
  assert.equal(pEmpty.layers, null);
  assert.equal(layerAllowed(pEmpty, "treasure"), true);

  const pNone = resolveRecallPlan({});
  assert.equal(layerAllowed(pNone, "diary"), true);
});

test("layers 去重并去空白", () => {
  const p = resolveRecallPlan({ layers: ["memo", "memo", " core ", ""] });
  assert.deepEqual(p.layers, ["memo", "core"]);
});

test("layers=['memo'] 时 bucket 上下文不使用非 memo 记忆", () => {
  // 模拟同一个 bucket 里混有 memo / diary / treasure 的记忆。
  const bucketMems = [
    { id: "1", layer: "memo", importance: 3, content: "memo: deploy notes" },
    { id: "2", layer: "diary", importance: 9, content: "diary: 今天好累" },
    { id: "3", layer: "treasure", importance: 8, content: "treasure: 我们的约定" },
    { id: "4", layer: "memo", importance: 5, content: "memo: usage dashboard" },
  ];
  const plan = resolveRecallPlan({ layers: ["memo"] });

  // 复用 server.js 中相同的过滤谓词。
  const filtered = plan.layers ? bucketMems.filter((m) => layerAllowed(plan, m.layer)) : bucketMems;

  assert.deepEqual(filtered.map((m) => m.id), ["1", "4"], "只应保留 memo 记忆");
  assert.ok(filtered.every((m) => m.layer === "memo"));

  // summary_snippet 取自最高 importance 的记忆——必须仍是 memo，而不是 diary(9)/treasure(8)。
  const topMem = [...filtered].sort((a, b) => b.importance - a.importance)[0];
  assert.equal(topMem.layer, "memo");
  assert.equal(topMem.id, "4");
  assert.ok(!topMem.content.includes("diary") && !topMem.content.includes("treasure"));
});

test("不传 layers 时 bucket 上下文保留全部 layer（不回归）", () => {
  const bucketMems = [
    { id: "1", layer: "memo" },
    { id: "2", layer: "diary" },
  ];
  const plan = resolveRecallPlan({});
  const filtered = plan.layers ? bucketMems.filter((m) => layerAllowed(plan, m.layer)) : bucketMems;
  assert.equal(filtered.length, 2, "不限制时 bucket 摘要可取任意 layer 作为背景");
});

test("resolveRecallPlan 是纯函数（同输入同输出）", () => {
  const a = resolveRecallPlan({ depth: "deep", layers: ["memo", "core"] });
  const b = resolveRecallPlan({ depth: "deep", layers: ["memo", "core"] });
  assert.deepEqual(a, b);
});
