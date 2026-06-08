// recallPlan.js
//
// recall_context 的「召回计划」纯逻辑：把 memory_sentinel 输出的 depth / layers
// 翻译成具体的召回参数（max_items / budget_chars / Tier 3 背景数量 / bucket 数量 /
// 是否限制 layer / 是否增强 anchor）。
//
// 纯函数、无副作用，便于单测。真正的取数 / 预算裁剪仍在 server.js 的
// buildRecallContext 中完成，这里只决定「醒多深」对应的参数。

// 各深度档位的默认召回参数。
// normal 必须与历史默认行为一致（max_items=20, budget_chars=4000, Tier3=3, buckets=5）。
export const DEPTH_PRESETS = {
  shallow: { max_items: 6, budget_chars: 1800, max_tier3: 0, max_buckets: 2 },
  normal: { max_items: 20, budget_chars: 4000, max_tier3: 3, max_buckets: 5 },
  deep: { max_items: 24, budget_chars: 6000, max_tier3: 8, max_buckets: 8 },
};

function isFiniteNumber(v) {
  return typeof v === "number" && Number.isFinite(v);
}

/**
 * 解析召回计划。
 * - depth 缺省或非法 → 走 normal（保持旧行为）。
 * - 显式传入的 budget_chars / max_items 永远覆盖深度默认值（尊重调用方）。
 * - layers 为非空数组时限制召回 layer；否则为 null 表示不限制。
 *
 * @param {{depth?: string, budget_chars?: number, max_items?: number, layers?: string[]}} input
 */
export function resolveRecallPlan(input = {}) {
  const { depth, budget_chars, max_items, layers } = input;
  const depthKey = DEPTH_PRESETS[depth] ? depth : "normal";
  const preset = DEPTH_PRESETS[depthKey];

  const layerSet =
    Array.isArray(layers) && layers.length
      ? [...new Set(layers.map((l) => String(l).trim()).filter(Boolean))]
      : null;

  return {
    depth: depthKey,
    max_items: isFiniteNumber(max_items) ? max_items : preset.max_items,
    budget_chars: isFiniteNumber(budget_chars) ? budget_chars : preset.budget_chars,
    max_tier3: preset.max_tier3,
    max_buckets: preset.max_buckets,
    // null = 不限制 layer；否则只召回这些 layer。
    layers: layerSet,
    // shallow 默认不追加 Tier 3 常驻背景（q 精确命中的 core/treasure 仍会经 Tier 1 出现）。
    wantTier3: preset.max_tier3 > 0,
    // deep 时让 anchor 记忆在常驻背景里优先。
    anchorBoost: depthKey === "deep",
  };
}

/**
 * 在给定召回计划下，某个 layer 是否允许进入召回结果。
 * plan.layers 为 null（不限制）时一律允许。
 */
export function layerAllowed(plan, layer) {
  if (!plan || !plan.layers) return true;
  return plan.layers.includes(layer);
}

export default resolveRecallPlan;
