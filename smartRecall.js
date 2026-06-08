// smartRecall.js
//
// smart_recall_context 的纯编排逻辑：把 memory_sentinel 的判断翻译成
// 「要不要查、用什么参数查」，不读数据库、不调用 recall_context、不写记忆。
// 真正的取数仍由 server.js 的 buildRecallContext 完成。

/**
 * 根据 sentinel 判断 + 调用方覆盖项，决定是否召回以及传给 recall_context 的参数。
 *
 * @param {object} args
 * @param {string} args.message               原始用户消息（q 兜底）。
 * @param {object} args.sentinel              evaluateSentinel 的输出。
 * @param {boolean} [args.force]              true 时即使 need_recall=false 也召回。
 * @param {boolean} [args.touch]             显式 touch 覆盖；未定义则用 sentinel.touch_recommended。
 * @returns {{should_recall: boolean, recall_args: object|null, skipped_reason: string}}
 */
export function planSmartRecall({ message, sentinel, force, touch } = {}) {
  const s = sentinel || {};
  const should_recall = Boolean(s.need_recall) || force === true;

  if (!should_recall) {
    return {
      should_recall: false,
      recall_args: null,
      skipped_reason: s.reason || "sentinel 判定无需召回记忆。",
    };
  }

  // q：优先用 sentinel 的具体检索词，空则兜底原始 message。
  const q = (s.q && String(s.q).trim()) || String(message || "").trim();

  // depth：none → normal（force 时 sentinel 可能给 none）。
  const depth = !s.depth || s.depth === "none" ? "normal" : s.depth;

  // layers：sentinel 的计划，空数组/缺省表示不限制。
  const layers = Array.isArray(s.layers) && s.layers.length ? s.layers : undefined;

  // touch：显式参数优先，否则跟随 sentinel 建议。
  const effTouch = typeof touch === "boolean" ? touch : Boolean(s.touch_recommended);

  return {
    should_recall: true,
    recall_args: { q, depth, layers, touch: effTouch },
    skipped_reason: "",
  };
}

export default planSmartRecall;
