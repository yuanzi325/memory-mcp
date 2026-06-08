// commitCandidates.js
//
// 「导入候选 → 正式记忆 / 年轮」提交工具的纯规划逻辑。
// planCandidate 决定每条候选该走什么动作（hold / comment / skip）、落在哪个 layer、
// 以及 dry_run 下应返回的 status。不读写数据库、不调用任何 memory 工具。
// 真正的写入（holdMemory / addRingComment）由 server.js 包裹执行。

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// hold 类候选的默认 layer。
export const DEFAULT_LAYER_BY_KIND = {
  preference: "core",
  project: "memo",
  memory: "treasure",
  diary: "diary",
};

// 缺省 importance 时按 kind 兜底。
const DEFAULT_IMPORTANCE_BY_KIND = {
  preference: 6,
  project: 5,
  memory: 7,
  diary: 3,
  comment: 4,
};

const HOLD_KINDS = ["preference", "project", "memory", "diary"];

function isUuid(v) {
  return typeof v === "string" && UUID_PATTERN.test(v);
}

function clampImportance(value, kind) {
  const n = Number(value);
  const base = Number.isFinite(n) ? n : DEFAULT_IMPORTANCE_BY_KIND[kind] ?? 2;
  return Math.max(1, Math.min(10, Math.round(base)));
}

/**
 * 规划单条候选的提交动作（纯逻辑）。
 * 返回 {
 *   action: "hold" | "comment" | "skip",
 *   status: "would_create" | "would_comment" | "needs_target" | "invalid",
 *   kind, layer, importance, message,
 *   hold?:    holdMemory 参数（action=hold 时）,
 *   comment?: addRingComment 参数（action=comment 时）,
 * }
 */
export function planCandidate(candidate = {}) {
  const kind = candidate.kind;
  const content = typeof candidate.content === "string" ? candidate.content.trim() : "";

  // content 为空 → 无法写入。
  if (!content) {
    return { action: "skip", status: "invalid", kind, message: "content 为空，无法提交。" };
  }

  // 不支持 ignore / 未知 kind。
  if (kind === "ignore" || (!HOLD_KINDS.includes(kind) && kind !== "comment")) {
    return { action: "skip", status: "invalid", kind, message: `不支持提交的 kind：${kind ?? "(空)"}。` };
  }

  // 年轮 comment：必须有合法 target_memory_id。
  if (kind === "comment") {
    if (!isUuid(candidate.target_memory_id)) {
      return {
        action: "skip",
        status: "needs_target",
        kind,
        message: "comment 候选缺少合法的 target_memory_id，需人工指定后再提交。",
      };
    }
    return {
      action: "comment",
      status: "would_comment",
      kind,
      message: "将作为年轮 comment 追加到目标记忆。",
      comment: {
        memory_id: candidate.target_memory_id,
        content,
        author: candidate.author,
        source: candidate.source,
      },
    };
  }

  // hold 类：preference/project/memory/diary。
  const layer =
    (typeof candidate.suggested_layer === "string" && candidate.suggested_layer.trim()) ||
    DEFAULT_LAYER_BY_KIND[kind];
  const importance = clampImportance(candidate.importance, kind);

  return {
    action: "hold",
    status: "would_create",
    kind,
    layer,
    importance,
    message: `将写入 memory_hold（layer=${layer}）。`,
    hold: {
      content,
      title: candidate.title,
      layer,
      keywords: candidate.keywords,
      importance,
      date: candidate.date,
      author: candidate.author,
    },
  };
}

// 规划整批候选（纯逻辑，dry_run 直接用）。
export function planCommit(candidates = []) {
  return (Array.isArray(candidates) ? candidates : []).map((c, index) => ({
    index,
    ...planCandidate(c),
  }));
}

export default planCommit;
