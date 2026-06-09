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

/**
 * 执行整批候选的提交（dry_run 规划 + 真正写入的统一编排）。
 *
 * 写库动作通过注入的 holdMemory / addRingComment 完成——本文件不直接依赖数据库，
 * 既便于单测注入 mock，也让 MCP tool 与 REST endpoint 共用同一份编排逻辑，避免两边漂移。
 *
 * - dry_run=true（默认）：只规划、绝不写库。
 * - dry_run=false：才真正写入；单条失败（error）不影响后续候选。
 * - kind=ignore / content 为空 → invalid；comment 缺合法 target_memory_id → needs_target。
 *
 * @param {{candidates?: any[], dry_run?: boolean, merge?: boolean}} input
 * @param {{holdMemory: Function, addRingComment: Function}} deps
 * @returns {Promise<{dry_run: boolean, committed_count: number, skipped_count: number, results: any[]}>}
 */
export async function commitImportCandidates(
  { candidates = [], dry_run = true, merge = true } = {},
  { holdMemory, addRingComment } = {}
) {
  const list = Array.isArray(candidates) ? candidates : [];
  const plans = planCommit(list);
  const results = [];
  let committed = 0;
  let skipped = 0;

  for (const plan of plans) {
    const base = { index: plan.index, kind: plan.kind ?? "" };

    // 规划阶段就已判定无法写入（invalid / needs_target）。
    if (plan.action === "skip") {
      results.push({ ...base, status: plan.status, message: plan.message });
      skipped++;
      continue;
    }

    // dry_run：只返回会执行什么，不写库。
    if (dry_run) {
      const extra = {};
      if (plan.action === "comment") extra.memory_id = plan.comment.memory_id;
      results.push({ ...base, status: plan.status, message: plan.message, ...extra });
      continue;
    }

    // 真正写入。单条失败不影响后续。
    try {
      if (plan.action === "comment") {
        const cand = list[plan.index];
        const { comment, comment_count } = await addRingComment({
          memory_id: plan.comment.memory_id,
          content: plan.comment.content,
          author: plan.comment.author,
          source: plan.comment.source || cand?.source,
        });
        results.push({
          ...base,
          status: "commented",
          memory_id: plan.comment.memory_id,
          comment_id: comment.id,
          message: `已追加年轮 comment（id=${comment.id}），目标记忆现有 ${comment_count} 条。`,
        });
        committed++;
      } else {
        // hold：附带导入溯源信息进 raw。
        const cand = list[plan.index];
        const holdResult = await holdMemory({
          ...plan.hold,
          merge,
          raw: {
            import_source: cand?.source ?? "",
            import_confidence: typeof cand?.confidence === "number" ? cand.confidence : null,
            import_kind: plan.kind,
            import_committed_at: new Date().toISOString(),
          },
        });
        const item = holdResult.item;
        results.push({
          ...base,
          status: holdResult.mode, // "created" | "merged"
          memory_id: item?.id,
          message:
            holdResult.mode === "merged"
              ? `已合并进已有记忆（id=${item?.id}，similarity=${holdResult.similarity}）。`
              : `已新建记忆（id=${item?.id}，layer=${plan.layer}）。`,
        });
        committed++;
      }
    } catch (err) {
      results.push({
        ...base,
        status: "error",
        message: err instanceof Error ? err.message : String(err),
      });
      skipped++;
    }
  }

  return { dry_run, committed_count: committed, skipped_count: skipped, results };
}

export default planCommit;
