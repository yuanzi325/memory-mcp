// importCandidates.js
//
// 「历史聊天导入候选池」P0 的纯抽取逻辑。
// 不读写数据库、不调用任何 memory 工具、不用大模型/embedding——只做轻量规则抽取，
// 产出「候选记忆」供人工审查。真正写入由后续的 memory_import_candidate_commit 完成。

import { randomUUID } from "node:crypto";

const CONTENT_CAP = 600;
const EXCERPT_CAP = 160;
const TITLE_CAP = 24;

// ── 信号词表（轻量规则，非穷举） ─────────────────────────────────────────────
// 「重新理解旧记忆」→ kind=comment（可挂年轮）。优先级最高。
const COMMENT_SIGNALS = [
  "重新理解",
  "重新认识",
  "重新想",
  "重新看",
  "现在才明白",
  "现在才懂",
  "现在想想",
  "现在回想",
  "回过头",
  "回头看",
  "原来其实",
  "其实当时",
  "当时其实",
  "纠正一下",
  "更正一下",
  "更正",
  "补充一下",
  "更新一下",
  "之前说错",
  "我错了",
  "现在重新",
  "looking back",
  "now i realize",
  "i was wrong",
  "actually it was",
];

// 偏好 / 雷区 / 边界。
const PREFERENCE_SIGNALS = [
  "特别喜欢",
  "最喜欢",
  "喜欢",
  "最讨厌",
  "讨厌",
  "最受不了",
  "受不了",
  "不喜欢",
  "最烦",
  "反感",
  "习惯于",
  "习惯",
  "忌口",
  "口味",
  "偏好",
  "我爱",
  "我恨",
  "prefer",
  "i like",
  "i hate",
  "can't stand",
  "cannot stand",
];
// 雷区/硬边界（更高重要度）。
const HARDLINE_SIGNALS = [
  "雷区",
  "底线",
  "不能接受",
  "无法接受",
  "别催",
  "不要催",
  "别打断",
  "别碰",
  "不要碰",
  "千万别",
  "绝对不",
  "最受不了",
  "受不了",
  "boundary",
  "hard line",
  "deal breaker",
];

// 项目 / 技术长期上下文。
const PROJECT_SIGNALS = [
  "项目",
  "部署",
  "上线",
  "接口",
  "数据库",
  "架构",
  "重写",
  "重构",
  "需求",
  "配置",
  "功能",
  "报错",
  "掉线",
  "断联",
  "断了",
  "挂了",
  "崩了",
  "崩溃",
  "bug",
  "api",
  "mcp",
  "bridge",
  "仪表盘",
  "dashboard",
  "usage",
  "status",
  "代码",
  "脚本",
  "服务器",
  "前端",
  "后端",
];

// 关系设定 / 身份 / 重要事件。
const MEMORY_SIGNALS = [
  "我们的关系",
  "我们之间",
  "我们是",
  "在一起",
  "承诺",
  "约定",
  "答应过",
  "答应",
  "身份设定",
  "身份",
  "设定",
  "名字叫",
  "纪念",
  "第一次",
  "重要的决定",
  "做了决定",
  "确认关系",
  "转折",
  "搬家",
  "分手",
  "和好",
];

// 日记 / 当天沉淀（需较完整的反思句，避免一次性情绪）。
const DIARY_SIGNALS = ["日记", "这几天", "这阵子", "最近我", "今天我", "今天一整天", "今天感觉"];

// kind → 建议 layer。
const LAYER_BY_KIND = {
  preference: "core",
  project: "memo",
  memory: "treasure",
  diary: "diary",
  comment: "", // comment 挂在已有记忆上，不指定 layer
};

// kind → 基础重要度。
const IMPORTANCE_BY_KIND = {
  preference: 6,
  project: 5,
  memory: 7,
  diary: 3,
  comment: 4,
};

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function hasAny(lowerText, list) {
  return list.filter((s) => s && lowerText.includes(s.toLowerCase()));
}

// 把文本按 chunk_chars 切块，尽量在换行处断开。
export function chunkText(text, chunkChars) {
  const src = String(text || "");
  const size = clamp(Number(chunkChars) || 6000, 500, 20000);
  if (!src.trim()) return [];
  const lines = src.split(/\r?\n/);
  const chunks = [];
  let buf = "";
  for (const line of lines) {
    if (buf && buf.length + line.length + 1 > size) {
      chunks.push(buf);
      buf = "";
    }
    // 单行超长：硬切。
    if (line.length > size) {
      if (buf) {
        chunks.push(buf);
        buf = "";
      }
      for (let i = 0; i < line.length; i += size) chunks.push(line.slice(i, i + size));
      continue;
    }
    buf = buf ? `${buf}\n${line}` : line;
  }
  if (buf.trim()) chunks.push(buf);
  return chunks;
}

// 把 chunk 切成「单元」（按句子/换行）。
function segmentChunk(chunk) {
  return String(chunk)
    .split(/[\n。！？!?；;]+/)
    .map((s) => s.trim())
    // 去掉常见聊天前缀，如 "沅沅：" / "小克:" / "- "
    .map((s) => s.replace(/^[-*>\s]*[一-龥A-Za-z0-9_]{1,8}[:：]\s*/, "").trim())
    .filter((s) => s.length >= 4);
}

function extractKeywords(content, matched) {
  const latin = (content.match(/[A-Za-z][A-Za-z0-9.\-_]{1,}/g) || []).map((s) => s);
  const merged = [...new Set([...matched, ...latin])].filter(Boolean);
  return merged.slice(0, 8);
}

// 为 comment 候选提取「指向哪条旧记忆」的线索短语。
function extractTargetHint(content) {
  const m = content.match(/(之前|上次|以前|那段|那件事|那次|那个[一-龥A-Za-z0-9]{0,8}|当时)[^，。！？\n]{0,12}/);
  return m ? m[0].trim() : "";
}

// 对单个单元分类，返回候选或 null（无长期价值时 null）。
function classifyUnit(unit, source) {
  const content = unit.length > CONTENT_CAP ? unit.slice(0, CONTENT_CAP) : unit;
  const lower = content.toLowerCase();

  const commentHits = hasAny(lower, COMMENT_SIGNALS);
  const hardlineHits = hasAny(lower, HARDLINE_SIGNALS);
  const prefHits = hasAny(lower, PREFERENCE_SIGNALS);
  const projectHits = hasAny(lower, PROJECT_SIGNALS);
  const memoryHits = hasAny(lower, MEMORY_SIGNALS);
  const diaryHits = hasAny(lower, DIARY_SIGNALS);

  let kind = null;
  let matched = [];
  let importance = 0;
  let confidence = 0;
  let reason = "";

  // 优先级：comment > preference/hardline > project > memory > diary
  if (commentHits.length) {
    kind = "comment";
    matched = commentHits;
    importance = IMPORTANCE_BY_KIND.comment;
    confidence = 0.6;
    reason = `重新理解信号「${commentHits.slice(0, 2).join("、")}」`;
  } else if (hardlineHits.length || prefHits.length) {
    kind = "preference";
    matched = [...new Set([...hardlineHits, ...prefHits])];
    importance = hardlineHits.length ? 8 : IMPORTANCE_BY_KIND.preference;
    confidence = hardlineHits.length ? 0.75 : 0.65;
    reason = hardlineHits.length
      ? `雷区/边界信号「${hardlineHits.slice(0, 2).join("、")}」`
      : `偏好信号「${prefHits.slice(0, 2).join("、")}」`;
  } else if (projectHits.length) {
    kind = "project";
    matched = projectHits;
    importance = IMPORTANCE_BY_KIND.project;
    confidence = 0.6;
    reason = `项目/技术信号「${projectHits.slice(0, 3).join("、")}」`;
  } else if (memoryHits.length) {
    kind = "memory";
    matched = memoryHits;
    importance = IMPORTANCE_BY_KIND.memory;
    confidence = 0.6;
    reason = `关系/身份/事件信号「${memoryHits.slice(0, 2).join("、")}」`;
  } else if (diaryHits.length && content.length >= 12) {
    kind = "diary";
    matched = diaryHits;
    importance = IMPORTANCE_BY_KIND.diary;
    confidence = 0.5;
    reason = `日记/沉淀信号「${diaryHits.slice(0, 2).join("、")}」`;
  } else {
    // 没有任何长期价值信号 → 不抽（寒暄/一次性情绪/未确认推测自然落到这里）。
    return null;
  }

  // 命中多类信号时略增信心。
  const multi = [commentHits, hardlineHits, prefHits, projectHits, memoryHits].filter((h) => h.length).length;
  if (multi > 1) confidence = clamp(confidence + 0.1, 0, 0.9);

  return {
    id: "cand_" + randomUUID(),
    source: source || "",
    kind,
    title: content.length > TITLE_CAP ? content.slice(0, TITLE_CAP) + "…" : content,
    content,
    suggested_layer: LAYER_BY_KIND[kind] ?? "",
    keywords: extractKeywords(content, matched),
    importance: clamp(importance, 1, 10),
    confidence: Math.round(confidence * 100) / 100,
    reason,
    target_memory_hint: kind === "comment" ? extractTargetHint(content) : "",
    raw_excerpt: content.length > EXCERPT_CAP ? content.slice(0, EXCERPT_CAP) + "…" : content,
  };
}

/**
 * 从历史聊天文本抽取候选记忆（纯逻辑，无副作用）。
 * @param {{text?: string, source?: string, profile?: string, chunk_chars?: number, max_candidates?: number}} input
 */
export function extractCandidates(input = {}) {
  const { text, source, profile, chunk_chars, max_candidates } = input;
  const maxCands = clamp(Number(max_candidates) || 50, 1, 200);

  const chunks = chunkText(text, chunk_chars);
  const seen = new Set();
  const collected = [];

  chunks.forEach((chunk, ci) => {
    for (const unit of segmentChunk(chunk)) {
      const dedupeKey = unit.toLowerCase().replace(/\s+/g, " ").trim();
      if (seen.has(dedupeKey)) continue;
      const cand = classifyUnit(unit, source);
      if (!cand) continue;
      seen.add(dedupeKey);
      collected.push({ ...cand, _chunk: ci, _order: collected.length });
    }
  });

  // 按 importance*confidence 排序，截到 max_candidates；保留稳定顺序作为 tie-break。
  collected.sort((a, b) => {
    const sa = a.importance * a.confidence;
    const sb = b.importance * b.confidence;
    if (sb !== sa) return sb - sa;
    return a._order - b._order;
  });
  const candidates = collected.slice(0, maxCands).map(({ _chunk, _order, ...c }) => c);

  return {
    source: source || "",
    profile: profile || "shared",
    chunk_count: chunks.length,
    candidate_count: candidates.length,
    candidates,
  };
}

export default extractCandidates;
