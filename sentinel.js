// sentinel.js
//
// memory_sentinel 的纯判断/规划逻辑（无副作用）。
// 它只回答「这一轮要不要召回记忆、查什么词、查多深」，
// 不读数据库、不调用 recall_context、不写入任何记忆。
//
// Pure planning layer for memory_sentinel. It decides whether a turn should
// recall memory, what to search for, and how deep — without touching the DB,
// recall_context, or any memory write path.

// 强召回信号：用户明确提到旧事/旧项目/旧设定，或要求翻记忆。
// Strong recall triggers — explicit references to the past or requests to look memory up.
const RECALL_TRIGGERS = [
  // 你知道我说的那个 …
  "你知道我说的那个",
  "你知道我说的",
  "你知道我说",
  "我说的那个",
  // 翻 / 查记忆
  "翻一下记忆",
  "翻一下之前",
  "翻一下",
  "翻记忆",
  "查一下记忆",
  "查查记忆",
  "查记忆",
  "调一下记忆",
  "调记忆",
  // 还记得
  "你还记得",
  "还记得吗",
  "还记得",
  "记不记得",
  "记得吗",
  // 上次 / 之前 / 以前
  "上次那个",
  "上回那个",
  "上次",
  "上回",
  "之前说过",
  "之前",
  "以前",
  "先前",
  // 接着 / 继续
  "接着上次",
  "接着那个",
  "接着",
  "继续",
  // 刚才
  "刚才那条",
  "刚才那个",
  "刚才",
  // 指代旧主题
  "那条线",
  "那件事",
  "那本书",
  "那个项目",
  "那次",
  // English
  "do you remember",
  "you remember",
  "remember when",
  "remember",
  "last time",
  "previously",
  "earlier we",
  "earlier",
  "you know the one",
  "you know the",
  "continue with",
  "continue",
  "pick up where",
  "pull up",
  "look up",
  "recall",
];

// 深层信号：身份/核心设定/长期关系/反复出现的雷区。
// Deep signals — identity, core settings, long-term relationship, recurring hard lines.
const DEEP_SIGNALS = [
  "核心设定",
  "核心",
  "身份设定",
  "身份",
  "关系设定",
  "我们的关系",
  "我们关系",
  "长期",
  "一直以来",
  "反复",
  "雷区",
  "底线",
  "原则",
  "重大",
  "我是谁",
  "你是谁",
  "我们是谁",
  "你的名字",
  "identity",
  "who am i",
  "who are you",
  "our relationship",
  "hard line",
  "boundary",
  "core rule",
  "core setting",
  "always been",
];

// 关系/珍宝信号 → treasure layer。
const RELATIONSHIP_SIGNALS = [
  "关系",
  "感情",
  "在一起",
  "承诺",
  "答应",
  "约定",
  "我们之间",
  "relationship",
  "promised",
  "between us",
];

// 偏好 / 长期身体状态信号 → 普通跨窗口记忆。
const PREFERENCE_SIGNALS = [
  "偏好",
  "喜欢",
  "讨厌",
  "习惯",
  "忌口",
  "口味",
  "身体状态",
  "长期身体",
  "preference",
  "prefer",
  "usually",
  "habit",
];

// 项目 / 技术上下文信号 → memo / project layer，通常 normal 深度。
const PROJECT_NORMAL_SIGNALS = [
  "项目",
  "部署",
  "接口",
  "数据库",
  "架构",
  "仪表盘",
  "服务",
  "配置",
  "功能",
  "需求",
  "dashboard",
  "usage",
  "status",
  "deploy",
  "api",
  "schema",
];

// 轻量技术 / bug 信号 → 通常 shallow 深度。
const BUG_LIGHT_SIGNALS = [
  "bug",
  "报错",
  "掉线",
  "断联",
  "断了",
  "崩了",
  "崩溃",
  "卡住",
  "出错",
  "挂了",
  "error",
  "crash",
  "broke",
  "broken",
];

// 通用技术词，仅用于 layer 判定（不单独决定深度）。
const TECH_LAYER_SIGNALS = [
  "mcp",
  "bridge",
  "代码",
  "脚本",
  "服务器",
  "前端",
  "后端",
  "函数",
  ".mjs",
  ".js",
  "code",
  "server",
];

// 日记 / 当天信号 → diary layer。
const DIARY_SIGNALS = ["日记", "当天", "昨天", "前几天", "那天", "diary"];

// 寒暄 / 简单情绪信号（用于 reason 说明，不单独决定 need_recall）。
const SMALL_TALK_SIGNALS = [
  "早安",
  "晚安",
  "你好",
  "哈喽",
  "嗨",
  "在吗",
  "亲亲",
  "抱抱",
  "么么",
  "摸摸",
  "想你",
  "爱你",
  "累了",
  "困了",
  "good morning",
  "good night",
  "hello",
  "hug",
  "miss you",
  "love you",
];

// q 提取时要去掉的泛词 / 填充词（保留有主题价值的词）。
// Generic fillers stripped from q (topic-bearing words are kept).
const Q_FILLERS_ZH = [
  "那个",
  "这个",
  "一下子",
  "一下",
  "沅沅",
  "用户",
  "今天",
  "帮我看看",
  "帮我",
  "帮忙",
  "请问",
  "请",
];

const Q_FILLERS_EN = [
  "the",
  "a",
  "an",
  "that",
  "this",
  "you",
  "do",
  "does",
  "did",
  "i",
  "my",
  "our",
  "please",
  "can",
  "could",
  "again",
  "about",
  "with",
];

// 句尾语气词 / 标点。
const TRAILING_PARTICLES = ["吗", "呢", "吧", "嘛", "啊", "呀", "哈", "哦", "嗯", "哒", "呐", "啦"];

// 空洞检索词：剥词后只剩这些泛动词/泛指代时，q 没有召回价值。
// Vague leftovers — if the query collapses to only one of these, it carries no recall value.
const VAGUE_Q = [
  "讲",
  "弄",
  "说",
  "搞",
  "做",
  "看",
  "聊",
  "想",
  "用",
  "整",
  "他",
  "她",
  "它",
  "这",
  "那",
  "事",
  "东西",
  "一下",
];

function findMatches(haystackLower, needles) {
  const hits = [];
  for (const n of needles) {
    if (n && haystackLower.includes(n.toLowerCase())) hits.push(n);
  }
  return hits;
}

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// 从 message 提取具体检索词：剥掉触发短语和泛词，保留主题词。
function buildQuery(message) {
  let work = ` ${String(message)} `;

  // 先去掉触发短语（长的优先，避免子串残留）。
  const phrases = [...RECALL_TRIGGERS].sort((a, b) => b.length - a.length);
  for (const p of phrases) {
    if (!p) continue;
    if (/[a-zA-Z]/.test(p)) {
      work = work.replace(new RegExp(escapeRegExp(p), "ig"), " ");
    } else {
      work = work.split(p).join(" ");
    }
  }

  // 去掉中文泛词。
  for (const f of Q_FILLERS_ZH) work = work.split(f).join(" ");

  // 去掉英文填充词（按整词）。
  for (const f of Q_FILLERS_EN) {
    work = work.replace(new RegExp(`\\b${escapeRegExp(f)}\\b`, "ig"), " ");
  }

  // 标点替换为空格。
  work = work.replace(/[，。！？、；：,.!?;:~～…—\-_/\\"'“”‘’()（）【】\[\]]+/g, " ");

  // 去掉句尾语气词（多次）。
  let changed = true;
  while (changed) {
    changed = false;
    let trimmed = work.trim();
    for (const t of TRAILING_PARTICLES) {
      if (trimmed.endsWith(t)) {
        trimmed = trimmed.slice(0, -t.length);
        changed = true;
      }
    }
    work = ` ${trimmed} `;
  }

  return work.replace(/\s+/g, " ").trim();
}

// 检索词是否太弱：剥词后为空，或只剩单个泛动词/泛指代（如「讲」「弄」「这个」）。
function isWeakQuery(q) {
  const compact = String(q).replace(/\s+/g, "");
  if (compact.length === 0) return true;
  if (compact.length <= 2 && VAGUE_Q.includes(compact)) return true;
  return false;
}

/**
 * 判断这一轮是否需要召回记忆，并给出检索规划。
 * @param {{message?: string, profile?: string, recent_context?: string}} input
 * @returns {{need_recall: boolean, depth: "none"|"shallow"|"normal"|"deep", q: string, layers: string[], reason: string, touch_recommended: boolean}}
 */
export function evaluateSentinel(input = {}) {
  const message = typeof input.message === "string" ? input.message : "";
  const lower = message.toLowerCase();

  const triggers = findMatches(lower, RECALL_TRIGGERS);
  const deepHits = findMatches(lower, DEEP_SIGNALS);
  const relationshipHits = findMatches(lower, RELATIONSHIP_SIGNALS);
  const preferenceHits = findMatches(lower, PREFERENCE_SIGNALS);
  const projectHits = findMatches(lower, PROJECT_NORMAL_SIGNALS);
  const bugHits = findMatches(lower, BUG_LIGHT_SIGNALS);
  const techHits = findMatches(lower, TECH_LAYER_SIGNALS);
  const diaryHits = findMatches(lower, DIARY_SIGNALS);
  const smallTalkHits = findMatches(lower, SMALL_TALK_SIGNALS);

  const hasTrigger = triggers.length > 0;
  const hasDeep = deepHits.length > 0;
  // 具体项目/技术主题 + 故障/bug 词：即使没说「上次/还记得」，也是典型的旧项目召回场景。
  // e.g. 「记忆库 MCP 又断联了」「memory-mcp bridge 又挂了」。
  const hasTopicFault = (projectHits.length > 0 || techHits.length > 0) && bugHits.length > 0;

  // ── 不需要召回 ────────────────────────────────────────────────
  if (!message.trim() || (!hasTrigger && !hasDeep && !hasTopicFault)) {
    let reason;
    if (smallTalkHits.length > 0) {
      reason = `普通寒暄/情绪回应（命中「${smallTalkHits.join("、")}」），无召回信号，当前上下文足够，无需召回记忆。`;
    } else if (!message.trim()) {
      reason = "空消息，无需召回记忆。";
    } else {
      reason = "未检测到旧事/旧项目/旧设定等召回信号，普通对话，无需召回记忆。";
    }
    return {
      need_recall: false,
      depth: "none",
      q: "",
      layers: [],
      reason,
      touch_recommended: false,
    };
  }

  // ── 需要召回 ──────────────────────────────────────────────────
  const q = buildQuery(message);

  // 弱检索词降级：当召回仅由宽泛触发词（如「继续/接着」）撑起、且剥词后 q 太弱时，
  // 说明用户只是「继续讲这个」，并没有指向具体旧记忆 —— 判定无需召回。
  // 深层信号或「主题+故障」信号足够具体，不在此降级范围内。
  if (!hasDeep && !hasTopicFault && isWeakQuery(q)) {
    return {
      need_recall: false,
      depth: "none",
      q: "",
      layers: [],
      reason: `命中宽泛触发词「${triggers.slice(0, 3).join("、")}」，但剥掉触发词/泛词后检索词为「${q || "空"}」，过于空洞、未指向具体旧记忆，无需召回。`,
      touch_recommended: false,
    };
  }

  // 深度判定。
  let depth;
  if (hasDeep) {
    depth = "deep";
  } else if (relationshipHits.length > 0 || preferenceHits.length > 0 || projectHits.length > 0) {
    depth = "normal";
  } else if (bugHits.length > 0 || findMatches(lower, ["刚才", "最近", "刚刚", "上次", "上回"]).length > 0) {
    depth = "shallow";
  } else {
    depth = "normal";
  }

  // layer 建议。
  const layerSet = [];
  const pushLayer = (l) => {
    if (!layerSet.includes(l)) layerSet.push(l);
  };
  if (hasDeep) pushLayer("core");
  if (relationshipHits.length > 0) pushLayer("treasure");
  if (preferenceHits.length > 0) pushLayer("treasure");
  if (diaryHits.length > 0) pushLayer("diary");
  if (projectHits.length > 0 || bugHits.length > 0 || techHits.length > 0) pushLayer("memo");

  // touch 建议：只有强召回请求且非浅层时才建议 touch。
  const strongRequest = findMatches(lower, [
    "翻一下",
    "翻记忆",
    "查记忆",
    "查一下记忆",
    "还记得",
    "记得吗",
    "接着",
    "继续",
    "上次那个",
    "之前说过",
  ]).length > 0;
  const touch_recommended =
    (depth === "normal" || depth === "deep") && strongRequest && !isWeakQuery(q);

  // reason。
  const signalParts = [];
  if (triggers.length > 0) signalParts.push(`召回触发词「${triggers.slice(0, 4).join("、")}」`);
  if (hasDeep) signalParts.push(`核心/长期信号「${deepHits.slice(0, 3).join("、")}」`);
  if (relationshipHits.length > 0) signalParts.push(`关系信号「${relationshipHits.slice(0, 2).join("、")}」`);
  if (projectHits.length > 0 || techHits.length > 0)
    signalParts.push(`项目/技术信号「${[...projectHits, ...techHits].slice(0, 3).join("、")}」`);
  if (bugHits.length > 0) signalParts.push(`轻量背景信号「${bugHits.slice(0, 2).join("、")}」`);

  const reason =
    `检测到 ${signalParts.join("、") || "召回信号"}；建议 depth=${depth} 召回，` +
    `检索词「${q || message.trim()}」` +
    (layerSet.length ? `，限定 layers=[${layerSet.join(", ")}]` : "，不限制 layer") +
    `${touch_recommended ? "，召回内容大概率会被使用，建议 touch。" : "。"}`;

  return {
    need_recall: true,
    depth,
    q,
    layers: layerSet,
    reason,
    touch_recommended,
  };
}

export default evaluateSentinel;
