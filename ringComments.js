// ringComments.js
//
// 「年轮 comments」的纯数据逻辑：构造 / 追加 / 排序 / 删除 raw.ring_comments。
// 不碰数据库、不碰 env/token。MCP 工具在 server.js 里读取 memory.raw、调用这些
// 纯函数、再写回，从而和前端的 raw.ring_comments MVP 兼容。

import { randomUUID } from "node:crypto";

// 把任意 raw.ring_comments 值规整成「对象数组」。
export function normalizeComments(value) {
  return Array.isArray(value) ? value.filter((c) => c && typeof c === "object") : [];
}

/**
 * 构造一条年轮 comment。content trim 后不能为空。
 * 形状稳定为 { id, created_at, author, source, content }，与前端 MVP 兼容。
 */
export function makeComment({ content, author, source, now, id, maxLen } = {}) {
  let text = typeof content === "string" ? content.trim() : "";
  if (!text) throw new Error("content must not be empty");
  if (maxLen && text.length > maxLen) text = text.slice(0, maxLen);
  return {
    id: id || "rc_" + randomUUID(),
    created_at: now || new Date().toISOString(),
    author: author != null ? String(author).trim() : "",
    source: source != null ? String(source).trim() : "",
    content: text,
  };
}

// 按 created_at 升序排序（无效时间排到最前，保持稳定）。
export function sortCommentsAsc(comments) {
  return [...normalizeComments(comments)].sort((a, b) => {
    const ta = Date.parse(a?.created_at) || 0;
    const tb = Date.parse(b?.created_at) || 0;
    return ta - tb;
  });
}

// 末尾追加一条，返回新数组（不修改入参）。
export function appendComment(rawComments, comment) {
  return [...normalizeComments(rawComments), comment];
}

// 按 id 删除，返回 { comments, deleted }。不存在时 deleted=false。
export function removeComment(rawComments, commentId) {
  const list = normalizeComments(rawComments);
  const next = list.filter((c) => c.id !== commentId);
  return { comments: next, deleted: next.length !== list.length };
}

export default { normalizeComments, makeComment, sortCommentsAsc, appendComment, removeComment };
