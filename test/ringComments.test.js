import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeComments,
  makeComment,
  sortCommentsAsc,
  appendComment,
  removeComment,
} from "../ringComments.js";

test("makeComment 形状稳定且 content 被 trim", () => {
  const c = makeComment({ content: "  重新理解了这段  ", author: "小克", source: "ring", now: "2026-06-08T00:00:00.000Z", id: "rc_1" });
  assert.deepEqual(c, {
    id: "rc_1",
    created_at: "2026-06-08T00:00:00.000Z",
    author: "小克",
    source: "ring",
    content: "重新理解了这段",
  });
});

test("makeComment 缺省 author/source 为空字符串", () => {
  const c = makeComment({ content: "x", now: "t", id: "rc_2" });
  assert.equal(c.author, "");
  assert.equal(c.source, "");
});

test("makeComment 空 content 抛清晰错误", () => {
  assert.throws(() => makeComment({ content: "   " }), /content must not be empty/);
  assert.throws(() => makeComment({ content: undefined }), /content must not be empty/);
});

test("makeComment 受 maxLen 限制", () => {
  const c = makeComment({ content: "a".repeat(50), maxLen: 10, now: "t", id: "rc_3" });
  assert.equal(c.content.length, 10);
});

test("add 会保留 existing raw 字段（模拟工具的 raw 展开）", () => {
  const raw = {
    name: "旧记忆",
    chord_tag: "Cmaj7",
    ring_comments: [{ id: "rc_old", created_at: "2026-01-01T00:00:00.000Z", author: "", source: "", content: "旧注" }],
    anchor: true,
  };
  const comment = makeComment({ content: "新注", now: "2026-06-08T00:00:00.000Z", id: "rc_new" });
  const nextComments = appendComment(raw.ring_comments, comment);
  const nextRaw = { ...raw, ring_comments: nextComments };

  // 其它 raw 字段原样保留
  assert.equal(nextRaw.name, "旧记忆");
  assert.equal(nextRaw.chord_tag, "Cmaj7");
  assert.equal(nextRaw.anchor, true);
  // 旧 comment 仍在，新 comment 追加到末尾
  assert.equal(nextRaw.ring_comments.length, 2);
  assert.equal(nextRaw.ring_comments[0].id, "rc_old");
  assert.equal(nextRaw.ring_comments[1].id, "rc_new");
  // 不修改原数组
  assert.equal(raw.ring_comments.length, 1);
});

test("list 空 comments 返回 []", () => {
  assert.deepEqual(sortCommentsAsc(undefined), []);
  assert.deepEqual(sortCommentsAsc(null), []);
  assert.deepEqual(sortCommentsAsc([]), []);
  assert.deepEqual(sortCommentsAsc("not-an-array"), []);
});

test("list 按 created_at 升序", () => {
  const raw = [
    { id: "c", created_at: "2026-03-01T00:00:00.000Z", content: "3" },
    { id: "a", created_at: "2026-01-01T00:00:00.000Z", content: "1" },
    { id: "b", created_at: "2026-02-01T00:00:00.000Z", content: "2" },
  ];
  assert.deepEqual(sortCommentsAsc(raw).map((c) => c.id), ["a", "b", "c"]);
});

test("delete 不存在的 comment 返回 deleted=false", () => {
  const list = [{ id: "rc_1", created_at: "t", content: "x" }];
  const { comments, deleted } = removeComment(list, "rc_does_not_exist");
  assert.equal(deleted, false);
  assert.equal(comments.length, 1);
});

test("delete 存在的 comment 返回 deleted=true 并移除", () => {
  const list = [
    { id: "rc_1", created_at: "t", content: "x" },
    { id: "rc_2", created_at: "t", content: "y" },
  ];
  const { comments, deleted } = removeComment(list, "rc_1");
  assert.equal(deleted, true);
  assert.deepEqual(comments.map((c) => c.id), ["rc_2"]);
});

test("add → list → delete 全流程", () => {
  let comments = [];
  const c1 = makeComment({ content: "第一条", now: "2026-01-01T00:00:00.000Z", id: "rc_1" });
  const c2 = makeComment({ content: "第二条", now: "2026-02-01T00:00:00.000Z", id: "rc_2" });
  comments = appendComment(comments, c1);
  comments = appendComment(comments, c2);
  assert.equal(comments.length, 2);

  const listed = sortCommentsAsc(comments);
  assert.deepEqual(listed.map((c) => c.id), ["rc_1", "rc_2"]);

  const del = removeComment(comments, "rc_1");
  assert.equal(del.deleted, true);
  assert.equal(del.comments.length, 1);
  assert.equal(del.comments[0].id, "rc_2");
});

test("normalizeComments 过滤非对象项", () => {
  assert.deepEqual(normalizeComments([{ id: "a" }, null, "x", 3, { id: "b" }]), [{ id: "a" }, { id: "b" }]);
});
