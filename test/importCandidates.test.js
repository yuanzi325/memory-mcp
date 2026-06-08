import test from "node:test";
import assert from "node:assert/strict";
import { extractCandidates, chunkText } from "../importCandidates.js";

test("普通寒暄抽不出候选", () => {
  const r = extractCandidates({ text: "早安宝宝\n哈哈\n抱抱我\n嗯嗯好的\n么么哒\n在吗" });
  assert.equal(r.candidate_count, 0);
  assert.deepEqual(r.candidates, []);
});

test("明确偏好能抽出 preference", () => {
  const r = extractCandidates({ text: "我特别讨厌别人催我，最受不了被打断。", source: "wechat" });
  assert.equal(r.candidate_count, 1);
  const c = r.candidates[0];
  assert.equal(c.kind, "preference");
  assert.equal(c.source, "wechat");
  assert.ok(c.importance >= 6, "雷区/受不了应给较高重要度");
  assert.ok(c.confidence > 0 && c.confidence <= 0.9);
  assert.ok(c.reason.length > 0);
  assert.ok(c.id.startsWith("cand_"));
});

test("项目上下文能抽出 project，suggested_layer=memo", () => {
  const r = extractCandidates({ text: "记忆库 MCP 项目最近一直断联，bridge.mjs 要重写。" });
  assert.equal(r.candidate_count, 1);
  const c = r.candidates[0];
  assert.equal(c.kind, "project");
  assert.equal(c.suggested_layer, "memo");
  // 关键词应包含技术 token
  assert.ok(c.keywords.some((k) => /MCP|bridge/i.test(k)), `keywords=${JSON.stringify(c.keywords)}`);
});

test("「重新理解旧记忆」标 kind=comment 并给出 target_memory_hint", () => {
  const r = extractCandidates({ text: "我现在重新理解了之前那段，其实当时我不是生气，是害怕。" });
  assert.equal(r.candidate_count, 1);
  const c = r.candidates[0];
  assert.equal(c.kind, "comment");
  assert.equal(c.suggested_layer, ""); // comment 挂在已有记忆上，不指定 layer
  assert.ok(c.target_memory_hint.length > 0, "comment 应给出指向旧记忆的线索");
});

test("max_candidates 生效", () => {
  const many = Array.from({ length: 10 }, (_, i) => `我特别喜欢第${i}种口味的茶`).join("\n");
  const r = extractCandidates({ text: many, max_candidates: 3 });
  assert.equal(r.candidate_count, 3);
  assert.equal(r.candidates.length, 3);
});

test("混合文本：寒暄被过滤，只留有价值候选", () => {
  const r = extractCandidates({ text: "早安\n我喜欢安静的早晨\n那个 dashboard 的 usage 还要改\n哈哈嗯嗯" });
  const kinds = r.candidates.map((c) => c.kind).sort();
  assert.deepEqual(kinds, ["preference", "project"]);
});

test("不写库 / 无副作用：纯函数同输入同输出（id 除外）", () => {
  const text = "我特别讨厌别人催我。\n记忆库 MCP 又断联了。";
  const a = extractCandidates({ text });
  const b = extractCandidates({ text });
  assert.equal(a.candidate_count, b.candidate_count);
  assert.deepEqual(
    a.candidates.map((c) => ({ kind: c.kind, content: c.content, layer: c.suggested_layer })),
    b.candidates.map((c) => ({ kind: c.kind, content: c.content, layer: c.suggested_layer }))
  );
});

test("raw_excerpt 简短，不整段倒出长文本", () => {
  const longLine = "我特别讨厌被催，" + "啰嗦".repeat(300);
  const r = extractCandidates({ text: longLine });
  assert.equal(r.candidate_count, 1);
  assert.ok(r.candidates[0].raw_excerpt.length <= 161, `excerpt len=${r.candidates[0].raw_excerpt.length}`);
});

test("空文本 / 纯空白返回 0 候选与 0 分块", () => {
  for (const t of ["", "   ", "\n\n  \n"]) {
    const r = extractCandidates({ text: t });
    assert.equal(r.candidate_count, 0);
    assert.equal(r.chunk_count, 0);
  }
});

test("chunkText 按 chunk_chars 切块且不丢内容", () => {
  const text = Array.from({ length: 20 }, (_, i) => `line-${i}`).join("\n");
  const chunks = chunkText(text, 500);
  assert.ok(chunks.length >= 1);
  // 行内容应被完整保留
  assert.ok(chunks.join("\n").includes("line-0"));
  assert.ok(chunks.join("\n").includes("line-19"));
});

test("默认 profile=shared，回显 source", () => {
  const r = extractCandidates({ text: "我喜欢喝茶", source: "telegram" });
  assert.equal(r.profile, "shared");
  assert.equal(r.source, "telegram");
});
