# recall_context v2 技术探查报告

> 探查日期：2026-06-02  
> 分支：`claude/recall-context-v2-exploration-2HVYd`  
> 范围：只读，不改代码、不改数据库、不部署

---

## 1. 后端源码位置

```
/memory-mcp/server.js   ← 唯一后端文件，4577 行，全量业务逻辑
```

没有 migrations、schema SQL 或其他业务文件。数据库 schema 在 Supabase 云端管理，不在 git 里。

---

## 2. 当前 Memory Tools（共 14 个）

| Tool | 层级 | 说明 |
|---|---|---|
| `memory_ping` | Tier 6 | 健康检查 |
| `memory_write` | Tier 1 | 写入 / 合并单条记忆 |
| `memory_read` | Tier 1 | 按 id 或 layer 读取 |
| `memory_query` | Tier 1 | 全文 + 关键词搜索 |
| `memory_surface` | Tier 2 | OB 衰减评分排名（默认 touch=true） |
| `search_memories_surface` | Tier 2 | 只读评分搜索（默认 touch=false） |
| `memory_hold` | Tier 3 | 模糊匹配写入 / 合并（智能去重） |
| `memory_trace` | Tier 3 | 标记 resolved / digested / pinned / archived |
| `memory_digest` | Tier 3 | 多条合并成长期摘要 |
| `memory_briefing` | Tier 4 | 会话启动快照，无参数 |
| `recall_context` | Tier 4 | 跨窗口三层召回，核心工具 |
| `vault_briefing` | Tier 4 | 旧版 vault_state 摘要 |
| `memory_bucket_surface` | Tier 5 | Bucket 衰减排名 |
| `memory_bucket_read` | Tier 5 | 读取 bucket 内所有记忆 |
| `memory_bucket_trace` | Tier 5 | Batch 更新 bucket 元数据 |
| `memory_debug_read` | Tier 6 | 诊断 dump 单条记忆 |

---

## 3. 当前召回输入

### `memory_briefing`

无任何参数。硬编码拉取 memo + diary + daily 三层。

### `recall_context`

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `q` | string | **required** | 查询词，不能用"沅沅"之类泛词 |
| `profile` | string | "shared" | shared / rowan / arion / all |
| `layer` | string | — | 可选层过滤 |
| `sub_layer` | string | — | 可选子层过滤 |
| `budget_chars` | int | 4000 | 输出硬字符上限（500–20000） |
| `max_items` | int | 20 | 软条目上限 |
| `include_resolved` | bool | false | — |
| `include_digested` | bool | false | — |
| `include_archived` | bool | false | — |
| `touch` | bool | **false** | 是否更新 activation_count |
| `include_buckets` | bool | true | 是否附带 Tier 2 bucket 上下文 |

---

## 4. 当前召回输出

### `memory_briefing` 输出

```
sections: [{label, items}]
briefing_text: markdown 格式字符串
  - 2 条未解决 memo
  - 3 条 diary（优先取 today_snapshot > title > content 前缀）
  - 3 条 daily 衰减最高（未解决）
  - 2 条高唤醒（arousal > 0.6）daily
```

### `recall_context` 输出

```
context_text:        完整 markdown，三层分段
selected_memories:   [{id, title, content, score, reason, activation_count, last_active}]
selected_buckets:    [{bucket_id, name, memory_count, ...}]
touched_ids:         []（touch=true 时才有值）
touched_count:       int
omitted_count:       int
omitted_reason:      string
```

三层结构：

- **Tier 1（精确搜索）**：`q` 文本 + keyword 匹配，按 `scoreSearchResult()` 排名
- **Tier 2（Bucket 上下文）**：Tier 1 命中项的所属 bucket 摘要
- **Tier 3（Core/Treasure）**：只有 Tier 1 有命中时追加；按 pinned > protected > importance > last_active 排序

---

## 5. activation_count / last_active 更新情况

| Tool | 更新 |
|---|---|
| `memory_briefing` | 否 |
| `recall_context` | 仅当 `touch=true`（默认 false） |
| `memory_surface` | 是（默认 `touch=true`，每次都更新） |
| `search_memories_surface` | 仅当 `touch=true`（默认 false） |
| `memory_hold`（merge 模式） | 是（JS 手动 +1，设 `last_active=now`） |
| 其余所有工具 | 否 |

更新路径：`touchMemoryRow(id)` → Supabase RPC `touch_memory_row(p_id)` → 写入 `raw.activation_count` 和 `raw.last_active`。使用 `Promise.allSettled()`，fire-and-forget，不阻塞主流程。

---

## 6. 冷却机制

**无任何冷却机制。** 没有节流、防抖、时间窗口限制、每日调用上限，也没有对同一条记忆重复 touch 的去重保护。

---

## 7. v2 需要改的文件

**只需改一个文件**：`server.js`

| 改动区域 | 目的 |
|---|---|
| `buildRecallContext()` | 三层召回逻辑主体 |
| `scoreSearchResult()` | Tier 1 评分公式 |
| `recall_context` tool Zod schema | 新增 / 修改入参 |
| `recall_context` tool handler | 输出字段变更 |
| `touchMemoryRow()` 调用位置 | 改 touch 策略（如冷却） |

冷却逻辑可直接读 denormalized 的 `last_active` 字段，**不需要改数据库 schema**（`raw` 是自由 JSONB）。

---

## 8. recall_context v2 最小实现方案

目标：召回质量更高、减少噪声 touch、输出更易区分层级。

### 变更 1：Tier 1 评分加时效 boost

当前 `scoreSearchResult()` 时效权重极低（`capped decay × 0.05`）。

```js
// scoreSearchResult() 里加一行
const recencyBoost = Math.max(0, 1 - daysSince / 30) * importance * 0.5;
score += recencyBoost;
```

### 变更 2：touch 冷却保护（同一条记忆 1 小时内不重复计数）

```js
// touch 循环里加判断
const lastActive = new Date(mem.last_active || 0);
const hoursSince = (Date.now() - lastActive) / 3600000;
if (hoursSince > 1) await touchMemoryRow(mem.id);
```

### 变更 3：输出字段加 `recall_tier`

让模型能区分"搜索命中（T1）"和"背景常驻（T3）"。

```js
// build context 时给每条记忆打标
{ ...mem, recall_tier: "T1" }   // or "T3"
```

---

三处改动全部在 `server.js` 内部，不碰数据库、不碰其他工具、不影响 Telegram / OpenClaw。
