# ADR-0008：search 命中携带 session_id 与正文摘要（Robot/MCP 契约 minor 变化）

> 治理记录（Governance Record）
>
> - decision_id: ADR-0008
> - title: search 命中携带 session_id 与正文摘要
> - status: **Proposed（2026-08-13 下轮规划，owner 裁定）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0
> - evidence_path: ux-mcp 实测（search 命中只有 {id,score}，AI 无法判断相关性、无法从 msg id 导航到会话，平均多花 3-4 倍 token）；review-features Top 3

## 决策

search 命中（CLI robot/json/jsonl 与 MCP `search_sessions`）新增 `session_id`（所属会话 wire id）与 `text` 摘要（受预算约束，复用 snippet 预算语义）字段。追加字段、不删字段、major 不变（schema minor 变化）。

## 背景

MCP AI 检索闭环断在半路：命中只有 `{id, score}`，AI 无法判断命中相关性，也无法从 `msg_v1_` 导航到所属会话（`get_session_context` 只收 `ses_v1_`），被迫翻 `list_sessions` 多页。实测最短路 3.2K tokens vs 现实路径 12-13K tokens。

## 后果

- robot 契约 minor 变化：新增字段，旧消费者不受影响；
- 摘要计入 `max_response_bytes` 预算（沿用现有 snippet 字节闸）；
- MCP 的 `content.text` 与 `structuredContent` 双载体开销另案处理（本轮记录，不在本 ADR 范围）。
