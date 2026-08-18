# ADR-0003：搜索查询语义为 plain-text-only（FTS 操作符一律按字面文本）

> 治理记录（Governance Record）
>
> - decision_id: ADR-0003
> - title: 搜索查询语义 plain-text-only
> - status: **Proposed（2026-08-13 UX review fix round）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0
> - evidence_path: `docs/contracts/CONTRACT-cli-robot-mcp-draft.md`；`crates/agent-session-grep-adapters-sqlite/src/lib.rs` `safe_fts_query`；8 路 review 交叉复现

## 决策

search 查询只支持 plain-text 关键词：按空白切分的字面 token、隐式 AND。FTS5 的 `AND`/`OR`/`NOT`、`NEAR(...)`、短语引号、前缀 `*` 等**不是查询语言**，一律作为字面文本参与匹配。`safe_fts_query` 是这一语义的强制边界。

## 背景

2026-08-13 新手自测修复轮发现：标点、路径、flag 名查询会触发原始 FTS5 语法错误（如 `search mcp.json` 报 `fts5: syntax error near "."`）。修复对每个 token 加引号字面化后，高级语法被一并禁用。8 路 review 交叉确认：CLI/MCP/Port 契约从未承诺高级语法；字面化消除整类错误，代价是丢失短语/前缀/布尔能力。

## 决策依据

- 新手场景下高级语法是噪声源，不是功能；
- 恢复高级语法会把已修掉的语法错误痛点带回来；
- 引入"高级模式开关"增加表面积，且当前无产品需求信号。

## 后果

- `alpha OR beta` 现在检索字面 token `OR`；CONTRACT、SKILL、教程必须写明此语义；
- 表驱动测试钉死字面语义（AND/OR/NEAR/引号/`*`/NUL/路径/撇号/CJK/全标点）；
- 若未来需要高级查询，必须设计独立、版本化的查询语言模式，绝不裸暴露 FTS5 语法。
