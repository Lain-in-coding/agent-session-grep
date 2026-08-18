# Competitor Comparison Table

> Open-source gate artifact:
> 与当前已核验外部参考项目的公开对比表。只列可复现事实(provider 数、
> 能力、license、形态);不能合法/稳定运行的竞品标「不可比」。
> 证据来源: 本地深读报告(报告本身不纳入公开树)与固定 clone(commit 见
> `docs/operations/REUSE-LICENSE-AUDIT.md`)。
> cass(coding_agent_session_search)因 LICENSE 含 restricted-party rider
> 仅 clean-room 思路可引用,不进入可复现对比基线。
> 更新:2026-08-18

## 事实基线

| 项目 | 形态 | License | Provider 覆盖 | 检索方式 | 其他可复现事实 |
|---|---|---|---|---|---|
| **agent-session-grep (本产品)** | Rust CLI + MCP + Robot + TUI + Web UI | MIT OR Apache-2.0 | 14 实现 + 2 deferred(16 行矩阵,诚实分级) | FTS5 lexical 默认 + optional semantic-candle (local E5) behind feature flag; default bigram-hash fuzzy-lexical; hybrid RRF 指标仅供参考 | evidence-first(source span)、handoff-pack/v1、resume dry-run、零遥测可验证、跨边界默认脱敏 |
| ctx | Rust CLI | MIT | 40+ | hybrid RRF | 语义+词法融合,分阶段发布 |
| coding_agent_session_search (cass) | Python CLI | **restricted-party rider** | 40+(claimed) | hybrid | 仅 clean-room 思路可引用;不可复现对比 |
| agentsview | TS CLI | MIT | 40+ | hybrid | secret 扫描但非分层边界 |
| AgentRecall | Python CLI | MIT | 16 | hybrid | — |
| hstry | TS adapter 生态 | MIT | 16 | FTS + adapter 架构 | UUID v5 身份最接近,但无 durable outbox |
| fast-resume | Rust CLI | MIT | 12 | FTS + 模糊 | — |
| Recall | Rust CLI | MIT | 11 | hybrid | — |
| agent-sessions | Go CLI | MIT | 10 | FTS5 | — |
| agf | Go CLI | MIT | 8 | fuzzy | — |
| cc-switch | 桌面 App | MIT | 7 | 无检索(配置切换器) | 非检索工具,「不可比」 |
| sessiongrep | Rust CLI | MIT | 5 | FTS5 | — |
| memex | Rust CLI | MIT | 4 | hybrid | — |
| claude-historian-mcp | Python MCP | MIT | 1 | 零存储全扫 | 仅 Claude Code |

## 已核验差异(agent-session-grep vs 参考项目)

| 维度 | agent-session-grep | 参考项目快照 | 已核验差异 |
|---|---|---|---|
| 检索 | FTS5 lexical 默认 + optional semantic-candle (local E5) behind feature flag; 默认 bigram-hash fuzzy-lexical; hybrid 使用 RRF | ctx 使用 hybrid RRF | 默认构建没有真实 semantic model(bigram-hash fuzzy-lexical);可选 semantic-candle feature 提供本地 Candle E5 后端(默认 off、离线导入);semantic/hybrid gate metrics 仅供参考、benchmark 门未闭,不据此宣称质量或中文优势 |
| 证据 | 每条命中带 source span,并定义 handoff pack 原文/推断分栏 | hstry 有 evidence 能力 | 契约形态不同;未做跨项目证据质量 benchmark |
| 身份 | StableId 三级 + durable outbox + CAS generation + 失败不删除 | hstry 使用 UUID v5;固定快照中未见 durable outbox | 两者身份与恢复机制不同;本表不作可靠性优劣结论 |
| 成熟度 | certified/GA/beta/experimental/unsupported 证据晋级 | 各项目使用各自 provider 支持口径 | 术语与证据门槛不可直接等同 |
| 隐私 | 零遥测代码约束 + CI 静态检查 + 跨边界默认脱敏 | agentsview 有 secret 扫描 | 边界模型不同;仅比较当前已实现的控制 |
| 入口 | CLI/MCP/Robot/TUI/Web 共用 Application ADT | 各参考项目入口形态不同 | 五入口终局一致性 harness 已全直接对比通过（`overall_verdict=consistent`，无 skipped/aliases/unimplemented）；未做跨项目入口质量 benchmark |

## 不可比清单

- **cc-switch**: 配置切换器,无检索能力。
- **cass**: 受限 license,不可复现对比。
- 其余 12 项:license 可自由引用,但 provider 数、能力为 deep-read 快照
  (2026-08-14),与最新上游可能有差异;发布 benchmark 时以固定 clone commit
  为准复现。

## 口径说明

- 「12 个外部项目」= 可自由引用集合(12 项);总名单 13 项(含 clean-room-only
  cass)。未补齐新的独立外部基线前,不使用更大的宣传口径。
- 本表与 PROVIDER-MATURITY-MATRIX.md、README 数字一致(16 行矩阵、
  14 实现 + 2 deferred)。
