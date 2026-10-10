# Competitor Comparison Table

> Open-source gate artifact:
> 与当前已核验外部参考项目的公开对比表。只列可复现事实(provider 数、
> 能力、license、形态);不能合法/稳定运行的竞品标「不可比」。
> 证据来源: 本地深读报告(15 份外部项目报告,不纳入公开树)与固定 clone
> (commit 见 `docs/operations/REUSE-LICENSE-AUDIT.md`)。
> 其中两项因 license 状态只能 clean-room 引用思路、不进入可复现对比基线:
> cass(coding_agent_session_search)的 LICENSE 含 restricted-party rider;
> cc-sessions-viewer 的 README 挂 MIT badge 但仓库内没有 LICENSE 文件
> (GitHub 仓库元数据 `licenseInfo: null`),在作者补上之前不存在可依赖的
> 授权。因此可自由引用的对比基线是 13 项,名单共 15 项。
> 更新:2026-08-29(新增 cc-sessions-viewer;并纠正上一版"cass 不产 deep-read
> 报告"的说法——报告存在于本地不公开的深读集内,受限的是代码复用而不是阅读)
> 更新:2026-10-06 B0(按源码级收据修正 9 处形态/检索表述;补 Wake 行,Rust+GPUI、
> FTS5 trigram、CLI/MCP;名单 14→15、可自由引用 12→13;cc-switch「无检索」改为
> FlexSearch 元数据检索,「不可比」限定为证据级检索不可比;表内数字仍为快照口径,未重数)

## 事实基线

> 快照口径:快照日期 2026-08-14（deep-read）。下表 Provider 覆盖等数字均按此口径
> 记录,本轮未重数(Wake 行除外:其 21 取自 2026-10-06 Wake 审计),与最新上游
> 可能有差异;发布 benchmark 时以固定 clone commit 复现为准。

| 项目 | 形态 | License | Provider 覆盖 | 检索方式 | 其他可复现事实 |
|---|---|---|---|---|---|
| **agent-session-grep (本产品)** | Rust CLI + MCP + Robot + TUI + Web UI | MIT OR Apache-2.0 | 14 实现 + 2 deferred(16 行矩阵,诚实分级) | FTS5 lexical 默认 + optional semantic-candle (local E5) behind feature flag; default bigram-hash fuzzy-lexical; hybrid RRF 指标仅供参考 | evidence-first(source span,14 家中 10 家格式可得)、handoff-pack/v1、resume dry-run、零遥测可验证、跨边界默认脱敏 |
| ctx | Rust CLI | MIT | 40+ | hybrid RRF | 语义+词法融合,分阶段发布 |
| coding_agent_session_search (cass) | Rust CLI/TUI (Tantivy 生态) | **restricted-party rider** | 40+(claimed) | hybrid | 仅 clean-room 思路可引用;不可复现对比 |
| agentsview | Go 后端 + Svelte 前端 | MIT | 40+ | hybrid | secret 扫描但非分层边界 |
| AgentRecall | TypeScript/Electron/React 桌面 | MIT | 16 | hybrid | node:sqlite + Node MCP |
| hstry | Rust core (hstry-core/cli/tui) + TS adapters | MIT | 16 | FTS + adapter 架构 | UUID v5 身份最接近,但无 durable outbox |
| fast-resume | Rust CLI | MIT | 12 | FTS + 模糊 | — |
| Recall | Rust CLI | MIT | 11 | hybrid | — |
| agent-sessions | Swift/SwiftUI macOS 桌面 | MIT | 10 | FTS5 | — |
| agf | Rust CLI + TUI | MIT | 8 | fuzzy | — |
| cc-switch | Tauri + React + Rust 桌面 App | MIT | 7 | FlexSearch 元数据检索(sessionId/title/summary/projectDir/sourcePath;不含正文/不持久化/无 source span) | 7 家会话管理与 resume 命令生成;「不可比」限定为证据级检索不可比 |
| cc-sessions-viewer | Tauri 2 桌面 App | **README 挂 MIT badge,仓库无 LICENSE 文件** | 7 | 无索引:rayon 并行全量扫描 + 进程内 (path→mtime) 缓存 | 仅匹配用户消息(工具调用/结果/文件改动不参与匹配);原始 JSONL 只读;不可复现对比 |
| sessiongrep | Rust CLI | MIT | 5 | FTS5 | — |
| memex | 两套形态:memex-lite(无索引现场 regex grep 本地 CLI)与 memex-rs(FTS + LanceDB 向量 + RRF + compact + Hook 注入;HTTP/MCP/remote 服务) | MIT | 4 | hybrid(仅 memex-rs;lite 为现场 regex) | 另有 web(Vue) 前端 |
| claude-historian-mcp | TypeScript/Node MCP | MIT | 1 | 零存储全扫 | 仅 Claude Code |
| Wake | Rust + GPUI 桌面 | MIT | 21 | FTS5 trigram | CLI + MCP;source/sidecar/remote;固定 clone commit 71aeca6(0.8.5) |

> 2026-10-06 B0 修正说明:形态/检索列按源码级收据更正 9 处(cass→Rust CLI/TUI、
> agentsview→Go 后端+Svelte、AgentRecall→TypeScript/Electron/React、hstry→Rust core+TS adapters、
> agent-sessions→Swift/SwiftUI、agf→Rust CLI+TUI、claude-historian-mcp→TypeScript/Node MCP、
> cc-switch→FlexSearch 元数据检索、memex→两套形态拆分),并补 Wake 行;证据锚点见
> `../operations/REUSE-LICENSE-AUDIT.md` 中的固定 revision 与公开项目身份。
> provider 数等数字未重数,原快照日期(2026-08-14)与 license 结论不变。

## 已核验差异(agent-session-grep vs 参考项目)

| 维度 | agent-session-grep | 参考项目快照 | 已核验差异 |
|---|---|---|---|
| 检索 | FTS5 lexical 默认 + optional semantic-candle (local E5) behind feature flag; 默认 bigram-hash fuzzy-lexical; hybrid 使用 RRF | ctx 使用 hybrid RRF | 默认构建没有真实 semantic model(bigram-hash fuzzy-lexical);可选 semantic-candle feature 提供本地 Candle E5 后端(默认 off、离线导入);semantic/hybrid gate metrics 仅供参考、benchmark 门未闭,不据此宣称质量或中文优势 |
| 证据 | 格式带得出字节区间的 provider 其命中带 source span(capability.rs 的 `source_span`:9 家 native、aider derived、opencode/cursor/hermes/cline 如实 unsupported),并定义 handoff pack 原文/推断分栏 | hstry 有 evidence 能力 | 契约形态不同;未做跨项目证据质量 benchmark |
| 身份 | StableId 三级 + durable outbox + CAS generation + 失败不删除 | hstry 使用 UUID v5;固定快照中未见 durable outbox | 两者身份与恢复机制不同;本表不作可靠性优劣结论 |
| 成熟度 | certified/GA/beta/experimental/unsupported 证据晋级 | 各项目使用各自 provider 支持口径 | 术语与证据门槛不可直接等同 |
| 隐私 | 零遥测代码约束 + CI 静态检查 + 跨边界默认脱敏 | agentsview 有 secret 扫描 | 边界模型不同;仅比较当前已实现的控制 |
| 入口 | CLI/MCP/Robot/TUI/Web 共用 Application ADT | 各参考项目入口形态不同 | 五入口终局一致性 harness 已全直接对比通过（`overall_verdict=consistent`，无 skipped/aliases/unimplemented）；未做跨项目入口质量 benchmark |

## 不可比清单

- **cc-switch**: 元数据检索(FlexSearch 内存索引:sessionId/title/summary/projectDir/
  sourcePath;不含正文、不持久化、无 source span)+ 7 家会话管理与 resume 命令生成;
  「不可比」限定为证据级检索不可比(metadata 检索不等价全文证据检索)。
  - 修正说明(2026-10-06):原写「配置切换器,无检索能力」,与源码复核不符,已按上述范围限定。
- **cass**: 受限 license,不可复现对比。
- **cc-sessions-viewer**: 仓库无 LICENSE 文件(README 的 MIT badge 无文件支撑,
  GitHub `licenseInfo: null`),因此只能 clean-room 引用思路;其检索为「无索引
  全量并行扫描 + 只匹配用户消息」,与本产品的持久 FTS5 全内容索引不是同一
  问题域,亦不作优劣结论。
- 其余 13 项:license 可自由引用,但 provider 数、能力为 deep-read 快照
  (快照日期 2026-08-14),与最新上游可能有差异;发布 benchmark 时以固定 clone commit
  为准复现。

## 口径说明

- 历史(2026-08-29 口径,保留):「12 个外部项目」= 可自由引用集合(12 项);总名单
  14 项(含 clean-room-only 的 cass 与 cc-sessions-viewer)。新增 cc-sessions-viewer
  同时让名单 +1 与 clean-room-only 集 +1,所以可自由引用数仍是 12——这个数字
  未过期,不是漏更。
- 2026-10-06 B0 更新:「13 个外部项目」= 可自由引用集合(13 项);总名单 15 项。
  补记 MIT 的 Wake 后,可自由引用数 12→13、名单 14→15。规则不变:未补齐新的
  独立外部基线前,不使用更大的宣传口径。
- 本表与 PROVIDER-MATURITY-MATRIX.md、README 数字一致(16 行矩阵、
  14 实现 + 2 deferred)。
