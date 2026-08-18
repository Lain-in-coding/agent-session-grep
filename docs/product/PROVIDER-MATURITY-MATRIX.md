# Provider Maturity 与 Capability Matrix

> 对外可见的 Provider 状态清单，是 `0.1.0`（首个计划公开版本，`Cargo.toml`）的公开状态记录。
> - 术语与晋级证据要求见 `../architecture/RFC-0002-provider-adapter-contract.md` §6。
> - 本文件是**当前实现状态**的事实记录，不是承诺；晋级必须有证据，不由代码存在自动推断。
> - 最后更新：2026-08-18（16-provider 证据链 + semantic-candle/handoff/context/TUI 投影）
> - 权威数据源：`crates/agent-session-grep-ports/src/capability.rs` 的
>   `ProviderCapabilityMatrix::current()`；本表与其保持一致，不一致以 capability.rs 为准。
> - Beta 本地/外部缺口分账见 `PROVIDER-BETA-READINESS.md`（不得仅凭代码存在晋级）。

## 术语

**整体成熟度**（Provider 级，独立于字段能力）：

| maturity | 含义 |
|---|---|
| `Experimental` | 可发现、可 probe、可解析小 fixture，限制明确 |
| `Beta` | 主路径 fixture、golden、contract、只读、增量、source span 均通过 |
| `Certified/GA` | 历史 variant、混合版本、未知字段、崩溃恢复、正式 target、性能与回滚证据齐备 |
| `Unsupported` | 明确不支持，附原因（含 deferred：无 transcript 证据，不实现不宣传） |

**字段能力**（capability，逐字段）：`native`（provider 原生提供）、`derived`（由内在内容确定性派生）、`partial`（部分场景可得）、`unsupported`（该 provider 无此概念）、`unknown`（尚未评估）。

## 成熟度总览（16 行，2026-08-16 事实）

| Provider | provider_id | variant | maturity | 证据 |
|---|---|---|---|---|
| Claude Code | `claude-code` | `claude-code/jsonl-v1` | **Experimental** | 单元 + e2e + golden（`crates/agent-session-grep-provider-claude/tests/golden.rs`）+ 确定性 property 套件（`tests/properties.rs`，固定种子）+ span round-trip |
| Codex | `codex` | `codex/rollout-jsonl-v1` | **Experimental** | 单元 + e2e + golden（`crates/agent-session-grep-provider-codex/tests/golden.rs`）+ 确定性 property 套件（含镜像去重性质）+ span round-trip |
| Grok Build | `grok-build` | `grok-build/acp-updates-v1` | **Experimental** | ACP `updates.jsonl`（`session/update` stream），主格式证据充分，variant 分层 + golden（`tests/golden.rs`） |
| Antigravity | `antigravity` | `antigravity/transcript-jsonl-v1` | **Experimental** | 本机真实格式核验（2026-08-15）：`brain/<uuid>/.system_generated/logs/transcript.jsonl`；identity 在目录名，文件内无 session id 字段 + golden（`tests/golden.rs`） |
| OpenCode | `opencode` | `opencode/sqlite-v1` | **Experimental** | `opencode.db` SQLite（session/message/part 表），只读打开（SQLITE_OPEN_READONLY + busy_timeout）+ golden（`tests/golden.rs`） |
| Pi | `pi` | `pi/session-jsonl-v1` | **Experimental** | session JSONL（`type:session` header + message）+ golden（`tests/golden.rs`） |
| Hermes | `hermes` | `hermes/session-json-v1` | **Experimental** | `~/.hermes/sessions/session_<id>.json`（session_id/messages），hstry@88b78b1 (MIT) 格式证据 + golden（`tests/golden.rs`） |
| Cursor | `cursor` | `cursor/vscdb-chat-v1` | **Experimental** | `state.vscdb` SQLite KV（ItemTable `chatdata`/`prompts` key），hstry@88b78b1 (MIT) 格式证据，多代格式分层待补 + golden（`tests/golden.rs`） |
| Kimi Code | `kimi-code` | `kimi-code/wire-jsonl-v1` | **Experimental** | wire.jsonl（`context.append_message`）+ golden（`tests/golden.rs`） |
| OpenClaw | `openclaw` | `openclaw/session-jsonl-v3` | **Experimental** | v3 JSONL header + message records，本机仅 config 无 transcript 样本 + golden（`tests/golden.rs`） |
| Qoder | `qoder` | `qoder/transcript-jsonl-v1` | **Experimental** | JSONL（`session_meta` + `type:user/assistant`），官方路径已实现 + golden（`tests/golden.rs`） |
| Tencent CodeBuddy | `tencent-codebuddy` | `tencent-codebuddy/cli-jsonl-v1` | **Experimental** | CLI OpenAI-style JSONL（`role`/`content`/`sessionId`），extension variant 待分层 + golden（`tests/golden.rs`） |
| Cline | `cline` | `cline/api-conversation-history-v1` | **Experimental** | `api_conversation_history.json` JSON family + golden（`tests/golden.rs`） |
| Aider | `aider` | `aider/chat-history-md-v1` | **Experimental** | Markdown chat history（`#### ` user prompts），`.aider.chat.history.md` 为候选 root 待核验 + golden（`tests/golden.rs`） |
| DeepSeek Harness | `deepseek-harness` | — | **Unsupported（deferred）** | 无任何 transcript 证据（本机无 `~/.deepseek`，参考项目无 adapter）；证据出现前不实现、不宣传 |
| ZCode | `zcode` | — | **Unsupported（deferred）** | 无任何 transcript 证据（本机无 `~/.zcode`，参考项目无 adapter）；证据出现前不实现、不宣传 |

14 个已实现 provider 均为 **Experimental**：golden、property、source span 以及
关系化 Message/Placement/Edge 的合成与 e2e 证据已入库（见下），授权真实数据全量
绿色回归亦已闭合（见「晋级到 Beta 的缺口」第 4 条）。剩余 blocker 为跨 target CI
认证与 provider 级回滚策略的 owner 批准——逐条见下方缺口清单。两个 deferred
provider（DeepSeek Harness、ZCode）保留 16 行但不宣传为已实现、不设 maturity
target。

## Capability Matrix（逐字段，2026-08-16）

字段对应 Canonical `Message`（`crates/agent-session-grep-domain/src/lib.rs`）与解析产出。

### 已实现 14 个 provider 的共同字段

| 字段 | 已实现 provider | 说明 |
|---|---|---|
| probe | `native` | 全部 14 个 adapter 均有 probe，歧义一律 `AmbiguousVariant` 拒绝（不低置信度猜测） |
| parse | `native` | 全部 14 个 adapter 均 streaming 到 `CanonicalEventSink` |
| search | `native` | 统一经 canonical 索引检索 |
| discover | `native`（claude-code/codex）；`unsupported`（其余） | 仅 claude-code/codex 注册了 discovery root；antigravity/opencode 已加入 `provider_data_root` |
| resume | `derived`（claude-code/codex/pi/grok）；`unknown`（opencode/kimi/qoder/codebuddy/hermes/antigravity/cursor）；`unsupported`（aider/cline/openclaw） | 未核验的 resume 命令一律不设默认值 |
| context / handoff / incremental | `unsupported` 或 `unknown` | 属后续全能力链工作，尚未逐 provider 评估 |
| tool_activity | `partial`（claude-code/codex/aider，schema v12 `tool_activities` 落库）；`unknown`（deepseek-harness/zcode，deferred）；`unsupported`（其余 11 个已实现 provider） | CLI `--tool-kind`/`--tool-name`/`--main-only`/`--subagent-only`/`--include-sidechain`、MCP 同名参数与 TUI 分面键（`m` sidechain / `k` tool-kind）已落地；handoff pack 投影 `tool_activity` + 权威 `role`/`is_sidechain`，context 响应投影 `tool_activities` |
| source_span | `native`（claude/codex/grok/pi/kimi/openclaw/qoder/codebuddy）；`derived`（aider）；`unsupported`（opencode/hermes/antigravity/cursor/cline） | SQLite/目录名身份/单文档 JSON 类 provider 无文件内字节 span；cline 的数组下标 pseudo-span 已移除并如实降级为 unsupported |

### 逐 provider 明细见 capability.rs（单源权威）

```bash
# 渲染当前矩阵（Human）：
cargo run -q -p agent-session-grep-cli -- providers
# 渲染当前矩阵（Robot JSON envelope）：
cargo run -q -p agent-session-grep-cli -- --output json providers
```

入口层不得硬编码 provider maturity 或 capability；上述命令与 MCP
`list_providers` 均从 `ProviderCapabilityMatrix::current()` 投影。

## 已知限制

各条与 `AdapterManifest.known_limitations` 一一对应（14 个已实现 provider 的
manifest 均已填真实限制，见各 `crates/agent-session-grep-provider-*/src/lib.rs`）。

- **Claude Code**：只抽取 `user`/`assistant`/`system` 对话记录；工具调用块（无 text）被忽略；`cwd`/`gitBranch`/`version` provenance 尚未落库。
- **Codex**：只取权威 `response_item` + 内层 `message`，忽略 `event_msg` UI 镜像以避免重复计数；`world_state`/`turn_context`/工具调用记录未抽取；无 threading（线性）。
- **Grok Build**：chunk 分组重建角色，无逐消息 native id（合成 `grok-msg-{seq}`）；逐消息时间戳未抽取；会话身份回退到首个 ACP `promptId`，非持久 session id。
- **Antigravity**：文件内无 session id 字段（identity 在 `brain/<uuid>` 目录名），parse 时 `session_native_id`/`provider_session_id` 如实留缺；`SYSTEM`/`CONVERSATION_HISTORY` 与工具活动步骤永不为消息；`span` 用字节区间。
- **OpenCode**：SQLite 源无字节 span；只提交 `text` part 且角色为 user/assistant；逐消息时间戳未抽取。
- **Pi**：`session_info`/`compaction`/`custom_message` 等非对话类型跳过；无 native 消息 id（合成 `pi-msg-{seq}`）。
- **Hermes**：`session_<id>.json` 为主格式；同目录 `<id>.jsonl` 仅含部分近期状态，忽略；无字节 span，消息时间戳缺失时回退 `session_start`。
- **Cursor**：`state.vscdb` 为 chatdata/prompts 两 key 的多代格式，版本分层待补；SQLite 无字节 span；无 native 消息 id（合成 `cursor-msg-{seq}`）。
- **Kimi Code**：`context.append_loop_event`（step/tool 事件）暂未解析；wire.jsonl 罕见携带 session id，通常留缺；逐消息时间戳未抽取。
- **OpenClaw**：resume 有意不支持（gateway-managed）；无 native 消息 id（合成 `openclaw-msg-{seq}`）。
- **Qoder**：身份字段（session_id/cwd）从 `session_meta` lenient 匹配；`progress`/`tool_use`/`tool_result` 非对话记录跳过。
- **Tencent CodeBuddy**：根启动关键字用户消息（content 恰为 `"code"`）被过滤；无 cwd pair 观察（无独立 cwd 头记录）；无 native 消息 id（合成 `codebuddy-msg-{seq}`）。
- **Cline**：JSON 数组文件内无 session id，`session_native_id` 留缺；无字节 span（数组下标 pseudo-span 已移除）；无 native 消息 id（合成 `cline-msg-{seq}`）。
- **Aider**：span 为派生近似（块起始行 + 文本长度），非逐字节整行切片；blockquote 工具/编辑输出并入助手正文；会话身份为首个 run 头时间戳。
- **OpenCode / Cursor / Hermes / Kimi（SQLite 类与文档类）**：一律只读打开（`SQLITE_OPEN_READONLY` + `busy_timeout`），绝不写 provider 数据库；无文件内字节 span（round-trip 标 N/A）。
- **共同（关系模型已实现，语料级回归已闭合）**：稳定 `Message` 与上下文
  `MessagePlacement` / `MessageEdge` 已分离，session-scoped graph、精确 placement
  evidence、不同上下文 parent 以及相应合成/e2e 覆盖均已实现。全量授权运行
  （`2026-08-09T21:10:16Z`，1,242 源、1,177,479,794 字节）六条不变量全绿、harness
  exit 0：sync 164,136 emitted / 0 skipped、no-parse-loss 164,136 claims、
  231 sessions 全 context 成功、659/659 byte 精度、rebuild 稳定。最新两次全量
  运行同样全绿：`2026-08-12T23:51:23Z`（1,328 源、1,253,494,481 字节；180,218
  emitted / 0 skipped；242 sessions；630/630 byte 精度；rebuild 166,380 →
  166,380）与 `2026-08-13T00:26:57Z`（1,330 源、1,255,049,984 字节；180,718
  emitted / 0 skipped；242 sessions；630/630 byte 精度；rebuild 166,882 →
  166,882）——后者由改名后的 `agent-session-grep` 二进制执行，验证改名无功能
  回归。早期 `2026-07-31T10:04:17Z` 运行（879 源，`INV-SYNC-OK` exit 5 失败，
  79,958 emitted、0 skipped，其余不变量未评估；aggregate 报告未保留精确 canonical
  code，故 `source_changed` 未证实）与 2026-08-10 子集运行（137 源全绿）如实保留
  在 `docs/evidence/integration-beta/real-data-regression.md`。真实数据 Gate D 已
  闭合。

## 晋级到 Beta 的缺口

1. ~~golden 测试~~ —— 已入库：`tests/golden/` fixture（BLAKE3 锁定字节）+ 结构化
   期望输出比对，任何 canonical 输出漂移即失败（2026-07-26）。
2. ~~property/fuzz 覆盖~~ —— 已入库：固定种子确定性 property 套件（畸形行、
   Unicode 多字节 span、大字段、threading、codex 镜像去重），失败可由种子复现（2026-07-26）。
3. ~~source span~~ —— 已入库：schema v6 + `MessageEvent.span` 契约，golden/e2e
   round-trip 锁定（2026-07-26，见 `docs/operations/migration-v5-to-v6.md`）。
4. ~~真实历史数据回归（隔离沙箱、授权数据集、不外传）~~ —— **已闭合**：最新全量
   授权运行（`2026-08-13T00:26:57Z`，改名后的 `agent-session-grep` 二进制，1,330
   源、1,255,049,984 字节）六条不变量全绿、harness exit 0：sync 180,718 emitted /
   0 skipped、no-parse-loss 180,718 claims、242 sessions 全 context 成功（11
   zero-placement，0 failed）、630/630 byte 精度、rebuild 稳定（catalog 166,882 →
   166,882，ids match）。此前运行均如实保留：2026-08-09/10 全量（1,242 源、164,136
   emitted、231 sessions、659/659 byte、rebuild 151,562 → 151,562）、2026-08-12
   v3（1,328 源、180,218 emitted、rebuild 166,380 → 166,380）、2026-08-10 子集
   （137 源）与 2026-07-31 失败运行（exit 5）见
   `docs/evidence/integration-beta/real-data-regression.md`。harness
   （`scripts/evidence/real_data_regression.py`）在抛弃式临时 data root 上跑
   sync → status + catalog walk → 逐会话 context → index rebuild，报告只含聚合计数
   （见 `docs/operations/REAL-DATA-REGRESSION.md`、证据行 `IB-REAL-DATA-REGRESSION-001`）。
   真实数据 Gate D 已闭合；Provider 晋级仍需独立审查与 owner 决策。
5. 跨正式 target（Windows/Linux/macOS）的 CI 认证——仍缺。`ci.yml` 的 `test` 与
   新增 `installer` job 已配置三平台矩阵（证据行 `IB-CI-INSTALLER-001`），但在
   PR 上跑绿并记录具体 run id 之前只能是 `ci_configured_only`；hosted runner 亦
   非 clean machine，不构成安装认证。`core-beta-evidence.yml` 的四 target job 现在也
   纳入 Claude/Codex provider evidence 与 open-source gate benchmark；但最新触发
   的运行未能完成（外部 CI 阻塞），尚无 named successful run，因此仍为
   `ci_configured_only`。
6. 回滚策略——**部分闭合，仍保持 Proposed**：`docs/adr/ADR-0010-provider-maturity-rollback.md`
   已记录 RFC-0002 §6 的晋级证据、降级触发条件、单源改动顺序、历史恒可检索不变量
   与 owner/approver 责任；CLI `providers`、human/Robot 投影及 MCP `list_providers`
   现在读取 `ProviderCapabilityMatrix::current()`，因此降级后的 maturity 会自动
   对外可见。剩余阻塞是 owner/approver 在 ADR-0010 治理记录中补 `accepted_at` 与
   关联实现/跨边界证据；在此之前不得把该条划掉或宣称 Accepted。
7. `AdapterManifest` 结构化声明——**已闭合实现，晋级证据仍待认证**：
   `ProviderAdapter::manifest()` 与 owned `AdapterManifest` 已落地，14 个 provider
   显式实现；14 个已实现 provider 均有 golden fixture，`fixture_revision=1`，
   `known_limitations` 已从空数组填上真实限制（见上文「已知限制」），
   `last_certified_targets` 均为空，等待 named successful cross-target run 后填写。
8. 只读约束的运行时断言——**已闭合**：全部 14 个已实现 provider 的 golden 测试通过
   `testkit::assert_read_only` 守护 probe/parse（含 opencode/cursor 的 SQLite
   只读打开路径）；真实回归 harness 新增 `INV-SOURCES-UNCHANGED`，以聚合
   checksum 计数验证扫描不改源且不泄露路径。
9. Codex 增量的直接证据——**已闭合**：新增 Codex 重 sync 幂等、源收缩 tombstone、
   空源 tombstone 三项合成 e2e，直接支撑 `incremental: native`。

上述缺口清单经 2026-08-16 的逐项只读核查确认（每项都核对了对应实现位置与测试
名），核查本身不构成晋级；晋级仍需 owner 决策。
