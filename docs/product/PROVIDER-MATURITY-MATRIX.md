# Provider Maturity 与 Capability Matrix

> 对外可见的 Provider 状态清单，是 `0.1.0`（首个公开版本，`Cargo.toml`）的公开状态记录。
> - 术语与晋级证据要求见 `../architecture/RFC-0002-provider-adapter-contract.md` §6。
> - 本文件是**当前实现状态**的事实记录，不是承诺；晋级必须有证据，不由代码存在自动推断。
> - 最后更新：2026-10-06（B5 生命周期 wave：Claude/Codex 的 append/shrink/同长改写/分叉证据入库并各自指向 `tests/lifecycle.rs` 与 64 种子 append property；移动/WAL 如实标注 provider 层 N/A 并指到 store 层证据。未晋级、无能力变化。前次 2026-08-25：property 全 14 家 + resume matrix 4 家新增 + tool_activity 7 家诚实盘点 + 3 个 Medium 修复 wave）
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

## 成熟度总览（16 行，2026-08-25 事实）

| Provider | provider_id | variant | maturity | 证据 |
|---|---|---|---|---|
| Claude Code | `claude-code` | `claude-code/jsonl-v1` | **Experimental** | 单元 + e2e + golden（`crates/agent-session-grep-provider-claude/tests/golden.rs`）+ 确定性 property 套件（`tests/properties.rs`，固定种子）+ span round-trip + 生命周期回归（append/shrink/同长改写/分叉 + 64 种子 append property；`tests/lifecycle.rs`） |
| Codex | `codex` | `codex/rollout-jsonl-v1` | **Experimental** | 单元 + e2e + golden（`crates/agent-session-grep-provider-codex/tests/golden.rs`）+ 确定性 property 套件（含镜像去重性质）+ span round-trip + 生命周期回归（append/shrink/同长改写；分叉为无父边的反向钉住 + 64 种子 append property；`tests/lifecycle.rs`） |
| Grok Build | `grok-build` | `grok-build/acp-updates-v1` | **Experimental** | ACP `updates.jsonl`（`session/update` stream），主格式证据充分，variant 分层 + golden（`tests/golden.rs`） |
| Antigravity | `antigravity` | `antigravity/transcript-jsonl-v1` | **Experimental** | 本机真实格式核验（2026-08-15）：`brain/<uuid>/.system_generated/logs/transcript.jsonl`；identity 在目录名，文件内无 session id 字段 + golden（`tests/golden.rs`） |
| OpenCode | `opencode` | `opencode/sqlite-v1` | **Experimental** | `opencode.db` SQLite（session/message/part 表），只读打开（SQLITE_OPEN_READONLY + busy_timeout）+ golden（`tests/golden.rs`） |
| Pi | `pi` | `pi/session-jsonl-v1` | **Experimental** | session JSONL（`type:session` header + message）+ golden（`tests/golden.rs`，含 v3 会话树 fixture `tests/golden/v3-branched.jsonl`） |
| Hermes | `hermes` | `hermes/session-json-v1` | **Experimental** | `~/.hermes/sessions/session_<id>.json`（session_id/messages），hstry@88b78b1 (MIT) 格式证据 + golden（`tests/golden.rs`） |
| Cursor | `cursor` | `cursor/vscdb-chat-v1` | **Experimental** | `state.vscdb` SQLite KV：ItemTable `chatdata`/`prompts`（hstry@88b78b1 MIT 格式证据）+ 增量变体 `cursor/disk-kv-v1`（`cursorDiskKV` composerData/bubbleId：header 顺序、坏槽位逐状态计数、有界只读副本；证据为固定 Wake@71aeca67 实现与合成探针，无官方版本化存储契约）+ golden（`tests/golden.rs`、`tests/disk_kv_golden.rs`） |
| Kimi Code | `kimi-code` | `kimi-code/wire-jsonl-v1` | **Experimental** | wire.jsonl（`context.append_message`）+ golden（`tests/golden.rs`） |
| OpenClaw | `openclaw` | `openclaw/session-jsonl-v3` | **Experimental** | v3 JSONL header + message records，本机仅 config 无 transcript 样本 + golden（`tests/golden.rs`） |
| Qoder | `qoder` | `qoder/transcript-jsonl-v1` | **Experimental** | JSONL（`session_meta` + `type:user/assistant`），官方路径已实现 + golden（`tests/golden.rs`） |
| Tencent CodeBuddy | `tencent-codebuddy` | `tencent-codebuddy/cli-jsonl-v1` | **Experimental** | CLI OpenAI-style JSONL（`role`/`content`/`sessionId`），extension variant 待分层 + golden（`tests/golden.rs`） |
| Cline | `cline` | `cline/api-conversation-history-v1` | **Experimental** | `api_conversation_history.json` JSON family + golden（`tests/golden.rs`） |
| Aider | `aider` | `aider/chat-history-md-v1` | **Experimental** | Markdown chat history（`#### ` user prompts），`.aider.chat.history.md` 为候选 root 待核验 + golden（`tests/golden.rs`） |
| DeepSeek Harness | `deepseek-harness` | — | **Unsupported（deferred）** | 无任何 transcript 证据（本机无 `~/.deepseek`，参考项目无 adapter）；证据出现前不实现、不宣传 ；守护测试 `deepseek_harness_and_zcode_are_deferred` |
| ZCode | `zcode` | — | **Unsupported（deferred）** | 无任何 transcript 证据（本机无 `~/.zcode`，参考项目无 adapter）；证据出现前不实现、不宣传 |

14 个已实现 provider 均为 **Experimental**：golden、property、source span 以及
关系化 Message/Placement/Edge 的合成与 e2e 证据已入库（见下），授权真实数据全量
绿色回归亦已闭合（见「晋级到 Beta 的缺口」第 4 条）。2026-08-25 wave 起，seeded
随机化 property 套件（`tests/properties.rs`，固定种子）覆盖**全部 14 个已实现
provider**（此前仅 Claude/Codex，见缺口第 2 条）；resume 命令矩阵新增 4 家
（antigravity/opencode/kimi-code/tencent-codebuddy → `derived`，见 Capability
Matrix resume 行）；tool_activity 完成 7 家诚实盘点（全部如实保持
`unsupported`，逐行理由见 capability.rs 注释与 `PROVIDER-BETA-READINESS.md`）。
剩余 blocker 为跨 target CI 认证与 provider 级回滚策略的 owner 批准——逐条见
下方缺口清单。两个 deferred provider（DeepSeek Harness、ZCode）保留 16 行但不
宣传为已实现、不设 maturity target。

## Capability Matrix（逐字段，2026-08-25）

字段对应 Canonical `Message`（`crates/agent-session-grep-domain/src/lib.rs`）与解析产出。

### 已实现 14 个 provider 的共同字段

| 字段 | 已实现 provider | 说明 |
|---|---|---|
| probe | `native` | 全部 14 个 adapter 均有 probe，歧义一律 `AmbiguousVariant` 拒绝（不低置信度猜测）。由 `capability_probe_claim_matches_real_probe_on_own_golden` 守护：逐 adapter 对自己的 golden 字节实跑 probe，声明可用则必须 `Ok` 且置信度非 `Ambiguous`（RFC-0002 §3 歧义即拒绝解析），且报出的 `variant_id` 必须与本行声明逐字相同——否则注册表选型会挂错 adapter |
| parse | `native` | 全部 14 个 adapter 均 streaming 到 `CanonicalEventSink`。由 `capability_parse_claim_matches_real_parse_on_own_golden` 守护：逐 adapter 实跑 parse，`report.committed` 必须 > 0 且与真实 emit 的消息数相等（计数与入库量不得脱节），每条消息正文非空（空正文无 FTS token，计入 committed 等于宣称索引了检索不到的内容） |
| search | `native` | 统一经 canonical 索引检索。由 e2e `capability_search_claim_matches_real_retrieval_for_every_provider` 守护：逐 provider sync 自己的 golden 源后，用**取自该 golden 正文**的 token 走真实 CLI 检索，必须至少命中一条且命中正文出自该源——固定关键词会因 fixture 语言不同而假阴性，故 query 由内容派生 |
| discover | `native`（claude-code/codex/openclaw/tencent-codebuddy/antigravity/opencode/pi/hermes/grok-build/kimi-code/qoder/cline）；`unsupported`（其余） | `PROVIDER_DISCOVERY_ROOTS` 逐 provider 登记 (root, 扩展名)：JSONL provider 收 `jsonl`，opencode 的源是单个 SQLite `opencode.db` 故收 `db`（`-wal`/`-shm` 旁文件的 extension 不是 `db`，精确匹配天然排除）。pi 的 root 为 `~/.pi/agent/sessions/<encoded-cwd>/`，逐层递归即可命中。hermes 的 root 为 `~/.hermes/sessions` 收 `json`（上游 hstry adapter 硬编码该根并只认 `session_*.json`；同目录 `<id>.jsonl` 是部分状态，扩展名精确匹配天然排除）。qoder 的 root 为 `~/.qoder/projects/<project>/transcript` 收 `jsonl`（本 adapter 的 transcript JSONL 面；Electron SQLite 面不在 adapter 范围内，见 provider-qoder 模块文档）。cline 的 root 为 `~/.cline/data/tasks` 收 `json`：同目录三个旁文件（`ui_messages.json` / `context_history.json` / `task_metadata.json`）都是 JSON 对象而非带 `role` 的数组，adapter 的 probe 逐个如实 `AmbiguousVariant` 拒绝，故收 `json` 是安全的；VS Code 扩展的 `globalStorage` 树不是 home 相对路径（Linux `~/.config`、macOS `~/Library`、Windows `%APPData%` 各不相同），本表只登记 home 相对根故不登记它。cursor 与 aider 结构上无法登记，理由见 capability.rs 两行注释：cursor 的两个已知面（VS Code `workspaceStorage/*/state.vscdb`、Cursor CLI `~/.cursor/chats/<id>/store.db`）前者非 home 相对、后者 schema 与本 adapter 的 ItemTable 不同源；aider 的 `.aider.chat.history.md` 按 **repo** 存放，上游 agentsview 也是遍历用户给的仓库根去发现，没有 home 相对根可登记 |
| resume | `derived`（claude-code/codex/pi/grok/antigravity/opencode/kimi-code/tencent-codebuddy）；`unknown`（qoder/hermes/cursor）；`unsupported`（aider/cline/openclaw） | 2026-08-25 wave 新增 4 家 evidence-backed 命令：`agy --conversation <id>`、`opencode <directory> --session <id>`、`kimi --session <id>`、`codebuddy --resume <id>`（证据逐行见 capability.rs 注释与 `PROVIDER-BETA-READINESS.md`）；hermes/qoder/cursor 因参考项目证据冲突或无证据保持 `unknown`；未核验的 resume 命令一律不设默认值 |
| context | `native`（claude-code）；`unsupported`（其余 13 个已实现 provider） | 上下文图靠 `message_edges` 的父指针拼装（`mainline` 逐边上溯），而边只能来自 adapter 发出的 `parent_native_id`——没有父指针就没有边，`context` 只能如实记 unsupported。仅 claude-code 的 JSONL 带 `parentUuid`；codex rollout 是线性序列、adapter 硬编码 `parent_native_id: None`（模块文档：不编造上层可推断的线性链），此前误记 `native` 已由 `capability_context_claim_matches_pinned_golden_parent_links` 抓出并更正 |
| handoff | `derived`（全部 14 个已实现 provider）；`unknown`（deepseek-harness/zcode，deferred） | handoff 不是 per-provider 特性：`generate_deterministic` 只消费 `SearchHit` + 权威 source placement，`provenance` 与 `matched_sessions[].provider_id` 一律 `None`（搜索型 pack 无单一提供商，不臆造），全流程不读 provider 身份、无 per-provider 分支。故"能否装出带原文证据的 pack"只取决于消息是否落库并带 source placement——`parse` 可用即成立。此前全列 `unsupported` 是少报：`asg handoff` 是已发布命令，对 codex（JSONL）、aider（markdown 且 native_id 恒空）、opencode（SQLite）三种结构迥异的真实 golden 源实测均产出 `confidence: high` 的带证据 pack。由 `handoff_pack_generation_is_provider_independent` 守护（逐 provider 身份走生成器，装配结果必须逐字段一致） |
| incremental | `derived`（全部 14 个已实现 provider）；`unknown`（deferred 2 个） | 与 handoff 同理，incremental 也不是 per-provider 特性：判定链全在 composition root + store 层——`sync` 先读 `source_scans` 的 `(len_bytes, fingerprint)` 缓存与当次快照的 BLAKE3 指纹比对，相同则**跳过 parse**（`unchanged` 上报已存消息数），再由 `commit_source_batches_if_changed` 做内容级 no-op 判定、不推进 `generation`。这条链上没有任何 per-provider 分支，adapter 也不参与。故一律 `derived`（由源字节确定性派生，而非 provider 原生提供）。此前 claude-code/codex 记 `native`、其余 12 个记 `unsupported` 都不准：前者把 store 层能力误记为 provider 原生，后者是少报——12 个 provider 的真实 golden 源实测 resync 均为 `committed=0` / `unchanged=N` / generation 不变。由 e2e `capability_incremental_claim_matches_real_resync_for_every_provider` 逐 provider 实测守护；claude-code/codex 另有 append/shrink/空源 tombstone 的专项 resync e2e，那是测试深度而非更高的能力档位 |
| tool_activity | `partial`（claude-code/codex，schema v12 `tool_activities` 落库）；`unknown`（deepseek-harness/zcode，deferred）；`unsupported`（其余 12 个已实现 provider，含 aider） | CLI `--tool-kind`/`--tool-name`/`--main-only`/`--subagent-only`/`--include-sidechain`、MCP 同名参数与 TUI 分面键（`m` sidechain / `k` tool-kind）已落地；handoff pack 投影 `tool_activity` + 权威 `role`/`is_sidechain`，context 响应投影 `tool_activities`。2026-08-25 七家诚实盘点（grok-build/antigravity/kimi-code/qoder/pi/openclaw/tencent-codebuddy）：四家格式携带结构化工具记录但无 per-message native id 可锚定（grok-build/antigravity/kimi-code/qoder），三家无结构化记录（pi/openclaw/tencent-codebuddy）——全部如实保持 `unsupported`，理由逐行记录于 capability.rs 注释与 `PROVIDER-BETA-READINESS.md`，并由 golden 钉住测试与 provider_matrix 双向断言守护 |
| source_span | `native`（claude/codex/grok/pi/kimi/openclaw/qoder/codebuddy/antigravity）；`derived`（aider）；`unsupported`（opencode/hermes/cursor/cline） | SQLite/单文档 JSON 类 provider 无文件内字节 span；cline 的数组下标 pseudo-span 已移除并如实降级为 unsupported。antigravity 虽无文件内 session id（身份在目录名），但 transcript 为行式 JSONL，逐消息 span 为真实字节区间并由 golden 测试 `golden_spans_slice_back_to_exact_source_lines` 逐字节校验 |

### 逐 provider 明细见 capability.rs（单源权威）

```bash
# 渲染当前矩阵（Human）：
cargo run -q -p agent-session-grep-cli -- providers
# 渲染当前矩阵（Robot JSON envelope）：
cargo run -q -p agent-session-grep-cli -- --output json providers
```

入口层不得硬编码 provider maturity 或 capability；上述命令与 MCP
`list_providers` 均从 `ProviderCapabilityMatrix::current()` 投影。

## Provider 生命周期证据（append/shrink/rewrite/fork/move/WAL，2026-10-06 B5）

> 判分边界：provider 只接收已验证快照字节（`crates/agent-session-grep-ports/src/lib.rs` 的
> `ProviderAdapter::parse`），拿不到路径，也没有"上次解析结果"；水位推进 /
> tombstone / last-good 回滚由 store 层负责。本节"覆盖"只指 provider 层性质，
> 不构成 maturity 晋级证据，也不改变任何 capability 列取值。

- **append / shrink / 同长改写（claude-code、codex 均覆盖）**：两个 crate 的
  `tests/lifecycle.rs` 钉住"追加后既有消息（seq/native_id/parent/角色/正文/
  时间戳/sidechain/span）逐字段不变"、"行边界截断 == 前缀解析"、"撕裂半行只
  可恢复跳过、不得整体失败或吞掉前缀"、"清空源返回空报告"、"同长正文/id 改写
  按当前字节生效（无陈旧缓存）"；既有 64 种子生成器新增
  `prop_append_keeps_prefix_byte_stable`（`tests/properties.rs`）做随机化复验。
  store 端的 no-op / tombstone / 撕裂尾保留旧索引语义另由 CLI e2e 守护
  （`crates/agent-session-grep-cli/tests/e2e.rs`）。
- **分叉 parent 边**：claude-code 已覆盖（兄弟共享同一父边、悬空父边原样保留
  给跨源解析、空串 parentUuid 归一为根；`tests/lifecycle.rs`）。codex rollout
  格式无父指针，provider 层 N/A，以反向测试钉住"复制前缀与 event_msg 镜像也
  不臆造父边/sidechain、不重复计数"。跨源父边解析属 store/application 层，
  不在该测试范围。
- **文件移动**：provider 层 N/A（`parse`/`probe` 只收字节，adapter 结构上
  拿不到路径，身份取自记录内 native id）。locator remap 与历史恒可检索证据在
  store 层：`crates/agent-session-grep-adapters-sqlite/src/relocation/tests.rs`
  与 `crates/agent-session-grep-cli/tests/e2e.rs`。
- **SQLite WAL**：claude-code/codex 源为 JSONL，provider 层 N/A；SQLite 读侧的
  WAL 证据在 `crates/agent-session-grep-adapters-sqlite/src/source_fs.rs`
  （WAL 帧逻辑捕获、WAL-only 变化触发快照失效、捕获/校验全程不写源）。
- **native resume**：本轮未执行 native resume（环境限制）；矩阵与 ledger 的
  resume 列只记录 CLI 命令证据（derived/unknown/unsupported），不是 native
  resume 成功证据，且本 wave 未改变该列任何取值。

## 已知限制

各条与 `AdapterManifest.known_limitations` 一一对应（14 个已实现 provider 的
manifest 均已填真实限制，见各 `crates/agent-session-grep-provider-*/src/lib.rs`）。

- **Claude Code**：只抽取 `user`/`assistant`/`system` 对话记录；工具调用块（无 text）被忽略；`cwd`/`gitBranch`/`version` provenance 尚未落库。
- **Codex**：只取权威 `response_item` + 内层 `message`，忽略 `event_msg` UI 镜像以避免重复计数；`world_state`/`turn_context`/工具调用记录未抽取；无 threading（线性）。
- **Grok Build**：chunk 分组重建角色，无逐消息 native id（合成 `grok-msg-{seq}`）；逐消息时间戳未抽取；会话身份回退到首个 ACP `promptId`，非持久 session id。
- **Antigravity**：文件内无 session id 字段（identity 在 `brain/<uuid>` 目录名），parse 时 `session_native_id`/`provider_session_id` 如实留缺；`SYSTEM`/`CONVERSATION_HISTORY` 与工具活动步骤永不为消息；`span` 用字节区间。
- **OpenCode**：SQLite 源无字节 span；只提交 `text` part 且角色为 user/assistant；逐消息时间戳未抽取。
- **Pi**：`session_info`/`compaction`/`custom_message`/`model_change` 等非对话类型跳过；消息以空 native id 上报（composition root 按 document+seq 派生 `Stability::Unstable` 身份，adapter 绝不编造假 id）。格式 v2/v3 是 parent-linked 会话树（头部 `version` + 逐条 `id`/`parentId`，同 parentId 即分支）：全部分支的正文都进索引，血缘如实上报为一条 parse 诊断，但不发出 parent 边——Pi 的 entry id 是 8 位十六进制的文件内标记，而消息 native 身份逐字采用且无命名空间，提升会跨会话碰撞。
- **Hermes**：`session_<id>.json` 为主格式；同目录 `<id>.jsonl` 仅含部分近期状态，忽略；无字节 span，消息时间戳缺失时回退 `session_start`。
- **Cursor**：`state.vscdb` 为 chatdata/prompts 两 key 的多代格式，版本分层待补；SQLite 无字节 span；无 native 消息 id（合成 `cursor-msg-{seq}`）。
- **Kimi Code**：`context.append_loop_event`（step/tool 事件）暂未解析；wire.jsonl 罕见携带 session id，通常留缺；逐消息时间戳未抽取。
- **OpenClaw**：resume 有意不支持（gateway-managed）；无 native 消息 id（合成 `openclaw-msg-{seq}`）。
- **Qoder**：身份字段（session_id/cwd）从 `session_meta` lenient 匹配；`progress`/`tool_use`/`tool_result` 非对话记录跳过。
- **Tencent CodeBuddy**：根启动关键字用户消息（content 恰为 `"code"`）被过滤；无 cwd pair 观察（无独立 cwd 头记录）；无 native 消息 id（合成 `codebuddy-msg-{seq}`）。
- **Cline**：JSON 数组文件内无 session id，`session_native_id` 留缺；无字节 span（数组下标 pseudo-span 已移除）；无 native 消息 id（合成 `cline-msg-{seq}`）。
- **Aider**：span 为派生近似（块起始行 + 文本长度），非逐字节整行切片；blockquote 工具/编辑输出并入助手正文；会话身份为首个 run 头时间戳。
- **OpenCode / Cursor（SQLite 类）**：源字节先落临时文件，再以
  `SQLITE_OPEN_READONLY` + `busy_timeout` 打开，绝不写 provider 数据库；无文件内
  字节 span（round-trip 标 N/A）。
- **Hermes / Cline（整文档 JSON 类）**：单个 JSON 文档一次读入，无逐记录字节
  边界，故无文件内字节 span（round-trip 标 N/A）。Kimi Code 不属此列：wire.jsonl
  是行式 JSONL，逐消息 span 为真实字节区间（见上表 `source_span` 行）。
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
   Unicode 多字节 span、大字段、threading、codex 镜像去重），失败可由种子复现
   （2026-07-26 起，Claude/Codex 先行）；2026-08-25 扩展至**全部 14 个已实现
   provider**（各自 `tests/properties.rs`），由
   `beta_readiness_property_column_matches_properties_test_existence` 双向守护
   ledger property 列与套件文件存在一致。
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
   纳入 Claude/Codex provider evidence 与 open-source gate benchmark；但最新推送
   的运行因 外部 CI 限制 在首步前失败，尚无 named successful
   run，因此仍为 `ci_configured_only`。
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
   空源 tombstone 三项合成 e2e。注意这三项证明的是 store 层增量链在 Codex 源上
   的行为深度，不是 provider 原生能力——`incremental` 现已如实记为全 14 个
   provider 一律 `derived`（理由见上表该行）。

公开树内的可核查证据
是本表逐行点名的守护测试（`crates/agent-session-grep-cli/tests/provider_matrix.rs`
与各 provider crate 的 `tests/golden.rs` / `tests/properties.rs`）。
