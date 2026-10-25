# Provider Maturity 与 Capability Matrix

> 对外可见的 Provider 状态清单，记录当前开发候选的实现事实；不是已完成 Beta 或原生宿主验收声明。
> - 术语与晋级证据要求见 `../architecture/RFC-0002-provider-adapter-contract.md` §6。
> - 本文件是**当前实现状态**的事实记录，不是承诺；晋级必须有证据，不由代码存在自动推断。
> - 最后更新：2026-10-19（M2：WorkBuddy、ZCode、DeepSeek Harness 的独立 adapter 与合成证据登记为 Experimental，目标 Beta；既有平台、宿主、回滚及 owner 晋级门槛保持。2026-10-06 B5 与早期 14-provider 证据按原范围保留。）
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

## 成熟度总览（17 行，2026-10-19 实现事实）

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
| WorkBuddy | `workbuddy` | `workbuddy/project-jsonl-v1` | **Experimental** | 与 Tencent CodeBuddy 独立；整数毫秒、正文空白、原生 ID、原始字节 span 与显式工具锚点。JSONL/删除状态合成证据见 `crates/agent-session-grep-provider-workbuddy/tests/provider.rs`、`crates/agent-session-grep-provider-workbuddy/tests/deletion_state.rs`；cloud 不等于空历史，softdelete/runtime 仍待接入 |
| DeepSeek Harness | `deepseek-harness` | `deepseek-harness/session-jsonl-zstd-v4` | **Experimental** | 固定官方 v4 契约；标准多帧 zstd、有界解压、原生 message ID、torn-tail/损坏/未知必需记录回归。合成证据见 `crates/agent-session-grep-provider-dsh/tests/provider.rs`；最高代次发现与原生宿主验收仍待接入 |
| ZCode | `zcode` | `zcode/sqlite-v1` | **Experimental** | session/message/part/session_entry 的逻辑 SQLite 图；可逆 `zcode:<native-id>` 消息来源身份、完整扫描/部分状态、私有 2/2 header 规范化。合成证据见 `crates/agent-session-grep-provider-zcode/tests/provider.rs`；真实发现、删除及宿主验收仍待接入 |

当前 17 个独立 provider 均为 **Experimental**。原有 14 个 provider 的 golden、
property 与历史合成/e2e 记录保留原范围；2026-10-19 新登记的三家只有各自冻结
adapter 的合成解析/逻辑快照证据，不继承历史 14 家或两宿主的验收结果。
WorkBuddy 与 Tencent CodeBuddy 的身份及生命周期分开。M2 三家目标为 Beta，
但真实发现、源生命周期、宿主调用、四目标包及 owner 晋级仍是独立未完成门槛。

## Capability Matrix（逐字段，2026-10-19）

字段对应 Canonical `Message`（`crates/agent-session-grep-domain/src/lib.rs`）与解析产出。

### 当前实现的能力字段

| 字段 | 已实现 provider | 说明 |
|---|---|---|
| probe | `native`（其余已实现 provider）；`partial`（deepseek-harness） | DSH 只以解压后的完整 v4 header 判候选，全部帧完整性与未知必需事件在 parse 校验；三家 variant 不与 CodeBuddy 合并 |
| parse | `native`（既有 14 家）；`partial`（workbuddy/zcode/deepseek-harness） | 新三家只承诺受测格式与有界成功/失败：WB 活跃状态依赖逻辑 DB、ZCode 未知消息保留 incomplete、DSH torn tail 明示 incomplete，均非完整宿主覆盖 |
| search | `native`（既有 14 家）；`partial`（workbuddy/zcode/deepseek-harness） | 已允许并成功提交的消息可走共享检索链；新三家完整来源覆盖与实时生命周期尚未验收 |
| discover | `native`（既有 12 家已登记根）；`partial`（workbuddy/zcode/deepseek-harness）；`unsupported`（aider/cursor） | M2 的 partial 表示只验证部分格式/来源；JSONL、逻辑 DB/WAL、DSH 最高代次与真实删除覆盖要由发现层接入，不从 parser 或路径存在推断完成 |
| resume | `derived`（claude-code/codex/grok-build/pi/kimi-code/tencent-codebuddy/opencode/antigravity）；`unknown`（qoder/hermes/cursor/workbuddy/zcode/deepseek-harness）；`unsupported`（aider/cline/openclaw） | 原生 session ID/cwd 是观察值，不等于宿主可加载或 native resume 成功；新三家仍保留真实调用门槛 |
| context | `native`（claude-code）；`unsupported`（其余当前 provider） | 当前字段指显式 message parent 图。ZCode 的 native session 父关系与 DSH delegationDepth 不伪造 message parent 边 |
| handoff | `derived`（当前 17 个实现 provider） | 共享生成器消费允许的已落库 SearchHit/source placement，不按 provider 分支；Derived 是共同实现机制，新三家不继承历史 native/e2e 验收 |
| incremental | `derived`（当前 17 个实现 provider） | 共享 source fingerprint/CAS/no-op 链确定性派生，非 provider 原生机制；M2 实际 append/rewrite/完整删除与后台发现验收另行完成 |
| tool_activity | `partial`（claude-code/codex/workbuddy/zcode）；`unsupported`（其余当前实现） | WB 必须显式当前 messageId/callId；ZCode tool/reasoning/file parts 锚定可逆消息身份；DSH 当前不 emit activity。没有真实锚点或状态不推断成功 |
| usage | `native`（claude-code）；`derived`（codex）；`unsupported`（其余 15 家） | 新三家当前 adapter 不 emit usage；只有实际记录且已验证的字段才能单独增加能力 |
| source_span | `native`（既有行式 JSONL 与 workbuddy）；`derived`（aider）；`unsupported`（opencode/hermes/cursor/cline/zcode/deepseek-harness） | WB span 切回原快照字节；SQLite 和 zstd 解压偏移不能冒作连续原始字节区间 |

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

各条与 `AdapterManifest.known_limitations` 对照（当前 17 个实现 provider 的
manifest 均声明限制，见各 `crates/agent-session-grep-provider-*/src/lib.rs`）。

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
- **WorkBuddy**：强 probe 需要已验证 hostKind 或 __codebuddyLocal marker；正文、native ID 与字节 span 保留。数据库 softdelete 优先于 JSONL 存在；cloud unavailable 与 orphan unknown 分开，不从读失败判删除。单记录 8 MiB、逻辑快照 128 MiB；批量 helper 一次解码，限 65,536 行与 32 MiB ID/cwd 内容，共用调用者 deadline，重复 ID 或畸形字段拒绝整批；当前 17 项 JSONL 与 16 项单 ID/批量状态测试为合成证据，非宿主验收。
- **ZCode / DeepSeek Harness**：无文件内字节 span。ZCode 只接收已取得的逻辑 SQLite 图，中央 manifest 单独限 256 MiB（通用 SQLite 仍为 128 MiB），使用可逆 `zcode:<native-id>` 消息身份；未知部分消息不伪装完整扫描。DSH 只读 v4 串接 zstd，输入 128 MiB、解压总量 256 MiB、单记录与 decoder window 各 8 MiB；torn final frame 只恢复完整行且 incomplete，checksum/未知必需记录拒绝。替换记录是历史证据，非当前 model surface 重放。
- **既有 14 家（关系模型与历史语料级回归记录）**：稳定 `Message` 与上下文
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

以下划掉的本地项与历史语料计数只记录原有 14 家的既有证据；
M2 三家的合成解析、只读与批量元数据证据不继承这些闭合结论。
各 provider 的当前缺口和全局晋级门槛以 readiness ledger 逐行记录为准。

1. ~~golden 测试~~ —— 已入库：`tests/golden/` fixture（BLAKE3 锁定字节）+ 结构化
   期望输出比对，任何 canonical 输出漂移即失败（2026-07-26）。
2. ~~property/fuzz 覆盖~~ —— 已入库：固定种子确定性 property 套件（畸形行、
   Unicode 多字节 span、大字段、threading、codex 镜像去重），失败可由种子复现
   （2026-07-26 起，Claude/Codex 先行）；2026-08-25 扩展至**当时全部 14 个已实现
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
   `ProviderAdapter::manifest()` 与 owned `AdapterManifest` 已落地，当前 17 个 provider
   显式实现；历史 14 个 provider 的 golden fixture 保持 `fixture_revision=1`；
   M2 三家声明合成证据 revision（WorkBuddy=2，ZCode/DSH=1），不冒称 pinned golden。
   `known_limitations` 已从空数组填上真实限制（见上文「已知限制」），
   `last_certified_targets` 均为空，等待 named successful cross-target run 后填写。
8. 只读约束的运行时断言——**已闭合**：历史 14 个 provider 的 golden 测试通过
   `testkit::assert_read_only` 守护 probe/parse（含 opencode/cursor 的 SQLite
   只读打开路径）；真实回归 harness 新增 `INV-SOURCES-UNCHANGED`，以聚合
   checksum 计数验证扫描不改源且不泄露路径。
9. Codex 增量的直接证据——**已闭合**：新增 Codex 重 sync 幂等、源收缩 tombstone、
   空源 tombstone 三项合成 e2e。注意这三项证明的是 store 层增量链在 Codex 源上
   的行为深度，不是 provider 原生能力——`incremental` 对历史 14 个
   provider 一律 `derived`（理由见上表该行）；当前 17 行均使用共享 CAS
   机制的 `derived` 声明，但 M2 实际生命周期覆盖仍待验收。

公开树内的可核查证据
是本表逐行点名的守护测试（`crates/agent-session-grep-cli/tests/provider_matrix.rs`
与各 provider crate 的 `tests/golden.rs` / `tests/properties.rs`）。
