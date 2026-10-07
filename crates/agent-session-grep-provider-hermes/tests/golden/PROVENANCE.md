# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.json` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.json` 为**人工手写的合成 JSON 文档**（单文件 `session_<id>.json`，非行式），
不基于任何真实会话记录做删减或脱敏。字节即权威：UTF-8（无 BOM）、LF 行尾，
BLAKE3 pin 在 `basic.expected.json`
（`1c6bb30025c23a798706fecba8c3761a1793d4c928cceaa938fe2252af13c6d1`），根
`.gitattributes` 的 `-text` 规则防止行尾改写。

## 逐条覆盖

顶层字段 `session_id`/`session_start`/`messages[]`。

| 条目 | 内容 | 覆盖点 |
|------|------|--------|
| 0 | `role:"system"` | 系统消息跳过 |
| 1 | `role:"user"`，自带 `timestamp` | 用户消息；消息级时间戳透传 |
| 2 | `role:"assistant"`，content 为空、reasoning 有值 | 空正文跳过 |
| 3 | `role:"assistant"`，content + reasoning | reasoning 包成 `[thinking]…[/thinking]` 块 |
| 4 | `role:"tool"` | 工具消息跳过 |
| 5 | `role:"user"`，无时间戳 | 时间戳回退到 `session_start` |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Hermes `session_<id>.json`（`~/.hermes/sessions/`）的格式观察，仅复用结构：
顶层 `session_id`、`session_start` 与 `messages[]`（`{role, content, reasoning?,
timestamp?, tool_call_id?, tool_calls?}`）。同目录 `<id>.jsonl` 只含部分近期状态，
adapter 忽略。消息提取适配自 hstry（MIT）的 idea-level 结构，未复制任何字节。

## 脱敏与合规声明

- **不含任何真实数据**：session_id 为 `hermes-sess-0001` 固定假值、时间戳为
  `2026-04-18T04:53:2Z` 固定基准、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

**N/A**：单文档 JSON 无行式字节坐标，adapter 全部消息 `span: None`
（golden 测试 `golden_messages_carry_no_byte_span`）。

---

## `state.db` — `hermes/sqlite-state-v1`（revision 1，2026-09-29 引入）

### 构造方式

`state.db` 为 **SQLite 二进制 fixture**，由本目录 `generate_sqlite_fixture.py`
（Python 3 标准库 `sqlite3`）生成：`sessions` + `messages` 两表、固定顺序的合成
行、`commit` 后关闭。SQL 是唯一来源；字节即权威，BLAKE3 pin 在
`sqlite.expected.json`（`2a21db8bcb9fa42da14243d231717ed6bc82369aafcd0521aa4712ff19aba4be`，
生成时的 16 KiB 布局）。**纯合成**：不基于任何真实 `~/.hermes/state.db` 做删减或
脱敏，也未从任何参考项目复制 fixture。

再生（仅审计用；committed 字节与 pinned BLAKE3 才是契约，SQLite 页面布局随库版本
可能变化）：

```text
python crates/agent-session-grep-provider-hermes/tests/golden/generate_sqlite_fixture.py
```

### 逐条覆盖

| 条目 | 内容 | 覆盖点 |
|------|------|--------|
| sessions | `hermes-state-sess-a`（`started_at` REAL）+ `hermes-state-sess-b`（`started_at` NULL） | 多会话来源；每消息带 session 归属；report 级 `multi_session` fail closed |
| messages(a) | 插入序 3 → 1 → 2 → 6 → 4 → 5，时间戳交错 | 排序必须是 `timestamp, id`（NULL 最先），不得按插入序/rowid |
| messages(a) id 1 | 正文两侧带空格 | 正文逐字透传，不 trim |
| messages(a) id 2 | `content` NULL + `reasoning` 非空 + `timestamp` NULL | NULL 时间戳显式保留为 absent；reasoning 折成 `[thinking]…[/thinking]`；不用 `started_at` 回填 |
| messages(a) id 6 | `content` NULL + OpenAI 形态 `tool_calls`（`{id,function:{name,arguments}}`） | 无正文行计入 `skipped` 并留 rowid 诊断；该行**未 emit**，故其 call 不进入关联窗口（见下方口径说明） |
| messages(a) id 4 | `role='tool'` + `tool_call_id`（ts 1700000004.5，早于 id 6 的 1700000005.0） | 关联 basis `unmatched_id`（窗口里没有该 call）：`authoritative=false`，不 emit activity/edge |
| messages(a) id 5 | `role='tool'` + `content` NULL | 坏行/空正文计入 `skipped` + rowid 诊断，绝不静默 |
| messages(b) id 7 | 精简形态 `tool_calls`（`{name,arguments}`） | 工具调用两形态之二 |
| messages(b) id 8 | `role='tool'` + `tool_name` 命中 | 关联 basis `name_only`，仍非权威 |
| messages(b) id 9/10 | `role='system'` / `'developer'` | 角色透传（上层按可见性策略过滤，adapter 不做语义裁剪） |
| messages(b) id 11 | Unicode 正文 + 小数秒 | REAL 秒 → 毫秒 ISO-8601（`.750Z`）、CJK/emoji 逐字透传 |

关联口径说明（pinned `sqlite.expected.json` 就是下列口径，不要按直觉改写）：

- 关联窗口只由**已 emit** 的 assistant 行建立。`messages(a) id 6` 正文为 NULL，在
  `src/sqlite_state.rs` 里按空正文跳过（`skipped` + rowid 诊断），它的 OpenAI 形态
  call 因此从未进入窗口；`ORDER BY timestamp, id` 又把 `messages(a) id 4`
  （1700000004.5）排在 id 6（1700000005.0）之前，所以它只能记为 `unmatched_id`。
- 结论：本 fixture 在 golden 层覆盖的是 **compact 形态解码 + `name_only`**（会话 b：
  `compact=1 … name_only=1`）、**`unmatched_id`**（会话 a：`compact=0 function=0 …
  unmatched_id=1`）以及"无正文行不建立关联窗口"这一事实。
- `observed_id`、`ambiguous_id`、`ambiguous_name`、`unmatched_name`、
  `missing_identity` 与两种形态的完整解码，由单元测试
  `parse_decodes_both_tool_call_shapes_without_claiming_authority`
  （`src/sqlite_state.rs`）覆盖；本 fixture 不做该声明。

断言位置：`tests/sqlite_golden.rs`（pinned 投影 = 消息 + session + 计数 + 诊断）与
`src/sqlite_state.rs` 的单元测试（排序、NULL、坏行、两形态、关联 basis、超限、
WAL 并发提交下的源不可变、WAL 临时副本成功/出错两条清理路径）。

### 编码的真实格式知识（仅字段名与列形状，无真实内容）

来自 NousResearch/hermes-agent 固定快照（提交
`bac0c45d8593ed9d53a8e3fcacecdc920b71a2c4`，`hermes_state_common.py` blob
`e35e61a06a3c69ebea6b37accec72d10cead20dc`：schema version 30，L362 起 sessions、
L379 `started_at REAL`、L428 起 messages、L433-L440 `tool_call_id`/`tool_calls`/
`tool_name`/`timestamp REAL`/`reasoning`）与合成结构探针。
只复用列形状与两种 tool-call 封套；未复制任何字节，也未把探针视为兼容性认证。

### 已知边界（未认证项，如实标注）

- **消息身份**：`messages.id` 是每库 rowid（删除后复用、跨 profile 不唯一），本变体
  以空 `native_id` 上报，由组合根派生 document-scoped id；rowid 只在点名某一行的
  诊断里原样出现。把 rowid 升为 canonical native id 需要先落地
  "document-scoped native message identity"（与 `pi` 同一架构决策）。
- **工具关联**：两种形态只做解码与计数；每个关联 `authoritative=false`，不合成原生
  call id、不产生 parent edge / tool activity（矩阵 `tool_activity` 保持
  `unsupported`）。
- **source span**：SQLite 行在已验证快照里没有连续字节区间，恒 `span: None`
  （与 opencode 同一结论）。
- **发现根**：`PROVIDER_DISCOVERY_ROOTS` 仍是 per-provider 单根表，`state.db` 需按
  显式路径 ingest；新增第二根属独立任务。
- **有界**：sessions 4096 / messages 250_000 / 单 cell 8 MiB / 库内 cell 合计
  64 MiB / 单消息工具调用 32 / 库内工具调用 200_000；adapter 内部另有 128 MiB
  快照上限（`SQLITE_MAX_SOURCE_BYTES`），只对"直接以字节调用 probe/parse"的调用方
  生效。**生产路径的实际有效上限是 32 MiB**：hermes 的 provider manifest 属
  whole-source 家族（`JSON_FAMILY_MAX_SOURCE_BYTES`，与 JSON 变体共享），
  `probe_source`/`parse_source` 先整源读取并按 32 MiB 拒绝，adapter 的 128 MiB
  检查在生产路径不可达。任一超限都是显式失败（`SourceTooLarge` /
  `RecordTooLarge`），绝不截断当成功；是否为该变体放宽整源上限属 owner 决策
  （见 `docs/product/PROVIDER-BETA-READINESS.md` 的 follow-ups）。
- **capture 层副作用（如实记录，非 adapter 行为）**：整链路 `sync` 一个 WAL 活跃
  的源时，`state.db` 与 `-wal` 的字节/mtime/尺寸不变，但 `-shm`（WAL-index）的
  内容会变——既有 capture 路径以 `SQLITE_OPEN_READONLY` 挂接 live WAL 库时会在
  WAL-index 里写读标记。adapter 层的保证更强也更简单：它**从不打开源文件**，只解析
  收到的已验证快照字节（证据：
  `source_database_files_stay_byte_identical_across_a_concurrent_wal_commit` 与
  `open_readonly_from_bytes` 的私有副本）。
- **安装边界（未闭合，需 owner 决策）**：本变体保证每个 `state.db` 各自形成来源，且
  `profiles/a` 与 `profiles/b` 的同名 native session id 经组合根的安装命名空间解析后
  仍是两个不同 Session（`crates/agent-session-grep-cli/tests/hermes_state_db.rs`
  的 `profiles_with_the_same_native_session_id_stay_separate_sources` 实测）。
  但组合根当前的安装解析会让**已登记的较浅根**吸收其下的更深处源：先 sync
  `~/.hermes/state.db` 再 sync `~/.hermes/profiles/<name>/state.db` 时，后者会并入
  前者的安装命名空间，同名 native session id 会折叠成同一个 Session
  （characterization 测试 `known_limitation_main_database_absorbs_a_profile_source`
  钉住该现状）。修复属于身份层决策（单文件 SQLite 源需要 file-level 安装边界，
  variant-aware 且有迁移证据），不是 adapter 内可完成的事；已作为 beta 缺口上报。
