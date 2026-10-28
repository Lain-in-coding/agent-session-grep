# Contract Draft：CLI / Robot / MCP / Cursor

> 治理记录
> - decision_id: CONTRACT-cli-robot-mcp
> - status: **Draft（待 R0 评审）**
> - owner: （待指派）  approver: 项目最终验收人
> - due_milestone: R0
> - evidence_path: docs/contracts/CONTRACT-cli-robot-mcp-draft.md
>
> 本合同是 CLI、Robot 与 MCP 入口语义的规范性来源：所有入口先映射同一组版本化 Application ADT，不各自定义业务语义。实体与 Stable ID 见 `../architecture/RFC-0001-canonical-model-and-stable-id.md`。

## 1. Application ADT（唯一业务语义来源）

SearchRequest { query, filters, limit, cursor: CursorToken?, response_budget }
SearchResult  { items[], next_cursor: CursorToken?, generation: GenerationBundleId, warnings[] }
ShowRequest   { session_id: SessionId, branch_id: BranchId?, message_id: MessageId?, context_policy, response_budget }
ShowResult    { session, selected_thread/branch, messages[], evidence[]: EvidenceSpan, truncation, generation }

SessionId/MessageId/BranchId/CursorToken 为带类型和协议版本的 opaque 值，入口不得互换字符串。

## 2. EvidenceSpan DTO（版本化）

{ occurrence_id, message_id, source_document_id, generation, source_fingerprint,
  byte_start, byte_end,            // UTF-8 半开区间
  line_start, line_end,            // 1-based
  record_ordinal, snippet_char_start, snippet_char_end,
  precision: byte|line|record|unknown }
默认不含绝对路径。无法精确定位时显式降级 precision。

## 3. ResponseBudget（版本化）

{ max_response_bytes, max_items, max_snippet_chars, max_messages, max_evidence_spans }
- max_response_bytes 是最终序列化字节硬门；排序后再截断；保留 envelope/error/generation；
- 返回结构化 truncation{reason} + next_cursor；预算过小返回校验错误，不输出无效 JSON。

## 4. JSON Envelope

{ schema_version, command, request_id, ok, data, warnings[], page{next_cursor,has_more}, meta{duration_ms,generation} }
- schema_version 走 major/minor；未知 major 拒绝，兼容 minor 按合同处理。
- 错误 Envelope: { code, message(安全), retryable, details(有界) }。
- JSONL 每行完整 frame，至少区分 response/diagnostic/progress/error；--robot 禁 progress。

## 5. Error Catalog Matrix（统一映射）

字段: canonical_code | layer | retryable | partial_allowed | CLI_exit | robot_ok | MCP_code | redaction | operator_action
全部 16 码: invalid_request | not_found | source_io | source_changed | snapshot_failed |
        catalog_error | provider_error | capability_not_supported | writer_busy | deadline_exceeded |
        schema_incompatible | cursor_invalid | cursor_expired | generation_mismatch |
        update_recovery_required | internal
Exit Code(权威为 `schemas/robot/v1/error-catalog.json` 的 16 码，实现镜像为 `protocol::CanonicalCode::exit_code`): 0 成功 / 2 校验(invalid_request, cursor_invalid, cursor_expired) / 4 不存在(not_found) / 5 IO(source_io, source_changed, snapshot_failed) / 6 Catalog(catalog_error, writer_busy, deadline_exceeded) / 7 Provider(provider_error, capability_not_supported) / 9 协议(schema_incompatible, generation_mismatch) / 10 部分成功(update_recovery_required) / 70 内部(internal)。无 3(配置)与 8(安全)退出码。retryable 仅 writer_busy 与 source_changed 两码。
- `get`/`show` 对缺失实体统一 exit 4 + `not_found` envelope，不返回 exit 0 + `payload:null`（ADR-0005，已实现）。

## 6. Output Truth Table（stdout/stderr 契约）

模式 human/json/jsonl/--robot/MCP 各自冻结: stdout frame、stderr、颜色、进度、warnings、零结果、
部分成功、fatal、broken pipe、取消、exit code。
- Robot JSON 单 envelope；Robot JSONL 只允许版本化协议 frame；进程诊断永远走 stderr。
- 有效的 `--help` / `--version` 请求在各输出模式下 exit 0：human 模式打印文本；robot/json/jsonl 模式返回 success envelope，帮助文本/版本号置于 `data.help_text` / `data.version`（ADR-0006，已实现）。当前实现仍先校验前置/全局参数：非法 `--output` 或 `--request-id` 返回 `invalid_request`（exit 2），help/version 不绕过校验。
- MCP stdout 只允许合法 MCP frame，panic/backtrace 不得污染 stdout。

## 7. Cursor 生命周期（无状态保留模型）

- Search v2 query digest 绑定 requested/effective mode、model、查询向量维度及内容、RRF/排序窗口版本、filters/facets、可见性/分组及当前仓库信号。旧 search cursor 明确拒绝；不静默重启查询。
- 搜索续页保留首次请求的 `issued_at_ms` 和 `expires_at_ms`，时效评分使用首次请求时刻，只更新 offset；15 分钟 TTL 从首次请求起算，续页不续期。List 保持既有行为。
- 当前实现的 Cursor 自包含且**未签名、无密钥完整性校验（unsigned, keyless integrity-checked）**：contract_major/generation/issued_at_ms/expires_at_ms/query_digest/sort_digest/offset/result_set。线格式保持 `base64url_no_pad(claims JSON) + "." + hex16(blake3("as-cursor-v1" || claims JSON))`；摘要不是签名，不认证签发者，也不能阻止调用者重新计算摘要来伪造 token。这里说明现有实现边界，不改变本 Draft 的治理状态或线格式。`list` 与 `list_sessions` 的 result_set 判别器互斥——跨结果集复用 cursor 显式拒绝，绝不静默从第一页继续。
- 系统不登记活动 Cursor；GC 按 activation + max_cursor_ttl + clock_skew 保留旧 generation。
- 当前错误分类保持区分：结构/摘要/查询/排序/result_set 不符 → `cursor_invalid`；超 TTL → `cursor_expired`；活动 generation 不符 → `generation_mismatch`；contract major 不兼容 → `schema_incompatible`。绝不静默从第一页继续。
- 已由 sqlite-snapshot-wal spike 验证：旧 generation 快照在新写入期间可只读打开，支撑分页 pinning。

## 8. MCP 契约

tools: search_sessions / get_session_context / get_session_resume / get_message / list_sessions / generate_handoff / list_providers / get_status / doctor
- `search_sessions` 的过滤轴与 CLI `search` 逐一对应，入口之间不得少一维：`providers`（OR）/ `since` / `until`（半开区间 [since, until)，只接受带 offset 的绝对 ISO-8601）/ `repo`（schema v16 的三段 slug `host/owner/name`，逐字相等，取值即 `get_status` 的 `repos` 清单；无仓库身份的会话被排除）。空串/纯空白取值一律 `invalid_request`，绝不静默降级为"无过滤"。
- Provider 过滤取值由 capability matrix 的已实现、可搜索行生成（当前 14 个），同时保留 `claude` → `claude-code` 别名。CLI、MCP schema/runtime、Web、hook 和 handoff 使用同一归一化；未知及 deferred provider 明确拒绝。
- CLI/MCP/Web 的 `semantic`/`hybrid` 共用本地模型选择、查询向量生成和 SemanticIndex 注入。只有语义索引确实未就绪才标注 `lexical_fallback`；存储、schema 或模型执行错误不能伪装成正常降级。默认构建的 bigram-hash 仍是实验性模糊词法向量化，不宣称真正的语义理解。
- `get_session_resume`（ADR-0009，只读 Resume Metadata）：入参 canonical `ses_v1_*`，返回固定可空字段（provider_id / provider_session_id / original_working_directory / resume_available / unavailable_reason）；绝不构造或执行 shell 命令、绝不返回 transcript/source path。
- `generate_handoff`：为查询组装 deterministic handoff pack（handoff-pack/v1）——证据带权威 source locator、预算（max_evidence/max_tokens/max_bytes）真实裁剪、默认跨边界脱敏（ADR-0009）；截断如实报 outcome partial。
- `list_sessions`（Peek Bundle 借用，hstry）：每条会话条目附 `peek` 对象——`first_user_text` / `last_user_text`（各 ≤200 字符，char 边界截断；无用户消息时字段为 null），每条序列化 ≤1 KiB（预算常量集中、超限截断有测试）。peek 字节计入 `max_response_bytes` 字节闸，不免费越闸；`list`（全实体）不携带 peek。
- 固定并测试 protocol version、capability negotiation、tool schema、错误映射、取消、超时、shutdown。
- handler 只校验协议 + 映射 ADT，不复制搜索/分支/分页/预算规则。
- 不提供任意文件读取、SQL 或命令执行。取消/超时后不留半提交 Catalog 或活动 IndexWriter。

## 9. Search 查询语义（plain-text-only）

- lexical/semantic/hybrid 使用相同 provider/time/repo/facet/系统消息可见性谓词，在最终 limit 与分页 sentinel 之前应用。两个 FTS corpus 按各自 BM25 排名，经 RRF k=60 合并；同分以 canonical wire ID 排序。语义索引 readiness 错误、非有限向量或分数显式失败。

`SearchRequest.query` 使用 plain-text 关键词：按空白切分的字面片段、隐式 AND。`AND`/`OR`/`NOT`、`NEAR(...)` 和用户输入的引号不启用高级 FTS 查询语言。当前 `safe_fts_query` 将片段引号化，但保留尾随 `*` 的前缀匹配，例如 `work*`；路径和标点仍经 FTS5 分词器处理。索引与查询先应用同一 CJK transform，再进行字面量化。CLI/MCP/Port 共用此边界，不另造分词规则。

查询文本上限 1024 个 Unicode 字符（`invalid_request`，exit 2）；handoff 的 256 字符上限不变。上限如此设定是因为 CJK transform 会把每个 Han 字符展开成约两个短语，超长粘贴会生成成千上万个 AND 短语。适配器另有 4096 短语的硬上限，作为直接 Port 调用方的防御边界。

- 命中的 `text` 是 Application 装配的显示摘要（ADR-0008），不是索引原文：有可证明的字面命中时取该命中的原文连续窗口（≤ `max_snippet_chars` 字符，以最早命中为中心按 2 右 : 1 左 扩展，锚点自身超限时取锚点起始切片）；无字面证据（无匹配、语义-only）时回退正文前缀。不插入省略号/高亮等合成字符，大小写不敏感匹配按小写展开回映到原字符边界；窗口字节经既有命中级估算计入 `max_response_bytes`，排名/游标/`why_matched`/建议命令不受影响。human 模式的片段行在此摘要上按同一字面词元重新居中（≤120 字符，命中左侧约 40 字符上下文）；无词元/未命中/正文更短时保持原前缀预览。

## 10. Web 搜索参数与向量重建

- `GET /api/search` 与 `/api/projection/search` 支持 `q`、`mode`、`limit`、`max_bytes`、`cursor`、可重复的 `provider`、`since`、`until`、`repo`、`include_system`、`group_by_session`、`sidechain`、`tool_kind`、`tool_name`。`limit` 同时设置页大小和 `max_items`；没有独立的第二个 item 预算。`sidechain` 接受 `include|main_only|subagent_only`，布尔值只接受 `true|false`。
- Web 请求在 HTTP 边界直接构造类型化命令，不在查询值与 CLI argv 之间往返。参数值按字面量进入对应字段，因此 `q=--repo` 检索文本 `--repo`，不会触发或改变 `repo` 过滤；MCP 对同名查询值采用同一字面量语义。
- 所有 Web 数据路由都拒绝未知参数、重复标量、空参数、控制字符及非法百分号编码（`invalid_request`），不静默丢弃过滤条件。`/api/search` 和 `/api/handoff` 的 `provider` 可重复，每个值进入 OR 集合。`/api/context` 支持 `policy`、`level`、`max_messages`、`max_bytes`；`/api/handoff` 支持 `q`、可重复 `provider`、`repo`、`since`、`until`、`max_evidence`、`max_tokens`、`max_bytes`。Web 时间参数沿用 CLI 的绝对或相对时间语法；MCP 保持只接受绝对时间。
- `/api/status` 的 `data.web_capabilities` 公布实际搜索参数、重复参数、provider 取值和检索模式，并明确 `mutation_and_execution=false`。Web 仍为只读预览入口。
- `GET /api/resume` 只构造命令描述和证据字段，绝不执行 provider、绝不写磁盘。首次预览标记只由可执行的 CLI `resume`/`resume --yes` 路径管理，查看 Web 预览不能让后续 `resume --yes` 跳过强制预览。
- `index embeddings` 以 128 行 keyset 批次扫描权威 catalog，只为含正文的 Message 编码；adapter 批次上限为 512。模型向量必须符合声明维度且全部有限。旧向量替换与 generation 推进在同一事务内完成，编码/写入失败回滚全部替换，原有向量与 generation 保持不变。

## 11. SQLite 源与只读目录

- 读取命令只读打开已有当前 schema 的目录，不创建数据库、不执行迁移；旧 schema 返回 `schema_incompatible`，迁移必须通过持 writer lease 的显式写路径。
- OpenCode/Cursor 活库以只读事务下的 Backup 捕获逻辑快照（上限 128 MiB），包含已提交 WAL；不得写入或 checkpoint 用户源库。源路径保留为 locator，指纹采用 `sqlite:<BLAKE3>`。
- 一份源可携带多个消息级 Session observation 和独立 resume claims；无 native ID 的 source-local key 不得冒充可恢复的 provider ID。解析版本 2 强制重新解析旧扫描；历史有效 `ses_v1` 派生规则保持不变。

## 12. Managed Beta contracts (implementation in progress)

This section specifies the approved managed-mode transition and records current
implemented seams separately from remaining requirements. The development
checkout includes setup, control, evidence and update commands; their presence
is not a complete Beta or published-package acceptance claim. Sections above
describe legacy behavior where explicitly marked as current.
Normal reads and indexing remain offline; only explicit installation or
program-update actions may invoke a bundled HTTPS helper.

### Authority, scope and publication

Private `control.db` owns selections, exclusions, pause and maintenance intent.
Permission is the union of enabled provider roots/exact files minus that
provider's global exclusions, intersected with explicit request restrictions.
Revoking an exact file covered by a selected parent excludes it from the parent
too. Catalog claims are eligibility evidence, never independent permission.
Every control mutation compares and advances `control_seq`; it only updates
the fields owned by that operation. Corrupt or missing control alongside a
managed catalog marker fails closed instead of falling back to unscoped reads.

Canonical IDs stay unchanged. Managed original text and metadata come from
verified per-source projections, not the longer merged legacy payload. An
individually complete source can become usable during partial root backfill.
Partial source parsing and unconfirmed rewrite/deletion publish no new managed
evidence; prior verified evidence remains available with honest update state.
Explicit managed import must be selected before reading source content; pause
cannot be overridden implicitly. Source database/WAL bytes and history content
are read-only; live SQLite SHM reader bookkeeping may change.

All matching, ranking, context, native resume, facets, counts and rendering use
the same allowed projections and qualifying occurrences before candidate caps.
FTS5 matching semantics remain shared with legacy queries, while managed BM25
statistics use distinct allowed logical variants. Copies cannot increase rank
merely by multiplying sources. Vector jobs bind projection/model identities,
reject stale work and disclose partial semantic coverage. Native paths/IDs are
explicit Resume Metadata, not default searchable/output metadata.

### Reads, pause and revocation

Each response uses one catalog snapshot. Latest waits happen before opening
that snapshot and require source/discovery observation receipts from a cycle
that started after admission; wall-clock time and catalog health are not proof
of freshness. Ordinary requests may return permitted stale evidence. Paused,
offline, busy or unmet latest requests return concrete bounded partial state.
Requests share one deadline across waiting, SQL, retry, rendering and emission.

MCP annotations describe side effects without changing client approval settings.
Legacy tools declare local read-only/idempotent reads. Managed tools accept
latest requests and may enqueue private observations or retain/evict regenerable
continuation caches; they declare readOnlyHint=false, destructiveHint=false,
idempotentHint=false and openWorldHint=false. These internal effects never change
source history, permissions, desired updates or authoritative catalog evidence.
No network service is contacted by the MCP retrieval handlers.

A managed get_message with around=0 reads the exact permitted message occurrence
without depending on the selected whole-session branch. If a requested nonzero
neighborhood lacks that anchor on the mainline (for example, ignored provider
metadata separates the parent chain), return only the verified anchor and
context_unavailable. Do not fabricate edges or neighboring conversation text.

Revocation first commits the deny and a durable intent, then drains prior
evidence emissions with separate OS owner/emission locks. Success is reported
only after no old-policy write can follow that acknowledgement; stalled holders
produce `scope_revoking`, not a forged success. OS lock ownership cannot be
stolen by a timestamp. Physical purge runs separately and reports pending or
blocked cleanup honestly. Already delivered host/user copies are outside ASG
ownership. Physical cleanup is whole-file work — FTS `optimize`, integrity
checks and `VACUUM` cannot be split — so its slice is sized from the catalog
instead of the 5 s admission slice and doubles after a miss; while it runs it
holds the catalog, writer and emission locks, and ordinary reads receive a
bounded busy response until the slice ends.

Managed continuations retain a bounded result set: 512 canonical candidates,
4 MiB per set, 64 sets/64 MiB total, and a 15-minute TTL. Generation is recorded
for as-of disclosure, not compared for equality after an append. Policy,
destructive evidence change, model change, restore or expiry invalidates the
relevant cursor. Cache failure retains a bounded one-shot response and reports
`continuation_unavailable`; it never fabricates an empty search or page one.

### Installation and recovery

The package path requires no Rust toolchain. A stable launcher validates a
version pointer, target, contained regular files and SHA-256, then executes an
immutable application version. Unix uses exec; Windows preserves inherited
stdio and child exit behavior. The launcher is not a publisher signature.
User login lifetime, owned host configuration and history update have separate
observable setup stages; config presence does not prove a model call.

Host configuration edits preserve unrelated settings, record ownership and
durable transaction state, and use displaced-original-preserving replacement.
Malformed input, a changed owned node or an unresolved concurrent writer ends
in a bounded conflict with private recovery artifacts. Uninstall compares the
parsed owned node and leaves user-modified entries intact.

All Beta catalog handles participate in a connection-lifetime lock. Upgrade
holds a durable maintenance fence and exclusive handle lock before mutation.
The required first migration from a legacy catalog must build a separate
managed catalog, without pretending old processes honor new fences or mutating
their open inode. That migration is not implemented by the current update path.
Program updates are user-triggered. Restore never restores older control
permissions: it rotates catalog incarnation, invalidates freshness/continuations
and retains current pause/revoke intent. Withdrawn or unclassified backup data
cannot be a restore fallback; verified forward repair or explicit attention is
required when no permitted rollback image remains.

The required default managed uninstall must remove ASG-owned index/cache/backup
state after draining owned components. Explicit keep-data must retain catalog
and policy together, including pending purges. That workflow and keep-data are
not yet implemented; the legacy source uninstaller does not supply them.
Original assistant histories must never be removed. Four native targets and all six required assistant flows, including
actual retrieval quality/token/latency evidence and owner daily-use acceptance,
remain release gates; foundation tests alone cannot close them.

### Current development program-update commands

The CLI parser/help exposes `update check`, `update apply --from <archive>`,
`update status` and `update recover`, with optional `--install-prefix <prefix>`.
Apply/recover use `--db <catalog>` for the same managed catalog recorded by the
update. These explicit commands are separate from evidence/MCP/background work;
ordinary reads never invoke an update helper or upgrade the program.

`check [--channel beta|stable]` verifies the installed identity and invokes only
its manifest-whitelisted packaged helper (built from
`scripts/install/update-check.ps1` or `scripts/install/update-check.sh`)
inside the immutable version directory. Both helper members and hashes are
required. Existing Windows PowerShell runs without execution-policy bypass;
Unix uses `/bin/sh` and discovered `curl`/`wget`. Helper arguments contain only
public release coordinates, never history/query/catalog/credentials. The helper
returns bounded `asg.update-fetch/v1`; Rust validates metadata size/digest/final
URL before returning `asg.update-check/v1` as the Robot `data` value. Status is
`up_to_date` or `update_available`, with selected version/tag and asset digests.
Check fetches inventory/checksums/manifest, never the archive. `--offline` refuses
check before transport.

Default channel derives from the installed SemVer. Stable excludes prereleases;
beta admits newer prereleases and stable releases. Drafts do not qualify.
Selection uses highest eligible SemVer precedence and matching required assets,
with at most three 100-release pages. A full exhausted inventory is an error,
not a guessed current result. Inventory uses the exact HTTPS `api.github.com`
endpoint; asset redirects permit only `github.com`,
`objects.githubusercontent.com` and `release-assets.githubusercontent.com`.
Three redirects/two transient retries share one 30-second check deadline.

Apply is offline and requires `.zip`/`.tar.gz`, its sibling `.manifest.json` and
`SHA256SUMS`; `--manifest`/`--checksums` override the sibling defaults. Current
apply requires a newer SemVer, the same target and equal catalog/control schemas.
A schema change is `schema_incompatible` (exit 9) before maintenance/catalog
mutation. There is no online apply, downgrade or force-migration switch. Package
checks cover checksums, layout/identity, bounded sizes, exact member set,
duplicate/case-colliding names, unsafe paths, links/special members, hashes/modes,
helper pair, native headers, current/release metadata and the candidate's
content-free build-info. Unsigned hashes are consistency evidence, not publisher
authentication.

The current package has 19 payload records plus `PACKAGE-MANIFEST.tsv`. Its 12
metadata fields include `supervisor` and `supervisor_sha256`; helpers are normal
hash-bound file records under the immutable version. Windows supervisor headers
must identify the x64 GUI subsystem. `release.json` keeps its strict existing
identity fields. First-install `asg.package-install/v1` receipts bind archive,
manifest and file inventory; coordinated update's v2 receipt also binds retained
launcher hash and active pointer hash/generation. Verified manifest/checksum
copies remain installed for later validation.

Apply persists a private `asg.update-state/v1` journal under real installation
lock ownership. It fences maintenance, drains cooperating catalog handles,
creates a verified logical catalog backup without control, stages an immutable
version and journals owned metadata/pointer changes before active verification.
Initial control/catalog checkpoint is immutable; a separate post-drain checkpoint
binds the backup to the drained identity. Background supervisor and worker locks
also drain before package effects. Candidate process exit must be successful;
active identity and exact pointer generation must match. The equal-schema
`migrated` phase is a verified no-op, not a migration receipt.
State reports are content-free: phase/sequence, from/to versions, target, pointer
generation, cleanup/recovery flags, bounded error code and `freshness: unknown`.
`status` inspects a retained journal, potentially reconciling interrupted
journal-file publication, without catalog recovery or worker start. A new install
without a journal has no idle-status response yet. Terminal `failed`/`rolled_back`
is a successful inspection, not successful upgrade; nonterminal state is partial
(exit 10). Apply returns an existing unfinished state instead of starting again.
Replacing a terminal journal is a hash-bound supersede transaction: all update
preflight finishes before the old terminal state is superseded, both complete
images are durable before publication, and the active `state.json` name never
disappears. Recovery accepts every complete staging side, including a Unix
exchange interrupted before the displaced old image moved, and finishes the old
archive before removing the intent.

`update_recovery_required` is a canonical business error (exit 10,
`retryable: false`, `partial_allowed: true`). It directs inspection of status and
explicit recover using the same prefix/catalog; it never authorizes deleting
locks, control, journal or receipts. Recover verifies observed ownership and
metadata effects, can finish an already switched candidate, or reconcile old
owned metadata for the equal-schema rollback. Rollback rotates incarnation and
invalidates freshness/progress/barrier/confirmation/continuation proof while
preserving current pause/stop/revoke policy. This is not generic backup restore
or legacy-to-managed migration. A recorded `restart_failed` self-check never
continues forward; recover selects rollback and reuses one recovery incarnation
so a repeated recover does not rotate or increment again.

Forward completion starts the verified next-version supervisor only for current
running intent, using the owned native registration or a hidden detached launch
without enabling autostart. Launch/readiness rechecks pause/stop; intentional
changes preserve that intent, while `restart_failed` under running intent keeps
the journal nonterminal and returns partial for recovery. Rollback restarts the
verified old supervisor when current intent is still running. Neither
completion nor heartbeat establishes refreshed history, actual host MCP reload
or native login identity. Update binds the private owned native-registration
receipt chain before replacing its supervisor command, and rollback reconciles
the original owned command. Unowned/changed/ambiguous registration is not adopted;
autostart is not newly enabled. Manager reload/readback is distinct from a login
receipt. Explicit selected-host setup remains available for registration/host
repair. Native two-version recovery, schema-changing/legacy
repair. A Windows x64 private same-schema two-version rollback/recover drill has
passed; schema-changing/legacy migration, other native targets, managed
uninstall, six-host flows and measured latency acceptance remain separate open
requirements. Setup history selection continues
through separate `sources add`; public background autostart enable/disable,
managed uninstall/default purge and keep-data are still unimplemented.

### Current development control commands

`setup` creates or validates a private managed catalog and reports individual
stages. Selected-host setup has local/configuration/native-manager stages but
remains partial (exit 10) while actual host recognition/model calls or login
acceptance are pending. Existing legacy catalogs
require explicit side-path migration. A per-catalog managed creation intent is
persisted before file creation; legacy opens reject that path even when a crash
left an empty header. The intent grants neither ownership nor recovery rights.

`sources add --provider <id> <root-or-file>` verifies the locator without reading
history content and records the enabled selection. It preserves all exclusions.
`sources list` reports opaque selection IDs and providers without private paths.
`sources revoke <selection-id>` persists deny before draining the emission gate;
the response distinguishes `revoked` from bounded `scope_revoking`, and always
reports outstanding physical cleanup. `background start|status|pause|resume|stop`
records desired intent separately from actual worker state and unknown coverage.
These controls do not claim that a host loaded ASG or an update became searchable.

Adding an eligible selection while desired updates are running starts the
worker; resume also starts it. A live OS lock plus registration establishes
worker liveness, never freshness. Windows background creation inherits no
caller handles, so the control command can finish its output while the worker
continues. Selected-host setup writes native login configuration and verifies
its manager stage using the owned receipt and exact program arguments. Linux
requires typed user-manager readback before a start request; macOS verifies the
GUI domain and loaded arguments. Native output stays private. Errors preserve
completed configuration receipts and leave setup partial. A lock or active-unit
claim alone never proves the running package identity; actual native login
remains a separate pending acceptance stage.

### Managed CLI evidence reads

Managed catalogs use a separate CLI composition path for `search`, `get`, `show`,
`list`, `status`, `context`, `get-message`, and `get-session-resume`. This path
never constructs the legacy Application/store. Executable resume and
other unimplemented managed commands return `capability_not_supported`; they
cannot fall back to unscoped reads. A missing/corrupt control store or mismatched
catalog/control identity fails closed, including when a durable managed catalog
marker or creation intent remains after control removal.

Provider, repository, half-open time, system-message and facet restrictions apply
to every request, including direct IDs and context enrichment. `--include-system`
must be explicitly enabled for system/developer messages; it does not loosen any
other restriction. Unknown/duplicate flags, malformed IDs and invalid budgets are
rejected before content reads. Ordinary reads remain available while ingestion
is paused. Revocation removes all forbidden search, direct-ID, list and aggregate
evidence under the same immutable policy and catalog snapshot.

The current defaults are five retained items/messages and an 8 KiB complete
frame, including envelope, provenance, freshness, escaping and trailing newline.
`--max-items`, `--max-messages` and `--max-bytes` retain the shared Application
budget validation (minimum 4096 bytes; maximum frame 4 MiB). Final serialization
overflow permits at most eight smaller Application renders inside the same read
snapshot and the original request deadline. Budget reduction is reported as
partial; evidence is never silently removed after rendering. A response that
cannot fit fails with a bounded invalid-request error. No legacy stateless cursor
is accepted or issued. All Application partial reasons affect outcome/exit 10,
even when the legacy response ADT has no truncation field.

`data.provenance` projects only canonical entity/provider/session/message/
placement/document anchors, verified revision digests and `byte|unknown`
precision. It never serializes private source/projection IDs, source locators,
installation IDs, worker IDs or native resume identifiers. Related supporting
claims disclose their revision digests without inventing canonical anchors.
`get-session-resume` remains the sole explicit read command allowed to return
its separate native Resume Metadata. Shared redaction runs before crossing the
output boundary, including structured JSON nested inside legacy string payloads.

`data.snapshot` discloses generation, destructive epoch and policy epoch.
Ordinary `data.freshness` reports `coverage=empty|partial|complete` from the
newest selected discovery and exact source receipts in the same catalog snapshot.
Coverage is as of that observation; it never asserts a post-request observation
and `latest_satisfied` remains false. Worker `update_state` is independent
(`running|idle|paused|stopped|offline|busy|failed|deferred|upgrading`). Selected and
complete scope counts disclose backfill, while contributing/verified/pending/
failed source counts and the oldest verified contributor observation time are
content-free. Direct evidence counts only its allowed proof contributors;
failed noncontributing sources cannot appear in those counts. Discovery coverage
remains selected-provider relevant even when project/time predicates narrow
output. Generation, heartbeat and health alone never prove coverage. `--latest` admits a
durable control barrier against the current selection revisions and root
identities, with at most three CAS attempts. It joins only a queued, not-started
compatible cycle. Provider restrictions limit discovery relevance; project/time
restrictions cannot exclude undiscovered sources. Direct IDs resolve provider
and stored identity from permitted typed projections, without inferring a
stability tier from a wire ID. Their final content is read again in the output
snapshot after admission.

Waiting releases each short catalog snapshot. Only matching post-admission
discovery and exact published source receipts, verified by `latest_satisfied`
inside the final output snapshot, permit `reason=verified` and
`latest_satisfied=true` (`coverage=complete` for that requested barrier). Control completion, an unrelated generation and an
old observing cycle do not suffice. Unsatisfied reads retain permitted evidence
with partial outcome and a bounded reason such as paused/stopped/offline/timeout
or policy_changed. No read starts a worker or resumes ingestion. OS worker-lock
availability can identify offline state; contention never proves freshness.

`--max-wait-ms` requires latest and is 0..30000, default 5000. Zero wait still
admits and checks once. The original monotonic request deadline is ten seconds
for ordinary reads and `max(10000, max_wait_ms + 5000)` milliseconds for latest.
Admission, waiting, SQL, retry, rendering and emission share that deadline.

MCP calls use `prepare_mcp(&Path, McpReadInput)` and the same pipeline. Input
contains a typed AppRequest, normalized filters for all operations, RPC id,
latest/wait values, start instant and an optional trusted static data override
for scoped Status requests. Output holds already-redacted payload plus private
emission authority, with no database handles retained. Search preserves its
typed facets/system option; non-search MCP requests currently exclude system
messages. Static provider/doctor data receives the same freshness and snapshot
before redaction. The exact `managed_result_frame` serialization, including RPC
id, duplicated `content[0].text`, `structuredContent`, escaping and newline, must
fit the final budget. The consumer must not modify the returned payload.

The complete prepared frame is passed to the ASG-owned emission helper with the
captured physical root identity, installation and policy epoch. The helper checks
current control under the shared emission gate. Deadline/I/O/unconfirmed-helper
termination stops this stdout transport; no normal error envelope is appended
to a possibly partial evidence frame. A pending helper never becomes a false
revocation acknowledgement. This composition contract does not certify all
MCP/TUI/Web routing, native cross-platform cancellation or full Beta acceptance.
For `doctor --db`, a sibling `control.db` selects this managed read path instead
of the legacy store reader. The managed response reports `managed: true`, a
bounded catalog check and its control-authorized snapshot, while
`diagnostics_complete: false` prevents that check from being advertised as
full freshness or host verification.

### Managed MCP transport and discovery recovery

Managed stdio MCP reuses the existing nine-tool protocol validator. Each tool
call opens only the current managed catalog; idle connections retain no SQLite
catalog handles. Unknown tools remain protocol errors, while private store and
Application failures remain sanitized business errors. The managed tool catalog
reports currently unavailable continuation features explicitly.

Managed requests accept JSON-RPC string IDs of at most 128 Unicode characters.
Oversized IDs are rejected with a bounded invalid-request frame and null ID;
they are never truncated into a different correlation ID. Input frames larger
than 1 MiB close the transport. Evidence responses obey the caller's complete
frame budget; sanitized errors stay within the minimum 4096-byte budget.

Content-free protocol and sanitized business-error frames use a separate
cancellable helper without acquiring the evidence gate. Ping and busy/error
responses therefore remain available during maintenance or pending revocation.
Only prepared evidence frames use the shared policy gate. In either path,
partial output or unconfirmed cancellation ends the transport; no later frame
is appended. StructuredContent and the text compatibility copy are identical.

Before a selection's filesystem discovery begins, the worker persists an empty
incomplete discovery receipt. Failed enumeration, a new malformed source or a
crash leaves that receipt incomplete, so no older complete receipt can prove
latest. The same cycle/policy/root/incarnation may promote it to complete only
with the exact published source set; completed receipts remain immutable.
Confirmed-absent source receipts are included in that set even though they are
absent from the live file enumeration. A repaired source progress mirror can
recover a committed receipt from an earlier worker boot; it remains partial
until another verified observation and cannot restore permissions or pause.

The current background worker supports selected Claude/Codex JSONL roots and
exact files; other provider adapters do not establish managed background coverage.
It holds its independent OS lifecycle lock for its full lifetime and polls at a
one-second ordinary cadence. Pause stays resident without source I/O;
stop or maintenance causes intentional exit 0 and releases catalog/lifecycle
handles. Full fingerprints and before-open/before-commit root, component and
current-policy checks govern source publication. Empty/malformed/unstable
rewrites keep the last complete projection. Nonempty fully parsed rewrites,
including shrinking JSONL, and absence need distinct qualifying observations
at least five monotonic seconds apart. Boot/restart, changed candidate/root or
policy/cycle mismatch restarts the confirmation proof. Offline/unreadable or
partial root discovery cannot confirm deletion. This grace is not a measured
five-second performance claim. Automatic rename/alias identity preservation and
full overlapping-root acceptance are not certified by this documentation.

### Managed evidence packs

CLI `handoff <query>` and MCP `generate_handoff` reuse the deterministic pack
generator inside the same authorized snapshot. Each retained passage, span,
source document and tool activity must match the exact searched source proof;
the legacy locator resolver is inaccessible. Provider, repository and time
restrictions apply throughout enrichment. Unavailable enrichment remains partial.

Defaults are five candidates/evidence items, 2048 estimated tokens and 8192
complete output bytes. The current handoff query bound is 256 Unicode characters;
at most 500 candidates are admitted. Explicit budgets may increase these output
limits within the ordinary frame cap. Final MCP serialization still includes
both payload copies and shares the original request deadline. Pack source
locators contain canonical document anchors; no source path or legacy cursor
hint is returned. A pack neither executes history nor launches another assistant.
