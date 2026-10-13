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
全部 14 码: invalid_request | not_found | source_io | source_changed | snapshot_failed |
        catalog_error | provider_error | capability_not_supported | writer_busy |
        schema_incompatible | cursor_invalid | cursor_expired | generation_mismatch | internal
Exit Code(权威为 `schemas/robot/v1/error-catalog.json` 的 14 码，实现镜像为 `protocol::CanonicalCode::exit_code`): 0 成功 / 2 校验(invalid_request, cursor_invalid, cursor_expired) / 4 不存在(not_found) / 5 IO(source_io, source_changed, snapshot_failed) / 6 Catalog(catalog_error, writer_busy) / 7 Provider(provider_error, capability_not_supported) / 9 协议(schema_incompatible, generation_mismatch) / 10 部分成功 / 70 内部(internal)。无 3(配置)与 8(安全)退出码。retryable 仅 writer_busy 与 source_changed 两码。
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

`SearchRequest.query` 只支持 plain-text 关键词：按空白切分的字面 token、隐式 AND。FTS5 操作符（`AND`/`OR`/`NOT`、`NEAR(...)`、短语引号、前缀 `*`）**不是查询语言**，一律作为字面文本参与匹配；不存在高级查询语法（ADR-0003，已实现）。`safe_fts_query` 是该语义的强制边界，CLI/MCP/Port 入口共用。

- 命中的 `text` 是 Application 装配的显示摘要（ADR-0008），不是索引原文：有可证明的字面命中时取该命中的原文连续窗口（≤ `max_snippet_chars` 字符，以最早命中为中心按 2 右 : 1 左 扩展，锚点自身超限时取锚点起始切片）；无字面证据（无匹配、语义-only）时回退正文前缀。不插入省略号/高亮等合成字符，大小写不敏感匹配按小写展开回映到原字符边界；窗口字节经既有命中级估算计入 `max_response_bytes`，排名/游标/`why_matched`/建议命令不受影响。human 模式的片段行在此摘要上按同一字面词元重新居中（≤120 字符，命中左侧约 40 字符上下文）；无词元/未命中/正文更短时保持原前缀预览。

## 10. Web 搜索参数与向量重建

- `GET /api/search` 与 `/api/projection/search` 支持 `q`、`mode`、`limit`、`max_bytes`、`cursor`、可重复的 `provider`、`since`、`until`、`repo`、`include_system`、`group_by_session`、`sidechain`、`tool_kind`、`tool_name`。`limit` 同时设置页大小和 `max_items`；没有独立的第二个 item 预算。`sidechain` 接受 `include|main_only|subagent_only`，布尔值只接受 `true|false`。
- 每个 `provider` 都进入 OR 集合，标量参数重复、未知参数、空参数及非法百分号编码返回 `invalid_request`；不静默丢弃过滤条件。Web 时间参数沿用 CLI 的绝对或相对时间语法；MCP 保持只接受绝对时间。
- `/api/status` 的 `data.web_capabilities` 公布实际搜索参数、重复参数、provider 取值和检索模式，并明确 `mutation_and_execution=false`。Web 仍为只读预览入口。
- `index embeddings` 以 128 行 keyset 批次扫描权威 catalog，只为含正文的 Message 编码；adapter 批次上限为 512。模型向量必须符合声明维度且全部有限。旧向量替换与 generation 推进在同一事务内完成，编码/写入失败回滚全部替换，原有向量与 generation 保持不变。

## 11. SQLite 源与只读目录

- 读取命令只读打开已有当前 schema 的目录，不创建数据库、不执行迁移；旧 schema 返回 `schema_incompatible`，迁移必须通过持 writer lease 的显式写路径。
- OpenCode/Cursor 活库以只读事务下的 Backup 捕获逻辑快照（上限 128 MiB），包含已提交 WAL；不得写入或 checkpoint 用户源库。源路径保留为 locator，指纹采用 `sqlite:<BLAKE3>`。
- 一份源可携带多个消息级 Session observation 和独立 resume claims；无 native ID 的 source-local key 不得冒充可恢复的 provider ID。解析版本 2 强制重新解析旧扫描；历史有效 `ses_v1` 派生规则保持不变。
