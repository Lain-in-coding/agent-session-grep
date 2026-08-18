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
关键码: source_changed | writer_busy | cursor_invalid | cursor_expired | generation_mismatch |
        snapshot_failed | catalog_error | schema_incompatible | provider_error | internal |
        invalid_request | not_found
Exit Code(权威为 `schemas/robot/v1/error-catalog.json` 的 13 码): 0 成功 / 2 校验(invalid_request, cursor_invalid) / 4 不存在(not_found) / 5 IO(source_io, source_changed, snapshot_failed) / 6 Catalog(writer_busy, catalog_error) / 7 Provider / 9 协议(schema_incompatible, generation_mismatch) / 10 部分成功 / 70 内部。无 3(配置)与 8(安全)退出码。
- `get`/`show` 对缺失实体统一 exit 4 + `not_found` envelope，不返回 exit 0 + `payload:null`（ADR-0005，已实现）。

## 6. Output Truth Table（stdout/stderr 契约）

模式 human/json/jsonl/--robot/MCP 各自冻结: stdout frame、stderr、颜色、进度、warnings、零结果、
部分成功、fatal、broken pipe、取消、exit code。
- Robot JSON 单 envelope；Robot JSONL 只允许版本化协议 frame；进程诊断永远走 stderr。
- `--help` / `--version` 在任何输出模式下恒 exit 0（语义上不是错误）：human 模式打印文本；robot/json/jsonl 模式返回 success envelope，帮助文本/版本号置于 `data.help_text` / `data.version`（ADR-0006，已实现）。
- MCP stdout 只允许合法 MCP frame，panic/backtrace 不得污染 stdout。

## 7. Cursor 生命周期（无状态保留模型）

- Cursor 自包含并签名: contract_major/generation/issued_at_ms/expires_at_ms/query_digest/sort_digest/offset/result_set。`list` 与 `list_sessions` 的 result_set 判别器互斥——跨结果集复用 cursor 显式拒绝，绝不静默从第一页继续。
- 系统不登记活动 Cursor；GC 按 activation + max_cursor_ttl + clock_skew 保留旧 generation。
- generation 回收/协议不兼容/签名失败/超 TTL → 明确 cursor_expired*，绝不静默从第一页继续。
- 已由 sqlite-snapshot-wal spike 验证：旧 generation 快照在新写入期间可只读打开，支撑分页 pinning。

## 8. MCP 契约

tools: search_sessions / get_session_context / get_session_resume / get_message / list_sessions / generate_handoff / list_providers / get_status / doctor
- `get_session_resume`（ADR-0009，只读 Resume Metadata）：入参 canonical `ses_v1_*`，返回固定可空字段（provider_id / provider_session_id / original_working_directory / resume_available / unavailable_reason）；绝不构造或执行 shell 命令、绝不返回 transcript/source path。
- `generate_handoff`：为查询组装 deterministic handoff pack（handoff-pack/v1）——证据带权威 source locator、预算（max_evidence/max_tokens/max_bytes）真实裁剪、默认跨边界脱敏（ADR-0009）；截断如实报 outcome partial。
- 固定并测试 protocol version、capability negotiation、tool schema、错误映射、取消、超时、shutdown。
- handler 只校验协议 + 映射 ADT，不复制搜索/分支/分页/预算规则。
- 不提供任意文件读取、SQL 或命令执行。取消/超时后不留半提交 Catalog 或活动 IndexWriter。

## 9. Search 查询语义（plain-text-only）

`SearchRequest.query` 只支持 plain-text 关键词：按空白切分的字面 token、隐式 AND。FTS5 操作符（`AND`/`OR`/`NOT`、`NEAR(...)`、短语引号、前缀 `*`）**不是查询语言**，一律作为字面文本参与匹配；不存在高级查询语法（ADR-0003，已实现）。`safe_fts_query` 是该语义的强制边界，CLI/MCP/Port 入口共用。
