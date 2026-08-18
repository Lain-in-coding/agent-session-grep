# RFC-0001：Canonical Model 与 Stable ID

> 治理记录（Governance Record）
>
> - decision_id: RFC-0001
> - title: Canonical Model 与 Stable ID
> - status: **Draft**（待 R0 Architecture Review）
> - owner: （待指派，负责起草与证据收集）
> - approver: 项目最终验收人（架构师本人；owner 与 approver 不得为同一人）
> - contributors: —
> - due_milestone: R0 Feasibility / Contract Gate
> - deadline: （R0 timebox 内）
> - evidence_path: `docs/architecture/RFC-0001-canonical-model-and-stable-id.md`、`spikes/source-snapshot/`、R0 脱敏 fixture
> - approved_at: —
> - exception_expiry: —
>
> 本 RFC 是 Canonical Model 与 Stable ID 的规范性来源；Provider 边界见 `RFC-0002-provider-adapter-contract.md`，入口 DTO 见 `../contracts/CONTRACT-cli-robot-mcp-draft.md`。在本文状态转为 Accepted 前，开放项仍按 §7 管理。

---

## 1. 背景与问题

agent-session-grep 需要把 Claude Code、Codex、CodeBuddy、Pi、Cursor 等 Provider 写入本机的异构历史记录，归一化到一个稳定的领域模型，使 CLI、Robot、MCP、TUI 能在其上提供一致的检索与渐进披露。

Canonical Model 要解决四个根问题：

1. **身份稳定**：同一逻辑会话/消息在文件被移动、重命名、增量追加、重新扫描后仍映射到同一 ID；调研中 `agent-sessions` 用全局 `session_id` 主键导致跨 Provider 同 ID 相互覆盖，是必须规避的确认缺陷。
2. **分支/重试语义**：Retry、Fork、Subagent、continuation 会形成非线性对话拓扑，线性 ordinal 无法表达。
3. **内容去重与归属**：同一内容可能在多个 Source 中出现；删除一处引用不得误删仍被其他 Source 引用的内容。
4. **缺失与删除区分**：权限拒绝、暂时离线、永久删除必须是不同状态，只有一次完整成功的 Root Scan 才能确认消失。

## 2. 决策摘要

- Canonical Model **不是各 Provider 字段的并集**；缺失字段保持 `null/unknown`，禁止用 mtime 或当前时间伪造消息时间。
- 逻辑身份与物理位置**解耦**：物理 root、绝对路径、可变 locator 不得进入 Session/Message 的首选逻辑身份。
- 身份稳定等级**显式暴露**为 `native | reconstructed | unstable`，不做虚假承诺。
- 内容去重 v1.0 采用**单层 `content_hash`**；完整三层 `ContentBlob`/`ContentOccurrence`/`SourceMembership` 只有在 R0 用真实脱敏 fixture 证明"跨 Source 重复引用确有发生"时才进入 v1.0，否则降级为 post-1.0（本 RFC 的核心开放项，见 §7）。

## 3. 核心实体

字段带 `?` 表示可空/可缺失。

### 3.1 Source 层

```text
SourceInstance
- id: SourceInstanceId
- provider: ProviderId               # 普通值，非 SQL CHECK 枚举
- installation_identity?: InstallationNamespaceId
- current_root_locator
- previous_root_locators[]
- display_name
- format_variant
- adapter_contract_version
- adapter_version
- capabilities
- last_scan_status

SourceDocument
- id: SourceDocumentId
- source_instance_id: SourceInstanceId
- current_source_locator
- location_independent_fingerprint?
- file_identity?                      # 平台文件身份（inode/file-id）
- size
- modified_at                         # 见 §6 mtime caveat
- content_fingerprint                 # 增量判断的权威
- parse_status
- first_seen_scan
- last_seen_scan
- missing_since?
- deletion_reason?
```

### 3.2 会话与拓扑层

```text
Session
- id: SessionId
- identity_stability: native | reconstructed | unstable
- provider: ProviderId
- source_instance_id: SourceInstanceId
- provider_session_id?
- title?
- summary?
- project_path?
- working_directory?
- repository_root?
- git_branch?
- created_at?
- updated_at?
- completeness

ConversationThread
- id: ThreadId
- session_id: SessionId
- parent_thread_id?: ThreadId
- thread_kind

ConversationBranch
- id: BranchId
- thread_id: ThreadId
- head_message_id?: MessageId
- branch_kind
- is_default: bool

Message
- id: MessageId
- identity_stability: native | reconstructed | unstable
- session_id: SessionId
- thread_id: ThreadId
- branch_id?: BranchId
- branch_local_ordinal                # 仅排序，不作身份
- provider_message_id?
- role
- author?
- created_at?
- completeness

MessageEdge
- parent_message_id: MessageId
- child_message_id: MessageId
- relation: reply | retry | fork | continuation | subagent | tool_result
```

### 3.3 内容层

```text
ContentBlob
- content_hash                        # v1.0 去重基线
- canonical_bytes
- media_type

ContentOccurrence                     # 完整三层时启用，否则内联进 Message
- id: OccurrenceId
- message_id: MessageId
- block_ordinal
- content_blob_id?
- kind: text | code | reasoning_summary | tool_call | tool_result |
        attachment_ref | metadata | unknown
- language?
- tool_name?
- tool_call_id?
- bounded_structured_payload?
- redaction_state
- source_span: SourceSpan

SourceMembership                      # 完整三层时启用
- occurrence_id: OccurrenceId
- source_document_id: SourceDocumentId
- first_seen_scan
- last_seen_scan
- missing_since?
- deletion_reason?

SourceSpan
- source_document_id: SourceDocumentId
- byte_start?
- byte_end?
- line_start?
- line_end?
- record_ordinal?
```

## 4. 分支感知（Branch-aware）规则

- `show` 与 `get_session_context` 必须返回 Thread/Branch 标识；
- 存在歧义分支时不得由 CLI、MCP、TUI 各自猜测；默认分支选择规则属于 Application Contract，无法确定时返回候选分支供调用方选择；
- `before/after` 沿指定 Branch 的 parent/child path 展开，不按全局 ordinal 粗切。

## 5. Stable ID

ID 使用带类型和算法版本前缀的 BLAKE3 表示：

```text
src_v1_...   # SourceInstance
doc_v1_...   # SourceDocument
ses_v1_...   # Session
msg_v1_...   # Message
```

身份优先级：

```text
Session: Provider 原生 Session ID
      → Provider 可证明稳定的逻辑复合键
      → 规范化内容/结构指纹重建
      → unstable fallback

Message: Provider 原生 Message/Event ID
      → Parent Identity + 规范化事件指纹 + occurrence key
      → 内容指纹 + 相邻稳定锚点
      → unstable fallback
```

约束：

- 原生身份至少为 `provider_id + stable_installation_namespace + native_id`；无法取得稳定 namespace 时不得标记为 `native`；
- `ordinal` 只负责排序，不作正式逻辑身份；中间插入记录不得让后续 Message ID 漂移；
- 路径移动由 relocation matching 更新 locator，必要时维护 `id_alias`，不得因目录迁移级联改变 Session/Message ID；
- ID 不包含可逆正文，不依赖数据库自增值；
- 明确路径大小写、分隔符、Unicode normalization 规则；
- 相同源数据在声明的稳定等级范围内重建一致；
- ID 算法升级使用新 namespace，不静默改变旧 ID。

### 5.1 InstallationNamespaceId

- 优先使用 Provider 原生稳定 installation ID；
- 否则由本地 installation registry 分配并持久化 namespace，通过 relocation evidence 续接，**不从当前绝对路径直接派生**；
- registry 丢失后的重建必须降级为 `reconstructed/unstable`，不能承诺原 ID。

## 6. 实现 caveat

- **mtime**：避免 `as i64` 纳秒截断（>2262 溢出）与 Windows/Unix 粒度差异；增量指纹以 `content_fingerprint` 为权威，`mtime`/`size` 仅作快速跳过前置条件。
- **隐藏思维链**：不得被推断、解密或特殊暴露；只接受 Provider 明确写入且允许读取的可见摘要。

## 7. 开放问题（R0 必须裁决）

1. **ContentBlob 三层是否为真实需求**（阻断级）：需在 R0 用真实脱敏 fixture 证明"同一内容跨多个 Source 重复引用"确实发生。有证据 → 三层进 v1.0；无证据 → 仅 `ContentBlob.content_hash` 单层去重，Occurrence/Membership 降级 post-1.0。决策记入 `docs/adr/`。
2. **`id_alias` 保留周期**：relocation 后旧 ID 别名保留多久，需明确上限，不能无期限隐式兼容。
3. **规范化指纹算法**：重建身份所用的"规范化内容/结构指纹"的确切归一化规则（空白、Unicode、字段顺序）需冻结并版本化。
4. **`completeness` 取值域**：Session/Message 的完整度枚举需定义（如 `complete | truncated_head | truncated_tail | partial`）。

## 8. 备选方案（已否决）

- **全局 `session_id` 主键**：`agent-sessions` 的做法，跨 Provider 同 ID 覆盖，否决。
- **线性 ordinal 作身份**：无法表达 retry/fork，且中间插入导致级联漂移，否决。
- **路径派生 ID**：文件移动即全量 ID 变化，与 local-first 场景冲突，否决。

## 9. R0 退出映射

本 RFC Accepted 的判据：

- §7 四个开放问题均有裁决或明确降级 ADR；
- 提供至少一组真实脱敏 fixture 支撑 ContentBlob 三层的 go/no-go；
- Stable ID 的 relocation、ordinal insertion、alias、stability 分级有对应的 property 测试方案（实现在 `0.1` 之后）；
- owner 与 approver 签署，并在治理记录中填写批准信息。
