# ADR-0009：会话恢复信息采用双 ID 与渐进披露

> **编号冲突警告**：本仓库有**两个** ADR 声明 `decision_id: ADR-0009`——本文件
> （会话恢复元数据，status **Accepted**）与
> `ADR-0009-cross-boundary-output-redaction.md`（跨边界输出默认脱敏，status
> **Proposed**）。两者的决策内容与状态都不同，因此裸引用「ADR-0009」是歧义的：
> 核对引用时必须看上下文——谈 resume/双 ID/`get_session_resume` 的指本文件，谈
> 脱敏/Robot/MCP/Web 输出边界的指另一份。改号需要同步约 90 处引用（含 20 个源码
> 文件的注释），属 owner 决策，未执行前保留本警告。

> 治理记录（Governance Record）
>
> - decision_id: ADR-0009
> - title: 会话恢复信息采用双 ID 与渐进披露
> - status: **Accepted（2026-08-14 契约冻结并进入实施；实现完成后由验收人确认）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: post-0.3
> - evidence_path: RFC-0001 §3.2/§5；CC-Switch `f748f3a` Session Manager 对读；Claude Code `--resume` 官方文档；本轮 Provider/协议/隐私对抗审查

## 决策

agent-session-grep 应提供只读的历史会话恢复信息，帮助用户或 Agent 从全文搜索命中定位并继续 Provider 原生会话。保留 canonical `session_id`（`ses_v1_*`）用于 Catalog 关联，另存精确、可空的 `provider_session_id`；原始工作目录以 `original_working_directory` 表达，不从 transcript 路径推断。Search 仅返回 `resume_available`，显式调用 `get_session_resume(canonical_session_id)` 才返回固定、可空的恢复元数据。第一版只返回结构化数据，不构造 shell 字符串、不启动终端、不执行恢复命令，也不暴露 transcript/source path。

## 背景

用户需要让 Agent 搜索旧对话后直接给出继续该会话所需的信息，避免手工翻历史记录和查找原生 Session ID。CC-Switch 证明了 `provider + native session id + optional cwd` 的产品价值，但其内存 metadata search、raw `resumeCommand`、`sourcePath` UI identity 和终端执行不适合本项目的持久化 Canonical Catalog、Robot/MCP、响应预算与源只读边界。canonical ID 与 Provider Session ID 解决不同问题：前者防止跨 Provider 冲突并维持内部关联，后者是 Provider resume 所需的精确值，二者不可互换。

## 后果

- `resume_available` 由 Provider 具备已认证的 resume 能力且存在唯一、可信的 `provider_session_id` 决定；cwd 缺失或后来失效不把可恢复会话误判为不可恢复。
- `get_session_resume` 固定返回 canonical session ID、Provider ID、Provider Session ID、Original Working Directory、availability 与不可用原因；未知或歧义值为 `null`，不省略、不猜测、不删除仍可检索的历史。
- Provider-native Session identity 必须先加入 Provider/installation namespace；多 Session transcript 不再以 first-wins 元数据宣称可恢复。
- Resume 元数据单独持久化并按显式请求披露，不写入普通 Session payload、FTS、Search 文本、错误、日志或 progress frame。
- Robot schema 需发布兼容的 minor 版本；MCP 增加只读 `get_session_resume` 工具，并对最终双载体 frame 重新证明字节预算。
