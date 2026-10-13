# ADR-0009:跨边界输出默认脱敏(修订 ADR-0004 适用范围)

> **编号冲突警告**:本仓库有**两个** ADR 声明 `decision_id: ADR-0009`——本文件
> (跨边界输出默认脱敏,status **Proposed**)与
> `ADR-0009-session-resume-metadata.md`(会话恢复信息双 ID 与渐进披露,status
> **Accepted**)。两者的决策内容与状态都不同,因此裸引用「ADR-0009」是歧义的:
> 核对引用时必须看上下文——谈脱敏/Robot/MCP/Web 输出边界的指本文件,谈
> resume/双 ID/`get_session_resume` 的指另一份。改号需要同步约 90 处引用(含 20 个
> 源码文件的注释),属 owner 决策,未执行前保留本警告。

> 治理记录(Governance Record)
>
> - decision_id: ADR-0009
> - title: 跨边界输出默认脱敏
> - status: **Proposed(2026-08-15,owner 决策确认)**
> - owner: QIN
> - approver: 项目最终验收人
> - due_milestone: 开源发布门
> - evidence_path: `docs/adr/ADR-0004-output-time-snippet-redaction.md`
> - governance: status=Proposed is a design decision only; the release gate
>   accepts this rule only after owner/approver records `accepted_at`, approver,
>   implementation evidence and passing cross-boundary fixture tests. Until then,
>   no roadmap or other document may claim the ADR is Accepted.

## 决策

Catalog 保留原文。输出脱敏按**输出边界**分两层:

- **本地人工输出(CLI human / TUI)**:维持 ADR-0004——不脱敏,
  本机屏幕显示密钥为可接受风险。
- **跨边界输出(Web UI、Handoff Pack、MCP、Robot JSON/JSONL、HTTP API)**:
  **默认脱敏**,高置信 secret(API key/token/password/private key/环境变量值)
  以模式引用替代值;用户显式 `reveal` 才显示原文,且输出保留 reveal 标记
  (如 `[revealed]`),使复制/导出内容可辨识发生过揭示。每次 reveal 必须在
  本地审计事件中记录边界、请求入口、时间、操作者确认和输出对象标识;
  审计事件不得包含被揭示的 secret 原文。

## 背景

开源发布将引入 Web UI(`asg serve`)、handoff pack(会被粘贴给其他
agent)、MCP/Robot(会被程序消费转发)。这些输出离开"本机人工查看"边界,
被自动转发、粘贴、注入的概率远高于终端屏幕;ADR-0004 的"零外发路径"
前提在跨边界场景不再成立。owner 在 2026-08-15 的产品评审中确认:
目录原文不动(保 evidence fidelity),脱敏在投影层做。

## 后果

- ADR-0004 不被推翻,但其适用范围收窄为本地人工输出;两份 ADR 并存,
  本文划出跨边界规则。
- 检测规则与脱敏 fixture 入库并进 CI;误报保守处理(脱敏优先)。
- 若未来增加网络能力(遥测/分享/云端),ADR-0004 的重评审条款仍适用,
  且跨边界默认脱敏不得放松。
- 实现落在离线与隐私 hook 阶段;Handoff pack 的
  redaction 状态字段属于 handoff-pack/v1 契约。
