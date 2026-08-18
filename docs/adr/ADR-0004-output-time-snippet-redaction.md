# ADR-0004：搜索 snippet 不做脱敏（本地显示密钥为可接受风险）

> 治理记录（Governance Record）
>
> - decision_id: ADR-0004
> - title: 搜索 snippet 不做脱敏
> - status: **Proposed（2026-08-13，owner 亲自裁定）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0
> - evidence_path: `docs/security/THREAT-MODEL.md` §5/§6.1；privacy/FTS reviewer 密钥回显复现

## 决策

human 搜索保留正文 snippet，**不做任何密钥脱敏**。工具是 local-first、零联网、零上传，transcript 不离开本机；密钥出现在本机终端屏幕属于可接受风险。snippet 仍受 `max_snippet_chars` / `max_response_bytes` 预算约束（该部分照常修复）。

## 背景

review 曾复现 snippet 直接打印 API key 值，违反 THREAT-MODEL §5 草案"密钥按 key 名引用，不回显 value"的承诺。owner 评估后裁定：数据无外发路径，风险仅存在于用户主动分享终端输出（录屏/截图/粘贴），不值得为此增加脱敏逻辑。

## 后果

- THREAT-MODEL §5 隐私承诺已同步修订为"默认搜索输出有界正文片段（human 模式，受预算约束）"，原"不回显 value"承诺撤回；§6.1 未决问题已裁定关闭；
- snippet 仍必须计入响应预算（绕过 `max_snippet_chars`/`max_response_bytes` 是独立的契约缺陷，不在本决策豁免范围）；
- ADR-0009 现已划出跨边界输出规则：本文仅约束 Human CLI/TUI 的本地人工
  search snippet；Web、Handoff、MCP、Robot、HTTP 等机器/跨边界输出不适用
  本文例外，统一按 ADR-0009 默认脱敏。
