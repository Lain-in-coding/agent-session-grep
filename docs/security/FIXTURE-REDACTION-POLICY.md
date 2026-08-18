# Fixture 脱敏规范与许可证边界

> 治理记录
> - decision_id: POLICY-fixture-redaction
> - status: **Proposed**（待 R0 Accepted）
> - owner: （待指派）  approver: 项目最终验收人
> - due_milestone: R0
> - evidence_path: `docs/security/FIXTURE-REDACTION-POLICY.md`

## 背景

所有调研项目的 fixtures provenance 均未核实，因此禁止复制任何真实 transcript；
Provider 认证与检索评测都需要 fixture。本规范冻结 fixture 的来源、脱敏和许可证边界，
复用许可判定见 `../operations/REUSE-LICENSE-AUDIT.md`。

## 硬约束

1. **禁止真实 transcript**：不得把任何真实 AI 会话记录（自己的或第三方项目的）纳入仓库 fixture。所有 fixture 必须是**人工合成**或**不可逆脱敏**生成。
2. **合成优先**：Provider golden fixture 以人工构造的最小样本为主，覆盖字段/变体/损坏/边界，而非采集真实数据后删减。
3. **不可逆脱敏**（仅当必须基于真实结构时）：路径→占位符、人名/邮箱/token/密钥→固定假值、时间戳→固定基准、项目名→通用名；脱敏必须不可逆，且经二次审阅确认无残留 PII。

## Provider fixture 要求

- 每个 Provider 的 fixture 覆盖：当前 + 历史 variant、缺字段、损坏记录、Unicode、Tool Event、大字段、多 Session、Branch/Retry/Fork；
- fixture 带 `fixture_revision`，格式修复必须新增 fixture 而非只改 parser；该要求与 `../architecture/RFC-0002-provider-adapter-contract.md` §7 一致；
- fixture 目录附 `PROVENANCE.md`：声明合成/脱敏方式、生成脚本、不含真实数据的确认。

## 检索评测 fixture

- search 评测语料（qrels）用合成 beacon 方法（见 `spikes/search-backend/`）：beacon 标记词只注入 beacon 文档，不污染随机填充池，保证 recall 有区分度；
- 语料覆盖中文两/三字术语、中英混合、snake_case、camelCase、`module::symbol`、Windows/POSIX 路径、错误栈。

## 许可证边界（与复用审查联动）

- 从同类项目**复制任何 fixture 一律禁止**（provenance 未核实）；
- 复用同类项目**代码**须遵守 `docs/operations/REUSE-LICENSE-AUDIT.md` 的 direct-copy/adapt/idea-only/reject 判定；
- **cass 是法律红线**：其 LICENSE 含 OpenAI/Anthropic Restricted-Party Rider，代码整体 reject，只能 clean-room 借鉴抽象思想。

## CI 门

- secret scan + PII 扫描覆盖 `fixtures/`，命中即 fail；
- 新增 fixture 的 PR 必须在描述中声明合成/脱敏来源。
