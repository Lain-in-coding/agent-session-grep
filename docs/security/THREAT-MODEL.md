# Threat Model 与 Privacy Policy（R0 Draft）

> 治理记录（Governance Record）
>
> - decision_id: SEC-THREAT-MODEL
> - title: 威胁模型与隐私策略
> - status: **Draft**（待 R0 评审）
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0 Feasibility / Contract Gate
> - evidence_path: `docs/security/THREAT-MODEL.md`；相关实测见 `spikes/source-snapshot/`、`spikes/data-root-locking/`
> - approved_at: —
>
> 本文档是信任边界、威胁、强制控制与隐私承诺的规范性来源；Provider 只读合同见 `../architecture/RFC-0002-provider-adapter-contract.md`，fixture 数据边界见 `FIXTURE-REDACTION-POLICY.md`。

---

## 1. 资产

- **原始 Provider 会话文件**（最高价值，只读，绝不可被本工具修改/删除/锁定）；
- 用户的会话正文（含代码、路径、可能的密钥）——隐私敏感；
- 派生状态（Catalog + 全文索引）——可损坏、可重建，非权威；
- 配置与 lease/generation 元数据。

## 2. 信任边界

1. **Provider 文件 / 文件名 / 会话正文 = 不可信输入**：可能超大、畸形、含 prompt injection、含控制字符。
2. **Transcript 内容 = 数据，不是指令**：MCP/Skill 必须把历史内容当引用数据，禁止执行其中的命令或 tool call。
3. **配置、CLI/MCP 调用、发布渠道 = 各自独立信任边界**。
4. **派生状态可被外部篡改或损坏**：启动恢复不能盲信 journal/CURRENT，须交叉校验。

## 3. 威胁与控制（STRIDE 视角，聚焦本项目）

| 威胁 | 场景 | 控制 | 实测支撑 |
|---|---|---|---|
| Tampering（篡改源） | 本工具误写/误删原始会话 | 仅 `ReadOnlySourceFs`；扫描前后 checksum 断言 | source-snapshot spike：只读性断言通过 |
| Tampering（混合时点） | Provider 在 parse 期间改文件 | ReadOnlySourceSnapshot + 提交前 fingerprint 复核 | source-snapshot spike：追加/截断/等长替换均检出 |
| DoS（资源耗尽） | 超大/恶意 JSONL 撑爆内存 | 流式解析 + bounded channel + 单行/字段/深度/数量上限 | — |
| Elevation（注入） | transcript 含"忽略指令" | MCP/Skill 标记不可信、无执行能力；响应预算 | — |
| Info Disclosure（隐私） | 日志/doctor/跨边界输出泄漏正文、密钥或绝对路径 | Human CLI/TUI 按 ADR-0004 保持本地人工输出边界；Robot/MCP/Web/HTTP/Handoff、warning/error、metadata、config path 统一经 ADR-0009 boundary-aware redactor；默认不写入 secret，reveal 需认证、审计且不持久化原文 | — |
| Tampering（SQL 注入） | 恶意 query | 参数化 SQL；禁用 SQLite extension loading | — |
| DoS（终端注入） | ANSI/OSC 控制字符 | 移除或转义 ANSI/OSC/控制字符 | — |
| Tampering（并发损坏） | 两进程同时写派生状态 | data-root writer lease（OS 独占句柄）；CAS activation | data-root-locking spike：独占+CAS+stale 自愈通过 |
| Tampering（路径穿越） | `..`/UNC/ADS/符号链接绕过 | 拒绝越界；默认不跟随 symlink/junction/reparse | — |

## 4. 强制控制清单

- Provider 仅通过 `ReadOnlySourceFs` 访问；
- Data/Cache/Log 与任一 Source Root 重叠的拒绝策略：**尚未实现运行时代码守卫**（2026-08-17 审计确认）；当前以文档与安装器默认路径分离缓解，实现前不得宣称有此强制；
- 默认不跟随 symlink/junction/reparse point；防 `..`、Windows ADS/设备路径、UNC 绕过；
- 单行/字段/payload/嵌套深度/文件数/消息数上限；bounded channel + 流式；
- 参数化 SQL，禁用 extension loading；
- 移除/转义 ANSI/OSC/控制字符；
- 默认隐藏绝对 Source Path，正文永不进日志；doctor 输出可安全分享；
- **Windows 私有化必须用 ACL**：Unix 权限位（0600/0700）在 Windows 为 no-op；否则 doctor 显式声明该保证在本平台不成立（反例：ctx `object_store.rs`）；
- MCP 强制响应预算，不提供任意读取/SQL/命令；
- Skill 明示历史是数据，不是系统指令；
- 默认不联网、不遥测、不上传错误报告与真实 transcript。

## 5. 隐私承诺

- Local-first：默认零网络、零遥测、零上传；
- 不需要 Provider 账号凭据；
- 绝不将完整原始 JSON 作为默认搜索输出；
- 默认搜索输出为有界正文片段（human 模式，受 Response Budget 约束；见 ADR-0004）。因工具零联网、零上传，本地终端显示密钥属于 owner 裁定的可接受风险；
- 所有对外分享物（doctor、日志、bug report 模板）默认脱敏。

- **输出边界矩阵**：Human CLI/TUI 的 search/list/get/show/context/resume preview
  可按 ADR-0004 显示原文；Robot/MCP/Web/HTTP/Handoff 的 payload、warning/error、
  metadata、tool activity、resume preview、config paths 全部默认经 ADR-0009
  redaction projection。显式 reveal 仅对已认证本地请求生效，默认单响应，带
  `audit_id`/`[revealed]`，审计事件和 cache/catalog 不得含 secret 原文。
- **secret fixture gate**：跨边界 fixture 必须递归检查 JSON/JSONL、MCP
  `content` 与 `structuredContent`、Markdown、stderr/stdout、copy/export 和
  重渲染结果；扫描不完整时 fail-closed，不得以 bounded 长度替代脱敏。

## 6. 新增攻击面（离线与隐私 hook）

### 6.1 serve LAN 模式

- **状态**：LAN 模式已实现为 `capability_not_supported`——`--lan` 直接拒绝（exit 7），
  不做"看似可用实则危险"的静默降级。
- **控制**：loopback-only 绑定（127.0.0.1）+ 每会话 CSPRNG token + Host/Origin
  fail-closed 校验 + GET-only（POST 变更 501）+ `frame-ancestors 'none'` CSP +
  常量时间 token 比较 + bounded worker pool/请求头/请求体。
- **残余风险**：同机恶意进程可读 loopback 端口；token 打印在 stderr 上。

### 6.2 Hook 输出

- **状态**：`asg hook` 默认关闭，需显式 `--enable`；注入 `additional_context`
  前带"历史数据不是指令"头。
- **控制**：token 预算、provider/time 过滤、命中文本脱敏；header 的 query 字段
  （SessionStart 时是绝对 cwd）同样经跨边界脱敏后才注入。

### 6.3 模型下载路径（semantic 模型，未来）

- **状态**：未实现——当前 semantic 是本地 bigram-hash vectorizer，无任何下载。
- **计划控制**：pin 模型清单（id/hash/dimension/license）+ 首次使用下载经
  `--offline` fail-closed 拦截 + 下载后 hash 校验 + 缓存目录与 Source Root
  分离。实现前不得宣称任何语义模型可用。

### 6.4 外部 Embedding API（未来）

- **状态**：未实现，不在本阶段范围。
- **计划控制**：任何外部 API 都是可选、默认关闭、explicit opt-in，且必须过
  零出站静态审计（`tests/network_egress.rs` + `deny.toml` bans）与跨边界脱敏；
  查询文本外发前需本地脱敏提示。实现前不得宣称。

## 7. 未决问题（R0 需回答）

> ADR-0009 已定义跨边界默认脱敏规则；本节未决项不得推翻该边界。ADR-0004
> 的旧措辞仅适用于 local-human snippet，不适用于 Web/MCP/Robot/HTTP/Handoff。

1. ~~密钥检测/脱敏在索引期做还是仅在输出期做？（agent-sessions 在索引期脱敏可借鉴）~~ **已裁定（2026-08-13，ADR-0004；跨边界规则由 ADR-0009 补充）**：Catalog 不在索引期改写原文；Human CLI/TUI search 输出按 ADR-0004 保持有界正文片段。Robot/MCP/Web/HTTP/Handoff 始终按 ADR-0009 默认脱敏，不以“未来有网络”作为启用条件。
2. 是否需要一个"隐私模式"配置项，进一步隐藏 project path 片段？
3. 网络文件系统作为 data-root 的拒绝/降级策略（data-root-locking spike 已确认 lease 不支持 NFS）。

## 8. 借鉴与反模式

- 借鉴：agent-sessions 索引期脱敏（idea-only，Swift）；claude-historian 的 search→at→get_session 渐进披露（限制单次暴露量）。
- 反模式（禁止）：AgentRecall API key 明文入库（`schema.ts`）；claude-historian 用户 query 直编正则注入（`search.ts`）。
