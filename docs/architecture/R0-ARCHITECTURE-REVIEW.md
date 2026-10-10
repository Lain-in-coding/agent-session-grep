# R0 Architecture Review（待签署）

> **Review status: Pending — not approved**
>
> 本文是项目所有者与指定批准人的决策包，不改变任何 RFC、ADR、Contract、Policy 或 Gate 的状态。owner/approver 明确签署前，R0 保持未通过。

## 1. 当前 Gate 状态

仓库已实现 Workspace、Domain/Ports/Application、SQLite Catalog + FTS5、CLI/Robot v1，以及 Claude Code/Codex Experimental Provider。工程实现越过了“R0 Accepted 后再开始生产实现”的原计划顺序；应通过显式例外或追认决定记录这一治理偏差，不得倒签或虚构批准。

证据分类统一使用：

| 分类 | 含义 |
|---|---|
| `implemented` | checked-in 产品代码或可执行探针已存在 |
| `locally verified` | 在明确记录的本机 OS/target/工具版本上实际运行通过 |
| `CI configured only` | workflow 已配置，但没有本次可复核的 target 运行结果 |
| `externally blocked` | 依赖证书、账号、专用主机、外部权限或责任人 |
| `accepted` | 指定 approver 已签署决定、时间和稳定证据路径 |

代码存在、checkbox、私有手工验证均不等于 `accepted`。

## 2. 记录级状态

| 记录 | 当前事实 | 待批准内容 |
|---|---|---|
| [RFC-0001](RFC-0001-canonical-model-and-stable-id.md) | Draft；StableId 与最小 Message 模型已实现 | ContentBlob 层次、alias 周期、规范化指纹、completeness |
| [RFC-0002](RFC-0002-provider-adapter-contract.md) | Draft；probe/parse 最小合同与两个 Adapter 已实现 | roots/excludes、指纹最小集、mixed-version、历史 variants |
| [ADR-0001](../adr/ADR-0001-fulltext-search-engine.md) | Proposed；FTS5 已实现，20k 合成语料仅 Windows 本地验证 | 正式 corpus、相关性指标、阈值与 FTS5 go/no-go |
| [ADR-0002](../adr/ADR-0002-platform-targets.md) | Proposed；Windows 证据有限，其他 target 至多为 CI configured only | 正式 target、musl 身份、最低 OS/glibc、认证门 |
| [CLI/Robot/MCP Contract](../contracts/CONTRACT-cli-robot-mcp-draft.md) | Draft；CLI/Robot v1 子集与 MCP v0（stdio JSON-RPC，6 工具）已实现并有 e2e 覆盖 | not-found、cursor/error、partial、机器模式 help/version |
| [Threat Model](../security/THREAT-MODEL.md) | Draft；脱敏时机已由 ADR-0004 裁定（2026-08-13：不做脱敏，本地显示为可接受风险） | 隐私模式、网络文件系统 |
| [Fixture Policy](../security/FIXTURE-REDACTION-POLICY.md) | Proposed | 合成优先、真实 transcript 禁入仓库及审阅责任 |
| [SLI Format](../product/SLI-AND-BENCHMARK-FORMAT.md) | Draft；当前数据仅为趋势锚点 | North Star 指标、query set/qrels、临时阈值 |
| [Reuse/License Audit](../operations/REUSE-LICENSE-AUDIT.md) | Draft | 来源、版本、attribution 与 clean-room 边界 |
| [External Readiness](../operations/external-readiness-gate.md) | Draft；签名、公证、OIDC、渠道仍 externally blocked | 凭据 owner、dry-run 与最终 release 责任 |

每项批准角色均由项目所有者指定，且 approver 不应与该项实现 owner 相同。

## 3. 推荐决策

### RFC-0001

- v1.0 先保留简单 `content_hash`；Occurrence/Membership 在可复现跨 Source 重复 fixture 出现后引入。
- alias 保留一个已发布 major 的兼容窗口，并设置数量与磁盘上限。
- 冻结版本化 `normalization_v1`：UTF-8、Unicode NFC、稳定字段顺序，不折叠正文语义空白。
- completeness 建议为 `complete | truncated_head | truncated_tail | partial | unknown`。

验证：重复引用/独立删除、relocation、旧 ID lookup、Unicode、字段重排、ordinal insertion 和 round-trip property tests。

### RFC-0002

- `DiscoveryContext` 由 Application 提供授权 roots 与 excludes，Adapter 不自行读取全局配置。
- 权威 fingerprint 至少包含可用的平台文件身份、size、mtime 和完整内容 fingerprint；head/tail 只能用于快速筛选。
- ProbeResult 报 source 级歧义，ParseReport 报 record 级 mixed-version 明细。
- 仅承诺有合成 golden 和 contract test 的历史 variant。

验证：隔离 HOME、越界 root、追加/截断/等长替换、混合 variant、unknown-field 和三平台测试。

### ADR-0001

建议继续以 SQLite Catalog + FTS5 作为当前默认，但 Selection Gate 保持 Pending。正式接受前需要竞争文档与分级 qrels、明确 Recall/NDCG 指标、P95/P99、恢复、增量、体积、正式 target 构建和已签署阈值。

### ADR-0002

建议四个正式 target：Windows MSVC x64、Linux glibc x64、macOS x64、macOS ARM64。Linux musl x64 暂作为补充分发实验 target，独立认证后再晋级。

### CLI / Robot / MCP

- typed `show` 不存在建议返回 `not_found` / exit 4；search 零命中保持成功。
- cursor invalid/expired/generation reclaimed 分码，不静默重置。
- partial 建议为 `ok:true`、`outcome:partial`，CLI exit 10。
- `--robot --version` 与机器 help 输出版本化 envelope；裸 `--help` 保持 human。

### Threat Model

- 脱敏边界已由 ADR-0004/ADR-0009 分层裁定：Human CLI/TUI search 输出保留
  有界正文片段；Web、Handoff、MCP、Robot、HTTP 等机器/跨边界输出统一按
  ADR-0009 默认脱敏，显式 reveal 需认证和审计，不得把“未来引入网络”作为
  脱敏启用条件。
- 提供显式隐私模式，隐藏 project/path 并收紧 snippets。
- v1.0 data-root 拒绝网络文件系统；Source root 可只读访问并提供降级诊断。

### Operations

- 补齐计划中的五项 North Star 指标并冻结 dataset hash。
- 未经许可证批准人签署的复用项仅允许 clean-room idea，不允许 direct copy。
- GitHub Release 作为 canonical release；下游渠道独立 promotion。

## 4. 已核实证据与漂移

- Data-root locking 已改为同一持锁句柄读回，`fs4 0.13` 的 `Ok(false)` 不再误判为成功；Windows 回归测试及 A/B/C/D 场景均通过：[`spikes/data-root-locking/`](../../spikes/data-root-locking/)。
- 四个原本只有 Evidence 的 Spike 已补 Spike Card，但卡片本身不构成批准。
- ADR-0002 对“四个正式 target”和五个 triple 的表述仍需批准人裁决 musl 身份。
- Robot 草案与 schema/runtime 的 `frame_type`、`outcome` 和错误码存在漂移。
- SLI 文档尚未覆盖计划中的全部 North Star 指标。
- 私有真实 transcript 手工验证不能作为 Provider promotion evidence。
- Windows 本地结果不能外推为 Linux/macOS 验证；CI YAML 也不能替代运行证据。
- Packaging Spike 已改为 checkout 相对路径，但仍是 Windows-only `.exe` 构建、模拟签名与稳定 re-hash，不是正式 release pipeline。

## 5. Architecture Review Checklist

### 事实与证据

- [x] Data-root locking 同句柄修复、回归测试及 Windows A/B/C/D 场景通过。
- [x] 每个 R0 Spike 具有 Card 或完整等价记录。
- [ ] Source snapshot、SQLite WAL、search backend 在固定 commit 上形成统一环境记录。
- [ ] Windows 本地结果与 Linux/macOS 未验证结果在所有汇总中分列。
- [ ] Robot runtime、schema、error catalog 与合同逐字段统一。
- [ ] R0 target 数量与 musl 状态无歧义。
- [ ] SLI 文档覆盖全部 North Star 指标。

### 决策与问责

- [ ] RFC-0001 四项开放问题签署。
- [ ] RFC-0002 四项开放问题签署。
- [ ] ADR-0001 的 corpus、指标、阈值和后端决定签署。
- [ ] ADR-0002 的 target、最低平台和认证门签署。
- [ ] CLI/Robot/MCP 的 not-found、cursor、partial、机器模式签署。
- [ ] Threat Model 两项开放问题（隐私模式、网络文件系统）签署；脱敏时机已由 ADR-0004 裁定（2026-08-13）。两项的事实基础与建议裁定已写入 `docs/security/THREAT-MODEL.md` §7.1 / §7.2（含对"spike 已确认 lease 不支持 NFS"这一错误证据宣称的纠正），待 owner 签署。
- [ ] Fixture、SLI、license 与 external readiness 各有 owner/approver。
- [ ] 对先实现后审批作显式 exception/追认决定，不回填虚假历史日期。

## 6. 签署状态

**Pending — not approved。** 只有项目所有者指派真实 owner/approver，各批准人完成验证并签署后，相关单项记录才可转为 `accepted`；此前 R0 Gate 整体保持未通过。
