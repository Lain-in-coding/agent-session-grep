# ADR-0010：Provider maturity 降级与回滚治理

> 治理记录（Governance Record）
>
> - decision_id: ADR-0010
> - title: Provider maturity 降级与回滚治理
> - status: **Proposed（2026-08-16）**
> - owner: QIN
> - approver: 项目最终验收人
> - due_milestone: 0.3 Integration Beta / Provider Promotion Train
> - evidence_path: `docs/architecture/RFC-0002-provider-adapter-contract.md` §6；
>   `crates/agent-session-grep-ports/src/capability.rs`；
>   `crates/agent-session-grep-cli/src/main.rs`、`src/human.rs`、`src/mcp.rs`；
>   `docs/product/PROVIDER-MATURITY-MATRIX.md`
> - governance: 本 ADR 当前仅为 Proposed。未经 owner/approver 记录
>   `accepted_at`、approver、实现证据与通过的跨边界测试，不得宣称 Accepted；
>   本文不替 owner 作出接受或晋级决定。

## 决策

Provider 的 maturity 是可回滚的治理事实，不是由 adapter 代码存在自动推断的宣传标签。晋级、维持与降级都必须由 owner 根据可复核证据作出决定；代码只提供证据与按单一权威矩阵公开事实的机制。

### 1. 晋级到 Beta 的证据清单

RFC-0002 §6 要求 `fixture + 共享 contract + 跨 target + 回滚策略`，并在 §6 明确要求 `AdapterManifest` 声明 provider/variant、maturity、能力矩阵、fixture revision、最后认证 target 与已知限制。本仓库当前证据逐项对应如下：

| RFC-0002 要求 | 可验证证据 | 当前状态 |
|---|---|---|
| 合成 fixture 与 golden | `crates/agent-session-grep-provider-claude/tests/golden.rs`、`crates/agent-session-grep-provider-codex/tests/golden.rs` 及各自 fixture；golden 锁定 canonical 输出漂移 | Claude/Codex 有直接路径；其余 provider 必须补同等可复核证据后才能按该项晋级 |
| 确定性 property/contract | `crates/agent-session-grep-provider-claude/tests/properties.rs`、`crates/agent-session-grep-provider-codex/tests/properties.rs`；共享 `ProviderAdapter` / `CanonicalEventSink` 见 `crates/agent-session-grep-ports/src/lib.rs` | Claude/Codex 有直接 property 路径；共享 contract 在代码中可验证；逐 provider 证据仍须按 promotion 记录 |
| 只读、原子 staging、source span 与增量不变量 | `crates/agent-session-grep-ports/src/lib.rs` 的 parse/sink 合同；`crates/agent-session-grep-application/src/lib.rs` 的 staging；CLI/provider e2e 测试与 `docs/evidence/integration-beta/real-data-regression.md` | 机制与部分实测证据存在；不能把通用机制自动等同于每个 provider 的晋级证据 |
| 跨正式 target | `.github/workflows/ci.yml` 的 `test (${{ matrix.os }})` job（ubuntu-latest、windows-latest、macos-latest）执行 `cargo test --workspace`；`docs/operations/core-beta-evidence-matrix.md` 的 CI 记录规则要求具体成功 run | workflow 已配置；在记录具体成功 run 前仍是待验证证据，不得宣称跨 target 已认证 |
| 回滚策略 | 本 ADR §2–§4；入口机制为 CLI `providers`（`ProviderCapabilityMatrix::current()`）与 MCP `list_providers` maturity 投影 | 文档与入口机制已落地；本 ADR 仍 Proposed，须 owner/approver 明确 accepted_at |
| AdapterManifest 声明 | RFC-0002 §6 的要求；当前 `ProviderAdapter` 最低 trait 位于 `crates/agent-session-grep-ports/src/lib.rs` | 结构化 `AdapterManifest`/fixture revision/最后认证 target 尚待独立 contract 工作落地；不能以本 ADR 代替 |

### 2. 必须降级/回滚的触发条件

当下列任一条件成立，owner 必须暂停该 provider 的晋级宣传，并评估将其从 `Beta` 降回 `Experimental`；若已无法证明基本 probe/parse 语义，则降为 `Unsupported`（含 deferred）：

1. 上游格式或 variant 发生变化，导致已锁定的 golden 输出漂移，且在完成 variant 分层或修复前无法解释漂移。
2. 授权真实数据回归出现 parse loss：provider emitted occurrence 与持久化 source-placement claim 不一致、出现未预期 skipped/diagnostics，或既有可检索历史无法重建。
3. 只读契约被破坏：扫描/解析修改、删除、移动、锁定上游源，或源快照一致性复核失败后仍提交混合时点数据。
4. 跨 target CI 的 provider contract、golden/property 或安装表面转红，且问题尚未证明为环境噪声。
5. 脱敏合成 fixture 无法再现已报告的行为，fixture revision 与实际格式不再对应，导致回归无法复核。
6. source span、probe 拒绝歧义、增量失败不删除等已承诺的不变量回归，或者出现无法解释的未知 variant 静默解析。

触发条件是证据门，不是自动改写评级的程序规则；owner 决定最终 maturity，并记录理由、范围（provider/variant/target）与复核证据。

### 3. 降级/回滚动作

按以下顺序执行：

1. **单源改事实**：由 owner/维护者修改 `crates/agent-session-grep-ports/src/capability.rs` 中对应行的 `maturity`。不得在 CLI、MCP、文档或 adapter 内另加 maturity 常量；`ProviderCapabilityMatrix::current()` 是唯一权威。
2. **入口自动反映**：CLI `providers` 读取 `ProviderCapabilityMatrix::current()`，输出 `provider_id`、`variant_id`、当前 `maturity`、`maturity_target` 与逐字段能力；human 输出和 Robot envelope 使用同一投影。MCP `list_providers` 同样从矩阵读取 maturity。降级后不需要再改入口代码，也不能让入口继续把 provider 平等呈现为已晋级。
3. **更新公开记录**：同步更新 `docs/product/PROVIDER-MATURITY-MATRIX.md` 的事实行与缺口状态，并在 `CHANGELOG.md` 记录 provider、旧/新 maturity、触发证据与复核链接。若仓库没有对应版本 CHANGELOG 条目，发布变更仍必须保留等价的 release record，不得静默降级。
4. **保留数据不变量**：降级不删除、不重写、不 tombstone 已入库历史；不影响既有 Catalog 的检索、show、context 与证据 span。只读扫描继续遵守失败不删除原则。历史恒可检索是产品不变量；无法恢复只代表当前 provider 能力受限，不代表历史消失。
5. **重新晋级**：只有补齐触发条件对应的 fixture、contract、跨 target、回滚记录与 manifest 证据，并由 owner 再次决定后，才可从 Experimental 晋级 Beta；Unsupported/deferred 需先补 transcript/variant 证据，不能靠入口显示 target 越级。

### 4. 决策责任与接受边界

owner 决定是否晋级、维持或降级；成熟度不会因某个 adapter 类型能被构造、某个测试偶然通过或矩阵存在一行而自动推断。approver 负责验收治理记录与证据边界。直到本 ADR 的治理记录补齐 `accepted_at` 及所需 approver/实现证据，状态保持 Proposed，所有发布材料必须使用“Proposed/待接受”口径。

## 后果

- Provider 的公开 maturity 有明确的降级路径，且 CLI/Robot/MCP 能在降级后看到同一事实。
- 晋级证据与治理接受分离：测试绿色不等于 owner 晋级，workflow 配置不等于跨 target 认证，文档存在不等于 Accepted。
- 降级不会破坏历史可检索性；用户仍可搜索已有 Canonical 数据，并能看到 provider 当前受限状态。
- 结构化 `AdapterManifest` 仍是独立 contract 缺口，本 ADR 不替代该实现。
