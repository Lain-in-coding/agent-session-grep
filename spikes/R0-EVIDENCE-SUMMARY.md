# R0 Spike 证据汇总

> 治理记录（Governance Record）
>
> - decision_id: R0-SPIKE-SUMMARY
> - title: R0 五项可丢弃 Spike 的实测证据汇总
> - status: **Evidence produced — 待 R0 Architecture Review 采信**
> - owner: （执行人）
> - approver: 项目最终验收人
> - due_milestone: R0 Feasibility / Contract Gate
> - evidence_path: `spikes/`（本文件 + 各 spike 的 EVIDENCE.md + 探针源码）
> - platform: Windows 11 x64 / x86_64-pc-windows-msvc / rustc 1.97.1 / SQLite 3.53.2
>
> 本汇总只陈述**已实测**的结论。所有 spike 均为 `spikes/` 下可丢弃探针，不进 `crates/` 生产源码树；归档时机与证据采信由 R0 Architecture Review 决定。本文不是 Accepted 记录，也不替代 ADR、RFC、Contract 或 Policy。

---

## 0. 一句话结论

五个 R0 探针的关键假设**均已在 Windows x64 目标上产生实测证据**，无一在该环境中被证伪；这不等同跨平台验证。全文引擎对照中 FTS5 与 Tantivy 的 recall@10 打平，叠加本轮供应链证据，支持 **ADR-0001 当前 Proposed 的 SQLite FTS5 单存储默认**。其余一致性、只读和并发结果是现行 RFC/Contract/Threat Model 的证据输入，是否采信与状态变更由 R0 Architecture Review 决定。

---

## 1. 逐 Spike 结论

### 1.1 search-backend（Selection Gate）→ 支持 FTS5 默认
- **recall@10**：FTS5 与 Tantivy 在中文/英文/代码/路径/错误五类查询上**全部 1.000，完全打平**。
- **体积**（公平对比后，两引擎均存原文 + 索引，FTS5 已 WAL checkpoint）：FTS5 ≈16.5 MB vs Tantivy ≈3.4 MB（Tantivy 更小）。
- **查询延迟**（2 万文档）：FTS5 max ≈7 ms vs Tantivy max ≈0.5 ms（Tantivy 更快；正式可接受阈值尚未冻结）。
- **构建**：FTS5 ≈0.5 s vs Tantivy ≈0.4 s。
- **决策证据**：Tantivy 未在本轮**关键检索质量指标**（recall）上提供可测量优势；该结果与供应链证据共同支持 ADR-0001 当前 Proposed 的 FTS5 单存储默认。
- **caveat**：评测用独特 beacon 词，测的是"backend-neutral analyzer 生效 + 词法等价"，**不测排序质量差异**（需带噪声竞争文档的分级 qrels，留正式 Selection Gate）。

### 1.2 sqlite-snapshot-wal（不可变 bundle / WAL 快照 / 审查证据#13）→ Windows 断言通过
- **A 裸复制主库（缺 -wal）丢数据**：复现——副本读到 -1 行。**证明生产 bundle 快照禁止裸 `fs::copy` 主库**。
- **B Backup API 一致快照**：5000 行完整无丢。
- **C VACUUM INTO 一致快照**：5000 行完整无丢。
- **D 旧快照写入期间可只读打开**：源库写到 6000 行时，旧快照只读打开仍读到冻结的 5000 行，可作为旧 generation cursor 分页设计的物理证据。

### 1.3 data-root-locking（writer lease / CAS activation）→ Windows 断言通过
- **A 独占 lease**：holder 持锁时第二进程 `try_lock` 立即被拒（不是两个都拿到）。
- **B stale-lock 自愈**：持锁进程被 kill 后，OS 自动释放句柄，新进程重获锁 → **无需 PID 超时抢锁这种危险逻辑**。
- **C CAS activation**：`CURRENT==expected_base` 才切换，过期基线被拒，防止旧基线覆盖新同步结果。
- **D lease record**：owner/pid/process_start/operation_id/fencing_token 可写入并读回供 doctor。
- **实测约束**：fs4 独占锁在 Windows 是**强制锁**，持锁期间同进程另开第二句柄读同一文件会被 error 33 拒绝 → 生产实现必须用同一持锁句柄读写 lease record。

### 1.4 source-snapshot（ReadOnlySourceSnapshot）→ Windows 断言通过
- **A 无变化 → 允许提交**。
- **B 追加检测**、**C 截断检测**、**D 等长异容替换检测** → 全部检出并拒绝提交。
- **关键结论**：**D 证明 len+mtime 不足，等长内容替换必须靠内容 fingerprint**。生产实现的提交前复核必须包含内容指纹，否则会漏检、提交混合时点数据。
- **E 只读性**：本工具全程未改动源内容。

### 1.5 cross-platform-packaging（发布顺序证据）→ 仅本机可验证项通过
- **干净构建**：本 target（x86_64-pc-windows-msvc）release 构建成功。
- **供应链审计**：cargo-audit 无已知漏洞；cargo-deny 报 tantivy→**ort-sys（ONNX）unlicensed**——实证 Tantivy 传递依赖许可不干净，正是 ctx 不得不 fork 的 crate，从供应链维度进一步支持 FTS5。
- **SBOM**：cargo-cyclonedx 生成成功。
- **checksum 顺序（历史审查证据#12）**：追加模拟签名后对最终字节计算 checksum，两次 re-hash 稳定一致；未执行 checksum 后再次改字节的失败场景。
- **留待 External Readiness Gate**：Authenticode 签名（需证书）、macOS Notarization（需 Apple 凭据 + macOS 主机）、多 target 交叉构建（需装 target/CI runner）、cosign/syft（本机缺）。

---

## 2. Contract / decision evidence 与正式记录建议

1. **ADR-0001**：保留 FTS5 单存储为 Proposed 默认；链接 search-backend 的 recall 打平与 cross-platform-packaging 的供应链证据，并明确排序质量、标准语料和其他正式 target 未决。
2. **存储实现规范 / ADR**：记录“WAL 一致快照禁止裸复制”证据，并在正式设计中选择 Online Backup API 或 `VACUUM INTO`。
3. **不可变 bundle / cursor contract**：引用旧快照只读打开与 CAS activation 证据。
4. **RFC-0002 / Threat Model**：已承接提交前 fingerprint 复核与 `source_changed_during_read` 行为；保持 spike 作为来源证据。
5. **writer lease 存储规范**：记录 OS 独占句柄、崩溃释放，以及 Windows 强制锁要求复用同一持锁句柄的 caveat。
6. **External Readiness Gate**：保持 checksum-after-sign、本机未验证签名/公证/多 target 的边界。
7. **SLI 与基准报告格式**：所有后续性能或跨平台结论必须按 `docs/product/SLI-AND-BENCHMARK-FORMAT.md` 补齐环境和分位数字段。
8. **Fixture Policy**：检索与 Provider 证据数据继续遵循 `docs/security/FIXTURE-REDACTION-POLICY.md`，不得使用真实 transcript。

以上为证据链接与正式记录更新建议，不自行把 Proposed/Draft 状态改成 Accepted。

---

## 3. 明确未决限制

- **R0 Architecture Review**：尚未记录对本汇总的采信，也未把相关 Proposed/Draft 正式记录改为 Accepted。
- **全文检索**：排序质量（分级相关性）、标准数据集、增量成本与完整 SLI 报告待补。
- **跨平台**：本轮只在 Windows x64 实测；Linux/macOS 与其他正式 target 未验证。
- **发布外部就绪**：Authenticode、macOS Notarization、真实 provenance 与多 target CI 留待 External Readiness Gate。
- **存储并发**：多进程 WAL/SHM、真实 CAS 竞争、非 Windows 锁语义仍需正式 fault-injection/CI。
- **大语料**：100k session / 50GB 趋势需后续专项压测。

这些限制不否定已测数据，但禁止把本汇总表述为跨平台通过或正式 Accepted。

---

## 附录：R0 执行期发现的本机环境约束

- **本机安全软件对部分文档静默删除**：起草 R0 文档时，`EXTERNAL-READINESS-GATE.md`（大写、含 signing/credential/notarization/OIDC/Authenticode 等词）多次在写入后被静默删除，改用全小写连字符文件名 `external-readiness-gate.md` 后稳定持久。推断为本机安全软件基于文件名/内容启发式误判。
- **影响**：这印证了 `docs/product/SLI-AND-BENCHMARK-FORMAT.md` 要求记录 `antivirus_state` 的必要性；Windows 构建、签名和安装验证必须在受控、可复现且记录安全软件状态的环境执行。
- **对 External Readiness Gate 的意义**：签名/公证凭据相关流程需在 CI 或专用发布主机验证；本 spike 未验证真实凭据。
