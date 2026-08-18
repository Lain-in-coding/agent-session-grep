# Spike Card：search-backend（SQLite FTS5 vs Tantivy）

> 治理记录（Governance Record）
>
> - decision_id: SPIKE-search-backend
> - title: 全文检索引擎 ADR-0001 对照证据
> - status: **Executed（初步证据已产出，待 approver 审阅）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0 Feasibility / Contract Gate
> - deadline: （R0 timebox 内，见下方 timebox）
> - evidence_path: `spikes/search-backend/`（探针代码 + `EVIDENCE.md` 测量报告）
> - approved_at: —
> - preliminary_finding: 在 20k 合成文档 + backend-neutral analyzer 下，FTS5 与 Tantivy 的 recall@10 完全打平（均 1.000）；Tantivy 在索引体积（3.4MB vs 16.5MB）与查询延迟（max 0.56ms vs 7.1ms）上占优，但 FTS5 绝对延迟为毫秒级。该证据支持 **ADR-0001 当前 Proposed 的 FTS5 单存储默认**，但不构成跨平台或最终接受结论。详见 `EVIDENCE.md`。
> - caveat: 本 spike 用独特 beacon 词，仅证明 analyzer 公平性与词法等价性，**未测排序质量差异**（需带噪声/竞争文档的分级 qrels）；还需按 `docs/product/SLI-AND-BENCHMARK-FORMAT.md` 在标准语料与全部正式 target 上复测。
>
> 本 Spike 是可丢弃探针，**不进入 `crates/` 生产源码树**，不形成正式 API/Crate/迁移承诺。是否归档由 R0 Architecture Review 决定；当前产出作为 ADR-0001 的证据输入。

---

## 1. Hypothesis（假设）

**SQLite FTS5 单存储足以在本项目的正式检索指标上达到硬门与评分阈值，且其单事务一致性显著低于 SQLite+Tantivy 双存储的实现与运维复杂度。因此默认应选 FTS5，除非 Tantivy 在关键检索质量/性能/扩展性上提供可测量且必要的优势。**

零假设（用于 go/no-go）：FTS5 不满足某条硬门，或在评分项上被 Tantivy 以足够权重差距超越，才推翻默认、承担双存储成本。

## 2. Timebox

- 建议 timebox：**5 个工作日**（owner 可在 R0 启动时按可用资源微调，但到期即触发 §7 默认决策，不允许开放式延长）。
- 到期未完成 → 默认决策：采用 FTS5 单存储（ADR-0001 的可复审默认）。

## 3. Fixture / 数据集

- 使用符合 `docs/security/FIXTURE-REDACTION-POLICY.md` 的**合成 corpus**，禁止真实 transcript。
- 规模分档：
  - Small：1k session / 100k event（快速迭代）；
  - Medium：10k session / 1M event（评分主档）；
  - Large：向标准数据集靠拢（100k session / 10M event / 50GB）做趋势外推，不要求跑满。
- 语料混合：中文两/三字术语、中英混合、`snake_case`、`camelCase`、`module::symbol`、Windows/POSIX 路径、错误栈。
- 检索评测集：带 qrels 的固定 query set，覆盖上述各语言/代码/路径类别，用于 Recall@10。

## 4. Fault model（故障注入）

两种后端都必须在同一故障集下验证：

- 构建/commit 中途进程强杀（building / 提交点 / 切换点）；
- 磁盘写满；
- 只读打开活动快照期间并发写；
- Windows 文件锁与杀毒软件延迟下的 rename/replace；
- 索引数据损坏后 rebuild 恢复。

## 5. Measurements（测量项）

每项按 `docs/product/SLI-AND-BENCHMARK-FORMAT.md` 记录（Commit、OS、Target Triple、CPU/RAM/Disk/FS、Dataset Hash、冷/热、样本数、预热、中位数、P95/P99、方差、安全软件状态）。

| 指标 | 说明 |
|---|---|
| Recall@10 | 中文 / 英文 / 代码 / 路径分别测 |
| 索引体积比 | index size / raw corpus size |
| 首次构建时间 | Medium/Large 档 |
| 增量构建时间 | 追加 1% 后的增量成本 |
| 查询 P50/P95/P99 | 冷/热分别 |
| snippet 质量 | 命中居中、无终端注入 |
| 过滤/分页正确性 | provider/project/role/时间 + cursor |
| 损坏恢复时间 | 故障注入后恢复到可服务 |
| 跨平台构建 | Windows/Linux/macOS x64/ARM64 干净构建 |
| 实现/运维复杂度 | 定性评级 + 双写一致性代码量 |

## 6. Pass/Fail（ADR-0001 复审输入）

**硬门（任一不达标即淘汰，不能用总分补偿）：**

- [ ] 正确性与一致性合同满足（以现行 RFC/contract 为准）；
- [ ] 故障注入后崩溃恢复通过；
- [ ] 全部正式 target 干净构建（尤其 Windows 与 macOS ARM64）；
- [ ] 安全构建约束满足（无联网构建依赖、无 protoc/模型下载等）。

**评分项（带权重与最低阈值，R0 冻结具体权重）：**

- 中英/代码/路径 Recall@10；
- 查询 P95/P99 延迟；
- 索引体积比；
- 增量构建成本；
- 实现与运维复杂度。

**决策规则：**

- FTS5 通过全部硬门 → 采用 FTS5（默认主线），除非 Tantivy 在评分项上以 R0 冻结的权重差距明显胜出且差距对产品 North Star 有实际意义；
- FTS5 未过某条硬门 → 评估 Tantivy 是否过硬门；两者都不过 → 升级为 R0 阻断问题重新设计；
- timebox 内证据不足 → 默认 FTS5。

## 7. 已知先验证据（来自同类项目调研，非本 Spike 结论）

- FTS5 侧：ctx、Recall、hstry、sessiongrep、memex 等多个可运行项目均选 FTS5；ctx 用自研 scriptgram 解决 CJK 分词；Recall 用 external-content + 触发器。
- Tantivy 侧：唯一采用 Tantivy 的 fast-resume 存在已实测的跨平台缺陷（Windows `is_absolute` 目录吞空、时区边界、CI 仅 ubuntu）。
- 这些是**先验倾向**，不替代本 Spike 在本项目 corpus/target 上的实测。

## 8. Evidence 产出物

- `spikes/search-backend/fts5/`、`spikes/search-backend/tantivy/`：两个最小探针；
- `spikes/search-backend/report.md`：填满 §5 测量表；
- `spikes/search-backend/selection-gate.md`：硬门勾选 + 评分表 + go/no-go 结论；
- 将证据链接回 ADR-0001；状态变更由 R0 Architecture Review 记录。
