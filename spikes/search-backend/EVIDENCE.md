# search-backend Spike — 证据记录

> Spike Card: [SPIKE-CARD.md](./SPIKE-CARD.md)
> 状态：**已完成 Windows x64 初步对照，作为 ADR-0001 证据输入**
> 执行日期：2026-07-21
> 探针性质：`spikes/` 下可丢弃代码，不进 `crates/`；归档时机由 R0 Architecture Review 决定

---

## 1. 基准环境（按 SLI 与基准报告格式记录）

| 项 | 值 |
|---|---|
| OS | windows |
| Arch / Target | x86_64 / x86_64-pc-windows-msvc |
| Rust | 1.97.1 (stable, MSVC) |
| SQLite | 3.53.2（rusqlite 0.40 bundled） |
| Tantivy | 0.26.1 |
| 文档数 | 20,000（合成，固定种子） |
| 冷/热 | 冷构建（每次全新临时目录） |
| 语料 | 合成多语言（中/英/代码/路径/错误栈），禁用真实 transcript |

评测查询与 qrels 基数：中文术语 541、代码标识符 488、路径 466、英文短语 426、错误标识 378。beacon 标记词只注入 beacon 文档，不进随机填充池，保证 qrels 干净。

---

## 2. 最终对照结果（消除混淆变量后）

| backend | mean recall@10 | 索引体积 | 构建耗时 | 最大查询延迟 |
|---|---|---|---|---|
| SQLite FTS5（contentless + WAL checkpoint） | **1.000** | 16.49 MB | 532 ms | 7115 µs |
| Tantivy（raw token 索引 + STORED 原文） | **1.000** | 3.47 MB | 393 ms | 560 µs |

- recall 差 (FTS5 − Tantivy) = **0.000**
- 索引体积比 (Tantivy / FTS5) = 0.21x（Tantivy 更小）
- 两个引擎吃**同一套 backend-neutral analyzer**（CJK 2-gram + 代码/路径/camelCase 切分），隔离引擎本身差异。

---

## 3. 方法论迭代（诚实记录，过程本身是证据）

体积对比经过三次修正才可信，记录以供正式 Selection Gate 复用：

1. **初版 50.11 MB**：FTS5 的 `docs` 表同时持久化了原文 + 预分析串 + FTS 索引三份；Tantivy 只存 id + 索引。混入存储模式差异，不可比。
2. **给 Tantivy 加 STORED 原文（→ Tantivy 3.48 MB）**：两边都存原文，但 FTS5 external-content 仍持久化膨胀的预分析串（CJK bigram 使文本膨胀 2-3x）。
3. **FTS5 改 contentless（`content=''`）+ WAL checkpoint（→ FTS5 16.49 MB）**：内容表只留原文（等价 catalog 本身），FTS 索引直接吃 token 不持久化分析串；checkpoint 让 `-wal` 落盘，体积诚实。

剩余 ~4.75x 体积差是引擎存储格式的真实差异，不再有测量瑕疵。

---

## 4. ADR-0001 决策证据

**已测硬门（本机 Windows x64 范围）**

| 硬门 | FTS5 | Tantivy |
|---|---|---|
| 检索质量（recall@10 达标） | ✅ 1.000 | ✅ 1.000 |
| 本机 target 干净构建 | ✅ MSVC bundled，无系统依赖 | ✅ 本机通过；其他正式 target 未验证 |
| 崩溃恢复可行性 | 本 spike 未覆盖；另见 sqlite-snapshot-wal spike | 待验证 |

**评分项**

| 维度 | 胜方 | 说明 |
|---|---|---|
| recall@10 | 平 | 均 1.000，无可测量差异 |
| 查询延迟 | Tantivy | 但 FTS5 在本轮 20k 文档测量中 <7.2 ms |
| 索引体积 | Tantivy | 4.75x，但 FTS5 本轮绝对值 16.5 MB |
| 一致性/运维复杂度 | **FTS5** | 单存储、同事务提交，无跨存储双写与 generation 漂移 |
| 构建可靠性 | **FTS5 倾向** | bundled 无系统依赖；跨平台结论尚待正式 target 验证 |

**证据倾向：支持 ADR-0001 当前 Proposed 的 FTS5 单存储默认。**

ADR-0001 的当前决策是：只有 Tantivy 在关键检索质量、性能或扩展能力上提供**可测量且必要的优势**时，才重新评估双存储成本。本 spike 显示：
- Tantivy 在体积和延迟上更优，但本轮数据不足以证明这些优势在标准语料和冻结 SLI 下属于“必要”优势；
- recall 完全打平，Tantivy 未在本轮**检索质量**指标上越过 FTS5；
- FTS5 的单存储一致性与 bundled 构建降低 generation 漂移和依赖风险。

因此本证据支持 FTS5 默认，但 ADR-0001 仍是 Proposed，最终采信与状态变更由 R0 Architecture Review 决定。

---

## 5. 明确未决限制

本 spike 是 **ADR-0001 的初步证据输入**，不等同跨平台验证或 R0 Architecture Review 接受。仍需补齐：

1. **规模**：本测 20k 文档；`docs/product/SLI-AND-BENCHMARK-FORMAT.md` 定义的标准数据集为 100k session / 10M message / 50GB。大规模下 FTS5 的查询延迟和体积增长曲线未知。
2. **跨平台**：本测仅 Windows x64。Linux x64、macOS x64/ARM64 尚未复测，不得据此宣称全部正式 target 通过。
3. **崩溃恢复**：本 spike 未覆盖；SQLite 路径只有独立 `sqlite-snapshot-wal` 探针证据，Tantivy 路径仍待验证。
4. **排名质量**：本测只量 recall@10 是否命中，未量相关性排序质量（NDCG）；需要带噪声竞争文档的分级 qrels。
5. **增量成本**：本测只量冷构建全量，未量增量 upsert/delete 成本。
6. **报告完整性**：本记录缺少 SLI 格式要求的部分环境字段与分位数，不能用于冻结正式 SLO。

在上述补齐前，FTS5 默认是 ADR-0001 中**可复审的 Proposed 决策**。Fixture 来源受 `docs/security/FIXTURE-REDACTION-POLICY.md` 约束；正式测量格式受 `docs/product/SLI-AND-BENCHMARK-FORMAT.md` 约束。
