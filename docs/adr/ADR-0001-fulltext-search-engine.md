# ADR-0001：全文检索引擎选型（SQLite FTS5 单存储 vs Tantivy 双存储）

> 治理记录（Governance Record）
>
> - decision_id: ADR-fulltext-engine
> - title: 全文检索引擎选型
> - status: **Proposed（基于 R0 spike 初步证据，待 approver 接受）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0 Feasibility / Contract Gate
> - evidence_path: `spikes/search-backend/EVIDENCE.md`、`spikes/R0-EVIDENCE-SUMMARY.md`
> - approved_at: —
>
> 本 ADR 记录全文引擎 Selection Gate；证据来自 `spikes/search-backend/EVIDENCE.md` 与 `spikes/R0-EVIDENCE-SUMMARY.md`，基准口径见 `../product/SLI-AND-BENCHMARK-FORMAT.md`。

---

## 决策

**默认采用 SQLite Catalog + SQLite FTS5 单存储**。Tantivy 双存储仅在后续出现可测量且必要的检索质量/性能优势时才重新评估。Application 只依赖 Search Port，引擎可替换。

## 背景

全文引擎必须经 Selection Gate 证据决策，不以预设偏好代替测量。R0 执行了 `spikes/search-backend` 对照探针，在同一套合成语料 + qrels + backend-neutral analyzer 下度量两个引擎。

## 证据（spike 实测，Windows x64 / SQLite 3.53.2 / 20k 合成文档）

| 指标 | SQLite FTS5 | Tantivy 0.26.1 |
|---|---|---|
| mean recall@10 | 1.000 | 1.000 |
| 索引体积 | 16.49 MB | 3.44 MB |
| 构建时间 | ~530 ms | ~430 ms |
| 最大查询延迟 | ~7.1 ms | ~0.56 ms |

补充实证：

- **供应链**：Tantivy 0.26 经 `ort` 传递引入 `ort-sys`（ONNX Runtime），cargo-deny 报 `unlicensed`（`spikes/cross-platform-packaging`）。这正是 ctx 不得不 fork 该 crate 的原因。FTS5 走 rusqlite(bundled)，依赖树干净。
- **一致性**：FTS5 单存储中 Canonical 表与 FTS5 影子表同事务提交，天然无跨存储双写与 generation 漂移；Tantivy 双存储方案必须承担完整 Durable Outbox 与跨存储提交协调。
- **先验**：调研的 7 个可运行同类项目多数选 FTS5（ctx/Recall/hstry/sessiongrep/memex），唯一用 Tantivy 的 fast-resume 有实测跨平台缺陷。

## 决策依据

- 硬门 recall 未被 Tantivy 超越（打平 1.000）→ Tantivy 未提供"关键检索质量优势"；
- Tantivy 的体积/延迟优势为毫秒级、绝对值可接受，不足以抵消双存储一致性与供应链成本；
- 因此按本 ADR 的 Selection Gate 原则：证据不足或 Tantivy 未越过关键硬门时采用 FTS5。

## 后果

**正面**：单事务一致性、依赖树干净、跨平台构建风险低、运维简单。

**负面 / 需守护**：

- FTS5 无内建 CJK 分词 → 必须用 backend-neutral analyzer 预分析（CJK bigram + 代码/路径切分），已在 spike 验证（含 camelCase 切分修复）；
- 若未来需要向量/语义检索，FTS5 不覆盖；该能力不属于 v1.0 范围，post-1.0 再评估；
- external-content/contentless FTS5 的体积随分析串膨胀 → 用 contentless 模式 + WAL checkpoint 后测体积（spike 已验证：50MB→16MB）。

## 局限（诚实标注）

- spike 用独特 beacon 词，能证明 analyzer 公平性与词法等价，但**测不出排序质量差异**（需带噪声竞争文档的分级相关性）；
- 规模只到 20k 文档；正式 Selection Gate 需在标准语料（100k session / 10M event）与全部正式 target 上复测；
- 未跑 macOS/Linux target（本机仅 windows-msvc），跨平台构建硬门留待 CI/External Readiness。

## 复审触发条件

- 标准语料复测显示 FTS5 recall 或延迟不达冻结 SLO；
- 出现必须的语义/向量检索需求（该能力不属于当前 v1.0 范围，需重新立项评审）；
- FTS5 在某正式 target 上无法干净构建。
