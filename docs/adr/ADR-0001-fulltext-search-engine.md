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

- **供应链更正（2026-10-12）**：H5 `36616b7957e504aa4c6d514a50545dcd9bbc47cd`
  的 `spikes/search-backend/Cargo.lock`（raw SHA256
  `77e547af8ff41e17429f334b13607a5bf7829ed7e04f7cbdb511352b8f1aa41d`）有
  151 个锁定包、记录的 Tantivy closure 为 140 个，没有 `ort-sys` 或可达路径。
  已提交证据不能支持旧的 Tantivy→ort→ort-sys / cargo-deny unlicensed 断言，
  也不能支持由此推导的 ctx fork 原因或 FTS5「依赖树干净」结论。
  packaging 探针仅运行 cargo-audit，不运行 cargo-deny；旧 INFO 字符串不是检查。
  历史失败的 source/lock/configuration/command/tool version/result 尚未建立。
  这不是新 cargo-deny PASS，也不证明历史事件从未发生；见
  [audit §5](../operations/REUSE-LICENSE-AUDIT.md#5-spike-dependency-evidence-correction-2026-10-12)
  及两份 spike 证据的 dated correction。
- **一致性**：FTS5 单存储中 Canonical 表与 FTS5 影子表同事务提交，天然无跨存储双写与 generation 漂移；Tantivy 双存储方案必须承担完整 Durable Outbox 与跨存储提交协调。
- **先验**：调研的 7 个可运行同类项目多数选 FTS5（ctx/Recall/hstry/sessiongrep/memex），唯一用 Tantivy 的 fast-resume 有实测跨平台缺陷。

## 决策依据

- 硬门 recall 未被 Tantivy 超越（打平 1.000）→ Tantivy 未提供"关键检索质量优势"；
- Tantivy 的体积/延迟优势在本轮 20k 合成文档中存在，但不足以证明其必要性以抵消双存储一致性/运维成本；不再以未经证实的许可链作为否决依据；
- 因此按本 ADR 的 Selection Gate 原则：证据不足或 Tantivy 未越过关键硬门时采用 FTS5。

## 后果

**正面**：单事务一致性、bundled SQLite 减少系统 SQLite 配置、运维简单。依赖许可与各正式 target 构建仍需实际验证，不由单存储或本机 spike 自动保证。

**负面 / 需守护**：

- FTS5 无内建 CJK 分词 → 必须用 backend-neutral analyzer 预分析（CJK bigram + 代码/路径切分），已在 spike 验证（含 camelCase 切分修复）；
- **历史范围更正（2026-10-12）**：R0 曾把向量/语义检索排除在 v1.0 之外、留 post-1.0 评估。当前仍默认 FTS5 lexical（bigram-hash 为 fuzzy-lexical），已有默认关闭的 `semantic-candle` 支持离线本地 E5 导入；FTS5 本身不提供向量能力。本次不增加/禁用 feature，不批准模型权重分发或语义质量晋级；
- external-content/contentless FTS5 的体积随分析串膨胀 → 用 contentless 模式 + WAL checkpoint 后测体积（spike 已验证：50MB→16MB）。

## 局限（诚实标注）

- spike 用独特 beacon 词，能证明 analyzer 公平性与词法等价，但**测不出排序质量差异**（需带噪声竞争文档的分级相关性）；
- 规模只到 20k 文档；正式 Selection Gate 需在标准语料（100k session / 10M event）与全部正式 target 上复测；
- 未跑 macOS/Linux target（本机仅 windows-msvc），跨平台构建硬门留待 CI/External Readiness。

## 复审触发条件

- 标准语料复测显示 FTS5 recall 或延迟不达冻结 SLO；
- 语义/向量需求要求改变默认引擎、扩大现有 opt-in semantic-candle 范围或分发模型权重时，需另行评审；旧 R0「v1.0 无语义」范围不是当前 feature 的否定；
- FTS5 在某正式 target 上无法干净构建。
