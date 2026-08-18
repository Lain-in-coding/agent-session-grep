# SLI 定义与基准报告格式

> 治理记录（Governance Record）
>
> - decision_id: DOC-SLI-BENCHMARK
> - status: **Draft**（待 R0 评审）
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0 Feasibility / Contract Gate
> - evidence_path: `docs/product/SLI-AND-BENCHMARK-FORMAT.md` + `spikes/*/EVIDENCE.md`
> - 本文是 SLI 定义、采样方法、标准数据集与基准报告格式的规范性来源；全文引擎选择见 `../adr/ADR-0001-fulltext-search-engine.md`

本文冻结 R0 阶段的 **SLI 指标定义、采样方法和基准环境格式**。R0 只冻结定义与方法，不提前用缺少测量依据的精确数值阻断开发；具体数值 SLO 在 0.1 垂直切片取得基线、0.2 完成真实存储与检索后冻结。

---

## 1. SLI 指标清单（R0 冻结定义）

| SLI | 定义 | 采样方法 | 冻结时机 |
|---|---|---|---|
| `cli_startup_latency_ms` | 从进程启动到可接收命令的墙钟时间 | 冷/热各 20 次取中位数 | 0.1 |
| `search_latency_ms_p50/p95/p99` | 从 search 请求到返回首屏结果 | 固定 query set，100 次 | 0.2 |
| `show_latency_ms_p95` | show 请求到返回有限上下文 | 固定 id set，100 次 | 0.2 |
| `initial_index_throughput_mb_s` | 首次全量索引吞吐（MB/s） | 标准语料冷构建 | 0.2 |
| `incremental_scan_latency_ms` | 无变化增量扫描的墙钟时间 | 连续 3 次取中位数 | 0.2 |
| `peak_rss_mb` | 索引/查询期峰值常驻内存 | 采样 100ms 间隔 | 0.2 |
| `index_size_ratio` | 索引落盘体积 / 原始语料体积 | 落盘后 checkpoint 测量 | 0.2 |
| `recall_at_10` | 中/英/代码/路径分类的 top-10 召回 | 带 qrels 的固定 query set | 0.2 |
| `source_parse_coverage` | 认证 Provider fixture 合法记录的 Canonical 覆盖率 | golden 对照 | 0.2 |
| `recovery_time_ms` | 崩溃/中断后恢复到可服务的时间 | fault injection 后测量 | 0.2 |
| `robot_response_bytes` | robot/JSON 单次响应字节 | 固定预算下测量 | 0.2 |

## 2. 基准报告必填字段（每份报告强制）

```text
commit           = <git sha>
os               = windows | linux | macos
target_triple    = x86_64-pc-windows-msvc | ...
cpu              = <型号 + 核数>
ram_gb           = <总内存>
disk             = <SSD/NVMe/HDD + 型号>
filesystem       = NTFS | ext4 | APFS
dataset_hash     = <合成语料哈希；算法必须随报告记录，v1 harness 使用 SHA-256>
state            = cold | warm
sample_count     = <样本数>
warmup           = <预热方法>
median           = <中位数>
p95 / p99        = <尾延迟>
variance         = <方差或标准差>
antivirus_state  = <Windows Defender 开/关等安全软件状态>
sqlite_version   = <sqlite3 version()>
```

未记录上述字段的性能数字不得进入 SLO 冻结决策，也不得作为 Release 阻断依据。

### 2.1 可复现 Core/Beta 报告契约

仓库脚本 `scripts/evidence/core_beta_benchmark.py` 生成的权威文件是 JSON，
`schema_version` 固定为 `agent-session-grep.core-beta-benchmark/v1`。同名 Markdown
仅是便于审阅的投影，不替代 JSON 原始样本。该契约不改变本文的 **Draft**
状态，也不表示 R0 已批准任何数值 SLO。

JSON 必须包含：

- `evidence_status`、`profile`、完整 40 位 `commit`、生成时间和完整 `environment`；
- 仅由脚本生成的合成数据集元数据、SHA-256 `dataset_hash`，以及
  `contains_real_transcripts: false`；
- release 二进制 SHA-256、artifact 字节数、store（含现存 sidecar）字节数，以及
  `binary.provenance`。调用者提供的预构建二进制必须明确披露 source-to-binary linkage
  未被独立证明；harness 自行构建时必须使用 `cargo build --locked --release`；
- full profile 必须记录实际 store SQLite 运行时版本及其证据来源，不能用 Python
  `sqlite3` 版本或 `not_recorded` 代替；
- 每项 metric 的 `raw_samples`、`required_sample_count`、单位、状态，以及按原始
  样本重算的 nearest-rank P50/P95/P99、mean、sample standard deviation；
- 可用时的 peak RSS 原始样本与统计；不可用时必须为 `null`/空样本并在
  `limitations` 解释，禁止用别的内存量冒充；验证器必须从原始 RSS 样本重算每项
  与 aggregate 汇总；
- `recovery.status` 与 `recovery_time_ms`。没有 production fault-injection 路径时，
  必须标为 `not_implemented`，不得把干净 open/doctor 时间表述为恢复耗时；
- 测量方法和限制，明确本地 smoke/full 结果不是正式 SLO 或 release certification。

`smoke` profile 用于快速验证 harness/report 管道；`full` profile 才满足本页冻结的
startup 20 次、search/show 100 次样本要求。验证命令会根据报告中的 profile 检查
样本数并从 raw samples 重算统计值：

```text
python scripts/evidence/core_beta_benchmark.py validate-report <report.json>
```

## 3. 标准数据集

- 100,000 Session / 10,000,000 Message-Event / 50GB 原始 transcript；
- 中/英/代码/路径/错误栈混合；
- 全部合成，遵循 fixture 脱敏规范，禁止真实 transcript；
- 该规模用于 0.2 之后的专项压测，不要求每个 PR CI 执行。

## 4. 已有实测锚点（来自 R0 spike）

search-backend spike 在 20k 合成文档上的初步数字（非正式 SLO，仅作趋势锚点）：

- recall@10：FTS5 与 Tantivy 均 1.000（backend-neutral analyzer 下打平）；
- 索引体积：FTS5 16.5MB / Tantivy 3.4MB；
- 查询延迟：FTS5 max 7.1ms / Tantivy max 0.56ms；
- 构建时间：FTS5 ~530ms / Tantivy ~430ms（20k 文档冷构建）。

正式 SLO 需在标准语料、正式 target 上按 §2 格式复测冻结。

## 5. 性能回归门

- 回归门槛在基线稳定后按各指标噪声分别制定，不统一硬编码 10%；
- 性能阈值只在固定基准环境冻结，不在普通 PR 机器上做硬阻断。
