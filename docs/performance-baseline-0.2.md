# agent-session-grep 0.2 性能基线

> 状态：初始可复现基线，不是正式 SLO；正式阈值只能在固定基准环境和标准 corpus 上冻结。
> 采集方式：`cargo test -p agent-session-grep-cli --test e2e perf_baseline_100_messages_index_and_search -- --nocapture`

## 测试配置

| 项目 | 值 |
|---|---|
| 数据规模 | 100 条独立 Message |
| 写入路径 | 100 次独立 CLI `index` 进程，SQLite + FTS5 + durable batch |
| 查询 | `search "performance baseline"` |
| 计时范围 | 包含 CLI 进程启动、数据库打开、lease/SQLite 初始化与终止开销 |
| 阈值性质 | 记录型 smoke，不设普通 CI 墙钟阻断；正式回归门由固定环境基准制定 |

## 运行结果

测试会在 stderr 输出：

```text
[perf-baseline] index 100 msgs: <index_ms>ms  search: <query_ms>ms
```

一次 Windows 开发机运行通过：

- Windows 记录型 smoke 示例：100 条消息独立索引 **1912 ms**、单次全文查询
  **16 ms**（历史观测，不作为当前阈值）。
- 普通 CI 只验证功能并输出本机观测值，不使用固定墙钟断言；跨环境结果不可直接比较。

## 解释与限制

该结果主要测量最差的 CLI 逐进程调用路径，不代表批量 sync 或单进程 Application API 的吞吐。它用于确认 durable outbox、writer lease、SQLite/FTS5 初始化没有出现数量级回归。

## 可复现证据 bundle（commit-pinned）

本页的单点 smoke 数字已被一份满足 SLI 方法的可复现基准取代，权威文件是
`docs/evidence/core-beta/88d86f4/`：

- 生成器：`scripts/evidence/core_beta_benchmark.py`（纯标准库、合成 Claude Code
  JSONL、不读取任何 provider 数据根）；报告契约见
  `docs/product/SLI-AND-BENCHMARK-FORMAT.md` §2.1。
- 样本量满足冻结方法：startup 冷/热各 20、search/show/get 各 100、sync 三种工作
  负载（首次 / no-op / 收缩）各 3。
- 每个 metric 保留 `raw_samples` 并按 nearest-rank 重算 P50/P95/P99、mean、样本标准
  差；peak RSS 100ms 采样，不可用时为 `null`。
- 环境、release 二进制 SHA-256、数据集 SHA-256、artifact 与 store 体积一并记录。
- SQLite 3.53.2 由同 commit、同 `rusqlite`/`libsqlite3-sys` 锁定版本的 WAL spike
  `rusqlite::version()` 输出交叉记录；Python sqlite3 版本不冒充 store 运行时版本。
- `recovery` 标为 `not_implemented`：CLI 在 open 时恢复，但无 fault-injection 入口，
  因此不宣称恢复耗时。
- 最终 capture 由 harness 在固定 commit 上执行 `cargo build --locked --release`，并记录
  `binary.provenance = built_by_harness_from_workspace`、release 二进制 SHA-256 和完整 Git SHA。

这仍是本地证据锚点，不是正式 SLO 或 release 认证。

## 已补齐 / 仍缺口

已在上述 bundle 中补齐：

- 固定 CPU/OS/Rust/SQLite 版本与冷/热定义；
- sync 首次、no-op、收缩/tombstone 工作负载；
- search/show/get P50/P95/P99、索引落盘体积、内存峰值采样。

仍缺口（未在本地采集，不得宣称通过）：

- 10k/100k sessions、10m messages / 50GB 标准 corpus 规模；
- 随机终止后的生产恢复耗时（需 production fault-injection 入口）；
- 中文、代码 identifier、路径和错误栈的 query set 与 recall/latency 对照；
- Linux（glibc 2.31 基线）/ macOS 上的同规格复测。

## 2026-08-13 post-optimization（性能修复实测）

> 2026-08-10 ~ 08-12 的性能修复（见下列条目）
> 已在本机真实语料与隔离测量中验证。下列数字是本机实测观测值，仍是本地
> 证据锚点，不是正式 SLO。

- **FTS 删除优化（fts_rowid 边车）**：`fts_ids` 边车新增 `fts_rowid` 列，
  每次 FTS 行的清除/删除从"按内容列匹配的全表扫描"改为经边车 `wire_id`
  主键取 rowid 的 O(1) 定位（无 fts 行时按 NULL 无操作）。32 MB 单文件在
  非空库上的首扫从 **16.5 s → 2.79 s**；非空库重扫同一目录从 **25.3 s →
  2.87 s**。
- **unchanged re-sync**：fingerprint skip + early no-op 检查让内容未变的源
  集合重同步跳过整个批处理，实测 **0.089 s**，不推进 generation、不失效
  游标。
- **rebuild**：`index rebuild` 经 `fts_rowid` 边车删除后重投影，8,990
  entities 实测 **0.71 s**。
- **batch-scoped 提交与完整性检查**：完整性检查与提交按批作用域执行，并
  消除相关读路径的 N+1。
- **prepared statements**：批量写入路径复用 prepared statements，减少重复
  解析开销。
- **IN 查询分块**：批量 IN 查询按 500/批分块，规避 SQLite 变量上限
  （`SQLITE_MAX_VARIABLE_NUMBER`）。

这些修复叠加后，全量授权真实语料回归已从小时级收敛到分钟级：连续两次全量
运行（1,328 / 1,330 源，~1.25 GB）的生成时间仅相隔约 35 分钟
（v3 `2026-08-12T23:51:23Z`、v4 `2026-08-13T00:26:57Z`），v4 由改名后的
`agent-session-grep` 二进制执行且六条不变量全绿；此前同一语料的慢批现象
（batch 级 10-40 分钟）不再出现。记录见
`docs/evidence/integration-beta/real-data-regression.md`。
