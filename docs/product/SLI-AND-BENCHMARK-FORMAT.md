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
- full profile 必须记录实际 store 所链接的 SQLite 版本及其证据来源，不能用 Python
  `sqlite3` 版本或 `not_recorded` 代替；直接运行时查询与下述经构建链证明的版本必须
  分别标注，不能把后者声称为已执行 `sqlite_version()`；
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

#### 可选的 current-source baseline 扩展

同一份 Core/Beta v1 JSON 可携带唯一可选顶层对象 `baseline`，其
`schema_version` 必须为 `agent-session-grep.current-source-baseline/v1`。
只有 `full` 可启用此扩展；普通 smoke/full 与历史无扩展报告保持原有语义。
扩展存在时，未知版本、缺字段、多字段、错误容器或不完整覆盖均须拒绝，不能
忽略后继续宣称验证通过。旧验证器会忽略未知顶层字段，因此扩展必须由报告绑定
版本的新版 harness/checker 校验。该扩展不改变 Draft 状态，也不冻结数值 SLO。

扩展记录 suite ID、运行序号 1/2/3、UTC 起止时间、共享单调时钟起点与已用时间、
`source_before` / `source_after`、`build_receipt` 及其 SHA-256、`binary_use`、
`child_policy`、固定 `plan`、`preflight`、`anchor`、三个 `workloads` 与 `coverage`。
每个 workload 分别保留阶段快照、按执行顺序排列的 observations、context anchor、
固定实体选择、summaries 和 derived；成功数值不得替代缺失的原始记录。

| 工作负载 | 生成输入 | 实际查询阶段 | shrink 后保留 |
|---|---|---|---|
| 原 full anchor | 20 文件 × 200 消息 | 第三 trial 的 post-shrink，2,000 消息 | 2,000 |
| `scale-2000` | 10 文件 × 200 消息 | 第三 trial 的 intact，2,000 消息 | 1,000 |
| `scale-10000` | 50 文件 × 200 消息 | 第三 trial 的 intact，10,000 消息 | 5,000 |
| `scale-50000` | 250 文件 × 200 消息 | 第三 trial 的 intact，50,000 消息 | 25,000 |

文件数是输入布局，不能直接冒充已观测的 canonical Session 数。每个阶段记录
生成 source occurrences、字节数、SHA-256 tree hash，以及独立只读 census 的
Message、Placement、Session、SourceDocument、FTS、source claims、edges 和
generation。initial → noop → shrink 各执行三次独立 trial；noop 是该 trial
initial 后的恰好一次无变化扫描。各 scale 仅在第三 trial 的 noop 后、shrink 前
查询。原 anchor 保留九项 legacy metrics、原始计数和原执行顺序，包括混合五类
查询的总计 100 个 search 样本与已经 shrink 的查询库。

三份完整报告使用各自新建的合成语料和 store，串行运行。scale 顺序固定轮换为
小/中/大、中/大/小、大/小/中。每轮先做 1 文件 × 20 消息的 untimed correctness
preflight；其 observations 不进入 measured 统计。每个 scale 的五个 search
类别、show、get、context mainline 与 full 各有 3 次独立记录的 warmup 和 100 次
measured 调用；search 在所有类别 warmup 后按类别 round-robin 采样。startup
复用 anchor 的每种 20 次观测，不按 scale 重复；warm startup 前仍有 3 次 warmup。

search 类别与 query 一一固定为 `token` → `benchmarktoken`、`latin` → `alpha`、
`cjk` → `配置`、`path` → `"src/main.rs"`、`identifier` → `EVIDENCE42`。
诊断 search 显式使用 `--output json --mode lexical --max-items 20
--max-bytes 4194304`，只取首屏，不声称 recall 认证。show/get 是单实体读取，按
固定 generator file/record 序列映射到各轮实际 wire ID。context 选 generator
file 0 对应的已验证 Session，使用 `--output json --level raw --policy
mainline|full --max-messages 500 --max-bytes 4194304`。主线选择非 sidechain
leaf 后沿 parent 链回溯，该链可能保留 sidechain 祖先；full 顺序遵从产品的
timestamp/source ordinal 契约。oracle 必须检查实体内容、policy-specific
membership/order、leaf、Placement 与 evidence 对齐；unexpected partial、
非零退出、错误 generation、错误实体或缺失结果均使本轮失败。

#### 时钟、环境与原始统计

同一次子进程生命周期记录两个独立命名的观测，禁止混合：

- `process-wall-before-observer/v1`：`process_wall_ms` 从进程创建前开始，到
  stdout/stderr 收集与进程退出完成后停止，停止点在 memory observer cleanup 前。
- `legacy-wall-with-observer/v1`：保留 observer cleanup 后的旧 `duration_ms`；
  anchor observations 用 legacy metric 名称和 sample index 与原九指标逐条关联。

共享 `run_process` 的默认环境、非零退出失败语义和三个返回 key（`duration_ms`、
`peak_rss_mb`、`stdout`）不变，gate/semantic 调用者无需 opt-in。两个时钟的差值
不是产品优化收益。可选 `cli_reported_duration_ms` 是整数毫秒的 CLI pre-render
观测，覆盖 parse/open/dispatch/drop/wake；不得称为纯 engine/SQLite latency，
也不得通过减去另一批 startup 中位数推算引擎耗时。

baseline child 从复制的 launcher environment 中移除 `ASG_INDEX_TRACE`、
`ASG_CURRENT_REPO`、`ASG_CLOCK_MS`（包括大小写变体），保留正常 bootstrap 变量，
cwd 固定为冻结 source root。报告记录 trace disabled、repo derived、system
application clock 与逻辑 cwd `source-root`；不修改父进程或全局配置。独立 trace
trial 只向自己的 child 加入其自有 trace target。记录安全 repository identity、
实际工具链/target、CPU、RAM、磁盘、文件系统、防病毒状态和 UTC 区间；三轮须兼容。
复制二进制的 cold startup 只是 best effort，OS page cache 未控制，不清缓存、
关闭安全软件或推断“新进程等于冷缓存”。

每次调用保留全局 ordinal、workload/phase/trial、warmup/measured/verification
角色、sample index、query/entity/policy、逻辑相对 argv、UTC、exit/outcome、
两种 duration、含最终 LF 的 UTF-8 stdout 字节数、correctness 结果和 memory
观测。RSS 记录平台方法、100ms 间隔和实际 observation count；无观测时 peak
为 `null`、count 为 0、reason 为 `no_observations`，不得填 0 或丢失样本位置。
周期 RSS 是近似观测，不保证捕获真实峰值；不发布完整 stdout 或环境 dump。

从已保存的六位小数原始毫秒值计算，不做中间 rounding：
`Qp(x)=sorted(x)[ceil(p*n/100)-1]`，`M=Q50(x)`，
`MAD=Q50(abs(x_i-M))`（未缩放）。summaries 包含 count、min/max、P50/P95/P99、
mean、sample standard deviation 和 MAD；不同类别、规模、阶段或时钟不混池。
仅 summary/display 最终按六位小数输出。三个可比 run P50 的 spread 为
`100*(max(m)-min(m))/Q50(m)`，仅严格大于 15% 才告警。分母与 range 都为零时
spread=0；分母为零且 range 为正时 spread=`null`，告警并记
`zero_median_with_positive_range`，不输出 Infinity。这是噪声提示，不是性能门槛；
保留全部运行与原始样本，不裁剪、不挑最快、不静默重试。三个 sync / 二十个
startup 样本的尾部辨识力有限，不能据其 legacy P95 认证 tail-latency SLO。

initial throughput 使用该 trial 的实际 source occurrences/bytes 除以其对应
wall duration；noop 与 shrink 不算新消息索引吞吐。每个 store/source ratio
必须对应同阶段输入，store bytes 包含 `catalog.db` 及进程退出后仍存在的
sidecars，覆盖标识为 `catalog.db-and-present-sidecars-after-exit-no-explicit-checkpoint`，
不能表述为执行了显式 checkpoint。文件清单与字节数在独立只读 census 打开
SQLite 之前固定：`mode=ro` 在可写目录仍可能创建 WAL/SHM，不把校验器产生的
sidecars 计入被测命令退出后的 footprint；数据库仍以普通只读模式核验。

#### 来源收据、有限执行与发布

先冻结干净 tooling commit **S**，harness/checker 必须从 S 自身执行（H=S）；
运行前后检查 tracked、index 和 relevant untracked cleanliness，保存 harness、
checker、Cargo.lock、Cargo.toml 哈希。run 1 以 locked release build 的 Cargo
artifact JSON 确认真实可执行文件，冻结 binary **B** 与带 hash 的 build receipt，
然后才开始共享 suite 时钟。runs 2/3 验证并复用同一 receipt/B，不重建、不重启
deadline。opt-in 拒绝外部 `--binary`；普通非 suite 的该选项保持可用。任何
prebuilt 消费（包括 runs 2/3）仍标 `caller_supplied_prebuilt`，保留无独立 attestation
的限制；receipt 不可升级该 provenance 标签或声称重新构建。

SQLite 证明需同时验证当前 lock 指定的 crate archive checksum、实际 bundled
source/header/build script、resolved features、无外部链接覆盖、该 build 的静态
native library 与最终 B。记录 `locked-bundled-source-and-build-linkage` 和
`runtime_query: false`，明确“locked bundled source + this build linkage;
no direct CLI runtime query”。Python SQLite、旧 spike 或只写一个版本字符串
均不能替代此证明。未解析的 Cargo 配置/编译链接覆盖、dirty/wrong source、
不匹配 B 或缺失 linkage 均不能形成 qualified suite；不自动改变全局设置。

suite 最多 60 分钟测量、单 child 最多 300 秒；build/test 在计时外。开始前至少
8 GiB scratch free space；trial 边界 managed scratch 超过 4 GiB 或已观测 child
RSS 超过 4 GiB 即停止。它们是采样/边界 guardrails，不是 OS 配额，进程创建也
不能由 Python timeout 抢占。所有 250 个文件保留单次显式 sync，运行前按实际
owned scratch 布局核验 native argv 限制。失败、deadline 或资源停止保留 ignored
output 下的 `attempt.json`、失败 phase、已有成功和失败 observations；返回失败，
不输出可冒充完整报告的残缺 v1 数据，不自动降规模或重试。已有 output/claim/
receipt 不覆盖；cleanup 只允许有匹配 owner marker 的确切 owned scratch root。

三轮主测量完成后，run 3 用剩余预算单独做一次最大规模 initial/noop/shrink
trace trial。trace-enabled 时延不进入主分布，缺文件/阶段为 unavailable；raw
trace 和 failed attempts 保留本地。阶段 scopes 有嵌套重叠、crate-local 时钟
不共享原点，不能求和当作完整 wall time；发布只用审阅过的 aggregate diagnosis。

实际接口如下，所有占位值必须来自 S/本次环境/收据，不从后续 publication HEAD
推断 S；三个输出目录共享一个新的 ignored suite parent：

```text
python -B scripts/evidence/core_beta_benchmark.py run --profile full --baseline-run 1 --suite-id <safe-id> --workspace . --output-dir evidence-output/<suite>/run-01 --expected-commit <full-S-SHA> --disk <disk> --filesystem <filesystem> --antivirus-state <state> --sqlite-version <linked-version> --sqlite-version-source <evidence>
```

随后串行使用同一 suite ID/环境，把 ordinal 与输出目录分别改为 2/run-02、
3/run-03。`validate-report` 条件校验完整扩展，重算每项 raw summary、throughput、
ratio、anchor legacy links 与 coverage；拒绝 bool-as-number、NaN/Infinity、负数、
错误版本/容器/ID/phase/order/count、缺失 memory reason、错误来源或失败结果。
集合校验要求三个不同完整报告、全部 ordinals/orders、同一 S/H/B/receipt、
固定 corpus/protocol 和兼容环境，三份同一报告或 legacy-only 报告不能通过：

```text
python -B scripts/evidence/core_beta_benchmark.py validate-report <report.json>
python -B scripts/evidence/core_beta_benchmark.py validate-baseline <report-01.json> <report-02.json> <report-03.json>
```

验证证明内部一致性，不证明对手重写全部相关字段后的真实性。Markdown 必须由
同一 S 的 renderer 从验证后的 JSON 生成。后续 publication commit **P** 只发布
原始三报告、投影、manifest 和说明；报告中的 `commit` 永远是 S，P/merge SHA
各自的 checks 和验收另行记录。历史 full 仅为历史锚点，没有匹配的 workload、
时钟、build 与环境证据时不得声称测得提升。新基线也不等于跨平台、独立复现、
release certification 或父任务的最终验收。

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
