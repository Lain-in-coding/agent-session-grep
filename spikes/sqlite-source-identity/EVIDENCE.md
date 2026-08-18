# sqlite-source-identity — Spike Evidence

> 可丢弃探针证据。本页只记录实测结果与推论边界，不构成正式 SLO、
> 平台认证或 provider 支持承诺。

- spike: `spikes/sqlite-source-identity/`
- 运行命令: 第一阶段 `cargo run --release --bin sqlite-source-identity-spike`；第二阶段 `cargo run --release --bin phase2`
- 采集环境: 两个平台各跑全部十条断言，均退出 0
  - Windows 11 x64, `x86_64-pc-windows-msvc`, SQLite 3.53.2 (rusqlite 0.40.1 bundled)
  - WSL2 Ubuntu, kernel 6.6.87.2, `x86_64-unknown-linux-gnu`, rustc 1.97.1, 同一 bundled SQLite 3.53.2
- 退出语义: 任一断言失败则进程非零退出

## 动机

`agent-session-grep-ports::SourceSnapshot` 当前把源身份定义为
`(path, len, mtime_ms, BLAKE3(整文件))`，`source_fs.rs` 的 capture/verify 按此实现。
该契约假设**一个源文件承载一个可独立校验的单元**。

若要支持以 SQLite 数据库为存储的 provider（例如 ForgeCode 的 `.forge.db`、
Kiro、Amazon Q、Goose、Crush、llm、Zed、Trae 这类把会话存在表里的工具），
上述假设不成立。本 spike 实测该假设失效的具体方式，并验证一个替代身份方案。

## 断言与结果

| 断言 | 结果 | 实测细节 |
|---|---|---|
| A 单文件承载多会话，文件级身份不足以定位单会话 | PASS | 单个 `.db` 内 3 个会话共享同一文件 fingerprint |
| B 无关写入使文件级快照失效（假阳性） | PASS | 改写会话 B 后整文件 fingerprint 变化，而会话 A 行内容未变 |
| C WAL 提交后主库 `len`+`mtime` 可保持不变 | PASS | 事务已提交且对新连接可见，主库仍为 12288 字节且 mtime 未变 |
| D 行级指纹检出等长异容替换 | PASS | 10→10 字节等长替换被行级 BLAKE3 检出，不依赖 mtime |
| E 行级快照对无关写入稳定 | PASS | 其他行改写+新增后，目标行快照保持不变 |
| F `PRAGMA data_version` 提供 O(1) 变更检测 | PASS | 外部写入后 data_version 2→3 |
| G 只读打开不修改源库 | PASS | 读取后文件身份不变；只读连接的写入被 SQLite 拒绝 |
| H schema 漂移下行级身份稳定 | PASS | 列 5→9：`ALTER TABLE ADD COLUMN` 后身份不变；语义列改动被检出；异名同义表身份一致 |
| I 并发写入下读快照一致 | PASS | 读事务内快照隔离；提交后变更被检出；读者未被并发写阻塞 |
| J 规模开销与 O(1) 门 | PASS | 5000 行 / 20627456 字节：全量行级指纹 25.5ms，单行重算 0.019ms，`data_version` 门 1.9µs |

## 推论

**A/B/C 成立 → 现有文件级契约不能直接套用于 SQLite 源。**

三种失效方式各自独立：

1. **粒度错配**（A）：`SourceSnapshot.path` 指向整个 `.db`，无法表达"这一个会话"。
   多个会话共享同一 `(len, mtime, fingerprint)`。
2. **假阳性**（B）：任何一个会话被写入都会改变整文件哈希，导致所有其他
   未变会话的快照校验失败，触发不必要的 `SnapshotChanged`。
3. **假阴性**（C）：WAL 模式下已提交事务可能仍在 `-wal` 中，主库 `len`+`mtime`
   不变。仅凭 `(len, mtime)` 会漏检真实变更。这与
   `spikes/sqlite-snapshot-wal/` 断言 A 是同一现象的两面：
   那里证明裸复制主库会丢数据，这里证明主库元数据不反映已提交写入。

**D/E 成立 → 行级身份可承担 `SnapshotChanged` 语义。**

把身份从"文件"下移到"行"：`(row key, BLAKE3(该行规范化内容))`。
该方案在等长异容替换下仍能检出（D），且不受同库无关写入干扰（E）。
注意这里刻意**不使用 mtime**——数据库行没有独立 mtime，内容指纹是唯一可靠信号。

**F 成立 → `data_version` 可做库级快速门。**

`PRAGMA data_version` 在其他连接提交后变化，可作为 O(1) 前置判定，
避免每次同步都重算全库或全行哈希。它只说明"库变过"，不说明"哪一行变了"，
因此是优化手段而非身份来源。

**G 成立 → 只读不变量可以维持。**

`SQLITE_OPEN_READ_ONLY` 打开后写入被拒绝，符合 provider 源严格只读的要求。

**H 成立 → 行级身份可以跨 schema 漂移存活。**

指纹只覆盖**语义列**（会话内容），不覆盖表的物理形状。因此
`ALTER TABLE ADD COLUMN` 把列数从 5 加到 9 后，已有行的身份不变；
真正改动语义列时身份变化被检出；两张列名不同但语义等价的表算出同一身份。
这使运行时列名候选解析（`PRAGMA table_info` + 候选名映射）成为可行的适配层：
适配层负责把不同 provider 的列映射到统一语义位置，身份计算只看映射结果。

这一点不是假设。本机 Zed 的真实 schema 就带着漂移痕迹：

```sql
CREATE TABLE threads (
  id TEXT PRIMARY KEY, summary TEXT NOT NULL, updated_at TEXT NOT NULL,
  data_type TEXT NOT NULL, data BLOB NOT NULL
, parent_id TEXT, folder_paths TEXT, folder_paths_order TEXT, created_at TEXT)
```

`data BLOB NOT NULL` 之后那个换行加逗号的续接形式，是 SQLite
`ALTER TABLE ADD COLUMN` 改写 schema 文本留下的签名——即后四列是后来加的。
固定列序、固定列数的读取方式会在这类库上直接失效。

**I 成立 → 并发读写下快照语义成立。**

WAL 模式下只读事务拿到一个一致读点：读事务内多次采样得到同一快照，
即便另一连接同时在写；写者提交后，新读事务能检出变更；读者不被写者阻塞，
也不阻塞写者。这正是"provider 正在写会话，本工具同时在索引"的场景，
不需要额外加锁或复制整库。

**J 成立 → 成本结构支持增量同步。**

5000 行 / 约 20MB 的库上，全量行级指纹 25.5ms，单行重算 0.019ms，
`data_version` 门 1.9µs。门比全量便宜两个数量级以上，
所以稳态同步的常态开销是"读一次 pragma 后立即返回"，
只在库确实变过时才付行级代价，且可按行收敛到变更行。

## 边界与未验证项

- macOS 未复测。Windows 与 Linux(WSL2) 已各跑全部十条断言、均退出 0，
  `data_version` 与 WAL 行为在这两个平台一致；`aarch64-apple-darwin`
  与真机 macOS 上的行为未取得证据（本机无 macOS，属 externally_blocked）。
- 未在**有数据的**真实 provider 库上实测。本机只有 Zed 与 OpenCode，
  ForgeCode / Kiro / Amazon Q / Goose / Crush / Cursor 均不存在；
  Zed 的 `threads` 表为 0 行。因此 H 的 schema 真实性有证据（见上），
  但真实数据量下的行为没有。J 的规模数字来自合成的 5000 行库。
- 未验证压缩 BLOB 载荷。Zed 的会话正文存在 `data BLOB` 列，
  按其实现为压缩字节。行级指纹对不透明字节同样成立，
  但"解压后再规范化"这一层的成本与失败模式未测。
- 未实现生产代码。本 spike 不修改 `crates/`，
  `SourceSnapshot` 与 `SourceDiscovery` 保持原样。

## 对设计的影响

若要支持 SQLite 类 provider，`SourceSnapshot` 需要从"文件三元组"泛化为
"可校验源单元"，容纳两种身份：

- 文件源：`(path, len, mtime_ms, content fingerprint)` — 现状
- 数据库行源：`(db path, table, row key, content fingerprint)` — 无 mtime

这是一次 ports 层的契约变更，影响 `SourceDiscovery::read_verified` 与
`source_fs.rs` 的 capture/verify。属于 0.3 及以后的设计决策，
需要独立 ADR，本 spike 只提供可行性证据，不作决定。

## 与 CCHV 的对照

`jhlee0409/claude-code-history-viewer`（MIT，v1.22.0）支持 28 个 provider，
其中多个为 SQLite 存储。它对本问题的处理方式是**绕过**而非解决：
为无文件路径的会话合成 URL（`kiro://{key}`、`cline://{base}:{cwd}`、
`copilot://{base64}`），并在 `commands/stats/cache.rs` 中明确记录该选择的代价：

> "Provider (non-Claude) stats paths are not cached: their session paths are
> virtual (`opencode://` …) and carry no `(size, mtime)` identity."

即：合成 URL 让它能快速接入大量 provider，但这些 provider 因此无法获得
`(size, mtime)` 身份，也就无法做缓存与增量刷新。CCHV 每次启动全量重扫，
并从文件大小估算消息数以让全量扫描可承受。

本 spike 的行级身份方案给出了另一条路：SQLite 源同样可以获得稳定、
细粒度、内容可验证的身份，从而支持增量与持久索引。这是本项目相对
CCHV 的技术差异点所在——但代价是每个 provider 的接入成本更高。

## CCHV provider 存储分档（观察快照，非规格）

> 以下是对 CCHV 公开源码的机械分类，**截至 v1.22.0 / 推送 2026-07-23**。
> 数字会随上游版本变化；不得当作本项目的 provider 支持承诺或验收数字。
> 判定依据：源文件是否调用 `Connection::open` / `rusqlite`，以及是否构造合成 URL。

`ProviderId` 枚举共 **28** 个用户可见 provider（`src-tauri/src/providers/mod.rs`）。
按存储形态粗分：

| 档位 | 约数 | 接入本项目的前置条件 | 代表 |
|---|---|---|---|
| 文件型（jsonl / 整文件 JSON） | ~17 | 现有文件级 `SourceSnapshot` 即可 | gemini、qwen、aider、kimi、copilot、continue、openhands、pi、vibe、codebuddy、antigravity… |
| SQLite 型 | ~11 | 需要行级身份 + 运行时列名适配 | zed、cursor、cline、trae、kiro、crush、forgecode、amazon_q、goose、llm、opencode |
| 混合型 | 1 | 文件级为主，SQLite 为辅 | codex（本仓库已支持） |

实测信号摘要（临时下载 CCHV `providers/*.rs` 后 grep，下载物已删除）：

- 真正 `Connection::open` 的文件：zed、trae、cursor、cline、kiro、crush、forgecode、amazon_q、goose、llm、codex、opencode。
- 使用 `PRAGMA table_info` 做运行时列适配的只有 **zed** 与 **forgecode**；其余 SQLite provider 为硬编码列序。本项目若做通用适配层，不能指望从 CCHV 抄到现成层。
- 合成 URL scheme 已观察到：`codex://`、`cursor://`、`cline://`、`kiro://`、`opencode://`、`forgecode://`、`gemini://`、`aider://`、`kimi://`、`vscode://`。合成路径是 CCHV 无法做增量的根因（见上一节引用）。

### 对本项目推进顺序的建议（仍是建议，不是决策）

1. **先完成已写明的身份建模**（Session/SourceDocument 独立身份）。行级身份作为该建模的一种形态，引用本文件为可行性证据；真正做决定时写 ADR，不在此升级为规格。
2. **再批量接入文件型 provider**。它们不需要契约变更，但依赖批次 4 的 fixture 规范（可审计、隐私安全、可复现），否则每个 provider 都会欠一笔 fixture 债。
3. **最后接 SQLite 型**。前置是 ADR 落地 + 通用列名适配层。

### 交接注意

- 本文件与 `src/` 探针代码同属可丢弃 spike；清理 spike 前须先把**耐久结论**写入 ADR，否则链接会断。
- 不得把本节的"~17 / ~11 / 28"写进任何验收标准；那些是对手某版本的观察。
- 生产代码未改：`crates/` 保持原样。
