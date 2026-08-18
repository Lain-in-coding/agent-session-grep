# sqlite-snapshot-wal Spike 证据

> 治理记录
>
> - decision_id: SPIKE-sqlite-snapshot-wal
> - status: **Executed（初步证据已产出）**
> - owner: 自主执行（R0 探针）
> - approver: 项目最终验收人（待确认）
> - due_milestone: R0 Feasibility / Contract Gate
> - evidence_path: `spikes/sqlite-snapshot-wal/`（探针代码 + 本文件）
>
> 本 Spike 是可丢弃探针，不进入 `crates/` 生产源码树，不形成正式 API/迁移承诺。是否归档与证据是否采信由 R0 Architecture Review 决定。

---

## 1. 目的

为以下条款在 **Windows** 上提供实测证据；是否成为正式约束由对应 ADR/Contract 与 R0 Architecture Review 决定：

- 历史 Plan §9.1：WAL 库的一致快照方法；
- 历史 Plan §6.5：不可变 Generation Bundle（旧 generation 在新写入期间仍可只读打开）；
- 历史架构审查第 13 项：裸复制 `.sqlite` 会丢失未 checkpoint 的已提交事务。

## 2. 环境（基准报告）

| 项 | 值 |
|---|---|
| OS | windows |
| Arch | x86_64 |
| Target | x86_64-pc-windows-msvc |
| SQLite | 3.53.2（rusqlite 0.40.1 bundled，libsqlite3-sys 0.38.1） |
| Rust | 1.97.1 stable-msvc |
| 数据规模 | 5000 行，`wal_autocheckpoint=0`（逼出"数据只在 -wal 中"的状态） |

## 3. 结论（四断言全部 PASS）

| 断言 | 结果 | 证据 |
|---|---|---|
| A. 裸复制主库（缺 `-wal`）丢数据 | **PASS（风险复现）** | live=5000 行，裸复制副本 `immutable=1` 打开读到 **-1 行**（副本无法完整读出） |
| B. Online Backup API 一致快照 | **PASS** | Backup 快照只读读到 **5000 行**，与源库相等 |
| C. VACUUM INTO 一致快照 | **PASS** | VACUUM INTO 快照只读读到 **5000 行**，与源库相等 |
| D. 旧快照在写入期间可只读打开 | **PASS** | 冻结时 5000 行 → 源库继续写到 6000 行 → 旧快照仍只读读到 **5000 行**（不受后续写入影响） |

## 4. Contract / decision evidence 与正式记录建议

1. **快照实现约束**：正式存储规范应禁止对 WAL 数据库只做裸 `fs::copy` 主库文件（断言 A 证明会丢数据），并在 Online Backup API 与 `VACUUM INTO` 中明确选择。
2. **不可变 Bundle / cursor contract 证据**：断言 D 证明 Windows 上旧 generation 快照可在新一轮 sync 写入期间只读打开并保持冻结数据，可供正式分页 pinning 设计引用。
3. **历史审查证据 #13**：裸复制风险在 Windows + SQLite 3.53.2 上真实复现；应链接到正式存储决策记录，而不是以历史 Plan 为当前权威。

## 5. Caveat（诚实边界）

- 本 spike 用 `wal_autocheckpoint=0` 放大了"数据滞留 -wal"的场景；生产默认 autocheckpoint 开启时，裸复制丢数据的窗口更小但依然存在（取决于 checkpoint 时机），因此结论方向不变：**不依赖裸复制**。
- 断言 A 的副本读到 -1 是"COUNT 查询失败/读不出"的哨兵值，表现为副本不可用；不同 SQLite 版本可能表现为"读到部分行"，但都属于数据不完整，均坐实风险。
- 未覆盖：多进程并发下的 `-wal`/`-shm` 竞争、杀毒软件文件锁延迟对 rename 的影响——这些留给 `data-root-locking` 与 `cross-platform-packaging` spike。
- SQLite 3.53.2 是 rusqlite 0.40 bundled 版本；本 spike 只记录实际链接版本，最低安全 SQLite 基线仍需由正式依赖/安全决策按 SQLite 官方修复公告确认。

## 6. 复现

```powershell
cd spikes/sqlite-snapshot-wal
cargo run --release
```

确定性结果，无随机性；每次全新临时目录。
