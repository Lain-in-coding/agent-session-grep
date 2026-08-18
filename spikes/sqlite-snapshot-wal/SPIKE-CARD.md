# Spike Card：sqlite-snapshot-wal（一致快照 / 不可变 Bundle）

> 治理记录（Governance Record）
>
> - decision_id: SPIKE-sqlite-snapshot-wal
> - status: **Executed（Windows x64 当前证据已产出，待 approver 审阅）**
> - owner: （待项目 owner 指派）
> - approver: 项目最终验收人（须与 owner 分离，待明确）
> - due_milestone: R0 Feasibility / Contract Gate
> - timebox: R0 timebox；精确 deadline 待 owner 指定，不允许开放式延长
> - evidence_path: `spikes/sqlite-snapshot-wal/`（`src/main.rs`、`EVIDENCE.md`）
> - approved_at: —
> - approval_required: 项目 owner 必须选择正式快照方法并批准 SQLite 安全基线；本卡不构成 R0 Accepted
>
> 本 Spike 是可丢弃探针，不进入 `crates/` 生产源码树，不形成正式 schema、migration 或依赖承诺。

---

## 1. Hypothesis（假设）

WAL 模式下仅复制 `.sqlite` 主文件不能保证包含已提交但未 checkpoint 的事务；SQLite Online Backup API 或 `VACUUM INTO` 可以生成一致快照，且冻结后的旧快照可在源库继续写入时保持只读、内容不变。

## 2. Fixture / Fault model

- 临时 SQLite 数据库，写入 5,000 行；
- `journal_mode=WAL` 且 `wal_autocheckpoint=0`，放大事务仍留在 `-wal` 的窗口；
- 故意只复制主库，不复制 `-wal` / `-shm`；
- 分别用 Online Backup API 与 `VACUUM INTO` 生成快照；
- 快照冻结后向源库再写入 1,000 行，同时读取旧快照。

## 3. Reproduce（Windows）

```text
cargo run --manifest-path spikes/sqlite-snapshot-wal/Cargo.toml --release
```

环境：Windows x86_64，`x86_64-pc-windows-msvc`，Rust 1.97.1 stable-msvc，SQLite 3.53.2，`rusqlite` 0.40.1 bundled，`libsqlite3-sys` 0.38.1。

## 4. Measurements / Pass-Fail

| Gate | 成功条件 | 当前证据 |
|---|---|---|
| 裸复制风险 | 副本少于 live 5,000 行或不可读，证明方法不安全 | Windows PASS（风险复现，副本哨兵值 -1） |
| Backup API | 快照恰有 5,000 行 | Windows PASS |
| VACUUM INTO | 快照恰有 5,000 行 | Windows PASS |
| 旧 generation | 源库增至 6,000 行后旧快照仍为 5,000 行 | Windows PASS |

Backup/VACUUM 快照少行、旧快照随源写入变化，或生产方案依赖裸 `fs::copy` 活跃 WAL 主库，均视为失败。

## 5. Proposed decision（待批准）

- 禁止把裸主库复制作为 Generation Bundle 快照方法；
- 正式实现从 Online Backup API 与 `VACUUM INTO` 中选择受控一致快照方案；
- immutable 只读打开前必须确认快照已冻结且不依赖活动 WAL sidecar；
- owner/approver 仍需冻结实际 SQLite 版本、crate feature、链接策略、checkpoint 与激活流程。

## 6. Evidence status / Limitations

当前证据仅为**单机 Windows x64 + SQLite 3.53.2** 的确定性本地结果。`wal_autocheckpoint=0` 是故障放大设置；它证明裸复制存在风险，但不等于生产负载基准。未覆盖多进程 WAL/SHM 竞争、checkpoint crash point、磁盘写满、杀毒软件 rename 延迟、Linux/macOS、正式 generation manifest/CAS 或 SQLite 安全版本审查，因此不能据此宣称跨平台 Gate 已通过。
