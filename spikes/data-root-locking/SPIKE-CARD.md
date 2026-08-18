# Spike Card：data-root-locking（Writer Lease / CAS）

> 治理记录（Governance Record）
>
> - decision_id: SPIKE-data-root-locking
> - status: **Executed（Windows x64 当前证据已产出，待 approver 审阅）**
> - owner: （待项目 owner 指派）
> - approver: 项目最终验收人（须与 owner 分离，待明确）
> - due_milestone: R0 Feasibility / Contract Gate
> - timebox: R0 timebox；精确 deadline 待 owner 指定，不允许开放式延长
> - evidence_path: `spikes/data-root-locking/`（`src/main.rs`、回归测试、`EVIDENCE.md`）
> - approved_at: —
> - approval_required: 项目 owner 必须明确 owner/approver，并显式批准正式 lease/CAS 设计；本卡不构成 R0 Accepted
>
> 本 Spike 是可丢弃探针，不进入 `crates/` 生产源码树，不形成正式 API、依赖或兼容承诺。

---

## 1. Hypothesis（假设）

在本地 Windows data root 上，OS 独占文件锁可以作为 writer lease 的权威；持锁进程退出或被杀后锁由 OS 自动释放。持锁者对 lease record 的读写必须复用**同一个已锁定 `File` 句柄**，并在 lease 内执行 `CURRENT == expected_base` 的 CAS，才能阻止旧基线覆盖新 generation。

## 2. Fixture / Fault model

- 临时 data root、锁文件和 `CURRENT` 文件；
- 主进程启动真实 `hold` / `try` 子进程竞争同一锁；
- 强杀持锁子进程，验证 stale-lock 自愈；
- 顺序执行 `CAS(17→18)` 与过期 `CAS(17→99)`；
- 持有 Windows 独占锁时，通过同一句柄写入、seek 并回读 lease record。

## 3. Reproduce（Windows）

```text
cargo fmt --manifest-path spikes/data-root-locking/Cargo.toml
cargo test --manifest-path spikes/data-root-locking/Cargo.toml
cargo run --manifest-path spikes/data-root-locking/Cargo.toml
```

环境：Windows x86_64，`x86_64-pc-windows-msvc`，Rust 1.97.1 stable-msvc，`fs4` 0.13（锁文件当前解析为 0.13.1）。

## 4. Measurements / Pass-Fail

| Gate | 成功条件 | 当前证据 |
|---|---|---|
| 独占性 | holder 持锁时 contender 返回 `DENIED` | Windows PASS |
| 崩溃释放 | holder 被 kill 后无需删文件或 PID 超时即可重获锁 | Windows PASS |
| CAS | 首次 CAS 成功、过期 CAS 被拒、最终 `CURRENT=18` | Windows PASS |
| lease record | `instance_id/pid/process_start/operation_id/fencing_token` 可经同一持锁句柄回读 | Windows PASS；有聚焦回归测试 |

任一竞争者同时取得锁、kill 后需人工清 stale lock、过期 CAS 写入 99，或持锁代码另开同路径句柄，均视为失败。

## 5. Proposed decision（待批准）

- 正式实现以 OS 锁句柄为 lease 权威，记录文件只用于诊断；
- Windows 持锁期间对 lease 文件的全部读写复用同一句柄；
- activation 的 CAS 必须在持有 data-root writer lease 时执行；
- 禁止仅凭 PID 或超时抢锁。

## 6. Evidence status / Limitations

当前 `EVIDENCE.md` 支持上述四项在**单机 Windows x64**上的本地验证；这不是 Linux/macOS 或网络文件系统证据。CAS 探针是持 lease 设计前提下的单进程顺序模拟，真实多进程 CAS、杀毒软件延迟及网络文件系统行为仍需正式 fault-injection E2E。`fs4` 仅为 spike 依赖，正式锁实现仍需 owner/approver 决策。
