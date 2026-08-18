# Spike Card：source-snapshot（读取期间源变化检测）

> 治理记录（Governance Record）
>
> - decision_id: SPIKE-source-snapshot
> - status: **Executed（Windows x64 当前证据已产出，待 approver 审阅）**
> - owner: （待项目 owner 指派）
> - approver: 项目最终验收人（须与 owner 分离，待明确）
> - due_milestone: R0 Feasibility / Contract Gate
> - timebox: R0 timebox；精确 deadline 待 owner 指定，不允许开放式延长
> - evidence_path: `spikes/source-snapshot/`（`src/main.rs`、`EVIDENCE.md`）
> - approved_at: —
> - approval_required: 项目 owner 必须显式批准正式 `ReadOnlySourceSnapshot` 合同；本卡不构成 R0 Accepted
>
> 本 Spike 是可丢弃探针，不进入 `crates/` 生产源码树，不形成正式 Provider API 或兼容承诺。

---

## 1. Hypothesis（假设）

Provider parse 前捕获长度、mtime、捕获范围和内容 fingerprint，并在提交 source-local staging 前复核，可以拒绝追加、截断和等长异容替换；仅使用长度与 mtime 不足以安全识别等长替换。检测到变化时必须返回 `source_changed_during_read` 并丢弃该 source staging。

## 2. Fixture / Fault model

- 临时合成 JSONL/文本文件，不使用真实 transcript；
- 无变化控制组；
- parse 后、提交前模拟外部 Provider 追加；
- 模拟截断；
- 用等长不同内容文件 rename 覆盖原文件；
- 对未扰动控制组检查本探针未修改 source 内容。

## 3. Reproduce（Windows）

```text
cargo run --manifest-path spikes/source-snapshot/Cargo.toml --release
```

环境：Windows x86_64；当前证据未记录完整 target triple、Rust 版本或文件系统类型。

## 4. Measurements / Pass-Fail

| Gate | 成功条件 | 当前证据 |
|---|---|---|
| 无变化 | staging 允许提交 | Windows PASS，`committed=true` |
| 追加 | 复核拒绝提交 | Windows PASS，`committed=false` |
| 截断 | 复核拒绝提交 | Windows PASS，`committed=false` |
| 等长替换 | fingerprint 变化导致拒绝 | Windows PASS，`committed=false` |
| 只读控制 | 未扰动 source 内容保持不变 | Windows PASS |

任何扰动场景被提交、无变化场景被误拒，或实现仅比较 len/mtime 而漏掉等长替换，均视为失败。

## 5. Proposed decision（待批准）

正式合同应要求：打开 source 时捕获平台文件身份、长度、mtime、捕获范围及生产级内容 fingerprint；parse 仅消费捕获范围；提交前重新验证；任一关键值变化即丢弃该 source staging，不允许部分提交混合时点数据。

## 6. Evidence status / Limitations

当前证据只证明合成小文件上的**本地 Windows 顺序扰动场景**。探针以 `(len, mtime, FNV-1a fingerprint)` 近似 source identity，没有验证平台 inode/FileId、真实并发写、读取过程中变化、超大文件流式解析、symlink/reparse point 或 Linux/macOS 行为；代码会把捕获内容读入内存，FNV-1a 也不是正式安全 fingerprint 选型。以上缺口必须留给正式合同测试与跨平台 E2E，不能由本卡视为已关闭。
