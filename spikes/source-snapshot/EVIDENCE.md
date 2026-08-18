# EVIDENCE：source-snapshot spike

> 可丢弃探针证据。为 `docs/architecture/RFC-0002-provider-adapter-contract.md` 的 `ReadOnlySourceSnapshot` 提供实测来源；Plan 审查 #6 / §5.2 仅作历史 provenance。
> 目的：验证 Provider 在 parse 期间追加/截断/等长替换源文件时能被检测，提交前复核，
> 变化则丢弃 staging 返回 source_changed_during_read，不提交混合时点数据。

## 环境

- os/arch: windows / x86_64
- 复现命令: `cargo run --release`（在 spikes/source-snapshot 下）

## 结论（全部 PASS）

| 断言 | 场景 | 结果 |
|---|---|---|
| A | 无变化 → 允许提交 | committed=true |
| B | parse 期间追加 → 检测并拒绝 | committed=false |
| C | parse 期间截断 → 检测并拒绝 | committed=false |
| D | 等长异容替换 → fingerprint 检测并拒绝 | committed=false |
| E | 只读性 → 源内容未被本工具改动 | true |

## Load-bearing 结论

1. **len + mtime 不足以检出等长内容替换**（断言 D）：攻击者/Provider 用等长不同内容替换文件时，
   仅比对长度和 mtime 会漏检并提交混合时点数据。**生产实现的提交前复核必须包含内容 fingerprint。**
2. 快照模型：打开句柄时捕获 (len, mtime, content_fingerprint)，parse 只读取捕获范围，
   提交前用同一三元组复核；任一不符即返回 `source_changed_during_read`，丢弃该 source 的 staging。
3. 只读性：全过程不修改源文件内容（断言 E 验证）。

## Contract / decision evidence 与正式记录建议

- `docs/architecture/RFC-0002-provider-adapter-contract.md` 已记录：`ReadOnlySourceSnapshot` 复核包含 content fingerprint，变化返回 `source_changed_during_read` 并丢弃 staging。
- `docs/security/THREAT-MODEL.md` 已引用本 spike 作为混合时点与只读性缓解证据。
- 正式 fault-injection E2E 应加入“parse 期间源文件变化”；本 spike 不单独形成 Accepted contract。
