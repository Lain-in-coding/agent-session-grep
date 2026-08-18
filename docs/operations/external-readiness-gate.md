# 外部就绪门（External Readiness Gate）

> 治理记录
> - decision_id: R0-EXTERNAL-READINESS
> - status: Draft（待 R0 评审）
> - owner: （待指派）  approver: 项目最终验收人
> - due_milestone: R0；正式发布前必须再次执行一次完整 dry-run
> - evidence_path: docs/operations/ + CI 发布日志

本门是外部发布就绪要求的规范性清单。目标：正式发布依赖的外部凭据与渠道，在不依赖本地开发机状态的前提下，提前完成配置或无密钥 dry-run，避免发布当天才发现凭据缺失。平台承诺与构建策略见 `../adr/ADR-0002-platform-targets.md`。

## 1. 门项清单（每项需 owner + 状态 + 最后一次 dry-run 记录）

状态含义与 evidence matrix 对齐：`ci_configured_only` 只证明 workflow
配置存在；`ci_verified` 还需要一个可定位的成功 run；`externally_blocked`
表示需要 owner、证书、平台账户或受治理身份，不能由本地 unsigned 输出替代。

| 门项 | 状态 | 说明 | 本机/仓库现状 |
|---|---|---|---|
| Unsigned release archives + SHA256SUMS | `ci_configured_only` | 四个承诺 target 的 versioned archive、hash、manifest 和 synthetic smoke | `.github/workflows/release.yml` 已配置；无成功 run 记录，不得写成 `ci_verified` |
| Third-party dependency attribution bundle | `ci_configured_only` | `cargo metadata --locked` + `Cargo.lock` 生成 JSON/CSV；缺失 license 元数据保持 null | helper 与 archive allowlist 已配置；不是完整 SPDX/legal clearance |
| Self-reported provenance metadata | `ci_configured_only` | source commit、target、version、Cargo.lock hash、member hashes | per-target manifest 已配置；不是密码学 attestation |
| Windows 代码签名 | `externally_blocked` | 证书就位或 dry-run | 需真实证书，本机无 |
| macOS 开发者签名 + 公证 | `externally_blocked` | Apple 凭据 + macOS 主机 | 本机无 macOS 身份 |
| 制品透明日志签名 | `externally_blocked` | cosign / OIDC | 本机缺 cosign，CI 阶段另行配置 |
| 制品来源证明 | `externally_blocked` | GitHub Artifact Attestation / governed provenance | unsigned manifest 不满足该门 |
| GitHub Release tag/visibility action | `externally_blocked` | owner 创建最终 tag、切换 visibility、确认公开 release | workflow 仅在 tag push 发布 unsigned assets；manual dispatch 不创建 Release |
| crates.io 可信发布 | `externally_blocked` | OIDC + 维护责任人 | 待配置 |
| 下游渠道 | `externally_blocked` | Homebrew Tap / Scoop bucket / 安装脚本 | 待配置，均为发布后 promotion |

## 2. 规则

- 凭据绝不写入仓库，不在 CI 日志或制品中出现；release workflow 不读取
  repository secrets，manual dispatch 不创建 GitHub Release；
- release workflow 的 configured matrix、local dry-run 与 successful run 是三种
  不同证据：只有具名成功 run 才能把 `ci_configured_only` 提升为 `ci_verified`；
- 任一外部渠道不可用时，权威 GitHub Release 仍可独立发布，渠道随后再 promotion；
- 门结果、证书有效期、责任人、回滚手册和最后一次 dry-run 时间戳作为发布证据保存；
- 正式发布前必须重新跑一次完整 dry-run，过期即视为未通过。

## 3. 与 spike 的关系

cross-platform-packaging spike 已实测本机可验证部分（干净构建、依赖审计、SBOM 生成、checksum-after-sign 顺序）。当前 release workflow 进一步把可本地闭合部分实现为 locked build、synthetic smoke、unsigned archive、`SHA256SUMS`、依赖 JSON/CSV 和 path-free manifest；截至本文仅记为 `ci_configured_only`。本门继续覆盖本机无法验证、需真实凭据、外部账户、正式 tag 或 owner 决策的部分。若未来加入签名，必须对最终签后制品重新计算并发布 checksum，不得沿用 unsigned archive 的 hash。
