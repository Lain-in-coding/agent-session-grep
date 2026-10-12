# EVIDENCE：cross-platform-packaging spike

> 可丢弃探针证据。为 `docs/operations/external-readiness-gate.md` 提供本机发布顺序证据；Plan §12.4 / 审查 #12 仅作历史 provenance。
> 本 spike 只验证 Windows x64 本机步骤，不证明跨平台构建、真实签名或公证通过。
> 探针脚本：`verify-release-pipeline.ps1`（本机实跑）。

## 环境
- os/arch = windows / x86_64
- 已装工具：cargo-audit、cargo-cyclonedx、cargo-deny、gh 2.83.0
- 缺失工具：cosign（签名）、syft（备选 SBOM）；仅装 x86_64-pc-windows-msvc target

## 本机可验证步骤（实测 PASS）
| step | 结论 |
|---|---|
| 1 干净构建（release，本 target） | PASS：`cargo build --release` 成功 |
| 2 供应链审计 | PASS：cargo-audit 无已知漏洞 |
| 3 SBOM (CycloneDX) | PASS：cargo-cyclonedx 生成真实 SBOM（约 48KB） |
| 4 checksum 顺序（审查#12） | PASS：先追加模拟签名，再对最终字节重复计算 checksum，re-hash 稳定一致；未执行 checksum 后篡改检测 |

## 关键结论
1. **历史审查 #12 的证据**：本探针支持在模拟签名后对最终字节计算 checksum，并验证未再变化时重复 re-hash 一致；它没有执行 checksum 后再次改字节的失败场景。正式发布顺序与篡改检测由 External Readiness Gate 维护。
2. **供应链证据可自动化**：cargo-audit + cargo-cyclonedx 在本机即可产出漏洞与 SBOM 证据，可进 PR/Release Gate。
3. **cargo-deny 对 tantivy 报 unlicensed**（ort-sys 传递依赖，见 search-backend EVIDENCE），FTS5 依赖树（rusqlite bundled）更干净——从供应链维度支持 FTS5 默认。

## 需 External Readiness Gate（本机不验证）
- Windows Authenticode 签名：需真实证书；
- macOS Notarization：需 Apple 凭据 + macOS 主机；
- 多 target 交叉构建：需安装 target 或 CI runner（当前仅 windows-msvc）；
- cosign / syft：本机缺，CI 或 External Readiness 阶段补齐。

## Contract / decision evidence 与正式记录建议
- `docs/operations/external-readiness-gate.md` 应继续引用本机已测的 checksum-after-sign、依赖审计与 SBOM 证据；
- 签名/公证/多平台构建仍是 External Readiness Gate 的未决项，本 spike 不构成通过声明；
- FTS5/Tantivy 供应链结果作为 ADR-0001 的证据输入，ADR 状态由 R0 Architecture Review 决定。


---

## 2026-10-12 correction: cargo-deny was not executed by this probe

The original text and all measurement/claim lines above are preserved as
historical evidence. The “关键结论” item 3 and the final recommendation to use
FTS5/Tantivy supply-chain results as ADR-0001 evidence are superseded:
the committed inputs do not substantiate the asserted Tantivy→ort-sys
`unlicensed` failure or the resulting “FTS5 依赖树更干净” conclusion.

At H5 `36616b7957e504aa4c6d514a50545dcd9bbc47cd`,
`spikes/search-backend/Cargo.lock` has raw SHA256
`77e547af8ff41e17429f334b13607a5bf7829ed7e04f7cbdb511352b8f1aa41d`:
151 locked packages, 140 in the recorded Tantivy closure, no `ort-sys`
and no path to it. `verify-release-pipeline.ps1` step 2 invokes `cargo audit`,
not cargo-deny. Having cargo-deny installed and printing an INFO statement
are not evidence of its execution. Only that misleading explanatory string
is corrected; tool invocations, control flow and exit handling are unchanged.
The legacy probe was not run for this correction.

The historical failure's source, lock/configuration, command, tool version
and result remain unestablished. No fresh cargo-deny PASS or universal license
cleanliness is claimed, nor is the event declared impossible historically.
The recorded build, cargo-audit, CycloneDX and simulated-signature/checksum
results are retained, not independently revalidated. Formal recommendations
may use those bounded historical measurements, but not infer license clearance
from cargo-audit/SBOM generation or the old INFO string.

FTS5 remains default for the measured/consistency reasons in ADR-0001, still
Proposed. Cross-platform, genuine signing/notarization and minimum-OS limits
remain unresolved by this spike. See [audit §5](../../docs/operations/REUSE-LICENSE-AUDIT.md#5-spike-dependency-evidence-correction-2026-10-12)
and [the R0 summary correction](../R0-EVIDENCE-SUMMARY.md).
