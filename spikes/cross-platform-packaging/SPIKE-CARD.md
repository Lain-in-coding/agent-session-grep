# Spike Card：cross-platform-packaging（发布链路模拟）

> 治理记录（Governance Record）
>
> - decision_id: SPIKE-cross-platform-packaging
> - status: **Executed（仅本地 Windows 模拟证据，待 approver 审阅）**
> - owner: （待项目 owner 指派）
> - approver: 项目最终验收人（须与 owner 分离，待明确）
> - due_milestone: R0 Feasibility / Contract Gate / External Readiness Gate
> - timebox: R0 timebox；外部凭据与正式平台验证须进入独立 External Readiness timebox
> - evidence_path: `spikes/cross-platform-packaging/`（`verify-release-pipeline.ps1`、`EVIDENCE.md`）
> - approved_at: —
> - approval_required: 项目 owner 必须明确发布、签名、公证和凭据责任人，并显式批准正式 release gate；本卡不构成 R0 Accepted
>
> 本 Spike 是**发布步骤模拟**，不是 release pipeline，不生成可发布制品，也不形成平台支持或渠道可用性承诺。

---

## 1. Hypothesis（假设）

在本地 Windows 环境可自动执行候选 crate 的 release build、`cargo audit` 和 CycloneDX SBOM 生成，并用合成 artifact 演示“模拟签名标记写入后再计算最终字节 checksum”的顺序；真实签名、公证、多 target、attestation 和 clean-machine 安装仍必须由 External Readiness Gate 验证。

## 2. Fixture / Fault model

- 被构建对象是现有 `spikes/search-backend`，不是正式 `agent-session-grep` release binary；
- 脚本通过 `$PSScriptRoot` 解析相邻 `search-backend` 目录，可从任意 checkout 路径运行；
- checksum fixture 是 100 字节合成文件，追加 ASCII `SIGNATURE` 仅模拟签名导致的字节变化；
- 没有调用 Authenticode、Apple notarization、cosign、GitHub Release 或安装渠道；
- 当前脚本在模拟签名后对未再变化的文件计算两次 SHA-256，只验证 re-hash 一致，没有实际注入“checksum 后再改字节”的失败场景。

## 3. Reproduce（Windows checkout）

```text
pwsh -NoProfile -File spikes/cross-platform-packaging/verify-release-pipeline.ps1
```

环境：Windows x86_64；仅安装 `x86_64-pc-windows-msvc` target；现有证据记录 `cargo-audit`、`cargo-cyclonedx`、`cargo-deny` 和 `gh` 可用，`cosign` / `syft` 缺失。脚本路径解析已改为 checkout 相对方式，但证据仍只覆盖 Windows 本地环境。

## 4. Measurements / Pass-Fail

| Gate | 成功条件 | 当前证据 |
|---|---|---|
| 本 target build | checkout 相对解析的 `search-backend-spike.exe` 存在 | Windows 本地 PASS |
| 漏洞审计 | `cargo audit` 退出码为 0 | Windows 本地 PASS |
| SBOM | 找到 CycloneDX JSON 产物 | Windows 本地 PASS |
| checksum 模拟 | 追加模拟签名后，两次 SHA-256 相同 | Windows 本地 PASS（仅确定性 re-hash） |
| 正式发布 Gate | 真实签名/公证、全部正式 target、attestation、clean-machine 安装均通过 | **未验证 / 不通过结论不可作出** |

本地任一步骤失败即为 spike 失败；但即使四个本地步骤通过，也不能把正式发布或跨平台 Gate 标为通过。

## 5. Proposed decision（待批准）

保留“签名/公证/最终打包完成后，再对最终归档字节生成 checksum 与 attestation”的候选顺序；同时把本脚本仅作为早期模拟证据。正式 pipeline 必须使用真实候选制品和平台签名工具，并在 Windows、Linux、macOS x64/ARM64 及 clean machine 上产出可复核证据。

## 6. Evidence status / Limitations

当前 `EVIDENCE.md` 支持的只有本地 Windows 工具链步骤；checked-in 脚本不是跨平台脚本、不是 CI workflow、不是 release pipeline，也没有验证实际签名、公证、provenance、渠道 promotion 或凭据安全。它仍把 `.exe` 写死，且未真正证明“checksum 后修改会被检测”。因此该证据只能记录为 **local simulation**，External Readiness Gate 与正式 target certification 必须保持 open，等待项目 owner 指派责任人并审批。
