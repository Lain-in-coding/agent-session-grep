# ADR-0002：正式平台 Target、最低 OS/glibc 与链接策略

> 治理记录
> - decision_id: ADR-0002
> - status: **Proposed**（待 R0 Accepted）
> - owner: （待指派）  approver: 项目最终验收人
> - due_milestone: R0
> - evidence_path: `spikes/cross-platform-packaging/`、`docs/adr/ADR-0002-platform-targets.md`、`docs/operations/core-beta-evidence-matrix.md`
>
> 本 ADR 仍为 **Proposed**。专用 CI 工作流只构成 `ci_configured_only` 证据；在成功 run URL 与产物被审阅前，不得把配置状态写成平台验证或发布认证。

## 背景

agent-session-grep 将 Windows x64、Linux x64、macOS x64/ARM64 作为 v1.0 正式平台候选；本 ADR 在 R0
冻结准确 target triple、最低 OS/glibc 和链接策略。Selection Gate 硬门之一是
"全部正式 target 干净构建"，因此平台集合必须先冻结。

## 决策

### 正式 target triple（v1.0 承诺）

| 平台 | target triple | 链接策略 |
|---|---|---|
| Windows x64 | `x86_64-pc-windows-msvc` | MSVC，静态 CRT（`+crt-static`）避免 VC++ 运行时依赖 |
| Linux x64 | `x86_64-unknown-linux-gnu` | glibc 动态；另出 `x86_64-unknown-linux-musl` 静态用于免依赖分发 |
| macOS x64 | `x86_64-apple-darwin` | 系统 libSystem 动态 |
| macOS ARM64 | `aarch64-apple-darwin` | 系统 libSystem 动态 |

### 最低 OS / glibc

- Windows：最低 Windows 10 x64；
- Linux glibc：最低 glibc 2.31（对应 Ubuntu 20.04）；在该 glibc 的 CI runner 上构建以避免过高符号版本。RHEL 8 的 glibc 2.28 更旧，不在该 floor 的已声明范围内，若要支持需单独认证；musl 构建无 glibc 依赖；
- macOS：最低 macOS 12（含 x64 与 ARM64）。

### 依赖与构建约束（Selection Gate 硬门）

- **禁止联网构建依赖**：不得依赖构建期下载模型、protoc 二进制或其他网络产物（反例：memex 的 LanceDB 需 protoc、Recall 的 candle 需模型）。
- SQLite 采用 `rusqlite` 的 `bundled` feature，随构建静态编入，免系统 SQLite；R0 冻结实际链接的 SQLite 版本，由 benchmark harness 记录并经 spike 的 `rusqlite::version()` 交叉核对（当前 spike 实测 3.53.2；`doctor` 输出的是 schema/generation/interrupted-batch 状态，不输出 SQLite 版本）。
- 全文引擎默认 FTS5（ADR-0001），避免 Tantivy 传递引入 `ort-sys` 等许可不干净、需上游 fork 的原生依赖。

### 非承诺 target

其他 target（如 `aarch64-unknown-linux-gnu`、Windows ARM64）先执行编译与 smoke，
未经后续 ADR 批准不写入 v1.0 正式支持承诺。

## 后果

- 普通 PR 质量门继续由 `.github/workflows/ci.yml` 承担；专用证据矩阵由 `.github/workflows/core-beta-evidence.yml` 配置 Windows x64、Ubuntu GNU x64、macOS Intel 与 macOS ARM64 的 release build、直接二进制 smoke、现有 SQLite adapter 测试和存储 feasibility spikes。
- 本机（Windows x64）已有 release 干净构建 spike 证据；其余平台行以及新工作流中的所有 job 在没有成功 run URL/下载产物前均仅为 `ci_configured_only`，不是已通过结论。
- Ubuntu 22.04 hosted runner 不认证 glibc 2.31；`MACOSX_DEPLOYMENT_TARGET=12.0` 不认证在 macOS 12 上实际运行；Windows job 的静态 CRT 构建也不替代 Windows 10 clean-machine 测试。
- Linux musl、glibc 2.31 基线、macOS 12 runtime、Windows 签名、macOS 签名/公证仍需额外基础设施。完整分类与证据 ID 见 `docs/operations/core-beta-evidence-matrix.md`。

## 备选与否决

- 全静态（musl）作为唯一 Linux 分发：否决为默认，因 glibc 动态在主流发行版兼容性更好；musl 作为免依赖补充。
- 动态链接 VC++ 运行时（Windows）：否决，避免用户机缺运行时导致启动失败。
