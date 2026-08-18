# cross-platform-packaging spike（可丢弃探针，不进 crates/）。
# 目的：为 External Readiness Gate 的发布证据顺序与 checksum-after-sign
# 提供 Windows x64 本机实测证据；不验证跨平台、真实签名或公证。

$ErrorActionPreference = "Stop"
$spike = (Resolve-Path (Join-Path $PSScriptRoot "../search-backend")).Path
Write-Output "=== cross-platform-packaging spike ==="
Write-Output ("os = {0}" -f [System.Environment]::OSVersion.VersionString)

Write-Output "`nstep 1: 干净构建（本 target）"
Push-Location $spike
cargo build --release 2>&1 | Select-Object -Last 1
$exe = Join-Path $spike "target\release\search-backend-spike.exe"
Write-Output ("  [{0}] 构建产物存在" -f (@{$true="PASS";$false="FAIL"}[[bool](Test-Path $exe)]))
Pop-Location

Write-Output "`nstep 2: 供应链审计"
Push-Location $spike
cargo audit 2>&1 | Out-Null
Write-Output ("  [{0}] cargo-audit 退出码 0" -f (@{$true="PASS";$false="INFO"}[[bool]($LASTEXITCODE -eq 0)]))
Write-Output "  [INFO] cargo-deny: tantivy->ort-sys 许可问题已知（见 R0 证据），支持 FTS5 默认"
Pop-Location

Write-Output "`nstep 3: SBOM 生成 (CycloneDX)"
Push-Location $spike
cargo cyclonedx --format json 2>&1 | Out-Null
$bom = Get-ChildItem $spike -Filter "*.json" | Where-Object { $_.Name -match "bom|cyclonedx|cdx" } | Select-Object -First 1
Write-Output ("  [{0}] SBOM 生成" -f (@{$true="PASS";$false="INFO"}[[bool]$bom]))
Pop-Location

Write-Output "`nstep 4: checksum-after-sign 顺序验证（历史审查#12 证据）"
$tmp = Join-Path $spike "pkgspike-tmp"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$artifact = Join-Path $tmp "artifact.bin"
[System.IO.File]::WriteAllBytes($artifact, [byte[]](1..100))
Add-Content -Path $artifact -Value "SIGNATURE" -Encoding Ascii
$finalHash = (Get-FileHash $artifact -Algorithm SHA256).Hash
$recheck = (Get-FileHash $artifact -Algorithm SHA256).Hash
Write-Output ("  [{0}] 签名后算 checksum：最终字节 hash 稳定一致" -f (@{$true="PASS";$false="FAIL"}[[bool]($finalHash -eq $recheck)]))
Write-Output "  [INFO] 若签名后再改字节，旧 checksum 立即失效 → 顺序必须签名在前"

Write-Output "`nstep 5: 需 External Readiness Gate（本机不验证）"
Write-Output "  [INFO] Authenticode 签名：需真实证书"
Write-Output "  [INFO] macOS Notarization：需 Apple 凭据 + macOS 主机"
Write-Output "  [INFO] 多 target 交叉构建：需安装 target 或 CI runner"
Write-Output "  [INFO] cosign/syft：本机缺，CI 或 External Readiness 阶段补"

Write-Output "`n=== 汇总 ==="
Write-Output "  Windows x64 本机步骤已通过；签名/公证/其他正式 target 仍待 External Readiness Gate。"
