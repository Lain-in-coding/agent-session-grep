#!/usr/bin/env pwsh
# Local install gate: install -> smoke both commands -> upgrade in place ->
# uninstall twice -> reinstall -> smoke -> final uninstall, all against a
# throwaway prefix.

[CmdletBinding()]
param(
    [string]$Prefix,
    [string]$Binary,
    [string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot 'scripts/evidence/out'
}
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# install.ps1 takes -Prefix/-SkipBuild; uninstall.ps1 takes only -Prefix. These
# are PowerShell parameters, so the wrapped calls splat hashtables rather than
# passing GNU-style flags, which bind as positional arguments and fail.
# install's -SkipBuild copies target/release/agent-session-grep, so a
# caller-supplied binary is staged into target/release first.
$installArgs = @{}
$uninstallArgs = @{}
if (-not [string]::IsNullOrWhiteSpace($Prefix)) {
    $installArgs['Prefix'] = $Prefix
    $uninstallArgs['Prefix'] = $Prefix
}
if (-not [string]::IsNullOrWhiteSpace($Binary)) {
    if (-not (Test-Path -LiteralPath $Binary)) {
        Write-Host "gate: error: binary not found: $Binary" -ForegroundColor Red
        exit 1
    }
    $repoArtifactDir = Join-Path $repoRoot 'target/release'
    if (-not (Test-Path -LiteralPath $repoArtifactDir)) {
        New-Item -ItemType Directory -Path $repoArtifactDir -Force | Out-Null
    }
    $exeSuffix = if ($IsWindows) { '.exe' } else { '' }
    $repoArtifact = Join-Path $repoArtifactDir "agent-session-grep$exeSuffix"
    # -Binary is commonly the repo artifact itself; Copy-Item refuses to
    # overwrite a file with itself, so compare resolved paths and skip staging.
    $binaryFull = (Resolve-Path -LiteralPath $Binary).Path
    $repoArtifactFull = if (Test-Path -LiteralPath $repoArtifact) {
        (Resolve-Path -LiteralPath $repoArtifact).Path
    } else {
        [System.IO.Path]::GetFullPath($repoArtifact)
    }
    $comparison = if ($IsWindows) {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    if ([string]::Equals($binaryFull, $repoArtifactFull, $comparison)) {
        Write-Host "gate: binary is already the repo artifact; skipping staging copy"
    } else {
        Copy-Item -LiteralPath $Binary -Destination $repoArtifact -Force
    }
    $installArgs['SkipBuild'] = $true
}

$script:Failures = 0
$script:Steps = @()

function Record-Step {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $script:Steps += @{ name = $Name; ok = $Ok; detail = $Detail }
    if (-not $Ok) { $script:Failures++ }
    $status = if ($Ok) { 'pass' } else { 'FAIL' }
    Write-Host "gate: $status  $Name" -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
    if ($Detail) { Write-Host "gate:       $Detail" }
}

$install = Join-Path $PSScriptRoot 'install.ps1'
$smoke = Join-Path $PSScriptRoot 'smoke.ps1'
$uninstall = Join-Path $PSScriptRoot 'uninstall.ps1'
foreach ($script in @($install, $smoke, $uninstall)) {
    if (-not (Test-Path -LiteralPath $script)) {
        Write-Host "gate: error: missing script $script" -ForegroundColor Red
        exit 1
    }
}

# 1. install (build, or skip-build with an explicit binary).
& $install @installArgs
Record-Step 'install' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"

# 2. smoke against the installed binary. The prefix is resolved by the
#    install script itself; resolve it the same way here for the smoke leg.
$exeSuffix = if ($IsWindows) { '.exe' } else { '' }
if ([string]::IsNullOrWhiteSpace($Prefix)) {
    if ($IsWindows) {
        $Prefix = Join-Path $env:LOCALAPPDATA 'agent-session-grep\bin'
    } else {
        $base = if ($env:XDG_BIN_HOME) { $env:XDG_BIN_HOME } elseif ($env:HOME) { Join-Path $env:HOME '.local/bin' } else { '' }
        $Prefix = $base
    }
}
$installed = Join-Path $Prefix "agent-session-grep$exeSuffix"
$installedAlias = Join-Path $Prefix "asg$exeSuffix"
function Run-Smoke {
    param([string]$Name)
    & $smoke -Binary $installed -AliasBinary $installedAlias
    Record-Step $Name ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
}
if ((Test-Path -LiteralPath $installed) -and (Test-Path -LiteralPath $installedAlias)) {
    Run-Smoke 'smoke-installed'
} else {
    Record-Step 'smoke-installed' $false "installed commands not found at $installed and $installedAlias"
}

# 3. upgrade in place: both managed commands already exist and must be
# replaced safely without a separate uninstall.
& $install @installArgs
Record-Step 'upgrade' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
if ((Test-Path -LiteralPath $installed) -and (Test-Path -LiteralPath $installedAlias)) {
    Run-Smoke 'smoke-upgraded'
} else {
    Record-Step 'smoke-upgraded' $false "upgraded commands not found at $installed and $installedAlias"
}

# 4. uninstall: both installer-owned files must be gone, and only those files.
& $uninstall @uninstallArgs
Record-Step 'uninstall' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
$cleanAfterUninstall = -not (Test-Path -LiteralPath $installed) -and -not (Test-Path -LiteralPath $installedAlias)
Record-Step 'uninstall-files-removed' $cleanAfterUninstall "canonical=$installed alias=$installedAlias"

# 5. uninstall again: second run must report "not installed" and exit 0.
& $uninstall @uninstallArgs
Record-Step 'uninstall-idempotent' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"

# 6. reinstall after a clean uninstall.
& $install @installArgs
Record-Step 'reinstall' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"

# 7. smoke against the reinstalled commands.
if ((Test-Path -LiteralPath $installed) -and (Test-Path -LiteralPath $installedAlias)) {
    Run-Smoke 'smoke-reinstalled'
} else {
    Record-Step 'smoke-reinstalled' $false "reinstalled commands not found at $installed and $installedAlias"
}

# 8. final uninstall leaves both installer-owned files absent.
& $uninstall @uninstallArgs
Record-Step 'uninstall-final' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
$cleanAfterFinal = -not (Test-Path -LiteralPath $installed) -and -not (Test-Path -LiteralPath $installedAlias)
Record-Step 'uninstall-final-files-removed' $cleanAfterFinal "canonical=$installed alias=$installedAlias"

$os = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' }
$result = [ordered]@{
    schema_version = 'agent-session-grep.install-gate/v1'
    os             = $os
    pass           = ($script:Failures -eq 0)
    failures       = $script:Failures
    steps          = @($script:Steps)
    generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
}
$outFile = Join-Path $OutputDir "install-gate-$os.json"
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $outFile -Encoding utf8NoBOM
Write-Host "gate: manifest $outFile"

if ($script:Failures -gt 0) {
    Write-Host "gate: $script:Failures step(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'gate: all install-gate steps passed'
exit 0
