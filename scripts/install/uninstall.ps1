#!/usr/bin/env pwsh
# Remove the two commands installed by install.ps1. This deletes only
# agent-session-grep[.exe] and its managed asg[.exe] copy; it never recurses
# into a shared bin directory or touches a data root. Missing files are success.

[CmdletBinding()]
param(
    [string]$Prefix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Fail {
    param([string]$Message)
    Write-Host "uninstall: error: $Message" -ForegroundColor Red
    exit 1
}

$exeSuffix = if ($IsWindows) { '.exe' } else { '' }
$binaryName = "agent-session-grep$exeSuffix"
$aliasName = "asg$exeSuffix"

# Prefix resolution mirrors install.ps1 exactly; a divergence here would leave
# an installed binary that uninstall cannot see.
if ([string]::IsNullOrWhiteSpace($Prefix)) {
    if ($IsWindows) {
        if (-not $env:LOCALAPPDATA) {
            Fail 'LOCALAPPDATA is not set; pass -Prefix <dir> to choose the install directory'
        }
        $Prefix = Join-Path $env:LOCALAPPDATA 'agent-session-grep\bin'
    } else {
        $base = if ($env:XDG_BIN_HOME) { $env:XDG_BIN_HOME } elseif ($env:HOME) { Join-Path $env:HOME '.local/bin' } else { '' }
        if (-not $base) {
            Fail 'neither XDG_BIN_HOME nor HOME is set; pass -Prefix <dir> to choose the install directory'
        }
        $Prefix = $base
    }
}

$target = Join-Path $Prefix $binaryName
$aliasTarget = Join-Path $Prefix $aliasName
$targetExists = Test-Path -LiteralPath $target
$aliasExists = Test-Path -LiteralPath $aliasTarget

if (-not $targetExists -and -not $aliasExists) {
    Write-Host "uninstall: not installed: $target or $aliasTarget"
    Write-Host 'uninstall: nothing to do'
    exit 0
}

# install.ps1 creates the Windows alias as an identical executable copy. If a
# custom shared prefix now contains a different asg.exe, fail closed instead of
# deleting a file this installer cannot identify as its own.
if ($aliasExists) {
    if (-not $targetExists -or
        -not (Test-Path -LiteralPath $target -PathType Leaf) -or
        -not (Test-Path -LiteralPath $aliasTarget -PathType Leaf)) {
        Fail "$aliasTarget exists without its managed canonical executable; refusing to remove it"
    }
    $targetHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    $aliasHash = (Get-FileHash -LiteralPath $aliasTarget -Algorithm SHA256).Hash
    if ($targetHash -ne $aliasHash) {
        Fail "$aliasTarget differs from $target; refusing to remove either file"
    }
    Remove-Item -LiteralPath $aliasTarget -Force
    if (Test-Path -LiteralPath $aliasTarget) {
        Fail "could not remove $aliasTarget"
    }
    Write-Host "uninstall: removed $aliasTarget"
}

if ($targetExists) {
    Remove-Item -LiteralPath $target -Force
    if (Test-Path -LiteralPath $target) {
        Fail "could not remove $target"
    }
    Write-Host "uninstall: removed $target"
}

Write-Host "uninstall: the directory $Prefix was left in place."
Write-Host 'uninstall: config, data, cache, and logs were not touched. To remove those,'
Write-Host 'uninstall: delete the paths reported by: agent-session-grep --robot config paths'
exit 0
