#!/usr/bin/env pwsh
# Compatibility entrypoint kept for older documentation, bookmarks, and scripts
# that still reference scripts/install.ps1. The installer implementation lives in
# scripts/install/install.ps1; this wrapper only forwards arguments so the two
# entrypoints cannot drift and only one of them can clone or build anything.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# The canonical script owns exit-code interpretation; PowerShell must not turn a
# non-zero exit into a terminating error before we can forward it.
$PSNativeCommandUseErrorActionPreference = $false

$canonical = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) { '' } else { Join-Path $PSScriptRoot 'install/install.ps1' }
if ([string]::IsNullOrWhiteSpace($canonical) -or -not (Test-Path -LiteralPath $canonical)) {
    Write-Host 'install: error: scripts/install/install.ps1 not found; run this script from a checkout of the repository' -ForegroundColor Red
    exit 1
}

& $canonical @args
exit $LASTEXITCODE
