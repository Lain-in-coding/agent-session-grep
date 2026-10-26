#!/usr/bin/env pwsh
# Build agent-session-grep from source and install both the canonical command and
# its asg alias into a user-level bin directory. Windows receives two executable
# copies so the install never depends on administrator-only symlink settings.
# The artifact is unsigned and unnotarized; this script deliberately does NOT
# touch PATH, the registry, or shell profiles.

# Requires PowerShell 7+: the script uses $IsWindows and $PSNativeCommandUse...
# Adding the requirement turns a PowerShell 5.1 strict-mode crash into a clear
# version error.
#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]$Prefix,
    [switch]$SkipBuild,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# We assert on native exit codes ourselves; PowerShell must not turn a non-zero
# exit into a terminating error before we can report a usable diagnostic.
$PSNativeCommandUseErrorActionPreference = $false

function Fail {
    param([string]$Message)
    Write-Host "install: error: $Message" -ForegroundColor Red
    exit 1
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'Cargo.toml'))) {
    Fail "cannot find Cargo.toml at $repoRoot; run this script from a checkout of the repository"
}

$exeSuffix = if ($IsWindows) { '.exe' } else { '' }
$binaryName = "agent-session-grep$exeSuffix"
$aliasName = "asg$exeSuffix"

if ([string]::IsNullOrWhiteSpace($Prefix)) {
    if ($IsWindows) {
        if (-not $env:LOCALAPPDATA) {
            Fail 'LOCALAPPDATA is not set; pass -Prefix <dir> to choose an install directory'
        }
        $Prefix = Join-Path $env:LOCALAPPDATA 'agent-session-grep\bin'
    } else {
        $base = if ($env:XDG_BIN_HOME) { $env:XDG_BIN_HOME } elseif ($env:HOME) { Join-Path $env:HOME '.local/bin' } else { '' }
        if (-not $base) {
            Fail 'neither XDG_BIN_HOME nor HOME is set; pass -Prefix <dir> to choose an install directory'
        }
        $Prefix = $base
    }
}

$artifact = Join-Path $repoRoot (Join-Path 'target/release' $binaryName)

if (-not $SkipBuild) {
    # cargo is only required on the build path; -SkipBuild exists precisely for
    # hosts that already have the artifact.
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) {
        Fail 'cargo not found on PATH; install a Rust toolchain from https://rustup.rs and re-run'
    }
    & cargo --version
    if ($LASTEXITCODE -ne 0) { Fail "cargo --version failed with exit code $LASTEXITCODE" }

    if ($DryRun) {
        Write-Host "install: dry run: would run cargo build --locked --release -p agent-session-grep-cli in $repoRoot"
    } else {
        $buildCode = 1
        Push-Location $repoRoot
        try {
            # --locked keeps the build reproducible: an install must never
            # silently resolve different dependency versions than CI did.
            & cargo build --locked --release -p agent-session-grep-cli
            $buildCode = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($buildCode -ne 0) { Fail "cargo build failed with exit code $buildCode" }
    }
}

if ($DryRun -and -not (Test-Path -LiteralPath $artifact)) {
    Write-Host "install: dry run: no file written"
    Write-Host "install: dry run: would install $artifact -> $(Join-Path $Prefix $binaryName)"
    Write-Host "install: dry run: would install $artifact -> $(Join-Path $Prefix $aliasName)"
    exit 0
}

if (-not (Test-Path -LiteralPath $artifact)) {
    if ($SkipBuild) {
        Fail "$artifact does not exist; -SkipBuild requires a prior cargo build --locked --release -p agent-session-grep-cli"
    }
    Fail "$artifact does not exist after a successful build"
}

$sha256 = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
$target = Join-Path $Prefix $binaryName
$aliasTarget = Join-Path $Prefix $aliasName
$journalPath = Join-Path $Prefix '.asg-install-journal.json'

# Finish or undo an interrupted earlier install first. A crash between the two
# file replacements leaves a half-upgraded pair that the alias guard below
# would otherwise refuse forever. The journal records a backup of both
# destinations before anything is replaced, so recovery always restores the
# previous consistent pair and then lets a normal install run.
if ($DryRun -and (Test-Path -LiteralPath $journalPath)) {
    Write-Host "install: dry run: an interrupted install is recorded in $journalPath and would be restored first"
} elseif (-not $DryRun -and (Test-Path -LiteralPath $journalPath)) {
    $journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
    if ($journal.schema -ne 'asg-source-install-journal/v1') {
        Fail "$journalPath is not an install journal created by this script; move it aside and re-run"
    }
    Write-Host "install: recovering an interrupted install recorded in $journalPath"
    try {
        foreach ($entry in $journal.entries) {
            if ($entry.existed) {
                if (-not $entry.backup -or -not (Test-Path -LiteralPath $entry.backup)) {
                    Fail "recovery backup for $($entry.destination) is missing; restore that file manually or re-run against an empty -Prefix"
                }
                Copy-Item -LiteralPath $entry.backup -Destination $entry.destination -Force
            } elseif (Test-Path -LiteralPath $entry.destination) {
                Remove-Item -LiteralPath $entry.destination -Force
            }
        }
    } catch {
        Fail "cannot restore the interrupted install; close any program using these commands and re-run: $($_.Exception.Message)"
    }
    foreach ($entry in $journal.entries) {
        if ($entry.backup -and (Test-Path -LiteralPath $entry.backup)) {
            Remove-Item -LiteralPath $entry.backup -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $journalPath -Force
    Write-Host 'install: previous install restored; continuing with this install'
}

# Refuse to touch a locked pair before anything changes: the alias guard below
# hashes both files and a running command holds its image open, so probing for
# an exclusive write handle first reports the lock as an install error instead
# of a raw I/O failure mid-script.
if (-not $DryRun) {
    foreach ($destination in @($target, $aliasTarget)) {
        if (-not (Test-Path -LiteralPath $destination)) { continue }
        try {
            $probe = [System.IO.File]::Open(
                $destination,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None)
            $probe.Dispose()
        } catch {
            Fail "$destination is in use; stop the programs running it (including any MCP host) and re-run: $($_.Exception.Message)"
        }
    }
}

# A custom prefix can be a shared bin directory. Refuse to replace an unrelated
# asg.exe; an alias previously installed by this script is byte-identical to the
# canonical executable before an upgrade.
if (Test-Path -LiteralPath $aliasTarget) {
    if (-not (Test-Path -LiteralPath $target -PathType Leaf) -or
        -not (Test-Path -LiteralPath $aliasTarget -PathType Leaf)) {
        Fail "$aliasTarget already exists and is not a managed agent-session-grep alias"
    }
    $targetHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    $aliasHash = (Get-FileHash -LiteralPath $aliasTarget -Algorithm SHA256).Hash
    if ($targetHash -ne $aliasHash) {
        Fail "$aliasTarget already exists and differs from $target; choose another -Prefix or move it aside"
    }
}

if ($DryRun) {
    Write-Host "install: dry run: no file written"
    Write-Host "install: dry run: would create directory $Prefix"
    Write-Host "install: dry run: would copy $artifact -> $target"
    Write-Host "install: dry run: would copy $artifact -> $aliasTarget"
    Write-Host "install: dry run: artifact sha256 $sha256"
    exit 0
}

if (-not (Test-Path -LiteralPath $Prefix)) {
    New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
}

# Replace both executables as one recoverable pair. Windows receives a physical
# alias copy; no symlink privilege is required.
#
# The staged file is created with FileMode::CreateNew so a pre-planted entry
# (including a symlink) at the random temp name fails closed instead of being
# written through. Both destinations are locked-probed and backed up before
# either is replaced; a failure or a crash mid-swap restores the previous
# pair rather than leaving one command upgraded and the other stale.
$destinations = @($target, $aliasTarget)
$staged = @()
$entries = @()
$failure = $null
try {
    foreach ($destination in $destinations) {
        $temp = Join-Path $Prefix ([System.IO.Path]::GetRandomFileName())
        $source = [System.IO.File]::OpenRead($artifact)
        try {
            $stream = [System.IO.File]::Open(
                $temp,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None)
            try { $source.CopyTo($stream) } finally { $stream.Dispose() }
        } finally {
            $source.Dispose()
        }
        $stagedHash = (Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($stagedHash -ne $sha256) {
            throw "staged copy of $destination does not match the artifact sha256"
        }
        $staged += [pscustomobject]@{ Destination = $destination; Temp = $temp }
    }

    foreach ($destination in $destinations) {
        if (Test-Path -LiteralPath $destination) {
            $backup = Join-Path $Prefix ([System.IO.Path]::GetRandomFileName())
            Copy-Item -LiteralPath $destination -Destination $backup -Force
            $entries += [pscustomobject]@{ destination = $destination; existed = $true; backup = $backup }
        } else {
            $entries += [pscustomobject]@{ destination = $destination; existed = $false; backup = $null }
        }
    }
    $journal = [pscustomobject]@{
        schema          = 'asg-source-install-journal/v1'
        artifact_sha256 = $sha256
        entries         = $entries
    }
    Set-Content -LiteralPath $journalPath -Value ($journal | ConvertTo-Json -Depth 4) -Encoding utf8

    foreach ($item in $staged) {
        Move-Item -LiteralPath $item.Temp -Destination $item.Destination -Force
    }
    Remove-Item -LiteralPath $journalPath -Force
} catch {
    $failure = $_
    if (Test-Path -LiteralPath $journalPath) {
        foreach ($entry in $entries) {
            if ($entry.existed) {
                Copy-Item -LiteralPath $entry.backup -Destination $entry.destination -Force
            } elseif (Test-Path -LiteralPath $entry.destination) {
                Remove-Item -LiteralPath $entry.destination -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-Item -LiteralPath $journalPath -Force -ErrorAction SilentlyContinue
    }
} finally {
    foreach ($item in $staged) {
        if (Test-Path -LiteralPath $item.Temp) {
            Remove-Item -LiteralPath $item.Temp -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($entry in $entries) {
        if ($entry.backup -and (Test-Path -LiteralPath $entry.backup)) {
            Remove-Item -LiteralPath $entry.backup -Force -ErrorAction SilentlyContinue
        }
    }
}
if ($failure) {
    Fail "install failed; the previous install was left in place: $($failure.Exception.Message)"
}

$versionLine = & $target --version
$versionCode = $LASTEXITCODE
if ($versionCode -ne 0) {
    Fail "installed binary failed its self check: $target --version exited $versionCode"
}
$aliasVersionLine = & $aliasTarget --version
$aliasVersionCode = $LASTEXITCODE
if ($aliasVersionCode -ne 0) {
    Fail "installed alias failed its self check: $aliasTarget --version exited $aliasVersionCode"
}
if (($versionLine -join ' ') -ne ($aliasVersionLine -join ' ')) {
    Fail 'installed commands reported different versions'
}

$pathHint = if ($IsWindows) {
    "`$env:PATH = `"$Prefix;`$env:PATH`""
} else {
    "export PATH=`"${Prefix}:`$PATH`""
}

Write-Host "install: installed $($versionLine -join ' ')"
Write-Host "install: command  $target"
Write-Host "install: alias    $aliasTarget"
Write-Host "install: sha256   $sha256"
Write-Host "install: this script does not modify PATH. To use the binary by name in"
Write-Host "install: the current shell session, run:"
Write-Host "install:   $pathHint"
Write-Host "install: to make it permanent, add $Prefix to PATH yourself."
Write-Host "install: the artifact is unsigned and unnotarized."
exit 0
