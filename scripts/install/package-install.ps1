#!/usr/bin/env pwsh
# Offline verified package install with explicit host/history setup.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Manifest,
    [Parameter(Mandatory = $true)][string]$Checksums,
    [string]$Prefix,
    [ValidateNotNullOrEmpty()][ValidateSet('claude', 'codex', 'workbuddy', 'zcode', 'deepseek-harness', 'antigravity')][string[]]$HostChoice = @(),
    [string]$ClaudeHistory,
    [string]$CodexHistory,
    [string]$WorkBuddyHistory,
    [string]$ZCodeHistory,
    [string]$DeepSeekHarnessHistory,
    [string]$AntigravityHistory,
    [string]$Catalog,
    [switch]$NoAutostart,
    [switch]$NoPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$stage = $null
$lock = $null
$lockPath = $null

# Validate all explicit choices before package/prefix/lock/staging I/O. Values
# remain literal argv; only the closed host enumeration is canonicalized.
$selectedHosts = @($HostChoice | ForEach-Object { $_.ToLowerInvariant() })
$historyOptions = @(
    [pscustomobject]@{ Parameter = 'ClaudeHistory'; HostName = 'claude'; Provider = 'claude-code'; Value = $ClaudeHistory }
    [pscustomobject]@{ Parameter = 'CodexHistory'; HostName = 'codex'; Provider = 'codex'; Value = $CodexHistory }
    [pscustomobject]@{ Parameter = 'WorkBuddyHistory'; HostName = 'workbuddy'; Provider = 'workbuddy'; Value = $WorkBuddyHistory }
    [pscustomobject]@{ Parameter = 'ZCodeHistory'; HostName = 'zcode'; Provider = 'zcode'; Value = $ZCodeHistory }
    [pscustomobject]@{ Parameter = 'DeepSeekHarnessHistory'; HostName = 'deepseek-harness'; Provider = 'deepseek-harness'; Value = $DeepSeekHarnessHistory }
    [pscustomobject]@{ Parameter = 'AntigravityHistory'; HostName = 'antigravity'; Provider = 'antigravity'; Value = $AntigravityHistory }
)
foreach ($parameterName in @('Manifest', 'Checksums', 'Prefix', 'Catalog')) {
    if ($PSBoundParameters.ContainsKey($parameterName)) {
        $value = [string]$PSBoundParameters[$parameterName]
        if ([string]::IsNullOrWhiteSpace($value)) { throw 'empty option value' }
        if ($value.IndexOf([char]0) -ge 0) { throw 'option value contains NUL' }
    }
}
foreach ($selection in $historyOptions) {
    if ($PSBoundParameters.ContainsKey($selection.Parameter)) {
        if ([string]::IsNullOrWhiteSpace($selection.Value)) { throw 'empty history option value' }
        if ($selection.Value.IndexOf([char]0) -ge 0) { throw 'history option value contains NUL' }
        if ($selection.Value.StartsWith('-')) { throw 'history option value cannot start with a flag' }
        if ($selection.HostName -notin $selectedHosts) { throw 'history selection requires the corresponding explicit HostChoice' }
    }
}
if ($selectedHosts.Count -eq 0 -and ($Catalog -or $NoAutostart -or $NoPath)) {
    throw 'post-install options require explicit HostChoice'
}
if (@($selectedHosts | Select-Object -Unique).Count -ne $selectedHosts.Count) {
    throw 'duplicate HostChoice'
}

function ConvertTo-NativeArgument([string]$Value) {
    # .NET Framework lacks ArgumentList. Encode one Windows native argv value
    # using documented CRT quote/backslash rules; no shell parses this string.
    $encoded = New-Object Text.StringBuilder
    [void]$encoded.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') { $slashes++; continue }
        if ($character -eq [char]'"') {
            [void]$encoded.Append([char]'\', (2 * $slashes + 1))
        } elseif ($slashes -gt 0) {
            [void]$encoded.Append([char]'\', $slashes)
        }
        [void]$encoded.Append($character)
        $slashes = 0
    }
    if ($slashes -gt 0) { [void]$encoded.Append([char]'\', (2 * $slashes)) }
    [void]$encoded.Append('"')
    return $encoded.ToString()
}

function Invoke-InstalledCommand([string]$Executable, [string[]]$LiteralArguments) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    if ($null -ne $info.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $LiteralArguments) { $info.ArgumentList.Add($argument) }
    } else {
        $info.Arguments = (($LiteralArguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' ')
    }
    # Inherit standard streams. No reader task/thread is created or left waiting
    # for EOF; the installed setup command owns its original process lifetime.
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'installed command failed to start' }
        $process.WaitForExit()
        return $process.ExitCode
    } finally {
        $process.Dispose()
    }
}

function Complete-SelectedSetup([string]$InstalledPrefix) {
    if ($selectedHosts.Count -eq 0) {
        Write-Output 'Select assistants and explicit history with -HostChoice and the matching -ClaudeHistory/-CodexHistory/-WorkBuddyHistory/-ZCodeHistory/-DeepSeekHarnessHistory/-AntigravityHistory option.'
        return
    }
    $launcher = Join-Path $InstalledPrefix 'agent-session-grep.exe'
    $setupArgs = @('--robot')
    if ($Catalog) { $setupArgs += @('--db', $Catalog) }
    $setupArgs += @('setup', '--install-prefix', $InstalledPrefix)
    foreach ($hostName in $selectedHosts) { $setupArgs += @('--host', $hostName) }
    foreach ($selection in $historyOptions) {
        if ($selection.Value) { $setupArgs += @('--history', $selection.Provider, $selection.Value) }
    }
    if ($NoAutostart) { $setupArgs += '--no-autostart' }
    $setupExit = Invoke-InstalledCommand $launcher $setupArgs
    if ($setupExit -notin @(0, 10)) { throw 'package is installed; selected setup failed and its durable stages are retained' }
    if (-not $NoPath) {
        $pathArgs = @('--robot')
        if ($Catalog) { $pathArgs += @('--db', $Catalog) }
        $pathArgs += @('path', 'install', '--install-prefix', $InstalledPrefix)
        $pathExit = Invoke-InstalledCommand $launcher $pathArgs
        if ($pathExit -notin @(0, 10)) { throw 'package/setup retained; user PATH registration is incomplete' }
    }
    Write-Output 'package-install: selected setup recorded; host loading/model calls and native login remain separately reported.'
}

function Assert-PlainPath([string]$Path) {
    # Inspect lexical components before GetFullPath collapses link/../.
    $lexical = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { [IO.Path]::Combine((Get-Location).Path, $Path) }
    $rootPart = [IO.Path]::GetPathRoot($lexical)
    $componentPath = $rootPart
    foreach ($part in $lexical.Substring($rootPart.Length).Split(@([char]'\', [char]'/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $componentPath = [IO.Path]::Combine($componentPath, $part)
        if (Test-Path -LiteralPath $componentPath) {
            if ((Get-Item -LiteralPath $componentPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'linked/reparse path is not supported' }
        }
    }
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'linked/reparse path is not supported'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-File([string]$Path) {
    Assert-PlainPath $Path
    if (-not [IO.File]::Exists($Path)) { throw 'required regular file is missing' }
}

function Ensure-Directory([string]$Path) {
    Assert-PlainPath $Path
    if ([IO.Directory]::Exists($Path)) { return }
    if (Test-Path -LiteralPath $Path) { throw 'directory path is occupied' }
    $parent = [IO.Path]::GetDirectoryName($Path)
    if (-not $parent -or $parent -eq $Path) { throw 'invalid directory root' }
    Ensure-Directory $parent
    Assert-PlainPath $parent
    [void][IO.Directory]::CreateDirectory($Path)
    Assert-PlainPath $Path
}

function Hash([string]$Path) {
    Assert-File $Path
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}

function Safe-Relative([string]$Path) {
    if ($Path -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.+-]*(/[A-Za-z0-9][A-Za-z0-9_.+-]*)*$') {
        throw 'unsafe package path'
    }
    foreach ($part in $Path.Split('/')) {
        if ($part.EndsWith('.') -or $part -match '^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])($|\.)') {
            throw 'unsafe package path component'
        }
    }
}

function File-Names([string]$Root) {
    # Check a directory before recursing; never traverse a junction to inspect it.
    Assert-PlainPath $Root
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'linked package member' }
        if ($item.PSIsContainer) {
            if (@(Get-ChildItem -LiteralPath $item.FullName -Force).Count -eq 0) { throw 'unexpected empty directory' }
            File-Names $item.FullName
        }
        else { $item.FullName }
    }
}

function Write-Durable([string]$Path, [string]$Text) {
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Read-Metadata([string]$Path, [string[]]$Keys) {
    Assert-File $Path
    if ((Get-Item -LiteralPath $Path).Length -gt 8192) { throw 'metadata exceeds size limit' }
    $raw = [IO.File]::ReadAllText($Path)
    $object = $raw | ConvertFrom-Json
    if (@(Compare-Object @($object.PSObject.Properties.Name | Sort-Object) @($Keys | Sort-Object)).Count -ne 0) { throw 'unexpected metadata fields' }
    foreach ($key in $Keys) {
        if ([regex]::Matches($raw, ('"' + [regex]::Escape($key) + '"\s*:')).Count -ne 1) { throw 'duplicate metadata field' }
    }
    # Recent PowerShell converts ISO dates implicitly; validate the original
    # wire string so an offset or malformed timestamp cannot be normalized away.
    foreach ($key in @('activated_at', 'built_at')) {
        if ($Keys -contains $key) {
            $match = [regex]::Match($raw, ('"' + $key + '"\s*:\s*"([^"\\]+)"'))
            if (-not $match.Success) { throw 'invalid timestamp representation' }
            $object.$key = $match.Groups[1].Value
        }
    }
    return $object
}

function Probe([string]$Executable, [string]$Argument) {
    Assert-File $Executable
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = $Argument
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $started = $false
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'version probe failed to start' }
        $started = $true
        $readers = @($process.StandardOutput, $process.StandardError)
        $buffers = @((New-Object char[] 1024), (New-Object char[] 1024))
        $texts = @((New-Object Text.StringBuilder), (New-Object Text.StringBuilder))
        $reads = @($readers[0].ReadAsync($buffers[0], 0, 1024), $readers[1].ReadAsync($buffers[1], 0, 1024))
        $ended = @($false, $false)
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (-not ($ended[0] -and $ended[1] -and $process.HasExited)) {
            if ($timer.ElapsedMilliseconds -ge 30000) { throw 'probe exceeded time limit' }
            for ($i = 0; $i -lt 2; $i++) {
                if (-not $ended[$i] -and $reads[$i].IsCompleted) {
                    $count = $reads[$i].GetAwaiter().GetResult()
                    if ($count -eq 0) { $ended[$i] = $true }
                    else {
                        if ($texts[$i].Length + $count -gt 8192) { throw 'probe exceeded output limit' }
                        [void]$texts[$i].Append($buffers[$i], 0, $count)
                        $reads[$i] = $readers[$i].ReadAsync($buffers[$i], 0, 1024)
                    }
                }
            }
            Start-Sleep -Milliseconds 10
        }
        if ($process.ExitCode -ne 0 -or $texts[1].Length -ne 0) { throw 'probe failed' }
        return $texts[0].ToString()
    } finally {
        if ($started -and -not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
}

function Verify-Programs([string]$Root, $Pointer, $Release) {
    foreach ($name in @('agent-session-grep.exe', 'asg.exe', "$($Pointer.dir)/$($Pointer.app)")) {
        $output = Probe (Join-Path $Root $name) '--version'
        if ($output -cnotmatch ('\A' + [regex]::Escape("agent-session-grep $($Pointer.version)") + '(\r?\n)?\z')) {
            throw 'unexpected product/version'
        }
    }
    $supervisorOutput = Probe (Join-Path $Root "$($Pointer.dir)/asg-supervisor.exe") '--version'
    if ($supervisorOutput -cnotmatch ('\A' + [regex]::Escape("asg-supervisor $($Pointer.version)") + '(\r?\n)?\z')) {
        throw 'unexpected supervisor version'
    }
    foreach ($name in @('agent-session-grep.exe', 'asg.exe')) {
        $info = (Probe (Join-Path $Root $name) '--asg-launcher-info') | ConvertFrom-Json
        if ($info.schema -cne 'asg.launcher-info/v1' -or $info.launcher_protocol -ne 1 -or $info.generation -ne 1 -or $info.version -cne $Pointer.version -or $info.target -cne $Release.target -or $info.source_commit -cne $Release.source_commit -or $info.app_sha256 -cne $Pointer.app_sha256 -or $info.catalog_schema -ne $Release.catalog_schema -or $info.control_schema -ne $Release.control_schema) {
            throw 'launcher identity mismatch'
        }
    }
}

function Assert-NativeImage([string]$Path, [bool]$Gui) {
    Assert-File $Path
    $stream = [IO.File]::OpenRead($Path)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw 'invalid PE image' }
        $stream.Position = 60
        $offset = $reader.ReadUInt32()
        if ($offset -gt $stream.Length - 94) { throw 'invalid PE header range' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'wrong executable target' }
        $stream.Position = $offset + 20
        if ($reader.ReadUInt16() -lt 70) { throw 'incomplete PE optional header' }
        $stream.Position = $offset + 24
        if ($reader.ReadUInt16() -ne 0x20b) { throw 'expected PE32+ image' }
        $stream.Position = $offset + 92
        if ($Gui -and $reader.ReadUInt16() -ne 2) { throw 'supervisor must use the Windows GUI subsystem' }
    } finally { $reader.Dispose() }
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'use package-install.sh on Unix' }
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($arch -ne 'AMD64') { throw 'this package requires native Windows x64' }
    Assert-PlainPath $PSScriptRoot
    Assert-PlainPath $Manifest
    Assert-PlainPath $Checksums
    $root = [IO.Path]::GetFullPath($PSScriptRoot)
    $Manifest = [IO.Path]::GetFullPath($Manifest)
    $Checksums = [IO.Path]::GetFullPath($Checksums)
    Assert-File $Manifest
    Assert-File $Checksums
    if ((Get-Item -LiteralPath $Manifest).Length -gt 524288 -or (Get-Item -LiteralPath $Checksums).Length -gt 262144) { throw 'release metadata exceeds size limit' }
    $sums = @{}
    foreach ($line in [IO.File]::ReadAllLines($Checksums)) {
        if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.+-]*)$') { throw 'invalid SHA256SUMS' }
        $name = $Matches[2]; $digest = $Matches[1]
        Safe-Relative $name
        if ($sums.ContainsKey($name) -or $sums.Count -ge 16) { throw 'duplicate or oversized SHA256SUMS inventory' }
        $sums[$name] = $digest
    }
    $manifestHash = Hash $Manifest
    if ($sums[[IO.Path]::GetFileName($Manifest)] -cne $manifestHash) { throw 'manifest checksum mismatch' }
    $metadata = [IO.File]::ReadAllText($Manifest) | ConvertFrom-Json
    if ($metadata.schema -cne 'agent-session-grep.release-archive-manifest/v1' -or $metadata.layout -cne 'asg.managed-candidate/v1') { throw 'unsupported package manifest' }
    $release = $metadata.release
    if ($release.target -cne 'x86_64-pc-windows-msvc') { throw 'package target mismatch' }
    $archiveRoot = "agent-session-grep-v$($release.version)-$($release.target)"
    Safe-Relative $archiveRoot
    if ($metadata.archive.root -cne $archiveRoot -or [IO.Path]::GetFileName($Manifest) -cne "$archiveRoot.manifest.json" -or $release.tag -cne "v$($release.version)") { throw 'package identity mismatch' }
    if ($metadata.archive.format -cnotin @('zip', 'tar.gz') -or $metadata.archive.filename -cne "$archiveRoot.$($metadata.archive.format)" -or $sums[$metadata.archive.filename] -cne $metadata.archive.sha256) { throw 'archive checksum identity mismatch' }
    $allowedSums = @('THIRD-PARTY-DEPENDENCIES.json', 'THIRD-PARTY-DEPENDENCIES.csv')
    foreach ($target in @('x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu', 'x86_64-apple-darwin', 'aarch64-apple-darwin')) {
        $assetRoot = "agent-session-grep-v$($release.version)-$target"
        $allowedSums += "$assetRoot.zip", "$assetRoot.tar.gz", "$assetRoot.manifest.json"
    }
    foreach ($name in $sums.Keys) {
        if ($name -cnotin $allowedSums) { throw 'unexpected release checksum asset' }
    }


    $files = @{}
    foreach ($entry in $metadata.archive.files) {
        Safe-Relative $entry.name
        if (-not $entry.name.StartsWith("$archiveRoot/", [StringComparison]::Ordinal)) { throw 'member outside package root' }
        $relative = $entry.name.Substring($archiveRoot.Length + 1)
        if ($files.ContainsKey($relative) -or $entry.mode -cnotin @('0644', '0755') -or $entry.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'duplicate or invalid member' }
        $source = Join-Path $root $relative
        if ((Hash $source) -cne $entry.sha256 -or (Get-Item -LiteralPath $source).Length -ne $entry.size_bytes) { throw 'package file checksum/size mismatch' }
        $files[$relative] = $entry
    }
    $actual = @(File-Names $root)
    if ($actual.Count -ne $files.Count) { throw 'extra package member' }
    foreach ($path in $actual) {
        if (-not $files.ContainsKey($path.Substring($root.Length + 1).Replace('\', '/'))) { throw 'extra package member' }
    }
    $pointer = Read-Metadata (Join-Path $root 'current.json') @('schema', 'generation', 'version', 'dir', 'app', 'app_sha256', 'launcher_protocol', 'activated_at')
    Safe-Relative $pointer.dir
    if ($pointer.schema -cne 'asg.current/v1' -or $pointer.generation -ne 1 -or $pointer.version -cne $release.version -or $pointer.app -cne 'agent-session-grep.exe' -or $pointer.launcher_protocol -ne 1 -or $pointer.app_sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'invalid current pointer' }
    if ($pointer.dir -cne "versions/$($pointer.version)-$($pointer.app_sha256.Substring(0,12))") { throw 'invalid version directory' }
    $appPath = "$($pointer.dir)/$($pointer.app)"
    $supervisorPath = "$($pointer.dir)/asg-supervisor.exe"
    $helperSh = "$($pointer.dir)/helpers/update-check.sh"
    $helperPs1 = "$($pointer.dir)/helpers/update-check.ps1"
    $uninstallTail = "$($pointer.dir)/helpers/package-uninstall.ps1"
    $versionInfo = Read-Metadata (Join-Path $root "$($pointer.dir)/release.json") @('schema', 'version', 'target', 'source_commit', 'app_sha256', 'catalog_schema', 'control_schema', 'launcher_protocol_min', 'launcher_protocol_max', 'built_at')
    if ($versionInfo.schema -cne 'asg.version/v1' -or $versionInfo.version -cne $pointer.version -or $versionInfo.target -cne $release.target -or $versionInfo.source_commit -cne $release.source_commit -or $versionInfo.app_sha256 -cne $pointer.app_sha256 -or $versionInfo.launcher_protocol_min -ne 1 -or $versionInfo.launcher_protocol_max -ne 1 -or $versionInfo.catalog_schema -lt 1 -or $versionInfo.control_schema -lt 1) { throw 'release identity mismatch' }
    foreach ($timestamp in @($pointer.activated_at, $versionInfo.built_at)) {
        if ($timestamp -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|\+00:00)$') { throw 'invalid UTC timestamp' }
        [void][DateTimeOffset]::Parse($timestamp, [Globalization.CultureInfo]::InvariantCulture)
    }
    $required = @('agent-session-grep.exe', 'asg.exe', 'current.json', $appPath, $supervisorPath, "$($pointer.dir)/release.json", 'package-install.ps1', 'package-install.sh', 'PACKAGE-MANIFEST.tsv', 'INSTALL-AND-UPGRADE.md', 'README.md', 'CHANGELOG.md', 'LICENSE-MIT', 'LICENSE-APACHE', 'NOTICE', 'SECURITY.md', 'THIRD-PARTY-DEPENDENCIES.json', 'THIRD-PARTY-DEPENDENCIES.csv')
    # The immutable helper pair is all-or-nothing: one member alone is a
    # truncated or forged inventory, never an older package. Packages without
    # the pair remain the historical 17-member layout.
    $hasHelperSh = $files.ContainsKey($helperSh)
    $hasHelperPs1 = $files.ContainsKey($helperPs1)
    if ($hasHelperSh -ne $hasHelperPs1) { throw 'incomplete helper inventory' }
    if ($hasHelperSh) { $required += @($helperSh, $helperPs1) }
    if ($files.ContainsKey($uninstallTail)) {
        if (-not $hasHelperSh) { throw 'uninstall helper requires complete helper inventory' }
        $required += @($uninstallTail)
    }
    if ($files.Count -ne $required.Count) { throw 'unexpected package file set' }
    foreach ($name in $required) { if (-not $files.ContainsKey($name)) { throw 'required package member missing' } }
    if ($files['agent-session-grep.exe'].sha256 -cne $files['asg.exe'].sha256 -or $files[$appPath].sha256 -cne $pointer.app_sha256 -or $files['PACKAGE-MANIFEST.tsv'].sha256 -cne $metadata.install_manifest_sha256) { throw 'launcher/application/manifest digest mismatch' }
    $supervisorHash = $files[$supervisorPath].sha256
    if ($supervisorHash -ceq $pointer.app_sha256 -or $supervisorHash -ceq $files['asg.exe'].sha256) { throw 'supervisor must be a distinct executable' }
    foreach ($name in $required) {
        $mode = if ($name -cin @('agent-session-grep.exe', 'asg.exe', $appPath, $supervisorPath, $helperSh, 'package-install.sh')) { '0755' } else { '0644' }
        if ($files[$name].mode -cne $mode) { throw 'unexpected member mode' }
    }
    foreach ($name in @('agent-session-grep.exe', 'asg.exe', $appPath, $supervisorPath)) {
        Assert-NativeImage (Join-Path $root $name) ($name -ceq $supervisorPath)
    }
    $lines = @('asg.package-files/v1', "version`t$($pointer.version)", "target`t$($release.target)",
        "source_commit`t$($release.source_commit)", "app`t$($pointer.app)", "app_sha256`t$($pointer.app_sha256)",
        "dir`t$($pointer.dir)", "supervisor`tasg-supervisor.exe", "supervisor_sha256`t$supervisorHash",
        "launcher_protocol`t1", "catalog_schema`t$($versionInfo.catalog_schema)",
        "control_schema`t$($versionInfo.control_schema)", "built_at`t$($versionInfo.built_at)")
    $names = [string[]]@($files.Keys | Where-Object { $_ -cne 'PACKAGE-MANIFEST.tsv' })
    [Array]::Sort($names, [StringComparer]::Ordinal)
    foreach ($name in $names) {
        $entry = $files[$name]
        $lines += "file`t$($entry.sha256)`t$($entry.mode)`t$($entry.size_bytes)`t$name"
    }
    if ([IO.File]::ReadAllText((Join-Path $root 'PACKAGE-MANIFEST.tsv')) -cne (($lines -join "`n") + "`n")) { throw 'package file manifest identity mismatch' }

    if (-not $Prefix) {
        if (-not $env:LOCALAPPDATA) { throw 'pass -Prefix with a dedicated user-owned directory' }
        $Prefix = Join-Path $env:LOCALAPPDATA 'agent-session-grep-candidate/bin'
    }
    $Prefix = [IO.Path]::GetFullPath($Prefix).TrimEnd('\', '/')
    $parent = [IO.Path]::GetDirectoryName($Prefix)
    Assert-PlainPath $Prefix
    if (-not $parent) { throw 'invalid prefix parent' }
    if ($Prefix -eq $root -or $Prefix.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase)) { throw 'prefix must be outside extracted package' }
    Ensure-Directory $parent
    $lockPath = "$Prefix.asg-install-lock"
    Assert-PlainPath $lockPath
    if (Test-Path -LiteralPath $lockPath) { Assert-File $lockPath }
    $lock = New-Object IO.FileStream($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $receiptPath = Join-Path $Prefix 'package-install.json'
    if (Test-Path -LiteralPath $Prefix) {
        if (-not [IO.Directory]::Exists($Prefix)) { throw 'prefix is not a directory' }
        if (@(Get-ChildItem -LiteralPath $Prefix -Force).Count -gt 0) {
            Assert-File $receiptPath
            $receipt = Read-Metadata $receiptPath @('schema', 'product', 'version', 'target', 'source_commit', 'launcher_protocol', 'manifest_sha256', 'archive_sha256', 'package_files_sha256')
            if ($receipt.schema -cne 'asg.package-install/v1' -or $receipt.product -cne 'agent-session-grep' -or $receipt.version -cne $pointer.version -or $receipt.target -cne $release.target -or $receipt.source_commit -cne $release.source_commit -or $receipt.launcher_protocol -ne 1 -or $receipt.manifest_sha256 -cne $manifestHash -or $receipt.package_files_sha256 -cne $metadata.install_manifest_sha256 -or $receipt.archive_sha256 -cne $metadata.archive.sha256) { throw 'unowned prefix or different package; upgrade is not implemented' }
            if (@(File-Names $Prefix).Count -ne $files.Count + 3) { throw 'installed file set changed' }
            if ((Hash (Join-Path $Prefix 'release.manifest.json')) -cne $manifestHash -or (Hash (Join-Path $Prefix 'SHA256SUMS')) -cne (Hash $Checksums)) { throw 'installed release metadata changed' }
            foreach ($name in $files.Keys) {
                if ((Hash (Join-Path $Prefix $name)) -cne $files[$name].sha256) { throw 'installed file changed; refusing repair' }
            }
            Verify-Programs $Prefix $pointer $versionInfo
            Write-Output "package-install: same verified developer candidate already installed at $Prefix"
            $lock.Dispose()
            $lock = $null
            Complete-SelectedSetup $Prefix
            exit 0
        }
        throw 'first install requires an absent dedicated prefix; refusing an existing empty directory'
    }
    $stage = "$Prefix.asg-stage-$([Guid]::NewGuid().ToString('N'))"
    if (Test-Path -LiteralPath $stage) { throw 'staging collision' }
    [void][IO.Directory]::CreateDirectory($stage)
    foreach ($name in ($files.Keys | Sort-Object)) {
        $destination = Join-Path $stage $name
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
        [IO.File]::Copy((Join-Path $root $name), $destination, $false)
        if ((Hash $destination) -cne $files[$name].sha256) { throw 'staged digest mismatch' }
        $stream = [IO.File]::Open($destination, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try { $stream.Flush($true) } finally { $stream.Dispose() }
    }
    foreach ($metadataFile in @(@($Manifest, 'release.manifest.json'), @($Checksums, 'SHA256SUMS'))) {
        $destination = Join-Path $stage $metadataFile[1]
        [IO.File]::Copy($metadataFile[0], $destination, $false)
        if ((Hash $destination) -cne (Hash $metadataFile[0])) { throw 'staged release metadata changed' }
        $stream = [IO.File]::Open($destination, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try { $stream.Flush($true) } finally { $stream.Dispose() }
    }
    Verify-Programs $stage $pointer $versionInfo
    $receipt = [ordered]@{
        schema = 'asg.package-install/v1'; product = 'agent-session-grep'
        version = $pointer.version; target = $release.target; source_commit = $release.source_commit
        launcher_protocol = 1; manifest_sha256 = $manifestHash
        archive_sha256 = $metadata.archive.sha256; package_files_sha256 = $metadata.install_manifest_sha256
    }
    Write-Durable (Join-Path $stage 'package-install.json.tmp') (($receipt | ConvertTo-Json -Depth 5) + "`n")
    [IO.File]::Move((Join-Path $stage 'package-install.json.tmp'), (Join-Path $stage 'package-install.json'))
    Assert-PlainPath $Prefix
    [IO.Directory]::Move($stage, $Prefix)
    $stage = $null
    Write-Output "package-install: verified developer candidate $($pointer.version) installed at $Prefix"
    $lock.Dispose()
    $lock = $null
    Complete-SelectedSetup $Prefix
} catch {
    [Console]::Error.WriteLine("package-install: $($_.Exception.Message)")
    if ($stage) { [Console]::Error.WriteLine("package-install: staging preserved at $stage") }
    exit 1
} finally {
    if ($null -ne $lock) {
        $lock.Dispose()
    }
}
