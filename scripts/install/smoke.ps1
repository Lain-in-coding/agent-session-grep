#!/usr/bin/env pwsh
# End-to-end surface smoke against an ALREADY-BUILT binary: robot envelopes,
# documented exit codes, and the MCP stdio handshake. This script never builds —
# building is the job of install.ps1 or CI, and a smoke run that builds cannot
# tell a broken artifact from a broken build.
#
# The fixture is synthetic and inlined below. No real transcript is ever read.

[CmdletBinding()]
param(
    [string]$Binary,
    [string]$AliasBinary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Assertions here own the interpretation of native exit codes; PowerShell must
# not abort on a non-zero exit before the assertion can report actual output.
$PSNativeCommandUseErrorActionPreference = $false

$script:Failures = 0
$script:TempDir = $null

function Write-Pass {
    param([string]$Message)
    Write-Host "smoke: pass  $Message"
}

function Write-Fail {
    param([string]$Message, [string]$Actual)
    $script:Failures++
    Write-Host "smoke: FAIL  $Message" -ForegroundColor Red
    if ($Actual) {
        Write-Host "smoke:       actual: $Actual" -ForegroundColor Red
    }
}

function Assert-That {
    param([bool]$Condition, [string]$Message, [string]$Actual)
    if ($Condition) { Write-Pass $Message } else { Write-Fail $Message $Actual }
}

function Exit-Smoke {
    param([int]$Code)
    # The temp store is disposable and must go even on the failure path, but only
    # after diagnostics have been printed.
    if ($script:TempDir -and (Test-Path -LiteralPath $script:TempDir)) {
        $cleanupPath = [System.IO.Path]::GetFullPath($script:TempDir)
        $cleanupParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([char[]]'\/')
        if ([System.IO.Path]::GetDirectoryName($cleanupPath) -ne $cleanupParent -or
            -not [System.IO.Path]::GetFileName($cleanupPath).StartsWith('agent-session-grep-smoke-')) {
            throw 'Refusing cleanup outside the owned smoke directory'
        }
        Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit $Code
}

function Abort {
    param([string]$Message)
    Write-Host "smoke: error: $Message" -ForegroundColor Red
    Exit-Smoke 1
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ([string]::IsNullOrWhiteSpace($Binary)) {
    $exeSuffix = if ($IsWindows) { '.exe' } else { '' }
    $Binary = Join-Path $repoRoot (Join-Path 'target/release' "agent-session-grep$exeSuffix")
}
if (-not (Test-Path -LiteralPath $Binary)) {
    Abort "binary not found: $Binary (build it first: cargo build --locked --release -p agent-session-grep-cli)"
}
$Binary = (Resolve-Path -LiteralPath $Binary).Path

if (-not [string]::IsNullOrWhiteSpace($AliasBinary)) {
    if (-not (Test-Path -LiteralPath $AliasBinary)) {
        Abort "alias binary not found: $AliasBinary"
    }
    $AliasBinary = (Resolve-Path -LiteralPath $AliasBinary).Path
    $canonicalVersion = (& $Binary --version | Out-String).Trim()
    $canonicalCode = $LASTEXITCODE
    $aliasVersion = (& $AliasBinary --version | Out-String).Trim()
    $aliasCode = $LASTEXITCODE
    Assert-That ($canonicalCode -eq 0) 'agent-session-grep --version exits 0' "exit=$canonicalCode"
    Assert-That ($aliasCode -eq 0) 'asg --version exits 0' "exit=$aliasCode"
    Assert-That ($canonicalVersion -eq $aliasVersion) 'agent-session-grep and asg report the same version' "canonical=$canonicalVersion alias=$aliasVersion"
}

# Robot invocation returning both the parsed first stdout frame and the exit
# code: every assertion below is about that pair.
function Invoke-Robot {
    param([string[]]$Arguments)
    $lines = & $Binary @Arguments
    $code = $LASTEXITCODE
    $text = ($lines | Out-String).Trim()
    $frame = $null
    if ($text) {
        $first = ($text -split "`r?`n")[0]
        try { $frame = $first | ConvertFrom-Json } catch { $frame = $null }
    }
    return @{ Code = $code; Frame = $frame; Text = $text }
}

function Test-HasProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    return [bool]($Object.PSObject.Properties.Name -contains $Name)
}

$script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("agent-session-grep-smoke-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null
$db = Join-Path $script:TempDir 'smoke.db'
$fixture = Join-Path $script:TempDir 'fixture.jsonl'

# Synthetic Claude Code transcript: root -> reply -> sidechain probe. The
# retrieval term is fixed so the search assertion does not depend on scoring.
$fixtureLines = @(
    '{"type":"user","uuid":"smoke-root-1","parentUuid":null,"sessionId":"smoke-session-1","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"smokezylograph root question"}}'
    '{"type":"assistant","uuid":"smoke-reply-2","parentUuid":"smoke-root-1","sessionId":"smoke-session-1","timestamp":"2026-01-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"text","text":"smokezylograph mainline answer"}]}}'
    '{"type":"assistant","uuid":"smoke-probe-3","parentUuid":"smoke-reply-2","sessionId":"smoke-session-1","isSidechain":true,"timestamp":"2026-01-01T00:00:02.000Z","message":{"role":"assistant","content":"smokezylograph sidechain probe"}}'
)
Set-Content -LiteralPath $fixture -Value ($fixtureLines -join "`n") -Encoding utf8NoBOM -NoNewline

Write-Host "smoke: binary  $Binary"
Write-Host "smoke: workdir $script:TempDir"

# An absent catalog stays absent on read; SQLite open failures map to catalog_error.
$r = Invoke-Robot @('--db', $db, '--robot', 'doctor')
Assert-That ($r.Code -eq 6 -and $null -ne $r.Frame -and $r.Frame.error.code -eq 'catalog_error') 'doctor on an absent store returns catalog_error (exit 6)' $r.Text
Assert-That (-not (Test-Path -LiteralPath $db)) 'doctor does not create an absent database' $r.Text

# 1. Only an explicit write initializes the fresh store; doctor is read-only.
$r = Invoke-Robot @('--db', $db, '--robot', 'sync', $fixture)
Assert-That ($r.Code -eq 0) 'sync exits 0' "exit=$($r.Code) stdout=$($r.Text)"
Assert-That ($null -ne $r.Frame -and $r.Frame.ok -eq $true) 'sync envelope reports ok:true' $r.Text
Assert-That ($null -ne $r.Frame -and $r.Frame.data.messages -eq 3) 'sync reports data.messages == 3' $r.Text

# 2. doctor reports the initialized store as openable with a numeric schema.
$r = Invoke-Robot @('--db', $db, '--robot', 'doctor')
Assert-That ($r.Code -eq 0) 'doctor exits 0' "exit=$($r.Code) stdout=$($r.Text)"
Assert-That (($null -ne $r.Frame) -and ($r.Frame.data.db -eq 'ok')) 'doctor reports data.db == ok' $r.Text
$schema = if ($null -ne $r.Frame) { $r.Frame.data.schema } else { $null }
Assert-That (($schema -is [int]) -or ($schema -is [int64]) -or ($schema -is [double])) 'doctor reports a numeric data.schema' $r.Text

# 3. search for the fixture term: hits are message-level entities.
$r = Invoke-Robot @('--db', $db, '--robot', 'search', 'smokezylograph')
$hitId = $null
Assert-That ($r.Code -eq 0) 'search exits 0' "exit=$($r.Code) stdout=$($r.Text)"
if ($null -ne $r.Frame) {
    $hits = @($r.Frame.data.hits)
    Assert-That ($hits.Count -gt 0) 'search returns a non-empty data.hits' $r.Text
    if ($hits.Count -gt 0) {
        $hitId = $hits[0].id
        Assert-That ($hitId -like 'msg_v1_*') 'first search hit id starts with msg_v1_' "id=$hitId"
    }
} else {
    Write-Fail 'search returns a non-empty data.hits' $r.Text
}

# 4. get the first hit: the stored canonical payload comes back verbatim. The
# session wire id is read out of that payload rather than hardcoded.
$sessionId = $null
if ($hitId) {
    $r = Invoke-Robot @('--db', $db, '--robot', 'get', $hitId)
    Assert-That ($r.Code -eq 0) 'get <hit-id> exits 0' "exit=$($r.Code) stdout=$($r.Text)"
    $payload = if ($null -ne $r.Frame) { $r.Frame.data.payload } else { $null }
    Assert-That (-not [string]::IsNullOrWhiteSpace($payload)) 'get <hit-id> returns a non-empty data.payload' $r.Text
    if (-not [string]::IsNullOrWhiteSpace($payload)) {
        $sessionId = ($payload | ConvertFrom-Json).session
    }
} else {
    Write-Fail 'get <hit-id> exits 0' 'no search hit id to resolve'
}

# 5. context for that session: mainline messages plus their evidence spans.
$mainlineMessageId = $null
if ($sessionId) {
    $r = Invoke-Robot @('--db', $db, '--robot', 'context', $sessionId)
    Assert-That ($r.Code -eq 0) 'context <ses-id> exits 0' "exit=$($r.Code) stdout=$($r.Text)"
    if ($null -ne $r.Frame) {
        $contextMessages = @($r.Frame.data.messages)
        Assert-That ($contextMessages.Count -gt 0) 'context returns non-empty data.messages' $r.Text
        Assert-That (@($r.Frame.data.evidence).Count -gt 0) 'context returns non-empty data.evidence' $r.Text
        if ($contextMessages.Count -gt 0) {
            $mainlineMessageId = $contextMessages[0].message_id
        }
    } else {
        Write-Fail 'context returns non-empty data.messages' $r.Text
    }
} else {
    Write-Fail 'context <ses-id> exits 0' 'no session id extracted from the hit payload'
}

# 6. status: 3 messages + 1 session + 1 document entity.
$r = Invoke-Robot @('--db', $db, '--robot', 'status')
Assert-That ($r.Code -eq 0) 'status exits 0' "exit=$($r.Code) stdout=$($r.Text)"
$count = if ($null -ne $r.Frame) { [int]$r.Frame.data.catalog_count } else { -1 }
Assert-That ($count -ge 5) 'status reports data.catalog_count >= 5' "catalog_count=$count"

# 7. get on a well-formed but absent id: exit 4 with a not_found envelope
# (ADR-0005; the message is generic and never echoes the wire id).
$r = Invoke-Robot @('--db', $db, '--robot', 'get', 'ses_v1_nope')
Assert-That ($r.Code -eq 4) 'get <absent id> exits 4' "exit=$($r.Code) stdout=$($r.Text)"
Assert-That ($null -ne $r.Frame -and $r.Frame.ok -eq $false) 'get <absent id> reports ok:false' $r.Text
Assert-That ($null -ne $r.Frame -and $r.Frame.error.code -eq 'not_found') 'get <absent id> reports error.code == not_found' $r.Text

# 8. context on an absent session: same not_found contract as get.
$r = Invoke-Robot @('--db', $db, '--robot', 'context', 'ses_v1_nope')
Assert-That ($r.Code -eq 4) 'context <absent session> exits 4' "exit=$($r.Code) stdout=$($r.Text)"
Assert-That ($null -ne $r.Frame -and $r.Frame.error.code -eq 'not_found') 'context <absent session> reports error.code == not_found' $r.Text

# 9. garbage cursor: rejected as a request error, not silently reset to page 1.
$r = Invoke-Robot @('--db', $db, '--robot', 'search', 'smokezylograph', '--cursor', 'garbage')
Assert-That ($r.Code -eq 2) 'search with a garbage cursor exits 2' "exit=$($r.Code) stdout=$($r.Text)"
Assert-That ($null -ne $r.Frame -and $r.Frame.error.code -eq 'cursor_invalid') 'garbage cursor reports error.code == cursor_invalid' $r.Text

# Advertised provider filters must accept every implemented row. A distinct
# Grok source makes filter enforcement observable, including semantic modes.
$grokFixture = Join-Path $script:TempDir 'grok.jsonl'
Set-Content -LiteralPath $grokFixture -Value '{"params":{"update":{"sessionUpdate":"user_message_chunk","content":"smokegrokfilter retained message"},"_meta":{"promptIndex":0}}}' -Encoding utf8NoBOM -NoNewline
$r = Invoke-Robot @('--db', $db, '--robot', 'sync', $grokFixture)
Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and $r.Frame.data.messages -eq 1) 'sync ingests one Grok message' $r.Text
$r = Invoke-Robot @('--db', $db, '--robot', 'providers')
Assert-That ($r.Code -eq 0) 'providers exits 0' $r.Text
$filterable = @(if ($null -ne $r.Frame) { $r.Frame.data.providers | Where-Object { $_.maturity -ne 'unsupported' } })
Assert-That ($filterable.Count -gt 2) 'providers advertises more than the legacy two providers' $r.Text
foreach ($provider in $filterable) {
    $r = Invoke-Robot @('--db', $db, '--robot', 'search', 'smokegrokfilter', '--provider', $provider.provider_id)
    $expected = if ($provider.provider_id -eq 'grok-build') { 1 } else { 0 }
    Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and @($r.Frame.data.hits).Count -eq $expected) "advertised provider filter $($provider.provider_id) selects the right messages" $r.Text
}
$r = Invoke-Robot @('--db', $db, '--robot', 'index', 'embeddings')
Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and $r.Frame.data.indexed -eq 4) 'index embeddings indexes all four synthetic messages' $r.Text
foreach ($retrievalMode in @('semantic', 'hybrid')) {
    $r = Invoke-Robot @('--db', $db, '--robot', 'search', 'smokegrokfilter', '--provider', 'grok-build', '--mode', $retrievalMode)
    Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and $r.Frame.data.retrieval_mode -eq $retrievalMode -and @($r.Frame.data.hits).Count -eq 1) "CLI $retrievalMode uses the index and Grok filter" $r.Text
}

# Relocation uses a separate synthetic catalog and preserves canonical IDs.
$relocationArea = Join-Path $script:TempDir 'relocation'
$relocationOld = Join-Path $relocationArea 'old-installation'
$relocationNew = Join-Path $relocationArea 'new-installation'
$relocationDb = Join-Path $relocationArea 'catalog.db'
$relocationBackup = Join-Path $relocationArea 'catalog-backup.db'
$relocationSource = Join-Path $relocationOld 'session.jsonl'
New-Item -ItemType Directory -Path $relocationOld -Force | Out-Null
Copy-Item -LiteralPath $fixture -Destination $relocationSource
$r = Invoke-Robot @('--db', $relocationDb, '--robot', 'relocate', '--provider', 'claude', '--from', $relocationOld, '--to', $relocationNew)
Assert-That ($r.Code -eq 6 -and $null -ne $r.Frame -and $r.Frame.error.code -eq 'catalog_error') 'relocate preview refuses an absent catalog' $r.Text
Assert-That (-not (Test-Path -LiteralPath $relocationDb)) 'relocate preview creates no catalog' $r.Text
$r = Invoke-Robot @('--db', $relocationDb, '--robot', 'sync', $relocationSource)
Assert-That ($r.Code -eq 0) 'relocation fixture sync succeeds' $r.Text
$relocationGeneration = if ($null -ne $r.Frame) { [long]$r.Frame.data.generation } else { -1 }
$r = Invoke-Robot @('--db', $relocationDb, '--robot', 'search', 'smokezylograph')
$relocationSession = if ($null -ne $r.Frame -and @($r.Frame.data.hits).Count -gt 0) { $r.Frame.data.hits[0].session_id } else { $null }
Assert-That (-not [string]::IsNullOrWhiteSpace($relocationSession)) 'relocation fixture has a canonical Session ID' $r.Text
$relocationBoundary = [System.IO.Path]::GetFullPath($script:TempDir).TrimEnd([char[]]'\/') + [System.IO.Path]::DirectorySeparatorChar
foreach ($candidate in @($relocationOld, $relocationNew)) {
    if (-not [System.IO.Path]::GetFullPath($candidate).StartsWith($relocationBoundary, [System.StringComparison]::OrdinalIgnoreCase)) {
        Abort 'Refusing fixture move outside the owned smoke directory'
    }
}
Move-Item -LiteralPath $relocationOld -Destination $relocationNew
$catalogHash = (Get-FileHash -LiteralPath $relocationDb).Hash
$sourceHash = (Get-FileHash -LiteralPath (Join-Path $relocationNew 'session.jsonl')).Hash
$r = Invoke-Robot @('--db', $relocationDb, '--robot', 'relocate', '--provider', 'claude', '--from', $relocationOld, '--to', $relocationNew, '--alias-ttl-days', '7')
Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and $r.Frame.command -eq 'relocate.preview' -and $r.Frame.data.status -eq 'planned') 'relocate preview returns a planned Robot result' $r.Text
Assert-That ((Get-FileHash -LiteralPath $relocationDb).Hash -ceq $catalogHash) 'relocate preview does not write the catalog' $r.Text
Assert-That (-not (Test-Path -LiteralPath $relocationBackup)) 'relocate preview creates no backup' $r.Text
$relocationPlan = if ($null -ne $r.Frame -and (Test-HasProperty $r.Frame.data 'plan')) { $r.Frame.data.plan } else { $null }

if (-not [string]::IsNullOrWhiteSpace($relocationPlan)) {
    Assert-That ($r.Frame.data.source_count -eq 1 -and $r.Frame.data.session_count -eq 1 -and $r.Frame.data.alias_ttl_days -eq 7) 'relocate preview reports bounded counts and selected retention' $r.Text
    Assert-That (-not (Test-HasProperty $r.Frame.data 'from') -and -not (Test-HasProperty $r.Frame.data 'to') -and -not (Test-HasProperty $r.Frame.data 'backup')) 'relocate results contain no private path fields' $r.Text
    $r = Invoke-Robot @('--db', $relocationDb, '--robot', 'relocate', '--provider', 'claude', '--from', $relocationOld, '--to', $relocationNew, '--alias-ttl-days', '7', '--apply', '--plan', $relocationPlan, '--backup', $relocationBackup)
    Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and $r.Frame.command -eq 'relocate.apply' -and $r.Frame.data.status -eq 'applied' -and $r.Frame.data.generation -eq ($relocationGeneration + 1)) 'relocate apply advances generation exactly once' $r.Text
    Assert-That (Test-Path -LiteralPath $relocationBackup) 'relocate apply creates a verified backup' $r.Text
    Assert-That ((Get-FileHash -LiteralPath (Join-Path $relocationNew 'session.jsonl')).Hash -ceq $sourceHash) 'relocate apply leaves provider source bytes unchanged' $r.Text
    $r = Invoke-Robot @('--db', $relocationBackup, '--robot', 'status')
    Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and $r.Frame.data.generation -eq $relocationGeneration) 'relocate backup retains the previous generation' $r.Text
    $r = Invoke-Robot @('--db', $relocationDb, '--robot', 'sync', (Join-Path $relocationNew 'session.jsonl'))
    Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and $r.Frame.data.generation -eq ($relocationGeneration + 1)) 'sync after relocation retains identity and generation' $r.Text
    if ($relocationSession) {
        $r = Invoke-Robot @('--db', $relocationDb, '--robot', 'context', $relocationSession)
        Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and @($r.Frame.data.messages).Count -gt 0) 'the original Session ID still resolves after relocation' $r.Text
    }
    $r = Invoke-Robot @('--db', $relocationDb, '--robot', 'relocate', '--provider', 'claude', '--from', $relocationOld, '--to', $relocationNew, '--alias-ttl-days', '7')
    Assert-That ($r.Code -eq 0 -and $null -ne $r.Frame -and $r.Frame.command -eq 'relocate.preview' -and $r.Frame.data.status -eq 'unchanged' -and $r.Frame.data.generation -eq ($relocationGeneration + 1)) 'repeated relocation preview is an unchanged no-op' $r.Text
} else {
    Write-Fail 'relocate preview provides an opaque plan' $r.Text
}
$r = Invoke-Robot @('--robot', 'relocate', '--help')
Assert-That ($r.Code -eq 0 -and $r.Text.Contains('--backup') -and $r.Text.Contains('--alias-ttl-days')) 'relocate help describes apply and alias lifetime without a catalog' $r.Text
$r = Invoke-Robot @('--robot', 'providers')
$relocationCapability = if ($null -ne $r.Frame -and (Test-HasProperty $r.Frame.data 'relocation')) { $r.Frame.data.relocation } else { $null }
Assert-That ($null -ne $relocationCapability -and ($relocationCapability.interfaces -join ',') -eq 'cli') 'capability metadata marks relocation CLI-only' $r.Text

# 10. MCP stdio handshake. stdout is the protocol channel, so every line must be
# a complete JSON-RPC frame; anything else means diagnostics leaked into it.
$mcpInput = @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
    '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_status","arguments":{}}}'
    (@{
        jsonrpc = '2.0'
        id = 4
        method = 'tools/call'
        params = @{
            name = 'get_message'
            arguments = @{ message_id = $mainlineMessageId; session_id = $sessionId; around = 0 }
        }
    } | ConvertTo-Json -Depth 5 -Compress)
    '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"search_sessions","arguments":{"query":"smokegrokfilter","providers":["grok-build"],"mode":"semantic"}}}'
    '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"search_sessions","arguments":{"query":"smokegrokfilter","providers":["grok-build"],"mode":"hybrid"}}}'
)
$mcpOut = $mcpInput | & $Binary --db $db mcp
$mcpCode = $LASTEXITCODE
$mcpText = ($mcpOut | Out-String).Trim()
Assert-That ($mcpCode -eq 0) 'mcp server exits 0 on stdin EOF' "exit=$mcpCode stdout=$mcpText"

$frames = @()
$pureJson = $true
foreach ($line in ($mcpText -split "`r?`n")) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    try { $frames += ($line | ConvertFrom-Json) } catch { $pureJson = $false }
}
Assert-That $pureJson 'every mcp stdout line is valid JSON' $mcpText

$listFrame = $frames | Where-Object { (Test-HasProperty $_ 'id') -and $_.id -eq 2 } | Select-Object -First 1
$toolCount = if ($null -ne $listFrame) { @($listFrame.result.tools).Count } else { -1 }
# 9 tools as of the 16-provider evidence wave (search_sessions, get_session_context,
# get_session_resume, get_message, list_sessions, generate_handoff, list_providers,
# get_status, doctor).
Assert-That ($toolCount -eq 9) 'tools/list returns exactly 9 tools' "tools=$toolCount"

$callFrame = $frames | Where-Object { (Test-HasProperty $_ 'id') -and $_.id -eq 3 } | Select-Object -First 1
Assert-That ($null -ne $callFrame -and $callFrame.result.isError -eq $false) 'tools/call get_status returns isError:false' $mcpText

$messageFrame = $frames | Where-Object { (Test-HasProperty $_ 'id') -and $_.id -eq 4 } | Select-Object -First 1
$messageData = if ($null -ne $messageFrame) { $messageFrame.result.structuredContent.data } else { $null }
Assert-That ($null -ne $messageFrame -and $messageFrame.result.isError -eq $false) 'tools/call get_message returns isError:false' $mcpText
Assert-That ($null -ne $messageData -and $messageData.message_id -eq $mainlineMessageId) 'get_message returns the real anchor message id' $mcpText
Assert-That ($null -ne $messageData -and @($messageData.messages).Count -eq 1) 'get_message around=0 returns exactly one message' $mcpText

foreach ($case in @(@{ Id = 5; Mode = 'semantic' }, @{ Id = 6; Mode = 'hybrid' })) {
    $searchFrame = $frames | Where-Object { (Test-HasProperty $_ 'id') -and $_.id -eq $case.Id } | Select-Object -First 1
    $searchData = if ($null -ne $searchFrame -and (Test-HasProperty $searchFrame 'result')) { $searchFrame.result.structuredContent.data } else { $null }
    Assert-That ($null -ne $searchData -and $searchFrame.result.isError -eq $false -and $searchData.retrieval_mode -eq $case.Mode -and @($searchData.hits).Count -eq 1) "MCP $($case.Mode) uses the index and Grok filter" $mcpText
}

if ($script:Failures -gt 0) {
    Write-Host "smoke: $script:Failures assertion(s) failed" -ForegroundColor Red
    Exit-Smoke 1
}
Write-Host 'smoke: all assertions passed'
Exit-Smoke 0
