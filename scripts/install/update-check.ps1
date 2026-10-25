#requires -Version 5.1
<#
Bounded update-check transport helper (asg.update-fetch/v1).

This helper is installed as an immutable versioned package member and is only
invoked by an explicit `update check`. It receives public release coordinates
only: repository, channel, native target, installed version, page or tag/asset.
It never receives a history root, catalog path, credential or query.

It supports exactly three bounded operations:

  -Mode page  -Repository <owner/name> -Channel <beta|stable>
              -Target <target> -CurrentVersion <semver> -Page <1..3>
  -Mode asset -Repository <owner/name> -Tag <v-semver> -Asset <asset-name>

It follows at most three HTTPS redirects, retries a transient failure at most
twice, and never resets the one 30-second deadline. It writes the response body
to a helper-owned temporary file and returns a small envelope on stdout. The
calling application revalidates the final URL, size, location and bytes.

This script never changes execution policy, unblocks files or edits trust
settings. It requires no Rust compiler, Python, Node.js or jq.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Mode,
    [Parameter(Mandatory = $true)][string]$Repository,
    [string]$Channel = '',
    [string]$Target = '',
    [string]$CurrentVersion = '',
    [int]$Page = 0,
    [string]$Tag = '',
    [string]$Asset = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

$script:Schema = 'asg.update-fetch/v1'
$script:TempFile = $null
$script:SemVer = '\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z'
$script:Targets = @(
    'x86_64-pc-windows-msvc',
    'x86_64-unknown-linux-gnu',
    'x86_64-apple-darwin',
    'aarch64-apple-darwin'
)

function Write-HelperError([string]$Code, [int]$ExitCode) {
    if ($null -ne $script:TempFile) {
        try { [IO.File]::Delete($script:TempFile) } catch { }
        $script:TempFile = $null
    }
    $payload = [ordered]@{
        schema = $script:Schema
        status = 'error'
        error = $Code
    }
    [Console]::Out.Write((ConvertTo-Json -Compress -InputObject $payload))
    [Console]::Out.Write("`n")
    exit $ExitCode
}

function Test-SafeToken([string]$Value, [int]$Maximum = 200) {
    return ($Value.Length -gt 0 -and $Value.Length -le $Maximum `
        -and $Value -cmatch '\A[A-Za-z0-9._+-]+\z')
}

function Test-Repository([string]$Value) {
    if ($Value.Length -eq 0 -or $Value.Length -gt 200 `
        -or $Value -cnotmatch '\A[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\z') {
        return $false
    }
    $parts = $Value.Split('/')
    return ($parts.Count -eq 2 -and $parts[0] -notin @('.', '..') `
        -and $parts[1] -notin @('.', '..'))
}

function Test-Version([string]$Value, [switch]$AllowVPrefix) {
    $raw = $Value
    if ($AllowVPrefix) {
        if (-not $raw.StartsWith('v')) { return $false }
        $raw = $raw.Substring(1)
    } elseif ($raw.StartsWith('v')) {
        return $false
    }
    if ($raw.Length -eq 0 -or $raw.Length -gt 64) { return $false }
    return ($raw -cmatch $script:SemVer)
}

function Get-RemainingSeconds {
    $remaining = [int][Math]::Floor(30 - $script:Clock.Elapsed.TotalSeconds)
    if ($remaining -lt 0) { return 0 }
    return $remaining
}

function Test-AllowedUrl([string]$Value, [string]$Kind, [string]$PageUrl) {
    if (-not $Value.StartsWith('https://')) { return $false }
    try { $uri = [Uri]$Value } catch { return $false }
    if ($uri.Scheme -ne 'https') { return $false }
    if ($Kind -eq 'page') {
        return ($Value -ceq $PageUrl)
    }
    return ($uri.Host -in @(
        'github.com',
        'objects.githubusercontent.com',
        'release-assets.githubusercontent.com'
    ))
}

function Invoke-Helper {
    if (-not (Test-Repository $Repository)) {
        Write-HelperError 'usage' 2
    }

    if ($Mode -ceq 'page') {
        if ($Channel -cnotin @('beta', 'stable')) { Write-HelperError 'usage' 2 }
        if ($Target -cnotin $script:Targets) { Write-HelperError 'usage' 2 }
        if (-not (Test-Version $CurrentVersion)) { Write-HelperError 'usage' 2 }
        if ($Page -lt 1 -or $Page -gt 3) { Write-HelperError 'usage' 2 }
        $url = "https://api.github.com/repos/$Repository/releases?per_page=100&page=$Page"
        $cap = 4194304
    } elseif ($Mode -ceq 'asset') {
        if (-not (Test-Version $Tag -AllowVPrefix)) { Write-HelperError 'usage' 2 }
        if (-not (Test-SafeToken $Asset)) { Write-HelperError 'usage' 2 }
        $url = "https://github.com/$Repository/releases/download/$Tag/$Asset"
        $cap = 524288
    } else {
        Write-HelperError 'usage' 2
    }

    # Windows PowerShell 5.1 does not load System.Net.Http automatically.
    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
    } catch {
        Write-HelperError 'capability' 3
    }
    try {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor `
            [Net.SecurityProtocolType]::Tls12
    } catch {
        Write-HelperError 'capability' 3
    }

    $handler = New-Object -TypeName System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $handler.AutomaticDecompression = `
        [System.Net.DecompressionMethods]::GZip -bor `
        [System.Net.DecompressionMethods]::Deflate
    $client = New-Object -TypeName System.Net.Http.HttpClient -ArgumentList $handler

    $script:Clock = [Diagnostics.Stopwatch]::StartNew()
    $currentUrl = $url
    $redirects = 0
    $retries = 0
    $finalUrl = $null
    $bytes = 0
    $tempPath = [IO.Path]::Combine(
        [IO.Path]::GetTempPath(),
        ('asg-update-check-' + [Guid]::NewGuid().ToString('N') + '.tmp'))
    $script:TempFile = $tempPath

    try {
        while ($true) {
            $remaining = Get-RemainingSeconds
            if ($remaining -le 0) { Write-HelperError 'timeout' 4 }
            $client.Timeout = [TimeSpan]::FromSeconds([Math]::Min($remaining, 10))

            $request = New-Object -TypeName System.Net.Http.HttpRequestMessage `
                -ArgumentList ([System.Net.Http.HttpMethod]::Get), $currentUrl
            [void]$request.Headers.TryAddWithoutValidation(
                'User-Agent', 'agent-session-grep-update-check')
            [void]$request.Headers.TryAddWithoutValidation(
                'Accept', 'application/vnd.github+json')
            [void]$request.Headers.TryAddWithoutValidation(
                'X-GitHub-Api-Version', '2022-11-28')

            try {
                $response = $client.SendAsync(
                    $request,
                    [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
                ).GetAwaiter().GetResult()
            } catch {
                $request.Dispose()
                if ($retries -lt 2 -and (Get-RemainingSeconds) -gt 0) {
                    $retries++
                    Start-Sleep -Milliseconds (200 * $retries)
                    continue
                }
                Write-HelperError 'network' 4
            }

            try {
                $status = [int]$response.StatusCode
                if ($status -ge 300 -and $status -le 399) {
                    $location = $response.Headers.Location
                    if ($null -eq $location) { Write-HelperError 'redirect_rejected' 6 }
                    if ($location.IsAbsoluteUri) {
                        $next = $location.AbsoluteUri
                    } else {
                        $next = (New-Object -TypeName System.Uri `
                            -ArgumentList ([Uri]$currentUrl), $location).AbsoluteUri
                    }
                    if (-not (Test-AllowedUrl $next $Mode $url)) {
                        Write-HelperError 'redirect_rejected' 6
                    }
                    $redirects++
                    if ($redirects -gt 3) { Write-HelperError 'redirect_rejected' 6 }
                    $currentUrl = $next
                    continue
                }
                if ($status -eq 429 -or ($status -ge 500 -and $status -le 599)) {
                    if ($retries -lt 2 -and (Get-RemainingSeconds) -gt 0) {
                        $retries++
                        Start-Sleep -Milliseconds (200 * $retries)
                        continue
                    }
                    Write-HelperError 'http_status' 5
                }
                if ($status -ne 200) {
                    Write-HelperError 'http_status' 5
                }

                $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $output = [IO.File]::Open(
                    $tempPath, [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write, [IO.FileShare]::None)
                $tooLarge = $false
                try {
                    $buffer = New-Object byte[] 81920
                    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $bytes += $read
                        if ($bytes -gt $cap) {
                            $tooLarge = $true
                            break
                        }
                        $output.Write($buffer, 0, $read)
                    }
                    $output.Flush()
                } finally {
                    $output.Dispose()
                    $stream.Dispose()
                }
                if ($tooLarge) { Write-HelperError 'too_large' 7 }
                $finalUrl = $currentUrl
                break
            } finally {
                $response.Dispose()
                $request.Dispose()
            }
        }

        if ($Mode -ceq 'page' -and $finalUrl -cne $url) {
            Write-HelperError 'redirect_rejected' 6
        }
        if ((Test-AllowedUrl $finalUrl $Mode $url) -ne $true) {
            Write-HelperError 'redirect_rejected' 6
        }

        $payload = [ordered]@{
            schema = $script:Schema
            status = 'ok'
            url = $finalUrl
            bytes = $bytes
            file = $tempPath
        }
        [Console]::Out.Write((ConvertTo-Json -Compress -InputObject $payload))
        [Console]::Out.Write("`n")
        $script:TempFile = $null
        exit 0
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

try {
    Invoke-Helper
} catch {
    Write-HelperError 'internal' 8
}
