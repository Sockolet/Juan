param(
    [ValidateSet('Generate', 'Verify')]
    [string]$Mode = 'Verify',
    [Parameter(Mandatory = $true)]
    [string]$Archive,
    [string]$ReferenceArchive,
    [string]$FiddlerPath = (Join-Path $env:LOCALAPPDATA 'Programs\Fiddler\Fiddler.exe')
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core') {
    throw 'Run this optional Fiddler Classic check with Windows PowerShell 5.1, not PowerShell Core.'
}
$FiddlerPath = (Resolve-Path -LiteralPath $FiddlerPath).Path
$Archive = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Archive)

function Get-ProxySnapshot {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings')
    try {
        $data = [ordered]@{}
        foreach ($name in 'ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL') {
            $data[$name] = $key.GetValue($name, $null)
        }
        return ($data | ConvertTo-Json -Compress)
    } finally {
        $key.Dispose()
    }
}

function Hash-Bytes([byte[]]$Bytes) {
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hash.Dispose()
    }
}

function Session-Report($Sessions) {
    @($Sessions | ForEach-Object {
        [ordered]@{
            method = $_.RequestMethod
            status = $_.responseCode
            urlSha256 = Hash-Bytes ([System.Text.Encoding]::UTF8.GetBytes($_.fullUrl))
            requestBytes = $_.requestBodyBytes.Length
            requestSha256 = Hash-Bytes $_.requestBodyBytes
            responseBytes = $_.responseBodyBytes.Length
            responseSha256 = Hash-Bytes $_.responseBodyBytes
        }
    })
}

$before = Get-ProxySnapshot
try {
    [void][Reflection.Assembly]::LoadFrom($FiddlerPath)
    # Only public offline Session/Utilities APIs are called. Never start or attach Fiddler's proxy.
    if ($Mode -eq 'Generate') {
        if (Test-Path -LiteralPath $Archive) { throw 'Choose a new synthetic fixture filename.' }
        $utf8 = [System.Text.Encoding]::UTF8
        $plain = $utf8.GetBytes('{"producer":"Fiddler","synthetic":true}')
        $response1 = $utf8.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: $($plain.Length)`r`nSet-Cookie: demo=not-a-real-cookie`r`n`r`n") + $plain
        $request1 = $utf8.GetBytes("GET https://example.test/fixture?kind=saz HTTP/1.1`r`nHost: example.test`r`nAuthorization: Bearer DEMO-NOT-A-REAL-TOKEN`r`n`r`n")
        $binary = [byte[]]@(0, 1, 255, 13, 10, 83, 65, 90)
        $request2 = $utf8.GetBytes("POST http://upload.example.test/binary HTTP/1.1`r`nHost: upload.example.test`r`nContent-Type: application/octet-stream`r`nContent-Length: $($binary.Length)`r`n`r`n") + $binary
        $memory = [System.IO.MemoryStream]::new()
        $gzip = [System.IO.Compression.GZipStream]::new($memory, [System.IO.Compression.CompressionMode]::Compress, $true)
        try { $gzip.Write($binary, 0, $binary.Length) } finally { $gzip.Dispose() }
        $compressed = $memory.ToArray()
        $memory.Dispose()
        $response2 = $utf8.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Encoding: gzip`r`nContent-Length: $($compressed.Length)`r`n`r`n") + $compressed
        $request3 = $utf8.GetBytes("HEAD https://example.test/metadata HTTP/1.1`r`nHost: example.test`r`n`r`n")
        $response3 = $utf8.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: 4096`r`n`r`n")
        $sessions = [Fiddler.Session[]]@(
            [Fiddler.Session]::new([byte[]]$request1, [byte[]]$response1, [Fiddler.SessionFlags]::IsHTTPS),
            [Fiddler.Session]::new([byte[]]$request2, [byte[]]$response2),
            [Fiddler.Session]::new([byte[]]$request3, [byte[]]$response3, [Fiddler.SessionFlags]::IsHTTPS)
        )
        $base = [DateTime]::Parse('2026-09-17T10:00:00.0000000Z', [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind)
        for ($i = 0; $i -lt $sessions.Length; $i++) {
            $session = $sessions[$i]
            foreach ($field in $session.Timers.GetType().GetFields()) {
                if ($field.FieldType -eq [DateTime]) { $field.SetValue($session.Timers, $base.AddSeconds($i)) }
            }
            $session.Timers.FiddlerGotResponseHeaders = $base.AddSeconds($i).AddMilliseconds(10)
            $session.Timers.ClientDoneResponse = $base.AddSeconds($i).AddMilliseconds(25)
            $session.Timers.ServerDoneResponse = $base.AddSeconds($i).AddMilliseconds(20)
            $session.oFlags['ui-comments'] = 'Synthetic offline interoperability fixture; no real traffic.'
        }
        if (-not [Fiddler.Utilities]::WriteSessionArchive($Archive, $sessions, $null, $false)) {
            throw 'Fiddler could not write the synthetic fixture.'
        }
    }
    $loaded = [Fiddler.Utilities]::ReadSessionArchive($Archive, $false)
    if ($null -eq $loaded -or $loaded.Length -eq 0) { throw 'Fiddler did not load any sessions.' }
    $report = @(Session-Report $loaded)
    if ($ReferenceArchive) {
        $referencePath = (Resolve-Path -LiteralPath $ReferenceArchive).Path
        $reference = [Fiddler.Utilities]::ReadSessionArchive($referencePath, $false)
        if ($null -eq $reference) { throw 'Fiddler could not read the reference archive.' }
        $expected = @(Session-Report $reference) | ConvertTo-Json -Depth 4 -Compress
        if (($report | ConvertTo-Json -Depth 4 -Compress) -cne $expected) {
            throw 'Fiddler session URLs, status codes, methods, or body bytes differ from the reference.'
        }
    }
    $report | ConvertTo-Json -Depth 4
} finally {
    if ((Get-ProxySnapshot) -cne $before) {
        throw 'Windows proxy settings changed during the offline Fiddler check.'
    }
}
