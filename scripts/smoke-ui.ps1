param(
    [string]$Executable = (Join-Path $PSScriptRoot '..\target\release\juan.exe'),
    [string]$Screenshot,
    [switch]$Saz
)

$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
if ((Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Juan\proxy-restore.dpapi')) -or
    (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Widdler\proxy-restore.dpapi'))) {
    throw 'A proxy recovery record already exists. Review it in Juan before running the UI smoke test.'
}
if ((Get-Item -LiteralPath $Executable).Length -gt 20MB) {
    throw 'The release desktop executable exceeds the 20 MiB smoke-test budget.'
}
if (@(Get-CimInstance Win32_Process -Filter "Name = 'juan.exe' OR Name = 'juan-cli.exe' OR Name = 'widdler.exe' OR Name = 'widdler-cli.exe'").Count -ne 0) {
    throw 'Juan or a legacy Widdler instance is running. Save and close it before testing; the smoke test will not close another capture.'
}

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class JuanUiSmoke {
    public delegate bool EnumProc(IntPtr window, IntPtr data);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")]
    public static extern IntPtr GetDlgItem(IntPtr parent, int id);
    [DllImport("user32.dll")]
    public static extern IntPtr GetLastActivePopup(IntPtr window);
    [DllImport("user32.dll")]
    public static extern bool EnumChildWindows(IntPtr parent, EnumProc callback, IntPtr data);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern int GetWindowTextW(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern int GetClassNameW(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll")]
    public static extern int GetDlgCtrlID(IntPtr window);
    [DllImport("user32.dll")]
    public static extern bool IsWindowEnabled(IntPtr window);
    [DllImport("user32.dll", EntryPoint="SendMessageW")]
    public static extern IntPtr Send(IntPtr hwnd, uint message, IntPtr wparam, IntPtr lparam);
    [DllImport("user32.dll", EntryPoint="SendMessageW", CharSet=CharSet.Unicode)]
    public static extern IntPtr SendText(IntPtr hwnd, uint message, IntPtr wparam, string text);
    [DllImport("user32.dll", EntryPoint="SendMessageW", CharSet=CharSet.Unicode)]
    public static extern IntPtr ReadText(IntPtr hwnd, uint message, IntPtr wparam, StringBuilder text);
    [DllImport("user32.dll")]
    public static extern bool PostMessageW(IntPtr hwnd, uint message, IntPtr wparam, IntPtr lparam);
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    public static IntPtr FindButton(IntPtr parent, string caption) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(parent, (child, _) => {
            var name = new StringBuilder(256);
            var cls = new StringBuilder(64);
            GetWindowTextW(child, name, name.Capacity);
            GetClassNameW(child, cls, cls.Capacity);
            if (cls.ToString() == "Button" && name.ToString() == caption) {
                found = child;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static IntPtr FindControlId(IntPtr parent, int id, string className = "") {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(parent, (child, _) => {
            var cls = new StringBuilder(64);
            GetClassNameW(child, cls, cls.Capacity);
            if (GetDlgCtrlID(child) == id && (className.Length == 0 || cls.ToString() == className)) {
                found = child;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@

function Get-ProxySnapshot {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings')
    if ($null -eq $key) { throw 'Windows Internet Settings registry key is unavailable.' }
    try {
        $snapshot = [ordered]@{}
        foreach ($name in 'ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL') {
            $snapshot[$name] = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
        return ($snapshot | ConvertTo-Json -Compress)
    } finally {
        $key.Dispose()
    }
}

function Get-RootTrustSnapshot {
    $result = @()
    foreach ($location in @([System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root, $location)
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $result += @($store.Certificates | ForEach-Object { "$location`:$($_.Thumbprint)" })
        } finally {
            $store.Dispose()
        }
    }
    return (($result | Sort-Object) -join "`n")
}

function Assert-That([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Wait-Until([scriptblock]$Condition, [string]$Failure) {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt 10) {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 100
    }
    throw $Failure
}

function Get-ControlText([IntPtr]$Control) {
    $length = [JuanUiSmoke]::Send($Control, 14, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
    $buffer = [System.Text.StringBuilder]::new($length + 1)
    [void][JuanUiSmoke]::ReadText($Control, 13, [IntPtr]::new($buffer.Capacity), $buffer)
    return $buffer.ToString()
}

function Set-ControlText([IntPtr]$Control, [string]$Text) {
    [void][JuanUiSmoke]::SendText($Control, 12, [IntPtr]::Zero, $Text)
}

function Get-RowCount([IntPtr]$List) {
    return [JuanUiSmoke]::Send($List, 4100, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
}

function Invoke-CommandId([IntPtr]$Window, [int]$Id) {
    [void][JuanUiSmoke]::Send($Window, 273, [IntPtr]::new($Id), [IntPtr]::Zero)
}

function Open-CaptureSetup([IntPtr]$Window) {
    Assert-That ([JuanUiSmoke]::PostMessageW($Window, 273, [IntPtr]::new(100), [IntPtr]::Zero)) 'Could not request capture setup.'
    Wait-Until {
        $popup = [JuanUiSmoke]::GetLastActivePopup($Window)
        $popup -ne $Window -and $popup -ne [IntPtr]::Zero -and
            [JuanUiSmoke]::FindButton($popup, 'Manual proxy') -ne [IntPtr]::Zero
    } 'Start capture did not ask how to route traffic; opening a listener alone leaves Windows apps uncaptured.'
    return [JuanUiSmoke]::GetLastActivePopup($Window)
}

function Open-HttpsSetup([IntPtr]$Window) {
    $checkbox = [JuanUiSmoke]::GetDlgItem($Window, 105)
    Assert-That ([JuanUiSmoke]::PostMessageW($checkbox, 245, [IntPtr]::Zero, [IntPtr]::Zero)) 'Could not request HTTPS setup.'
    Wait-Until {
        $popup = [JuanUiSmoke]::GetLastActivePopup($Window)
        $popup -ne $Window -and $popup -ne [IntPtr]::Zero -and
            [JuanUiSmoke]::FindButton($popup, 'Trust CA and enable HTTPS') -ne [IntPtr]::Zero
    } 'HTTPS activation did not guide missing CA trust before enabling decryption.'
    return [JuanUiSmoke]::GetLastActivePopup($Window)
}

function Select-CaptureOption([IntPtr]$Dialog, [int]$Id) {
    # TaskDialog command links use DirectUI wrappers; TDM_CLICK_BUTTON addresses their public IDs.
    [void][JuanUiSmoke]::Send($Dialog, 1126, [IntPtr]::new($Id), [IntPtr]::Zero)
}

function Wait-Modal([IntPtr]$Window, [string]$Title) {
    try {
        Wait-Until {
            $popup = [JuanUiSmoke]::GetLastActivePopup($Window)
            $popup -ne $Window -and $popup -ne [IntPtr]::Zero -and (Get-ControlText $popup) -eq $Title
        } "The expected dialog '$Title' did not appear."
    } catch {
        $popup = [JuanUiSmoke]::GetLastActivePopup($Window)
        throw "Expected dialog '$Title'; active test dialog is '$(Get-ControlText $popup)'."
    }
    return [JuanUiSmoke]::GetLastActivePopup($Window)
}

function Choose-File([IntPtr]$Window, [string]$Title, [string]$Path) {
    $dialog = Wait-Modal $Window $Title
    Wait-Until {
        [JuanUiSmoke]::FindControlId($dialog, 1001, 'Edit') -ne [IntPtr]::Zero -or
            [JuanUiSmoke]::FindControlId($dialog, 1148, 'Edit') -ne [IntPtr]::Zero
    } 'The native file picker did not finish creating its filename editor.'
    $preferred = if ($Title.StartsWith('Save')) { 1001 } else { 1148 }
    $alternate = if ($preferred -eq 1001) { 1148 } else { 1001 }
    $filename = [JuanUiSmoke]::FindControlId($dialog, $preferred, 'Edit')
    if ($filename -eq [IntPtr]::Zero) { $filename = [JuanUiSmoke]::FindControlId($dialog, $alternate, 'Edit') }
    Set-ControlText $filename $Path
    Assert-That ((Get-ControlText $filename) -eq $Path) 'The file picker did not accept the explicit test output path.'
    $button = [JuanUiSmoke]::FindControlId($dialog, 1, 'Button')
    Assert-That ($button -ne [IntPtr]::Zero) 'The file picker did not expose its confirmation button.'
    [void][JuanUiSmoke]::PostMessageW($button, 245, [IntPtr]::Zero, [IntPtr]::Zero)
}

function Test-Listening([int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.Connect('127.0.0.1', $Port)
        return $true
    } catch [System.Net.Sockets.SocketException] {
        if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) {
            return $false
        }
        throw
    } finally {
        $client.Dispose()
    }
}

function Invoke-LocalProxyProbe([int]$Port) {
    $origin = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $origin.Start()
    $originPort = $origin.LocalEndpoint.Port
    $client = [System.Net.Sockets.TcpClient]::new()
    $upstream = $null
    try {
        $client.Connect('127.0.0.1', $Port)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $stream.WriteTimeout = 5000
        $bytes = [System.Text.Encoding]::ASCII.GetBytes("GET http://127.0.0.1:$originPort/ui-probe HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nConnection: close`r`n`r`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $accepted = $origin.AcceptTcpClientAsync()
        Assert-That ($accepted.Wait(5000)) 'The UI-started proxy did not connect to the local test origin.'
        $upstream = $accepted.GetAwaiter().GetResult()
        $originStream = $upstream.GetStream()
        $originStream.ReadTimeout = 5000
        $request = [System.Text.StringBuilder]::new()
        while (-not $request.ToString().EndsWith("`r`n`r`n")) {
            $next = $originStream.ReadByte()
            Assert-That ($next -ge 0 -and $request.Length -lt 65536) 'The local origin received an incomplete or oversized request.'
            [void]$request.Append([char]$next)
        }
        $body = 'Juan UI forwarding probe'
        $reply = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body")
        $originStream.Write($reply, 0, $reply.Length)
        $upstream.Dispose()
        $upstream = $null
        $output = [System.IO.MemoryStream]::new()
        try {
            $buffer = [byte[]]::new(4096)
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $output.Write($buffer, 0, $read)
            }
            $response = [System.Text.Encoding]::UTF8.GetString($output.ToArray())
            Assert-That ($response.StartsWith('HTTP/1.1 200') -and $response.EndsWith($body)) 'The UI-started proxy did not forward the origin response intact.'
        } finally {
            $output.Dispose()
        }
    } finally {
        if ($null -ne $upstream) { $upstream.Dispose() }
        $client.Dispose()
        $origin.Stop()
    }
}

$before = Get-ProxySnapshot
$trustBefore = Get-RootTrustSnapshot
$profile = Join-Path ([System.IO.Path]::GetTempPath()) ("juan-ui-" + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($profile)
$start = [System.Diagnostics.ProcessStartInfo]::new()
$start.FileName = $Executable
$fixture = (Join-Path $PSScriptRoot '..\tests\fixtures\fiddler-reference.saz')
$start.Arguments = if ($Saz) { '"' + (Resolve-Path -LiteralPath $fixture).Path + '"' } else { '--demo' }
$start.UseShellExecute = $false
$start.WorkingDirectory = $profile
$start.EnvironmentVariables['LOCALAPPDATA'] = $profile
$process = $null
$window = [IntPtr]::Zero
try {
    $process = [System.Diagnostics.Process]::Start($start)
    Wait-Until {
        $process.Refresh()
        if ($process.HasExited) { throw "Juan exited during startup with code $($process.ExitCode)." }
        $process.MainWindowHandle -ne [IntPtr]::Zero
    } 'Juan did not create its native main window.'
    $window = $process.MainWindowHandle
    $list = [JuanUiSmoke]::GetDlgItem($window, 110)
    $search = [JuanUiSmoke]::GetDlgItem($window, 108)
    $response = [JuanUiSmoke]::GetDlgItem($window, 115)
    Assert-That ($list -ne [IntPtr]::Zero) 'The native session list was not created.'
    if ($Saz) {
        Wait-Until { (Get-RowCount $list) -eq 3 } 'The startup SAZ archive did not load its three synthetic sessions.'
        Assert-That ((Get-ControlText $response).Contains('Fiddler')) 'The imported JSON body did not appear in the inspector.'
        Assert-That ((Get-ControlText ([JuanUiSmoke]::GetDlgItem($window, 100))) -eq 'Start capture') 'Opening SAZ started the proxy.'
        foreach ($id in 104, 105) {
            Assert-That ([JuanUiSmoke]::Send([JuanUiSmoke]::GetDlgItem($window, $id), 240, [IntPtr]::Zero, [IntPtr]::Zero) -eq [IntPtr]::Zero) 'Opening SAZ enabled routing or decryption.'
        }
        $output = Join-Path $profile 'exported.saz'
        [void][JuanUiSmoke]::PostMessageW($window, 273, [IntPtr]::new(212), [IntPtr]::Zero)
        Choose-File $window 'Save visible sessions as SAZ' $output
        Wait-Until { Test-Path -LiteralPath $output } 'The native SAZ export did not create a file.'
        Wait-Until { [JuanUiSmoke]::IsWindowEnabled([JuanUiSmoke]::GetDlgItem($window, 103)) } 'The export completion was not acknowledged by the UI.'
        $cli = Join-Path (Split-Path -Parent $Executable) 'juan-cli.exe'
        $rows = @(& $cli inspect $output | ForEach-Object { $_ | ConvertFrom-Json })
        Assert-That ($LASTEXITCODE -eq 0 -and $rows.Count -eq 3) 'The GUI-exported SAZ could not be read back.'
        [void][JuanUiSmoke]::PostMessageW($window, 273, [IntPtr]::new(211), [IntPtr]::Zero)
        $warning = Wait-Modal $window 'Export sensitive full SAZ?'
        [void][JuanUiSmoke]::Send([JuanUiSmoke]::GetDlgItem($warning, 7), 245, [IntPtr]::Zero, [IntPtr]::Zero)
        Wait-Until { [JuanUiSmoke]::GetLastActivePopup($window) -eq $window } 'Cancelling sensitive SAZ export did not dismiss the warning.'
        [void][JuanUiSmoke]::PostMessageW($window, 273, [IntPtr]::new(210), [IntPtr]::Zero)
        $open = Wait-Modal $window 'Open Fiddler session archive'
        [void][JuanUiSmoke]::PostMessageW($open, 273, [IntPtr]::new(2), [IntPtr]::Zero)
        Wait-Until { [JuanUiSmoke]::GetLastActivePopup($window) -eq $window } 'Cancelling Open SAZ did not dismiss the dialog.'
        Assert-That ((Get-RowCount $list) -eq 3) 'Cancelling Open SAZ replaced the previous sessions.'
        Write-Output 'SAZ UI smoke passed: offline startup import, body inspector, native Save SAZ, read-back, sensitive export cancellation, and Open SAZ cancellation.'
        return
    }
    Wait-Until { (Get-RowCount $list) -eq 12 } 'The native session list did not load the twelve demo sessions.'
    Assert-That ((Get-ControlText $response).Contains('Access token expired')) 'The selected response did not appear in the JSON inspector.'
    $process.Refresh()
    $idleMiB = [math]::Round($process.WorkingSet64 / 1MB, 1)
    Assert-That ($process.WorkingSet64 -lt 128MB) 'Idle desktop working set exceeds the 128 MiB smoke-test budget.'

    if ($Screenshot) {
        $destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Screenshot)
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($destination))
        Start-Sleep -Milliseconds 400
        $bounds = [JuanUiSmoke+RECT]::new()
        Assert-That ([JuanUiSmoke]::GetWindowRect($window, [ref]$bounds)) 'Could not read the Juan window bounds.'
        $image = [System.Drawing.Bitmap]::new($bounds.Right - $bounds.Left, $bounds.Bottom - $bounds.Top)
        $graphics = [System.Drawing.Graphics]::FromImage($image)
        try {
            $dc = $graphics.GetHdc()
            try {
                Assert-That ([JuanUiSmoke]::PrintWindow($window, $dc, 2)) 'Could not render the Juan window screenshot.'
            } finally {
                $graphics.ReleaseHdc($dc)
            }
            $image.Save($destination, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally {
            $graphics.Dispose()
            $image.Dispose()
        }
    }

    $https = [JuanUiSmoke]::GetDlgItem($window, 105)
    $setup = Open-HttpsSetup $window
    Assert-That ([JuanUiSmoke]::Send($https, 240, [IntPtr]::Zero, [IntPtr]::Zero) -eq [IntPtr]::Zero) 'HTTPS was enabled before trust setup completed.'
    Select-CaptureOption $setup 2
    Wait-Until { [JuanUiSmoke]::GetLastActivePopup($window) -eq $window } 'Cancelling HTTPS setup did not close the prompt.'
    Assert-That ([JuanUiSmoke]::Send($https, 240, [IntPtr]::Zero, [IntPtr]::Zero) -eq [IntPtr]::Zero) 'Cancelling HTTPS setup left decryption enabled.'
    $setup = Open-HttpsSetup $window
    Assert-That ([JuanUiSmoke]::FindButton($setup, 'Use client-specific trust') -ne [IntPtr]::Zero) 'Client-specific trust is no longer available.'
    Select-CaptureOption $setup 1102
    Wait-Until { [JuanUiSmoke]::Send($https, 240, [IntPtr]::Zero, [IntPtr]::Zero) -eq [IntPtr]::new(1) } 'Explicit client-specific trust did not enable HTTPS.'
    Assert-That ((Get-RootTrustSnapshot) -ceq $trustBefore) 'Client-specific trust modified a Windows root store.'
    [void][JuanUiSmoke]::Send($https, 245, [IntPtr]::Zero, [IntPtr]::Zero)
    Assert-That ([JuanUiSmoke]::Send($https, 240, [IntPtr]::Zero, [IntPtr]::Zero) -eq [IntPtr]::Zero) 'HTTPS could not be turned off.'

    Set-ControlText $search 'status:4xx'
    Wait-Until { (Get-RowCount $list) -eq 1 } 'The 4xx filter did not select the expected session.'
    Set-ControlText $search 'method:POST type:json'
    Wait-Until { (Get-RowCount $list) -eq 2 } 'Combined method/content filters returned the wrong rows.'
    Set-ControlText $search 'status:700'
    Wait-Until { (Get-RowCount $list) -eq 0 } 'Invalid filters should not silently show unfiltered traffic.'
    Set-ControlText $search ''
    Wait-Until { (Get-RowCount $list) -eq 12 } 'Clearing the filter did not restore the session list.'

    $reservation = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $reservation.Start()
    $port = $reservation.LocalEndpoint.Port
    $reservation.Stop()
    Set-ControlText ([JuanUiSmoke]::GetDlgItem($window, 106)) "$port"
    $setup = Open-CaptureSetup $window
    Assert-That (-not (Test-Listening $port)) 'Capture started before a routing choice was made.'
    Assert-That ([JuanUiSmoke]::FindButton($setup, 'Capture Windows traffic') -ne [IntPtr]::Zero) 'The Windows capture choice is missing.'
    Select-CaptureOption $setup 2
    Wait-Until { ([JuanUiSmoke]::GetLastActivePopup($window)) -eq $window } 'Cancelling capture setup did not dismiss the dialog.'
    Assert-That (-not (Test-Listening $port)) 'Cancelling capture setup left a listener running.'
    Assert-That ((Get-RowCount $list) -eq 12) 'Cancelling capture setup cleared the existing sessions.'
    $setup = Open-CaptureSetup $window
    Select-CaptureOption $setup 1002
    Wait-Until { Test-Listening $port } 'The Start capture button did not start the listener.'
    foreach ($id in 104, 105) {
        $checked = [JuanUiSmoke]::Send([JuanUiSmoke]::GetDlgItem($window, $id), 240, [IntPtr]::Zero, [IntPtr]::Zero)
        Assert-That ($checked -eq [IntPtr]::Zero) 'Starting capture unexpectedly enabled Windows proxy or HTTPS decryption.'
    }
    Invoke-LocalProxyProbe $port
    Wait-Until { (Get-RowCount $list) -eq 1 } 'The UI-started proxy did not log the request.'
    Invoke-CommandId $window 100
    Assert-That ((Get-ControlText ([JuanUiSmoke]::GetDlgItem($window, 100))) -eq 'Resume capture') 'Pause did not update the native capture control.'
    Invoke-LocalProxyProbe $port
    Start-Sleep -Milliseconds 350
    Assert-That ((Get-RowCount $list) -eq 1) 'Paused recording unexpectedly added a session.'
    Invoke-CommandId $window 100
    Invoke-LocalProxyProbe $port
    Wait-Until { (Get-RowCount $list) -eq 2 } 'Resume did not resume session recording.'
    Invoke-CommandId $window 101
    Wait-Until { -not (Test-Listening $port) } 'Stop did not release the proxy listener.'
    Write-Output "Native UI smoke passed: rendering, inspectors, filters, HTTPS trust prompt/cancel/client-specific choice, routing choice, manual capture, pause/resume/stop. Idle working set: $idleMiB MiB."
} catch {
    Write-Error $_ -ErrorAction Continue
    throw
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        if ($window -ne [IntPtr]::Zero) {
            $popup = [JuanUiSmoke]::GetLastActivePopup($window)
            if ($popup -ne $window -and $popup -ne [IntPtr]::Zero) {
                if ([JuanUiSmoke]::FindButton($popup, 'Manual proxy') -ne [IntPtr]::Zero -or
                    [JuanUiSmoke]::FindButton($popup, 'Use client-specific trust') -ne [IntPtr]::Zero) {
                    Select-CaptureOption $popup 2
                } else {
                    $no = [JuanUiSmoke]::GetDlgItem($popup, 7)
                    if ($no -ne [IntPtr]::Zero) {
                        [void][JuanUiSmoke]::Send($no, 245, [IntPtr]::Zero, [IntPtr]::Zero)
                    } else {
                        [void][JuanUiSmoke]::PostMessageW($popup, 273, [IntPtr]::new(2), [IntPtr]::Zero)
                    }
                }
            }
            [void][JuanUiSmoke]::PostMessageW($window, 16, [IntPtr]::Zero, [IntPtr]::Zero)
        }
        if (-not $process.WaitForExit(5000)) {
            Stop-Process -Id $process.Id -Force
            Write-Warning 'The smoke-test-owned process did not close normally and was terminated.'
        }
    }
    if ($null -ne $process) { $process.Dispose() }
    $ca = Join-Path $profile 'Juan\root-ca.dpapi'
    if (Test-Path -LiteralPath $ca) { Remove-Item -LiteralPath $ca }
    $dataDirectory = Join-Path $profile 'Juan'
    if (Test-Path -LiteralPath $dataDirectory) { Remove-Item -LiteralPath $dataDirectory }
    foreach ($name in 'exported.saz') {
        $artifact = Join-Path $profile $name
        if (Test-Path -LiteralPath $artifact) { Remove-Item -LiteralPath $artifact }
    }
    $shellCache = Join-Path $profile 'Microsoft\Windows\Caches'
    if (Test-Path -LiteralPath $shellCache) { Remove-Item -LiteralPath $shellCache -Recurse -Force }
    foreach ($relative in 'Microsoft\Windows', 'Microsoft') {
        $directory = Join-Path $profile $relative
        if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory }
    }
    Remove-Item -LiteralPath $profile
    Assert-That ((Get-ProxySnapshot) -ceq $before) 'Windows proxy settings changed during the smoke test.'
    Assert-That ((Get-RootTrustSnapshot) -ceq $trustBefore) 'Windows certificate trust changed during the smoke test.'
}
