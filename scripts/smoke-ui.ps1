param(
    [string]$Executable = (Join-Path $PSScriptRoot '..\target\release\juan.exe'),
    [string]$Screenshot,
    [switch]$Saz,
    [switch]$Har,
    [switch]$HarBom,
    [switch]$Troubleshooting,
    [switch]$RecentFiles
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
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr window);
    public static string Describe(IntPtr window) {
        var result = new StringBuilder();
        var text = new StringBuilder(2048);
        var cls = new StringBuilder(128);
        GetWindowTextW(window, text, text.Capacity);
        GetClassNameW(window, cls, cls.Capacity);
        result.AppendLine("Window " + window + " class=" + cls + " text=" + text);
        EnumChildWindows(window, (child, _) => {
            text.Clear(); cls.Clear();
            GetWindowTextW(child, text, text.Capacity);
            GetClassNameW(child, cls, cls.Capacity);
            result.AppendLine("Child " + child + " id=" + GetDlgCtrlID(child) + " class=" + cls + " visible=" + IsWindowVisible(child) + " text=" + text);
            return true;
        }, IntPtr.Zero);
        return result.ToString();
    }
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
    [DllImport("user32.dll")]
    public static extern IntPtr GetMenu(IntPtr window);
    [DllImport("user32.dll")]
    public static extern IntPtr GetSubMenu(IntPtr menu, int position);
    [DllImport("user32.dll")]
    public static extern int GetMenuItemCount(IntPtr menu);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern int GetMenuStringW(IntPtr menu, uint item, StringBuilder text, int count, uint flags);
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

function Assert-RenderedErrorText([IntPtr]$List, [string]$Name, [string]$Directory) {
    $bounds = [JuanUiSmoke+RECT]::new()
    Assert-That ([JuanUiSmoke]::GetWindowRect($List, [ref]$bounds)) 'Cannot measure synthetic list.'
    $image = [System.Drawing.Bitmap]::new($bounds.Right - $bounds.Left, $bounds.Bottom - $bounds.Top)
    $graphics = [System.Drawing.Graphics]::FromImage($image)
    try {
        $dc = $graphics.GetHdc()
        try { Assert-That ([JuanUiSmoke]::PrintWindow($List, $dc, 0)) 'Cannot render native error list.' }
        finally { $graphics.ReleaseHdc($dc) }
        $image.Save((Join-Path $Directory "$Name.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        $left = 2
        # Check real glyph pixels in ID, numeric status (excluding icon), method,
        # protocol and host. Pale backgrounds and the error icon cannot pass.
        for ($column = 0; $column -lt 5; $column++) {
            $width = [JuanUiSmoke]::Send($List, 4125, [IntPtr]::new($column), [IntPtr]::Zero).ToInt32()
            $right = [Math]::Min($left + $width - 3, $image.Width - 3)
            if ($column -eq 1) { $right -= [Math]::Ceiling($width * 0.35) }
            $red = 0
            for ($x = $left + 2; $x -lt $right; $x++) {
                for ($y = 2; $y -lt $image.Height - 2; $y++) {
                    $pixel = $image.GetPixel($x, $y)
                    if ($pixel.R -ge 140 -and $pixel.G -lt 110 -and $pixel.B -lt 110) { $red++ }
                }
            }
            Assert-That ($red -ge 5) "$Name column $column has no red foreground glyphs; see native screenshot."
            $left += $width
        }
    } finally {
        $graphics.Dispose()
        $image.Dispose()
    }
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

function Click-ModalButton([IntPtr]$Window, [IntPtr]$Dialog, [int]$Id) {
    $initial = [JuanUiSmoke]::GetDlgItem($Dialog, $Id)
    Write-Output "Modal readiness: title='$(Get-ControlText $Dialog)' button=$Id exists=$($initial -ne [IntPtr]::Zero) visible=$([JuanUiSmoke]::IsWindowVisible($initial)) enabled=$([JuanUiSmoke]::IsWindowEnabled($initial))"
    Write-Output ([JuanUiSmoke]::Describe($Dialog))
    Wait-Until {
        $button = [JuanUiSmoke]::GetDlgItem($Dialog, $Id)
        if ($button -eq [IntPtr]::Zero -and $Id -eq 1) {
            $button = [JuanUiSmoke]::FindButton($Dialog, 'OK')
        }
        $button -ne [IntPtr]::Zero -and [JuanUiSmoke]::IsWindowVisible($button) -and
            [JuanUiSmoke]::IsWindowEnabled($button) -and -not [JuanUiSmoke]::IsWindowEnabled($Window)
    } "Dialog button $Id did not become ready."
    $button = [JuanUiSmoke]::GetDlgItem($Dialog, $Id)
    if ($button -eq [IntPtr]::Zero -and $Id -eq 1) {
        $button = [JuanUiSmoke]::FindButton($Dialog, 'OK')
    }
    Write-Output "Clicking actual dialog button id=$([JuanUiSmoke]::GetDlgCtrlID($button)) caption='$(Get-ControlText $button)'"
    [void][JuanUiSmoke]::Send($button, 245, [IntPtr]::Zero, [IntPtr]::Zero)
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
    Wait-Until {
        if (-not [JuanUiSmoke]::IsWindowVisible($filename) -or -not [JuanUiSmoke]::IsWindowEnabled($filename)) { return $false }
        Set-ControlText $filename $Path
        Start-Sleep -Milliseconds 100
        (Get-ControlText $filename) -eq $Path
    } 'The file picker did not accept the explicit test output path.'
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
$profile = Join-Path (Join-Path $PSScriptRoot '..\target') ("juan-ui-" + [guid]::NewGuid().ToString('N'))
$profile = [System.IO.Path]::GetFullPath($profile)
[void][System.IO.Directory]::CreateDirectory($profile)
$start = [System.Diagnostics.ProcessStartInfo]::new()
$start.FileName = $Executable
$fixture = (Join-Path $PSScriptRoot '..\tests\fixtures\fiddler-reference.saz')
if ($HarBom) { $Har = $true }
if ($Har) { $fixture = Join-Path $PSScriptRoot '..\tests\fixtures\har\chrome.har' }
if ($HarBom) { $fixture = Join-Path $PSScriptRoot '..\tests\fixtures\har\utf8-bom.har' }
if ($Troubleshooting) { $fixture = Join-Path $PSScriptRoot '..\tests\fixtures\har\troubleshooting.har' }
if ($RecentFiles) {
    $recentFixtures = @()
    foreach ($i in 0..6) {
        $directory = Join-Path $profile "synthetic-$i"
        [void][System.IO.Directory]::CreateDirectory($directory)
        $destination = Join-Path $directory 'capture.har'
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\tests\fixtures\har\chrome.har') -Destination $destination
        $recentFixtures += $destination
    }
    $sazFixture = Join-Path $profile 'capture.saz'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\tests\fixtures\fiddler-reference.saz') -Destination $sazFixture
    $fixture = $recentFixtures[0]
}
$start.Arguments = if ($Saz -or $Har -or $Troubleshooting -or $RecentFiles) { '"' + (Resolve-Path -LiteralPath $fixture).Path + '"' } else { '--demo' }
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
    if ($RecentFiles) {
        $historyFile = Join-Path $profile 'Juan\recent-files.json'
        Wait-Until { (Test-Path -LiteralPath $historyFile) -and (Get-RowCount $list) -eq 1 } 'Startup HAR was not recorded after successful import.'
        foreach ($path in @($recentFixtures[1..6]) + @($sazFixture)) {
            [void][JuanUiSmoke]::PostMessageW($window,273,[IntPtr]::new(210),[IntPtr]::Zero)
            Choose-File $window 'Open HAR or SAZ archive' $path
            $confirm = Wait-Modal $window 'Replace retained sessions?'
            Click-ModalButton $window $confirm 6
            Wait-Until {
                $saved = @(Get-Content -LiteralPath $historyFile -Raw | ConvertFrom-Json)
                $saved.Count -gt 0 -and $saved[0].EndsWith($path, [StringComparison]::OrdinalIgnoreCase)
            } 'Successful archive import was not persisted newest-first.'
        }
        $saved = @(Get-Content -LiteralPath $historyFile -Raw | ConvertFrom-Json)
        Assert-That ($saved.Count -eq 5) 'Recent files did not enforce the five-entry cap.'
        Assert-That ($saved[0].EndsWith('capture.saz')) 'SAZ was not recorded newest-first.'
        $recentMenu = [JuanUiSmoke]::GetSubMenu([JuanUiSmoke]::GetSubMenu([JuanUiSmoke]::GetMenu($window),0),1)
        Assert-That ([JuanUiSmoke]::GetMenuItemCount($recentMenu) -eq 7) 'Recent submenu should contain five paths, separator, and Clear history.'
        $labels = @()
        foreach ($i in 0..4) {
            $label = [System.Text.StringBuilder]::new(32768)
            [void][JuanUiSmoke]::GetMenuStringW($recentMenu,[uint32]$i,$label,$label.Capacity,1024)
            $labels += $label.ToString()
        }
        Assert-That (($labels | Select-Object -Unique).Count -eq 5 -and $labels[1].Contains('synthetic-6')) 'Identical archive filenames were not disambiguated.'
        # Close only the smoke-owned process, then reopen with the same isolated profile.
        [void][JuanUiSmoke]::PostMessageW($window,16,[IntPtr]::Zero,[IntPtr]::Zero)
        Assert-That ($process.WaitForExit(10000)) 'Synthetic instance did not close for persistence check.'
        $process.Dispose()
        $start.Arguments = ''
        $process = [System.Diagnostics.Process]::Start($start)
        Wait-Until { $process.Refresh(); $process.MainWindowHandle -ne [IntPtr]::Zero } 'Could not restart isolated recent-file smoke.'
        $window = $process.MainWindowHandle
        $list = [JuanUiSmoke]::GetDlgItem($window,110)
        Invoke-CommandId $window 230
        Wait-Until { (Get-RowCount $list) -eq 3 } 'Persisted SAZ did not reopen through the regular importer.'
        Assert-That (@(Get-Content -LiteralPath $historyFile -Raw | ConvertFrom-Json).Count -eq 5) 'Reopening duplicated the recent path.'
        Remove-Item -LiteralPath $sazFixture
        [void][JuanUiSmoke]::PostMessageW($window,273,[IntPtr]::new(230),[IntPtr]::Zero)
        $errorDialog = Wait-Modal $window 'Juan'
        Click-ModalButton $window $errorDialog 1
        Assert-That ((Get-RowCount $list) -eq 3) 'Missing recent file replaced retained sessions.'
        $savedJson = Get-Content -LiteralPath $historyFile -Raw
        Remove-Item -LiteralPath $historyFile
        [void][System.IO.Directory]::CreateDirectory($historyFile)
        [void][JuanUiSmoke]::PostMessageW($window,273,[IntPtr]::new(235),[IntPtr]::Zero)
        $errorDialog = Wait-Modal $window 'Juan'
        Click-ModalButton $window $errorDialog 1
        Assert-That ((Get-RowCount $list) -eq 3) 'Failed history write changed retained sessions.'
        Remove-Item -LiteralPath $historyFile
        [System.IO.File]::WriteAllText($historyFile,$savedJson)
        Invoke-CommandId $window 235
        Wait-Until { @(Get-Content -LiteralPath $historyFile -Raw | ConvertFrom-Json).Count -eq 0 } 'Clear history was not persisted.'
        Assert-That ((Get-RowCount $list) -eq 3) 'Clear history cleared captured sessions.'
        Assert-That ((Get-ControlText ([JuanUiSmoke]::GetDlgItem($window,100))) -eq 'Start capture') 'Recent-file actions started capture.'
        Write-Output 'Recent-files UI smoke passed: successful HAR/SAZ imports, five-entry cap, local disambiguated paths, restart/reopen, deduplication, missing-file preservation, visible write failure, persistent clear.'
        return
    }
    if ($Troubleshooting) {
        Wait-Until { (Get-RowCount $list) -eq 10 } 'Default asset hiding did not leave ten synthetic rows.'
        $hide = [JuanUiSmoke]::GetDlgItem($window, 213)
        $restore = [JuanUiSmoke]::GetDlgItem($window, 214)
        $review = [JuanUiSmoke]::GetDlgItem($window, 215)
        $url = [JuanUiSmoke]::GetDlgItem($window, 117)
        $query = [JuanUiSmoke]::GetDlgItem($window, 217)
        $findInfo = [JuanUiSmoke]::GetDlgItem($window, 222)
        Assert-That ($restore -eq [IntPtr]::Zero) 'Redundant Restore assets control still exists.'
        Assert-That ([JuanUiSmoke]::Send($hide, 240, [IntPtr]::Zero, [IntPtr]::Zero) -eq [IntPtr]::new(1)) 'Hide assets was not checked by default.'
        Assert-That ((Get-ControlText $hide) -eq 'Hide assets (3 hidden)') 'Default hidden count is incorrect.'
        [void][JuanUiSmoke]::Send($hide, 245, [IntPtr]::Zero, [IntPtr]::Zero)
        Wait-Until { (Get-RowCount $list) -eq 13 } 'Unchecking Hide assets did not restore all synthetic rows.'
        Assert-That ((Get-ControlText $hide) -eq 'Hide assets (0 hidden)') 'Unchecked count is incorrect.'
        [void][JuanUiSmoke]::Send($hide, 245, [IntPtr]::Zero, [IntPtr]::Zero)
        Wait-Until { (Get-RowCount $list) -eq 10 } 'Asset toggle did not hide exactly CSS/JS/image successes.'
        Assert-That ((Get-ControlText $hide).Contains('3 hidden')) 'Hidden count is incorrect.'
        $renderDirectory = Join-Path (Split-Path -Parent $Executable) 'synthetic-error-render'
        [void][System.IO.Directory]::CreateDirectory($renderDirectory)
        foreach ($probe in @(@('status:400','http400'), @('status:500','http500'), @('transport','transport'))) {
            Set-ControlText $search $probe[0]
            Wait-Until { (Get-RowCount $list) -eq 1 } 'Synthetic error probe did not isolate one row.'
            Assert-RenderedErrorText $list $probe[1] $renderDirectory
        }
        Set-ControlText $search ''
        Wait-Until { (Get-RowCount $list) -eq 10 } 'Could not restore synthetic rows after rendering checks.'
        Assert-That ((Get-ControlText $review).Contains('6 visible')) 'Review counts should include errors only, not missing bodies.'
        $scopeControl = [JuanUiSmoke]::GetDlgItem($window,109)
        [void][JuanUiSmoke]::Send($scopeControl,334,[IntPtr]::new(4),[IntPtr]::Zero)
        [void][JuanUiSmoke]::Send($window,273,[IntPtr]::new(65645),$scopeControl)
        Wait-Until { (Get-RowCount $list) -eq 6 } 'JSON scope did not combine with asset hiding.'
        Assert-That ((Get-ControlText $review).Contains('4 visible')) 'Review count ignored JSON scope.'
        [void][JuanUiSmoke]::Send($scopeControl,334,[IntPtr]::Zero,[IntPtr]::Zero)
        [void][JuanUiSmoke]::Send($window,273,[IntPtr]::new(65645),$scopeControl)
        Wait-Until { (Get-RowCount $list) -eq 10 } 'All scope failed to restore non-assets.'
        Invoke-CommandId $window 215
        Wait-Until { (Get-ControlText $url).EndsWith('/transport') } 'Review did not prioritize recorded transport evidence.'
        Invoke-CommandId $window 215
        Wait-Until { (Get-ControlText $url).EndsWith('/server') } 'Review did not navigate next to 5xx.'
        Assert-That ((Get-RowCount $list) -eq 10) 'Review navigation changed visibility.'
        Set-ControlText $search 'status:400'
        Wait-Until { (Get-RowCount $list) -eq 1 } 'HTTP 400 asset failure was incorrectly hidden.'
        Invoke-CommandId $window 215
        Wait-Until { (Get-ControlText $url).EndsWith('/bad-request.css') } 'Review skipped HTTP 400.'
        $mainTabs = [JuanUiSmoke]::GetDlgItem($window,111)
        [void][JuanUiSmoke]::Send($window,40,$mainTabs,[IntPtr]::new(1))
        [void][JuanUiSmoke]::PostMessageW($mainTabs,256,[IntPtr]::new(39),[IntPtr]::Zero)
        Wait-Until { (Get-ControlText ([JuanUiSmoke]::GetDlgItem($window,116))).Contains('400 Bad Request') } 'HTTP 400 detail explanation is missing.'
        [void][JuanUiSmoke]::PostMessageW($mainTabs,256,[IntPtr]::new(37),[IntPtr]::Zero)
        Wait-Until { [JuanUiSmoke]::Send($mainTabs,4875,[IntPtr]::Zero,[IntPtr]::Zero) -eq [IntPtr]::Zero } 'Could not restore inspectors tab.'
        Set-ControlText $search 'status:403'
        Wait-Until { (Get-RowCount $list) -eq 1 } 'Filter did not combine with hide assets.'
        Assert-That ((Get-ControlText $review).Contains('1 visible')) 'Review did not disclose visible-scope count.'
        Invoke-CommandId $window 215
        Wait-Until { (Get-ControlText $url).EndsWith('/access') } 'Review failed within the current filter.'
        [void][JuanUiSmoke]::Send($hide, 245, [IntPtr]::Zero, [IntPtr]::Zero)
        Assert-That ((Get-RowCount $list) -eq 1) 'Unchecking Hide assets silently cleared other filters.'
        [void][JuanUiSmoke]::Send($hide, 245, [IntPtr]::Zero, [IntPtr]::Zero)
        Set-ControlText $search 'api.js'
        Wait-Until { (Get-RowCount $list) -eq 1 } 'JSON API ending in .js was hidden.'
        # Select the only row with the native keyboard path, preserving the owning UI thread's focus.
        [void][JuanUiSmoke]::Send($window, 40, $list, [IntPtr]::new(1))
        [void][JuanUiSmoke]::PostMessageW($list, 256, [IntPtr]::new(36), [IntPtr]::Zero)
        Wait-Until { (Get-ControlText $response).Contains('Écho') } 'Could not select Unicode response.'
        [void][JuanUiSmoke]::Send($window, 40, $response, [IntPtr]::new(1))
        Invoke-CommandId $window 216
        Set-ControlText $query 'écho'
        Wait-Until { (Get-ControlText $findInfo).Contains('1 / 2') } 'Case-insensitive find did not match both Unicode occurrences.'
        $display = Get-ControlText $response
        $expected = $display.IndexOf('Écho', [StringComparison]::Ordinal)
        $selection = [JuanUiSmoke]::Send($response, 176, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
        Assert-That (($selection -band 65535) -eq $expected) 'Native UTF-16 selection offset is incorrect after emoji.'
        [void][JuanUiSmoke]::PostMessageW($query, 256, [IntPtr]::new(114), [IntPtr]::Zero)
        Wait-Until { (Get-ControlText $findInfo).Contains('2 / 2') } 'F3 did not find the next occurrence.'
        Invoke-CommandId $window 219
        Wait-Until { (Get-ControlText $findInfo).Contains('wrapped') } 'Find did not report wrapping.'
        $previous = [JuanUiSmoke]::GetDlgItem($window,220)
        [void][JuanUiSmoke]::Send($window,40,$previous,[IntPtr]::new(1))
        [void][JuanUiSmoke]::PostMessageW($previous,256,[IntPtr]::new(13),[IntPtr]::Zero)
        Wait-Until { (Get-ControlText $findInfo).Contains('2 / 2 (wrapped)') } 'Enter on Previous did not search backward and wrap.'
        $next = [JuanUiSmoke]::GetDlgItem($window,219)
        [void][JuanUiSmoke]::Send($window,40,$next,[IntPtr]::new(1))
        [void][JuanUiSmoke]::PostMessageW($next,256,[IntPtr]::new(13),[IntPtr]::Zero)
        Wait-Until { (Get-ControlText $findInfo).Contains('1 / 2 (wrapped)') } 'Enter on Next did not search forward.'
        [void][JuanUiSmoke]::Send($window,40,$query,[IntPtr]::new(1))
        [void][JuanUiSmoke]::Send([JuanUiSmoke]::GetDlgItem($window, 218), 245, [IntPtr]::Zero, [IntPtr]::Zero)
        Wait-Until { (Get-ControlText $findInfo).Contains('Not found') } 'Match-case setting was not applied.'
        Set-ControlText $query 'Écho'
        Wait-Until { (Get-ControlText $findInfo).Contains('1 / 1') } 'Case-sensitive Unicode find failed.'
        [void][JuanUiSmoke]::PostMessageW($query, 256, [IntPtr]::new(13), [IntPtr]::Zero)
        Wait-Until { (Get-ControlText $findInfo).Contains('wrapped') } 'Enter did not find next.'
        $request = [JuanUiSmoke]::GetDlgItem($window,114)
        [void][JuanUiSmoke]::Send($window,40,$request,[IntPtr]::new(1))
        Wait-Until { (Get-ControlText $findInfo).StartsWith('Request preview selected') } 'Find did not follow request focus.'
        Assert-That ([JuanUiSmoke]::Send($response,176,[IntPtr]::Zero,[IntPtr]::Zero) -eq [IntPtr]::Zero) 'Changing panes retained a stale response highlight.'
        Set-ControlText $query 'HeaderNeedle'
        Wait-Until { (Get-ControlText $findInfo).StartsWith('Request: 1 / 1') } 'Find did not search displayed request headers.'
        $responseTabs = [JuanUiSmoke]::GetDlgItem($window,113)
        [void][JuanUiSmoke]::Send($window,40,$responseTabs,[IntPtr]::new(1))
        [void][JuanUiSmoke]::PostMessageW($responseTabs,256,[IntPtr]::new(37),[IntPtr]::Zero)
        Wait-Until { [JuanUiSmoke]::Send($responseTabs,4875,[IntPtr]::Zero,[IntPtr]::Zero).ToInt32() -eq 1 } 'Could not switch response JSON to Text.'
        Set-ControlText $query 'Écho'
        Wait-Until { (Get-ControlText $findInfo).StartsWith('Response: 1 / 1') } 'Find did not follow the displayed response Text pane.'
        [void][JuanUiSmoke]::PostMessageW($query, 256, [IntPtr]::new(27), [IntPtr]::Zero)
        Wait-Until { -not [JuanUiSmoke]::IsWindowVisible($query) } 'Escape did not close message find.'
        Invoke-CommandId $window 216
        $closeFind = [JuanUiSmoke]::GetDlgItem($window,221)
        [void][JuanUiSmoke]::Send($window,40,$closeFind,[IntPtr]::new(1))
        [void][JuanUiSmoke]::PostMessageW($closeFind,256,[IntPtr]::new(13),[IntPtr]::Zero)
        Wait-Until { -not [JuanUiSmoke]::IsWindowVisible($query) } 'Enter on Close searched instead of closing Find.'
        Invoke-CommandId $window 216
        Set-ControlText $search 'status:599'
        Wait-Until { (Get-RowCount $list) -eq 0 } 'Could not clear selection through filtering.'
        Invoke-CommandId $window 219
        Assert-That ((Get-ControlText $findInfo).Contains('Select a session')) 'Find did not handle a filtered-away selection safely.'
        Set-ControlText $search ''
        Wait-Until { (Get-RowCount $list) -eq 10 } 'Clearing the filter changed the asset checkbox.'
        [void][JuanUiSmoke]::Send($hide, 245, [IntPtr]::Zero, [IntPtr]::Zero)
        Wait-Until { (Get-RowCount $list) -eq 13 } 'Unchecking Hide assets did not preserve all original sessions.'
        Assert-That ((Get-ControlText ([JuanUiSmoke]::GetDlgItem($window,100))) -eq 'Start capture') 'Troubleshooting started capture.'
        Write-Output 'Troubleshooting UI smoke passed: default assets checkbox/count, no Restore button, visible-scope review/navigation, Unicode message find/case/next/previous/wrap/Enter/Escape, filter switching, no capture.'
        return
    }
    if ($Har) {
        Wait-Until { (Get-RowCount $list) -eq 1 } 'The startup HAR did not load.'
        Assert-That ((Get-ControlText $response).Contains('Not valid, complete JSON')) 'The plain-text HAR body did not reach the JSON inspector without double decompression.'
        Assert-That ((Get-ControlText $response).Contains('HAR SOURCE')) 'HAR provenance is missing.'
        Assert-That ((Get-ControlText ([JuanUiSmoke]::GetDlgItem($window, 100))) -eq 'Start capture') 'HAR import started capture.'
        foreach ($id in 104, 105) {
            Assert-That ([JuanUiSmoke]::Send([JuanUiSmoke]::GetDlgItem($window, $id), 240, [IntPtr]::Zero, [IntPtr]::Zero) -eq [IntPtr]::Zero) 'HAR import enabled routing or decryption.'
        }
        Set-ControlText $search 'type:text'
        Wait-Until { (Get-RowCount $list) -eq 1 } 'HAR MIME fallback filtering failed.'
        Set-ControlText $search ''
        $output = Join-Path $profile 'exported.har'
        [void][JuanUiSmoke]::PostMessageW($window, 273, [IntPtr]::new(103), [IntPtr]::Zero)
        Choose-File $window 'Save visible sessions as HAR' $output
        Wait-Until { Test-Path -LiteralPath $output } 'HAR export did not create a file.'
        Wait-Until { [JuanUiSmoke]::IsWindowEnabled([JuanUiSmoke]::GetDlgItem($window, 103)) } 'HAR export did not finish.'
        $cli = Join-Path (Split-Path -Parent $Executable) 'juan-cli.exe'
        $rows = @(& $cli inspect $output | ForEach-Object { $_ | ConvertFrom-Json })
        Assert-That ($LASTEXITCODE -eq 0 -and $rows.Count -eq 1) 'GUI-exported HAR failed read-back.'
        Assert-That (-not ([System.IO.File]::ReadAllText($output).Contains('private-body'))) 'Sanitized HAR leaked a form value.'
        [void][JuanUiSmoke]::PostMessageW($window, 273, [IntPtr]::new(210), [IntPtr]::Zero)
        $open = Wait-Modal $window 'Open HAR or SAZ archive'
        [void][JuanUiSmoke]::PostMessageW($open, 273, [IntPtr]::new(2), [IntPtr]::Zero)
        Wait-Until { [JuanUiSmoke]::GetLastActivePopup($window) -eq $window } 'Cancel open failed.'
        Wait-Until { [JuanUiSmoke]::IsWindowEnabled($window) } 'File picker did not re-enable its owner.'
        # Owner reactivation precedes return from the native file picker and command busy guard.
        Start-Sleep -Milliseconds 250
        Assert-That ((Get-RowCount $list) -eq 1) 'Cancelled open replaced existing HAR.'
        [void][JuanUiSmoke]::PostMessageW($window, 273, [IntPtr]::new(212), [IntPtr]::Zero)
        $errorDialog = Wait-Modal $window 'Juan'
        Click-ModalButton $window $errorDialog 1
        Wait-Until { [JuanUiSmoke]::GetLastActivePopup($window) -eq $window } 'SAZ refusal did not dismiss.'
        Assert-That ((Get-RowCount $list) -eq 1) 'SAZ refusal changed the capture.'
        $invalid = Join-Path $profile 'invalid.har'
        [System.IO.File]::WriteAllText($invalid, '{invalid')
        [void][JuanUiSmoke]::PostMessageW($window, 273, [IntPtr]::new(210), [IntPtr]::Zero)
        Choose-File $window 'Open HAR or SAZ archive' $invalid
        $confirm = Wait-Modal $window 'Replace retained sessions?'
        Click-ModalButton $window $confirm 6
        $errorDialog = Wait-Modal $window 'Juan'
        Click-ModalButton $window $errorDialog 1
        Wait-Until { [JuanUiSmoke]::GetLastActivePopup($window) -eq $window } 'Invalid HAR error did not dismiss.'
        Assert-That ((Get-RowCount $list) -eq 1) 'Failed import replaced the previous capture.'
        $process.Refresh()
        Write-Output "HAR UI smoke passed: startup, decoded inspector, provenance, MIME filter, sanitized export/read-back, Open cancellation, SAZ refusal, failed import preservation. Working set: $([math]::Round($process.WorkingSet64 / 1MB, 1)) MiB."
        return
    }
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
        $open = Wait-Modal $window 'Open HAR or SAZ archive'
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
    if (Test-Path -LiteralPath $dataDirectory) { Remove-Item -LiteralPath $dataDirectory -Recurse -Force }
    foreach ($name in 'exported.saz', 'exported.har', 'invalid.har') {
        $artifact = Join-Path $profile $name
        if (Test-Path -LiteralPath $artifact) { Remove-Item -LiteralPath $artifact }
    }
    $shellCache = Join-Path $profile 'Microsoft\Windows\Caches'
    if (Test-Path -LiteralPath $shellCache) { Remove-Item -LiteralPath $shellCache -Recurse -Force }
    foreach ($relative in 'Microsoft\Windows', 'Microsoft') {
        $directory = Join-Path $profile $relative
        if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory }
    }
    Remove-Item -LiteralPath $profile -Recurse -Force
    Assert-That ((Get-ProxySnapshot) -ceq $before) 'Windows proxy settings changed during the smoke test.'
    Assert-That ((Get-RootTrustSnapshot) -ceq $trustBefore) 'Windows certificate trust changed during the smoke test.'
}
