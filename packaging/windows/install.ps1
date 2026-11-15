#Requires -Version 5.1
<#
.SYNOPSIS
Installs ZeroPass for every user of this computer (ADR-0008).

.DESCRIPTION
Copies the ZeroPass programs from this directory to Program Files, where only
administrators can change them. The vault daemon trusts the programs that
connect to it by where they are installed, so that place must not be writable
by the user (docs/adr/0008-windows-installation.md).

Also adds the desktop application to the Start menu and the directory to the
PATH, starts ZeroPass at logon for every user
(it does nothing for a user without a vault), lets the sync daemon accept
connections from the local subnet (Windows Firewall, any kind of network),
and registers the uninstaller in "Installed apps". Asks Windows for
administrator rights if it does not have them. A running ZeroPass from an earlier installation is ended
first: its vaults lock, as they would on a restart.

Vaults are never touched: they stay in each user's
%LOCALAPPDATA%\ZeroPass\Vault (or wherever they were created).

.PARAMETER Destination
Where to install. Default: %ProgramFiles%\ZeroPass. It should stay a directory
that only administrators can write to.

.PARAMETER RequireSignature
Refuse to install programs that do not carry a valid Authenticode signature,
all by the same certificate.

.PARAMETER NoAutostart
Do not start ZeroPass at logon.
#>
[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $env:ProgramFiles 'ZeroPass'),
    [switch]$RequireSignature,
    [switch]$NoAutostart,
    # Set when this script started itself with administrator rights: keeps
    # the new window open so that its output can be read.
    [switch]$PauseAtEnd
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath),
        '-Destination', ('"{0}"' -f $Destination), '-PauseAtEnd')
    if ($RequireSignature) { $arguments += '-RequireSignature' }
    if ($NoAutostart) { $arguments += '-NoAutostart' }
    $elevated = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    exit $elevated.ExitCode
}

trap {
    Write-Host "error: $_" -ForegroundColor Red
    if ($PauseAtEnd) { Read-Host 'Press Enter to close this window' | Out-Null }
    exit 1
}

$Programs = @('zeropass.exe', 'zp-cli.exe', 'zp-vaultd.exe', 'zp-syncd.exe', 'zp-keyagent.exe', 'zp-autostart.exe', 'zp-nmh.exe')
$Documents = @('uninstall.ps1', 'LICENSE', 'README.txt', 'VERSION')
$RunKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZeroPass'
$EnvironmentKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$FirewallGroup = 'ZeroPass'
# The Start menu entry of the desktop application, for every user.
$Shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\ZeroPass.lnk'
# The browser extension's bridge (docs/spec/extension.md §2, §3): its name,
# and the extensions it serves. Keep in step with bins/zp-nmh/src/main.rs.
$NativeHost = 'io.github.makomo_oss.zeropass'
$ChromeExtensions = @('gehobienihkbhglhnibeobdkgeinamdn')
$FirefoxExtensions = @('zeropass@makomo-oss.github.io')
$NativeHostKeys = @{
    'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts' = 'zp-nmh-chrome.json'
    'HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts' = 'zp-nmh-chrome.json'
    'HKLM:\SOFTWARE\Chromium\NativeMessagingHosts' = 'zp-nmh-chrome.json'
    'HKLM:\SOFTWARE\Mozilla\NativeMessagingHosts' = 'zp-nmh-firefox.json'
}

# Removes ZeroPass's own firewall rules, and every other rule for the sync
# daemon at `$program`: those Windows created when it asked whether the
# program may listen ("public" networks, connections from anywhere).
function Remove-SyncDaemonRules([string]$program) {
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Program -and [Environment]::ExpandEnvironmentVariables($_.Program) -ieq $program } |
        Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule
}

# Tells running programs (Explorer, new terminals) that the environment changed.
function Send-EnvironmentChange {
    $signature = '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);'
    $user32 = Add-Type -MemberDefinition $signature -Name 'User32' -Namespace 'ZeroPassSetup' -PassThru
    $result = [UIntPtr]::Zero
    # HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG
    [void]$user32::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}

$source = $PSScriptRoot
$Destination = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\')

# 1. What is to be installed.
foreach ($name in $Programs + $Documents) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $name) -PathType Leaf)) {
        throw "$name is missing from $source"
    }
}
$version = (Get-Content -LiteralPath (Join-Path $source 'VERSION') -Raw).Trim()

$signatures = @($Programs | ForEach-Object { Get-AuthenticodeSignature -LiteralPath (Join-Path $source $_) })
$unsigned = @($signatures | Where-Object { $_.Status -ne 'Valid' })
if ($unsigned.Count -gt 0) {
    $names = ($unsigned | ForEach-Object { Split-Path -Leaf $_.Path }) -join ', '
    if ($RequireSignature) {
        throw "these programs are not validly signed: $names"
    }
    Write-Warning "these programs are not signed: $names"
} else {
    $signers = @($signatures | ForEach-Object { $_.SignerCertificate.Thumbprint } | Sort-Object -Unique)
    if ($signers.Count -ne 1) {
        throw 'the programs are signed by different certificates'
    }
    Write-Host "signed by: $($signatures[0].SignerCertificate.Subject)"
}

# 2. End what runs from an earlier installation: its programs are in use.
function Stop-ZeroPass([string]$directory) {
    # Others' processes too: an administrator may end them once it asks for
    # the debug privilege (the daemons let only their own user end them).
    try { [System.Diagnostics.Process]::EnterDebugMode() } catch { }
    $prefix = $directory + '\'
    $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $path = $null
        try { $path = $_.Path } catch { }
        $path -and $path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
    })
    foreach ($process in $running) {
        Write-Host "ending $($process.ProcessName) (process $($process.Id))"
        try { $process.Kill() } catch { Write-Warning "could not end process $($process.Id): $_" }
    }
    foreach ($process in $running) {
        try { $process.WaitForExit(10000) | Out-Null } catch { }
    }
}
if (Test-Path -LiteralPath $Destination) {
    Stop-ZeroPass $Destination
}

# 3. The files. A new directory under Program Files inherits its access
#    rights: administrators and the system may change it, users and app
#    containers (the vault daemon's sandbox) may read and run it.
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
foreach ($name in $Programs + $Documents) {
    Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $Destination $name) -Force
}

# 4. The PATH of every user, so that `zp-cli` can be typed anywhere. Read and
#    written as stored, with its %VARIABLES% unexpanded and its kind of value
#    kept, and only if the entry is missing.
$environment = Get-Item -LiteralPath $EnvironmentKey
$rawPath = [string]$environment.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
$pathKind = $environment.GetValueKind('Path')
$present = @($rawPath -split ';' | Where-Object {
    [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ieq $Destination
})
if ($present.Count -eq 0) {
    $newPath = if ($rawPath) { $rawPath + ';' + $Destination } else { $Destination }
    Set-ItemProperty -LiteralPath $EnvironmentKey -Name 'Path' -Value $newPath -Type $pathKind
    Send-EnvironmentChange
}

# 4b. The sync daemon listens for the user's other devices: allow that from
#     the local subnet only, on any kind of network. Windows files many home
#     networks as "public", and the connections are authenticated and
#     encrypted, and never leave the link, wherever they are (ADR-0008).
#     Without a rule, Windows asks when the daemon first listens, a standard
#     user cannot say yes, and an administrator's "yes" allows connections
#     from anywhere. So every rule for this program is replaced by this one,
#     including those such a question left behind.
$syncd = Join-Path $Destination 'zp-syncd.exe'
Remove-SyncDaemonRules $syncd
New-NetFirewallRule -DisplayName 'ZeroPass sync (local network)' -Group $FirewallGroup `
    -Direction Inbound -Action Allow -Profile Any -RemoteAddress LocalSubnet `
    -Program $syncd | Out-Null

# 5. Start at logon, for every user.
if ($NoAutostart) {
    Remove-ItemProperty -Path $RunKey -Name 'ZeroPass' -ErrorAction SilentlyContinue
} else {
    Set-ItemProperty -Path $RunKey -Name 'ZeroPass' -Value ('"{0}"' -f (Join-Path $Destination 'zp-autostart.exe'))
}

# 5b. The desktop application in the Start menu, for every user.
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($Shortcut)
$link.TargetPath = Join-Path $Destination 'zeropass.exe'
$link.WorkingDirectory = $Destination
$link.IconLocation = (Join-Path $Destination 'zeropass.exe') + ',0'
$link.Description = 'ZeroPass password manager'
$link.Save()

# 5c. The browser extension's bridge, for Chrome, Edge, Chromium and Firefox:
#     a manifest beside the programs (only administrators can change it) and
#     the registry key each browser looks for.
$nmh = Join-Path $Destination 'zp-nmh.exe'
$chromeManifest = [ordered]@{
    name            = $NativeHost
    description     = 'ZeroPass'
    path            = $nmh
    type            = 'stdio'
    allowed_origins = @($ChromeExtensions | ForEach-Object { "chrome-extension://$_/" })
}
$firefoxManifest = [ordered]@{
    name               = $NativeHost
    description        = 'ZeroPass'
    path               = $nmh
    type               = 'stdio'
    allowed_extensions = @($FirefoxExtensions)
}
# Without a byte order mark: browsers read the manifests as plain UTF-8.
$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText((Join-Path $Destination 'zp-nmh-chrome.json'), ($chromeManifest | ConvertTo-Json), $utf8)
[System.IO.File]::WriteAllText((Join-Path $Destination 'zp-nmh-firefox.json'), ($firefoxManifest | ConvertTo-Json), $utf8)
foreach ($parent in $NativeHostKeys.Keys) {
    $key = Join-Path $parent $NativeHost
    New-Item -Path $key -Force | Out-Null
    Set-Item -Path $key -Value (Join-Path $Destination $NativeHostKeys[$parent])
}

# 6. "Installed apps".
$size = [int]((Get-ChildItem -LiteralPath $Destination -File | Measure-Object -Property Length -Sum).Sum / 1KB)
New-Item -Path $UninstallKey -Force | Out-Null
$uninstall = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $Destination 'uninstall.ps1')
$values = @{
    DisplayName     = 'ZeroPass'
    DisplayVersion  = $version
    Publisher       = 'ZeroPass contributors'
    InstallLocation = $Destination
    DisplayIcon     = (Join-Path $Destination 'zeropass.exe')
    UninstallString = $uninstall
    URLInfoAbout    = 'https://github.com/makomo-oss/ZeroPass'
}
foreach ($name in $values.Keys) {
    Set-ItemProperty -Path $UninstallKey -Name $name -Value $values[$name]
}
foreach ($name in 'NoModify', 'NoRepair') {
    Set-ItemProperty -Path $UninstallKey -Name $name -Value 1 -Type DWord
}
Set-ItemProperty -Path $UninstallKey -Name 'EstimatedSize' -Value $size -Type DWord

Write-Host "ZeroPass $version is installed in $Destination."
Write-Host 'Open ZeroPass from the Start menu to create your vault (or, in a new terminal:  zp-cli init).'
if (-not $NoAutostart) {
    Write-Host 'From the next logon on, ZeroPass starts by itself for users who have a vault.'
}
if ($PauseAtEnd) {
    Read-Host 'Press Enter to close this window' | Out-Null
}
