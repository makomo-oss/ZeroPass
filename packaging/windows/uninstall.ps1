#Requires -Version 5.1
<#
.SYNOPSIS
Removes ZeroPass from this computer (ADR-0008).

.DESCRIPTION
Ends the running ZeroPass programs (the vaults lock), then removes the
programs, the logon start, the PATH entry, the firewall rule and the entry in
"Installed apps". Asks Windows for administrator rights if it does not have
them (as when started from "Installed apps").

Vaults are NOT removed: each user's vault stays in
%LOCALAPPDATA%\ZeroPass\Vault (or wherever it was created). Delete them by
hand once you no longer need them, and keep the recovery kit if you may.

.PARAMETER Destination
The installation to remove. Default: the directory this script is in.
#>
[CmdletBinding()]
param(
    [string]$Destination = $PSScriptRoot,
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
    $elevated = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    exit $elevated.ExitCode
}

trap {
    Write-Host "error: $_" -ForegroundColor Red
    if ($PauseAtEnd) { Read-Host 'Press Enter to close this window' | Out-Null }
    exit 1
}

$RunKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZeroPass'
$EnvironmentKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$FirewallGroup = 'ZeroPass'

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
$Destination = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\')

if (-not (Test-Path -LiteralPath (Join-Path $Destination 'zp-vaultd.exe'))) {
    throw "$Destination does not hold a ZeroPass installation"
}

# 1. End what runs from it.
try { [System.Diagnostics.Process]::EnterDebugMode() } catch { }
$prefix = $Destination + '\'
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

# 2. The logon start, the firewall rules and "Installed apps".
Remove-SyncDaemonRules (Join-Path $Destination 'zp-syncd.exe')
$run = Get-ItemProperty -Path $RunKey -Name 'ZeroPass' -ErrorAction SilentlyContinue
if ($run -and $run.ZeroPass -like ('*' + $Destination + '*')) {
    Remove-ItemProperty -Path $RunKey -Name 'ZeroPass'
}
$entry = Get-ItemProperty -Path $UninstallKey -ErrorAction SilentlyContinue
if ($entry -and $entry.InstallLocation -ieq $Destination) {
    Remove-Item -Path $UninstallKey -Recurse
}

# 3. The PATH: only the entry for this installation goes, the rest stays as
#    stored (unexpanded, same kind of value), and nothing is written if it is
#    not there.
$environment = Get-Item -LiteralPath $EnvironmentKey
$rawPath = [string]$environment.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
$pathKind = $environment.GetValueKind('Path')
$entries = @($rawPath -split ';')
$kept = @($entries | Where-Object {
    [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ine $Destination
})
if ($kept.Count -ne $entries.Count) {
    Set-ItemProperty -LiteralPath $EnvironmentKey -Name 'Path' -Value ($kept -join ';') -Type $pathKind
    Send-EnvironmentChange
}

# 4. The files. Leave the directory first: it cannot be removed while in use.
Set-Location -LiteralPath $env:SystemRoot
Remove-Item -LiteralPath $Destination -Recurse -Force

Write-Host "ZeroPass was removed from $Destination."
Write-Host 'Your vault was kept: %LOCALAPPDATA%\ZeroPass\Vault (for each user who had one).'
if ($PauseAtEnd) {
    Read-Host 'Press Enter to close this window' | Out-Null
}
