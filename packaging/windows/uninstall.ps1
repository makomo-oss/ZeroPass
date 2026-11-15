#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Removes ZeroPass from this computer (ADR-0008).

.DESCRIPTION
Ends the running ZeroPass programs (the vaults lock), then removes the
programs, the logon start, the PATH entry and the entry in "Installed apps".

Vaults are NOT removed: each user's vault stays in
%LOCALAPPDATA%\ZeroPass\Vault (or wherever it was created). Delete them by
hand once you no longer need them, and keep the recovery kit if you may.

.PARAMETER Destination
The installation to remove. Default: the directory this script is in.
#>
[CmdletBinding()]
param(
    [string]$Destination = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RunKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZeroPass'
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

# 2. The logon start and "Installed apps".
$run = Get-ItemProperty -Path $RunKey -Name 'ZeroPass' -ErrorAction SilentlyContinue
if ($run -and $run.ZeroPass -like ('*' + $Destination + '*')) {
    Remove-ItemProperty -Path $RunKey -Name 'ZeroPass'
}
$entry = Get-ItemProperty -Path $UninstallKey -ErrorAction SilentlyContinue
if ($entry -and $entry.InstallLocation -ieq $Destination) {
    Remove-Item -Path $UninstallKey -Recurse
}

# 3. The PATH.
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$entries = @($machinePath -split ';' | Where-Object { $_ -ne '' -and $_.TrimEnd('\') -ine $Destination })
[Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'Machine')

# 4. The files. Leave the directory first: it cannot be removed while in use.
Set-Location -LiteralPath $env:SystemRoot
Remove-Item -LiteralPath $Destination -Recurse -Force

Write-Host "ZeroPass was removed from $Destination."
Write-Host 'Your vault was kept: %LOCALAPPDATA%\ZeroPass\Vault (for each user who had one).'
