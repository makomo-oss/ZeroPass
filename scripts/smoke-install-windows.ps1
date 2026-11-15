#Requires -Version 7
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs the Windows package on this (clean) machine, uses it, and removes it
again (P3-07). CI runs it on a fresh runner; it needs administrator rights,
like the installer.

.PARAMETER Package
The package directory made by scripts\package-windows.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Package
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$destination = Join-Path $env:ProgramFiles 'ZeroPass'
$cli = Join-Path $destination 'zp-cli.exe'
$vault = Join-Path $env:LOCALAPPDATA 'ZeroPass\Vault\vault.zpvault'
$password = 'correct horse battery staple'
$totpUri = 'otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example'

function Assert([bool]$condition, [string]$message) {
    if (-not $condition) { throw "FAILED: $message" }
    Write-Host "ok: $message"
}

# Runs the installed client; each element of $Answers answers one prompt.
function Invoke-Cli([string[]]$Arguments, [string[]]$Answers = @()) {
    $output = $Answers | & $cli @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "zp-cli $($Arguments -join ' ') failed: $($output -join "`n")"
    }
    return ($output -join "`n")
}

function Wait-Until([scriptblock]$condition, [string]$what) {
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (& $condition)) {
        if ((Get-Date) -gt $deadline) { throw "FAILED: $what (gave up after 30 s)" }
        Start-Sleep -Milliseconds 250
    }
    Write-Host "ok: $what"
}

Assert (-not (Test-Path $destination)) 'nothing is installed yet'
Assert (-not (Test-Path $vault)) 'this user has no vault yet'

# 1. Install.
& (Join-Path $Package 'install.ps1')
foreach ($name in 'zp-cli.exe', 'zp-vaultd.exe', 'zp-syncd.exe', 'zp-keyagent.exe', 'zp-autostart.exe', 'uninstall.ps1') {
    Assert (Test-Path (Join-Path $destination $name)) "$name is installed"
}
$run = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').ZeroPass
Assert ($run -eq ('"{0}"' -f (Join-Path $destination 'zp-autostart.exe'))) 'ZeroPass starts at logon'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Assert ($machinePath -split ';' -contains $destination) 'the PATH holds the installation'
$entry = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZeroPass'
Assert ($entry.InstallLocation -eq $destination) 'ZeroPass is listed in Installed apps'
$acl = Get-Acl $destination
Assert (-not ($acl.Access | Where-Object {
    $_.IdentityReference -match '\Users$|Authenticated Users|Everyone' -and
    $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl'
})) 'users cannot change the installed programs'

# 2. A logon without a vault starts nothing.
& (Join-Path $destination 'zp-autostart.exe')
Start-Sleep -Seconds 2
Assert ((Invoke-Cli @('daemon', 'status')) -match 'the vault daemon is not running') 'without a vault, nothing was started at logon'

# 3. Create a vault in the default place and use every domain. The software
#    key store stands in for Windows Hello, which a CI runner does not have.
$created = Invoke-Cli @('--insecure-software-keystore', 'init') @($password, $password)
Assert ($created -match 'totp:\s+available') "the vault was created ($vault)"
Assert (Test-Path $vault) 'the vault is in the default place'
$added = Invoke-Cli @('--insecure-software-keystore', 'add', 'totp') @($totpUri)
$id = ($added -split '\s+')[1]
$code = Invoke-Cli @('--insecure-software-keystore', 'totp', $id)
Assert ($code -match '^\d{6}') 'a TOTP code comes from the worker started from Program Files'
$status = Invoke-Cli @('daemon', 'status')
Assert ($status -match 'sandbox: yes') 'the vault daemon runs in its sandbox'
Invoke-Cli @('daemon', 'stop') | Out-Null

# 4. A logon with a vault starts both daemons, without a console.
& (Join-Path $destination 'zp-autostart.exe')
Wait-Until { (Invoke-Cli @('daemon', 'status')) -match 'the vault daemon is running' } 'the vault daemon was started at logon'
Wait-Until { (Invoke-Cli @('daemon', 'status')) -match 'the sync daemon is running' } 'the sync daemon was started at logon'
$status = Invoke-Cli @('daemon', 'status')
Assert ($status -match 'sandbox: yes') 'the daemon started at logon runs in its sandbox'
$unlocked = Invoke-Cli @('unlock', 'password') @($password)
Assert ($unlocked -match 'unlocked') 'the vault opens'

# 5. Installing again over the running programs replaces them.
& (Join-Path $Package 'install.ps1')
Assert ((Invoke-Cli @('daemon', 'status')) -match 'the vault daemon is not running') 'reinstalling ended the running daemons'

# 6. Uninstall.
& (Join-Path $destination 'uninstall.ps1')
Assert (-not (Test-Path $destination)) 'the programs are gone'
Assert ($null -eq (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').PSObject.Properties['ZeroPass']) 'nothing starts at logon any more'
Assert (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZeroPass')) 'ZeroPass is no longer listed'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Assert (-not ($machinePath -split ';' -contains $destination)) 'the PATH no longer holds the installation'
Assert (Test-Path $vault) 'the vault was kept'
Write-Host 'smoke test passed'
