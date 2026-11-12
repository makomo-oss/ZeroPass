# Captures this machine's ZeroPass traffic while it syncs and checks that
# nothing leaves the local link (docs/spec/lan.md section 6, plan task P2-12).
#
# Run from an elevated PowerShell (packet capture needs administrator rights):
#
#   .\scripts\check-lan-capture.ps1 -Vault C:\path\to\vault.zpvault
#
# It starts zp-syncd on the vault, captures the packets on the ports it uses
# (its TCP port and mDNS) with the built-in Packet Monitor, and analyses the
# capture. While it waits, sync from another device of the vault on the same
# network. The vault is never unlocked: zp-syncd works on the locked file.
param(
    [Parameter(Mandatory = $true)][string]$Vault,
    [int]$Seconds = 45,
    # Where to leave the capture and the logs.
    [string]$OutDir = (Join-Path $env:TEMP "zeropass-capture")
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Packet capture needs administrator rights: start PowerShell with 'Run as administrator'."
}
if (-not (Test-Path $Vault)) { Write-Error "No vault file at $Vault" }

$syncd = Join-Path $repo "target\release\zp-syncd.exe"
$checker = Join-Path $repo "target\release\examples\capture_check.exe"
if (-not (Test-Path $syncd) -or -not (Test-Path $checker)) {
    Write-Error ("Build first, in a normal terminal: " +
        "cargo build --release -p zp-syncd; cargo build --release -p zp-transport --example capture_check")
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$log = Join-Path $OutDir "zp-syncd.log"
$etl = Join-Path $OutDir "capture.etl"
$pcap = Join-Path $OutDir "capture.pcapng"
Remove-Item -Force -ErrorAction SilentlyContinue $log, $etl, $pcap

$daemon = Start-Process -FilePath $syncd -ArgumentList "--vault", "`"$Vault`"" `
    -RedirectStandardError $log -WindowStyle Hidden -PassThru
try {
    # zp-syncd logs where it listens: "... (local network endpoints: [192.168.0.10:50123])".
    $endpoints = @()
    foreach ($attempt in 1..50) {
        Start-Sleep -Milliseconds 200
        $text = Get-Content -Raw -ErrorAction SilentlyContinue $log
        if ($text -match "local network endpoints: \[([^\]]*)\]") {
            $endpoints = $Matches[1] -split ",\s*" | Where-Object { $_ }
            break
        }
    }
    if ($endpoints.Count -eq 0) {
        Write-Error "zp-syncd is not listening on a local network (see $log)."
    }
    $addresses = $endpoints | ForEach-Object { ($_ -split ":")[0] } | Sort-Object -Unique
    $ports = $endpoints | ForEach-Object { ($_ -split ":")[1] } | Sort-Object -Unique
    Write-Host "zp-syncd listens on $($endpoints -join ', ')"

    pktmon stop | Out-Null
    pktmon filter remove | Out-Null
    foreach ($port in $ports) { pktmon filter add zeropass-tcp -t TCP -p $port | Out-Null }
    pktmon filter add zeropass-mdns -t UDP -p 5353 | Out-Null
    pktmon start --capture --comp nics --pkt-size 96 --file-name $etl | Out-Null

    Write-Host "Capturing for $Seconds seconds. Sync from another device of this vault NOW (twice if you can)."
    Start-Sleep -Seconds $Seconds
}
finally {
    pktmon stop | Out-Null
    pktmon filter remove | Out-Null
    if (-not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force }
}

pktmon etl2pcap $etl --out $pcap | Out-Null
Write-Host ""
Write-Host "zp-syncd log:"
Get-Content $log | ForEach-Object { Write-Host "  $_" }
Write-Host ""
& $checker $pcap @addresses
$result = $LASTEXITCODE
Write-Host ""
Write-Host "Capture kept at $pcap"
exit $result
