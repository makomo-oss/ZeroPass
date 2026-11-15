#Requires -Version 5.1
<#
.SYNOPSIS
Builds the Windows package of ZeroPass: the programs, the installer and the
uninstaller, in a directory and a .zip (ADR-0008).

.DESCRIPTION
Builds the shipped programs in release mode, with the features they ship with
(never the test-only `probe` feature of zp-sandbox), and checks that.

Signs the programs and the scripts with Authenticode when a certificate is
given (code signing is decided in P8-03; this is the preparation):

  -CertificateThumbprint, or ZEROPASS_SIGN_CERT_THUMBPRINT: the SHA-1
  thumbprint of a code-signing certificate in the current user's or the
  machine's certificate store, with its private key.
  -TimestampUrl, or ZEROPASS_SIGN_TIMESTAMP_URL: an RFC 3161 time-stamping
  service, so that signatures stay valid after the certificate expires.

Without a certificate the package is unsigned, and says so.

.PARAMETER OutDir
Where the package goes. Default: target\package.
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'target\package',
    [string]$CertificateThumbprint = $env:ZEROPASS_SIGN_CERT_THUMBPRINT,
    [string]$TimestampUrl = $env:ZEROPASS_SIGN_TIMESTAMP_URL
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
# The programs that ship, by executable name, and the Cargo package of each.
$Programs = [ordered]@{
    'zp-cli'       = 'zp-cli'
    'zp-vaultd'    = 'zp-vaultd'
    'zp-syncd'     = 'zp-syncd'
    'zp-keyagent'  = 'zp-keyagent'
    'zp-autostart' = 'zp-autostart'
    'zeropass'     = 'zeropass-desktop'
}

function Invoke-Checked([string]$program, [string[]]$arguments) {
    & $program @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$program $($arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

# 1. Build what ships. First the desktop application's user interface, which
#    the application embeds when it is compiled: without it, the build would
#    embed the placeholder page that says it was not built.
$ui = Join-Path $root 'apps\desktop'
Push-Location -LiteralPath $ui
try {
    Invoke-Checked 'npm' @('ci', '--no-audit', '--no-fund')
    Invoke-Checked 'npm' @('run', 'build')
} finally {
    Pop-Location
}
$page = Get-Content -LiteralPath (Join-Path $ui 'dist\index.html') -Raw
if ($page -match 'zeropass-ui-not-built') {
    throw 'apps\desktop\dist holds the placeholder page, not the user interface'
}
$packages = @($Programs.Values | ForEach-Object { '-p', $_ })
Invoke-Checked 'cargo' (@('build', '--release', '--locked') + $packages)

# The memory probe exists for the tests only; it must not be in a program.
$features = & cargo tree --locked --edges normal,features --target x86_64-pc-windows-msvc @packages
if ($LASTEXITCODE -ne 0) { throw 'cargo tree failed' }
if ($features -match 'zp-sandbox feature "probe"') {
    throw 'a shipped program was built with the test-only "probe" feature of zp-sandbox'
}

$metadata = & cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
$version = ($metadata.packages | Where-Object { $_.name -eq 'zp-cli' }).version
$name = "ZeroPass-$version-windows-x64"
$stage = Join-Path $OutDir $name
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# 2. Gather.
foreach ($program in $Programs.Keys) {
    Copy-Item -LiteralPath (Join-Path 'target\release' "$program.exe") -Destination $stage
}
foreach ($file in 'install.ps1', 'uninstall.ps1', 'README.txt') {
    Copy-Item -LiteralPath (Join-Path 'packaging\windows' $file) -Destination $stage
}
Copy-Item -LiteralPath 'LICENSE' -Destination $stage
Set-Content -LiteralPath (Join-Path $stage 'VERSION') -Value $version -Encoding ascii

# 3. Sign, if a certificate was given.
if ($CertificateThumbprint) {
    $certificate = @(Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My |
        Where-Object { $_.Thumbprint -eq $CertificateThumbprint -and $_.HasPrivateKey })
    if ($certificate.Count -eq 0) {
        throw "no certificate with thumbprint $CertificateThumbprint and its private key"
    }
    $files = @(Get-ChildItem -LiteralPath $stage -File | Where-Object { $_.Extension -in '.exe', '.ps1' })
    foreach ($file in $files) {
        $arguments = @{ FilePath = $file.FullName; Certificate = $certificate[0]; HashAlgorithm = 'SHA256' }
        if ($TimestampUrl) { $arguments.TimestampServer = $TimestampUrl }
        $signed = Set-AuthenticodeSignature @arguments
        if (-not $signed.SignerCertificate -or $signed.SignerCertificate.Thumbprint -ne $CertificateThumbprint) {
            throw "signing $($file.Name) failed: $($signed.StatusMessage)"
        }
        if ($signed.Status -ne 'Valid') {
            # Signed, but this machine does not trust the certificate (a test
            # certificate, say). The installer will treat it as unsigned.
            Write-Warning "$($file.Name): $($signed.StatusMessage)"
        }
    }
    if (-not $TimestampUrl) {
        Write-Warning 'signed without a time stamp: the signatures end with the certificate'
    }
    Write-Host "signed $($files.Count) files with $($certificate[0].Subject)"
} else {
    Write-Warning 'no certificate given: the package is NOT signed'
}

# 4. Pack.
$zip = Join-Path $OutDir "$name.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$zip.sha256" -Value "$hash  $name.zip" -Encoding ascii
Write-Host "package: $zip"
Write-Host "sha256:  $hash"
