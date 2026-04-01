<#
.SYNOPSIS
    Prepare an offline deployment bundle for the Local CA Installer.
.DESCRIPTION
    Run this on an ONLINE machine to download all prerequisites and package
    them into a self-contained bundle directory that can be copied to
    air-gapped / offline targets.

    The output bundle directory can then be used with:
      Install-LocalCA-Localhost.ps1 -BundleDir "<path>" -NetworkMode Offline

.PARAMETER OutDir
    Output directory for the bundle. Default: .\bundle
.PARAMETER IncludeInstaller
    Also copies the installer script into the bundle for a single-folder deployment.
.PARAMETER OpenSSLMsiUrl
    Override the OpenSSL MSI download URL.
.PARAMETER VerifySHA256
    SHA256 hash to verify the downloaded MSI. Empty = skip.
.PARAMETER LogFile
    Log file path. Default: <OutDir>\prepare-bundle.log
.EXAMPLE
    .\Prepare-OfflineBundle.ps1
    .\Prepare-OfflineBundle.ps1 -OutDir "D:\deploy\bundle" -IncludeInstaller
#>

[CmdletBinding()]
param(
    [string]$OutDir          = ".\bundle",
    [switch]$IncludeInstaller,
    [string]$OpenSSLMsiUrl   = "https://slproweb.com/download/Win64OpenSSL_Light-3_4_1.msi",
    [string]$VerifySHA256    = "",
    [string]$LogFile         = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:StartTime = Get-Date
if ([string]::IsNullOrWhiteSpace($LogFile)) { $LogFile = Join-Path $OutDir "prepare-bundle.log" }

# ── Logging ──────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $line = "$ts [$($Level.PadRight(7))]  $Message"
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    switch ($Level) {
        "ERROR"   { Write-Host "  [ERROR] $Message" -ForegroundColor Red }
        "SUCCESS" { Write-Host "  [OK]    $Message" -ForegroundColor Green }
        "WARN"    { Write-Host "  [WARN]  $Message" -ForegroundColor Yellow }
        default   { Write-Host "          $Message" }
    }
}

# ── Main ─────────────────────────────────────────────────────────────────────
try {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  Offline Bundle Preparation Tool                ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Write-Log "Bundle output: $OutDir"
    Write-Log "MSI URL: $OpenSSLMsiUrl"

    # Create output structure
    if (-not (Test-Path $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
        Write-Log "Created bundle directory: $OutDir" "SUCCESS"
    }

    # ── 1. Download OpenSSL MSI ──────────────────────────────────────────────
    Write-Log "--- Downloading OpenSSL MSI ---"
    $msiDest = Join-Path $OutDir "openssl-installer.msi"

    if (Test-Path $msiDest) {
        Write-Log "OpenSSL MSI already in bundle — skipping download." "WARN"
    } else {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($OpenSSLMsiUrl, $msiDest)
        $size = [math]::Round((Get-Item $msiDest).Length / 1MB, 2)
        Write-Log "Downloaded OpenSSL MSI (${size} MB)" "SUCCESS"
    }

    # Hash verification
    $actualHash = (Get-FileHash -Path $msiDest -Algorithm SHA256).Hash
    Write-Log "SHA256: $actualHash"

    if ($VerifySHA256 -ne "") {
        if ($actualHash -eq $VerifySHA256) {
            Write-Log "SHA256 hash VERIFIED." "SUCCESS"
        } else {
            Write-Log "SHA256 MISMATCH — expected: $VerifySHA256" "ERROR"
            throw "Hash mismatch."
        }
    } else {
        Write-Log "No expected hash provided — skipping verification." "WARN"
        Write-Log "Pin this hash for production: -VerifySHA256 `"$actualHash`"" "WARN"
    }

    # ── 2. Copy installer script ─────────────────────────────────────────────
    if ($IncludeInstaller) {
        Write-Log "--- Copying installer script ---"
        $installerSource = Join-Path $PSScriptRoot "Install-LocalCA-Localhost.ps1"
        if (Test-Path $installerSource) {
            Copy-Item $installerSource -Destination $OutDir -Force
            Write-Log "Copied Install-LocalCA-Localhost.ps1 into bundle." "SUCCESS"
        } else {
            Write-Log "Installer script not found at $installerSource — skipped." "WARN"
        }

        # Also copy companion scripts if they exist
        foreach ($companion in @("Uninstall-LocalCA.ps1", "Renew-ServerCert.ps1")) {
            $src = Join-Path $PSScriptRoot $companion
            if (Test-Path $src) {
                Copy-Item $src -Destination $OutDir -Force
                Write-Log "Copied $companion into bundle." "SUCCESS"
            }
        }
    }

    # ── 3. Create manifest ───────────────────────────────────────────────────
    Write-Log "--- Creating bundle manifest ---"
    $manifest = @{
        created      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        machine      = $env:COMPUTERNAME
        user         = $env:USERNAME
        openssl_url  = $OpenSSLMsiUrl
        openssl_sha  = $actualHash
        contents     = (Get-ChildItem $OutDir -File | Select-Object Name, Length, LastWriteTime)
    }
    $manifestPath = Join-Path $OutDir "MANIFEST.json"
    $manifest | ConvertTo-Json -Depth 3 | Set-Content -Path $manifestPath -Encoding UTF8
    Write-Log "Manifest written: $manifestPath" "SUCCESS"

    # ── 4. Create quick-start readme ─────────────────────────────────────────
    $readmePath = Join-Path $OutDir "OFFLINE-README.txt"
    $readmeContent = @"
OFFLINE BUNDLE — Local CA Installer
====================================
Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Source:   $env:COMPUTERNAME

USAGE ON TARGET MACHINE:
  1. Copy this entire folder to the target machine.
  2. Open an elevated PowerShell prompt.
  3. Run:

     .\Install-LocalCA-Localhost.ps1 -BundleDir "$(Resolve-Path $OutDir)" -NetworkMode Offline

     Or with custom settings:

     .\Install-LocalCA-Localhost.ps1 ``
         -BundleDir "<path-to-this-folder>" ``
         -AppName "OMNIS" ``
         -HttpsPort 5001 ``
         -NetworkMode Offline

CONTENTS:
$(Get-ChildItem $OutDir -File | ForEach-Object { "  $($_.Name) ($([math]::Round($_.Length/1KB,1)) KB)" } | Out-String)

OPENSSL MSI HASH (SHA256):
  $actualHash
"@
    Set-Content -Path $readmePath -Value $readmeContent -Encoding UTF8
    Write-Log "Offline readme written: $readmePath" "SUCCESS"

    # ── Summary ──────────────────────────────────────────────────────────────
    $elapsed = ((Get-Date) - $script:StartTime).TotalSeconds
    $totalSize = [math]::Round(((Get-ChildItem $OutDir -File | Measure-Object -Property Length -Sum).Sum / 1MB), 2)

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  Bundle Ready                                   ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Log "Bundle directory: $OutDir"
    Write-Log "Total size: ${totalSize} MB"
    Write-Log "Duration: $([math]::Round($elapsed,2))s"
    Write-Log ""
    Write-Log "Copy this folder to target machines and run:"
    Write-Log "  Install-LocalCA-Localhost.ps1 -BundleDir `"<path>`" -NetworkMode Offline"

} catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    exit 1
}
