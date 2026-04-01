<#
.SYNOPSIS
    Uninstall the Local CA — removes certificates, trust entries, and firewall rules.
.DESCRIPTION
    Reverses everything done by Install-LocalCA-Localhost.ps1:
      1. Removes the Root CA from LocalMachine and CurrentUser trust stores
      2. Removes the firewall inbound rule
      3. Optionally removes the entire CA directory (certs, keys, etc.)

    Requires Administrator privileges for trust-store and firewall cleanup.

.PARAMETER RootDir
    The CA directory to clean up. Default: C:\LocalCA
.PARAMETER AppName
    Application name used when the CA was installed (for firewall rule matching).
    Default: "MyApp"
.PARAMETER HttpsPort
    HTTPS port used during install (for firewall rule matching). Default: 443
.PARAMETER RemoveFiles
    If set, deletes the entire RootDir and all CA artefacts.
    Without this flag, only trust-store and firewall entries are removed.
.PARAMETER RemoveOpenSSL
    If set, also attempts to uninstall OpenSSL (winget/choco/MSI).
.PARAMETER LogFile
    Log file path. Default: %TEMP%\uninstall-localca.log
    (Uses TEMP because RootDir may be deleted.)
.PARAMETER Confirm
    Suppresses the confirmation prompt. USE WITH CAUTION.
.EXAMPLE
    .\Uninstall-LocalCA.ps1
    .\Uninstall-LocalCA.ps1 -RemoveFiles -RemoveOpenSSL -Confirm
    .\Uninstall-LocalCA.ps1 -AppName "OMNIS" -HttpsPort 5001 -RemoveFiles
#>

[CmdletBinding()]
param(
    [string]$RootDir       = "C:\LocalCA",
    [string]$AppName       = "MyApp",
    [int]   $HttpsPort     = 443,
    [switch]$RemoveFiles,
    [switch]$RemoveOpenSSL,
    [string]$LogFile       = (Join-Path $env:TEMP "uninstall-localca.log"),
    [switch]$Confirm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ExitCode  = 0
$script:StartTime = Get-Date

# ── Logging ──────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $line = "$ts [$($Level.PadRight(7))]  $Message"
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
try {

    Write-Log "================================================================"
    Write-Log "  Local CA Uninstaller"
    Write-Log "  Started : $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Log "  RootDir : $RootDir"
    Write-Log "  AppName : $AppName"
    Write-Log "  Port    : $HttpsPort"
    Write-Log "  Remove files  : $RemoveFiles"
    Write-Log "  Remove OpenSSL: $RemoveOpenSSL"
    Write-Log "================================================================"

    # ── Pre-flight ───────────────────────────────────────────────────────────
    if (-not (Test-Admin)) {
        Write-Log "WARNING: Not running elevated — trust-store and firewall removal will fail." "WARN"
    }

    if (-not $Confirm) {
        Write-Log "Waiting for user confirmation..." "INFO"
        $prompt = @"

  This will:
    - Remove the Root CA from Windows trust stores
    - Remove firewall rule: '$AppName HTTPS (localhost:$HttpsPort)'
"@
        if ($RemoveFiles)   { $prompt += "`n    - DELETE all files in $RootDir" }
        if ($RemoveOpenSSL) { $prompt += "`n    - Attempt to uninstall OpenSSL" }
        $prompt += "`n`n  Type YES to continue: "

        Write-Host $prompt -ForegroundColor Yellow -NoNewline
        $answer = Read-Host
        if ($answer -ne "YES") {
            Write-Log "User cancelled." "WARN"
            Write-Host "  Cancelled." -ForegroundColor Red
            exit 0
        }
        Write-Log "User confirmed." "SUCCESS"
    }

    # ── 1. TRUST STORE REMOVAL ───────────────────────────────────────────────
    Write-Log "--- Phase 1: Trust Store Cleanup ---"

    $caCertPath = Join-Path $RootDir "certs\ca.crt"
    $thumbprint = $null

    if (Test-Path $caCertPath) {
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caCertPath)
            $thumbprint = $cert.Thumbprint
            Write-Log "CA cert thumbprint: $thumbprint"
        } catch {
            Write-Log "Could not read CA cert: $($_.Exception.Message)" "WARN"
        }
    } else {
        Write-Log "CA cert not found at $caCertPath — will search stores by subject." "WARN"
    }

    foreach ($loc in @("LocalMachine","CurrentUser")) {
        try {
            $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$loc
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                [System.Security.Cryptography.X509Certificates.StoreName]::Root, $storeLocation)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

            $toRemove = @()
            if ($thumbprint) {
                $toRemove = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint }
            } else {
                # Fallback: match by subject CN
                $toRemove = $store.Certificates | Where-Object {
                    $_.Subject -like "*$AppName Localhost Root CA*"
                }
            }

            foreach ($c in $toRemove) {
                $store.Remove($c)
                Write-Log "Removed from $loc\Root: $($c.Subject) [$($c.Thumbprint)]" "SUCCESS"
            }

            if ($toRemove.Count -eq 0) {
                Write-Log "No matching cert found in $loc\Root." "INFO"
            }

            $store.Close()
        } catch {
            Write-Log "Error cleaning $loc\Root: $($_.Exception.Message)" "WARN"
        }
    }

    # ── 2. FIREWALL RULE REMOVAL ─────────────────────────────────────────────
    Write-Log "--- Phase 2: Firewall Cleanup ---"

    $ruleName = "$AppName HTTPS (localhost:$HttpsPort)"
    try {
        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($rule) {
            Remove-NetFirewallRule -DisplayName $ruleName
            Write-Log "Removed firewall rule: $ruleName" "SUCCESS"
        } else {
            Write-Log "No firewall rule found: $ruleName" "INFO"
        }
    } catch {
        Write-Log "Firewall cleanup error: $($_.Exception.Message)" "WARN"
    }

    # ── 3. FILE REMOVAL ─────────────────────────────────────────────────────
    Write-Log "--- Phase 3: File Cleanup ---"

    if ($RemoveFiles) {
        if (Test-Path $RootDir) {
            # Log what we're about to delete
            $fileCount = (Get-ChildItem $RootDir -Recurse -File -ErrorAction SilentlyContinue).Count
            $totalSize = [math]::Round(((Get-ChildItem $RootDir -Recurse -File -ErrorAction SilentlyContinue |
                          Measure-Object -Property Length -Sum).Sum / 1KB), 2)
            Write-Log "Deleting $fileCount files (${totalSize} KB) in $RootDir..."

            # List key files being deleted
            foreach ($important in @("private\ca.key","certs\ca.crt","server\localhost.key",
                                      "server\localhost.crt","server\localhost.pfx",
                                      "server\localhost-fullchain.pem")) {
                $p = Join-Path $RootDir $important
                if (Test-Path $p) { Write-Log "  Deleting: $p" "WARN" }
            }

            Remove-Item $RootDir -Recurse -Force
            Write-Log "Deleted $RootDir and all contents." "SUCCESS"
        } else {
            Write-Log "Directory not found: $RootDir — nothing to delete." "INFO"
        }

        # Also clean up extracted tools if they exist
        $toolsDir = Join-Path $RootDir "tools"
        if (Test-Path $toolsDir) {
            Remove-Item $toolsDir -Recurse -Force
            Write-Log "Deleted tools directory: $toolsDir" "SUCCESS"
        }
    } else {
        Write-Log "File removal SKIPPED (use -RemoveFiles to delete $RootDir)." "INFO"
    }

    # ── 4. OPENSSL UNINSTALL ─────────────────────────────────────────────────
    Write-Log "--- Phase 4: OpenSSL Uninstall ---"

    if ($RemoveOpenSSL) {
        $uninstalled = $false

        # Try winget
        try {
            $wg = Get-Command winget -ErrorAction SilentlyContinue
            if ($wg) {
                Write-Log "Attempting winget uninstall..."
                $result = & winget uninstall --id "ShiningLight.OpenSSL" --silent 2>&1
                Write-Log "winget: $result" "INFO"
                $uninstalled = $true
            }
        } catch {
            Write-Log "winget uninstall failed: $($_.Exception.Message)" "WARN"
        }

        # Try choco
        if (-not $uninstalled) {
            try {
                $ch = Get-Command choco -ErrorAction SilentlyContinue
                if ($ch) {
                    Write-Log "Attempting choco uninstall..."
                    & choco uninstall openssl -y 2>&1 | ForEach-Object { Write-Log "  $_" "INFO" }
                    $uninstalled = $true
                }
            } catch {
                Write-Log "choco uninstall failed: $($_.Exception.Message)" "WARN"
            }
        }

        # Try MSI uninstall via registry
        if (-not $uninstalled) {
            Write-Log "Searching registry for OpenSSL MSI product..." "INFO"
            $regPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            foreach ($rp in $regPaths) {
                $entry = Get-ItemProperty $rp -ErrorAction SilentlyContinue |
                         Where-Object { $_.DisplayName -like "*OpenSSL*" } |
                         Select-Object -First 1
                if ($entry -and $entry.UninstallString) {
                    Write-Log "Found: $($entry.DisplayName) — $($entry.UninstallString)"
                    try {
                        if ($entry.UninstallString -match "msiexec") {
                            $productCode = $entry.UninstallString -replace '.*(\{[A-F0-9-]+\}).*','$1'
                            Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -NoNewWindow
                        } else {
                            Start-Process $entry.UninstallString -ArgumentList "/VERYSILENT" -Wait -NoNewWindow
                        }
                        Write-Log "OpenSSL uninstalled via registry entry." "SUCCESS"
                        $uninstalled = $true
                    } catch {
                        Write-Log "Registry-based uninstall failed: $($_.Exception.Message)" "WARN"
                    }
                    break
                }
            }
        }

        if (-not $uninstalled) {
            Write-Log "Could not find OpenSSL to uninstall — it may already be removed or was portable." "WARN"
        }
    } else {
        Write-Log "OpenSSL uninstall SKIPPED (use -RemoveOpenSSL)." "INFO"
    }

    # ── Summary ──────────────────────────────────────────────────────────────
    $elapsed = ((Get-Date) - $script:StartTime).TotalSeconds
    Write-Log ""
    Write-Log "================================================================"
    Write-Log "  Uninstall complete."
    Write-Log "  Duration: $([math]::Round($elapsed,2))s"
    Write-Log "  Log: $LogFile"
    Write-Log "  Exit code: $($script:ExitCode)"
    Write-Log "================================================================"

} catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack: $($_.ScriptStackTrace)" "ERROR"
    if ($script:ExitCode -eq 0) { $script:ExitCode = 99 }
} finally {
    exit $script:ExitCode
}
