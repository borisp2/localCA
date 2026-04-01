<#
.SYNOPSIS
    Renew the localhost server certificate issued by the Local CA.
.DESCRIPTION
    Rotates the server (leaf) certificate while keeping the existing Root CA.
    Backs up the current certificate before generating a new one.

    Can be run on a schedule (e.g. Task Scheduler) or manually when the
    server cert approaches expiry.

    Features:
      - Checks current cert expiry and only renews if within threshold
      - Backs up old certs with timestamp
      - Regenerates server key + cert + PFX + fullchain PEM
      - Can optionally restart a Windows service after renewal
      - Supports -Force to renew regardless of expiry

.PARAMETER RootDir
    CA directory. Default: C:\LocalCA
.PARAMETER AppName
    Application name for cert subject fields. Default: "MyApp"
.PARAMETER ServerValidDays
    New server cert validity in days. Default: 825
.PARAMETER RenewThresholdDays
    Renew only if the cert expires within this many days. Default: 30
.PARAMETER RestartService
    Windows service name to restart after renewal (e.g. "nginx", "w3svc").
    Leave empty to skip.
.PARAMETER Force
    Renew even if the current cert is not near expiry.
.PARAMETER LogFile
    Log file path. Default: <RootDir>\renew-cert.log
.EXAMPLE
    .\Renew-ServerCert.ps1
    .\Renew-ServerCert.ps1 -RenewThresholdDays 60 -RestartService "MyAppService"
    .\Renew-ServerCert.ps1 -Force
#>

[CmdletBinding()]
param(
    [string]$RootDir             = "C:\LocalCA",
    [string]$AppName             = "MyApp",
    [int]   $ServerValidDays     = 825,
    [int]   $RenewThresholdDays  = 30,
    [string]$RestartService      = "",
    [switch]$Force,
    [string]$LogFile             = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SERVER_KEY_BITS = 2048
$script:ExitCode  = 0
$script:StartTime = Get-Date

if ([string]::IsNullOrWhiteSpace($LogFile)) { $LogFile = Join-Path $RootDir "renew-cert.log" }

$LOCALHOST_SANS = @(
    "DNS.1 = localhost",
    "DNS.2 = $($env:COMPUTERNAME.ToLower())",
    "DNS.3 = $($env:COMPUTERNAME.ToLower()).local",
    "IP.1  = 127.0.0.1",
    "IP.2  = ::1"
)

# ── Logging ──────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $line = "$ts [$($Level.PadRight(7))]  $Message"
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Invoke-OpenSSL {
    param([string]$Arguments, [string]$StepName)
    Write-Log "exec: openssl $Arguments"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $script:OpenSSLExe
    $psi.Arguments              = $Arguments
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $process = [System.Diagnostics.Process]::Start($psi)
    $stdout  = $process.StandardOutput.ReadToEnd()
    $stderr  = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if ($stdout.Trim()) { foreach ($l in $stdout.Trim() -split "`n") { Write-Log "  [out] $l" } }
    if ($stderr.Trim()) { foreach ($l in $stderr.Trim() -split "`n") { Write-Log "  [err] $l" } }

    if ($process.ExitCode -ne 0) {
        Write-Log "$StepName FAILED (exit $($process.ExitCode))" "ERROR"
        throw "$StepName failed."
    }
    Write-Log "$StepName — done." "SUCCESS"
    return $stdout
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
try {

    Write-Log "================================================================"
    Write-Log "  Server Certificate Renewal"
    Write-Log "  Started: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Log "  RootDir: $RootDir"
    Write-Log "  Threshold: $RenewThresholdDays days"
    Write-Log "  New validity: $ServerValidDays days"
    Write-Log "================================================================"

    # ── Validate CA exists ───────────────────────────────────────────────────
    $caKeyPath  = Join-Path $RootDir "private\ca.key"
    $caCertPath = Join-Path $RootDir "certs\ca.crt"
    $serverDir  = Join-Path $RootDir "server"

    foreach ($required in @($caKeyPath, $caCertPath, $serverDir)) {
        if (-not (Test-Path $required)) {
            Write-Log "Required path missing: $required" "ERROR"
            throw "CA not found. Run Install-LocalCA-Localhost.ps1 first."
        }
    }
    Write-Log "CA structure validated." "SUCCESS"

    # ── Find OpenSSL ─────────────────────────────────────────────────────────
    $script:OpenSSLExe = $null
    $candidates = @(
        (Get-Command openssl -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\Program Files\Git\usr\bin\openssl.exe"
    ) | Where-Object { $_ }
    foreach ($c in $candidates) {
        if (Test-Path $c) { $script:OpenSSLExe = $c; break }
    }
    if (-not $script:OpenSSLExe) { throw "OpenSSL not found." }
    Write-Log "OpenSSL: $($script:OpenSSLExe)" "SUCCESS"

    # ── Check current cert expiry ────────────────────────────────────────────
    $srvCrtPath = Join-Path $serverDir "localhost.crt"

    if (-not (Test-Path $srvCrtPath)) {
        Write-Log "No existing server cert found — will generate fresh." "WARN"
        $needsRenewal = $true
        $daysRemaining = 0
    } else {
        $endDateRaw = Invoke-OpenSSL "x509 -in `"$srvCrtPath`" -noout -enddate" "Read cert expiry"
        # Parse: notAfter=Mar 15 12:00:00 2027 GMT
        $dateStr = ($endDateRaw.Trim() -replace "notAfter=","").Trim()
        $expiryDate = [datetime]::ParseExact($dateStr, "MMM  d HH:mm:ss yyyy 'GMT'", $null, [System.Globalization.DateTimeStyles]::AllowWhiteSpaces)

        # Fallback parse for single-digit day without double space
        if (-not $expiryDate) {
            try { $expiryDate = [datetime]::Parse($dateStr) } catch {}
        }

        $daysRemaining = [math]::Floor(($expiryDate - (Get-Date)).TotalDays)
        Write-Log "Current cert expires: $($expiryDate.ToString('yyyy-MM-dd')) ($daysRemaining days remaining)"

        if ($Force) {
            Write-Log "Force flag set — renewing regardless of expiry." "WARN"
            $needsRenewal = $true
        } elseif ($daysRemaining -le $RenewThresholdDays) {
            Write-Log "Within renewal threshold ($RenewThresholdDays days) — renewal needed." "WARN"
            $needsRenewal = $true
        } else {
            Write-Log "Cert is still valid for $daysRemaining days — no renewal needed." "SUCCESS"
            $needsRenewal = $false
        }
    }

    if (-not $needsRenewal) {
        Write-Log "No renewal performed. Use -Force to override."
        Write-Log "Exit code: 0"
        exit 0
    }

    # ── Backup existing certs ────────────────────────────────────────────────
    Write-Log "--- Backing up current certificates ---"
    $backupTag = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $backupDir = Join-Path $serverDir "backup-$backupTag"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

    foreach ($file in (Get-ChildItem $serverDir -File -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -notmatch "^backup-" })) {
        Copy-Item $file.FullName -Destination $backupDir -Force
        Write-Log "  Backed up: $($file.Name)" "SUCCESS"
    }
    Write-Log "Backup directory: $backupDir"

    # ── Generate new server certificate ──────────────────────────────────────
    Write-Log "--- Generating new server certificate ---"

    $srvKeyPath = Join-Path $serverDir "localhost.key"
    $srvCsrPath = Join-Path $serverDir "localhost.csr"
    $srvExtPath = Join-Path $serverDir "localhost.ext"
    $srvPfxPath = Join-Path $serverDir "localhost.pfx"
    $srvPemPath = Join-Path $serverDir "localhost-fullchain.pem"

    # New key
    Invoke-OpenSSL "genrsa -out `"$srvKeyPath`" $SERVER_KEY_BITS" "New server key ($SERVER_KEY_BITS-bit)"

    # CSR
    $srvSubj = "/C=XX/O=$AppName/CN=localhost"
    Invoke-OpenSSL "req -new -key `"$srvKeyPath`" -out `"$srvCsrPath`" -subj `"$srvSubj`"" "New server CSR"

    # SAN extension
    $extContent = @"
authorityKeyIdentifier = keyid,issuer
basicConstraints       = CA:FALSE
keyUsage               = digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names

[alt_names]
$($LOCALHOST_SANS -join "`n")
"@
    Set-Content -Path $srvExtPath -Value $extContent -Encoding ASCII

    # Sign
    Invoke-OpenSSL "x509 -req -in `"$srvCsrPath`" -CA `"$caCertPath`" -CAkey `"$caKeyPath`" -CAcreateserial -out `"$srvCrtPath`" -days $ServerValidDays -sha256 -extfile `"$srvExtPath`"" "Sign new cert"

    # PFX
    Invoke-OpenSSL "pkcs12 -export -out `"$srvPfxPath`" -inkey `"$srvKeyPath`" -in `"$srvCrtPath`" -certfile `"$caCertPath`" -passout pass:" "New PFX"

    # Fullchain PEM
    $chain = (Get-Content $srvCrtPath -Raw) + "`n" + (Get-Content $caCertPath -Raw)
    Set-Content -Path $srvPemPath -Value $chain -Encoding ASCII -NoNewline
    Write-Log "Fullchain PEM updated." "SUCCESS"

    # Verify
    Invoke-OpenSSL "verify -CAfile `"$caCertPath`" `"$srvCrtPath`"" "Chain verification"
    Invoke-OpenSSL "x509 -in `"$srvCrtPath`" -noout -subject -dates -fingerprint" "New cert details"

    # ── Restart service if configured ────────────────────────────────────────
    if ($RestartService -ne "") {
        Write-Log "--- Restarting service: $RestartService ---"
        try {
            $svc = Get-Service -Name $RestartService -ErrorAction SilentlyContinue
            if ($svc) {
                Restart-Service -Name $RestartService -Force
                Start-Sleep -Seconds 3
                $svc = Get-Service -Name $RestartService
                Write-Log "Service '$RestartService' restarted — status: $($svc.Status)" "SUCCESS"
            } else {
                Write-Log "Service '$RestartService' not found." "WARN"
            }
        } catch {
            Write-Log "Service restart failed: $($_.Exception.Message)" "WARN"
        }
    }

    # ── Cleanup old backups (keep last 5) ────────────────────────────────────
    Write-Log "--- Cleanup old backups ---"
    $allBackups = Get-ChildItem $serverDir -Directory -Filter "backup-*" |
                  Sort-Object Name -Descending
    if ($allBackups.Count -gt 5) {
        $toDelete = $allBackups | Select-Object -Skip 5
        foreach ($old in $toDelete) {
            Remove-Item $old.FullName -Recurse -Force
            Write-Log "Pruned old backup: $($old.Name)" "INFO"
        }
    }
    Write-Log "Keeping $([math]::Min($allBackups.Count, 5)) most recent backups."

    # ── Summary ──────────────────────────────────────────────────────────────
    $elapsed = ((Get-Date) - $script:StartTime).TotalSeconds
    $newEndDate = (Get-Date).AddDays($ServerValidDays).ToString("yyyy-MM-dd")

    Write-Log ""
    Write-Log "================================================================"
    Write-Log "  Renewal complete."
    Write-Log "  Previous: $daysRemaining days remaining"
    Write-Log "  New expiry: $newEndDate ($ServerValidDays days)"
    Write-Log "  Backup: $backupDir"
    Write-Log "  Duration: $([math]::Round($elapsed,2))s"
    Write-Log "================================================================"

} catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack: $($_.ScriptStackTrace)" "ERROR"
    if ($script:ExitCode -eq 0) { $script:ExitCode = 1 }
} finally {
    Write-Log "Exit code: $($script:ExitCode)"
    exit $script:ExitCode
}
