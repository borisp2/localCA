<#
.SYNOPSIS
    Silent Local CA Installation Wizard — Localhost Edition (Offline-Capable)
.DESCRIPTION
    Fully self-contained installer that provisions all prerequisites (OpenSSL),
    deploys a local Certificate Authority on localhost, issues a server
    certificate, trusts it machine-wide, and configures firewall rules.

    Works in THREE network modes:
      ONLINE  — downloads OpenSSL via winget / Chocolatey / direct MSI
      OFFLINE — uses a pre-staged bundle directory with all needed tools
      AUTO    — detects connectivity and picks the best strategy

    For air-gapped / offline deployments, place the OpenSSL installer
    in the bundle directory before running:

      .\Install-LocalCA-Localhost.ps1 -BundleDir "D:\installers"

    Accepted bundle contents (any of):
      <BundleDir>\openssl-installer.msi       — Win64 OpenSSL MSI
      <BundleDir>\openssl-installer.exe        — Win64 OpenSSL EXE installer
      <BundleDir>\openssl\bin\openssl.exe      — portable / pre-extracted OpenSSL
      <BundleDir>\openssl.zip                  — ZIP containing bin\openssl.exe

.PARAMETER RootDir
    Base directory for all CA artefacts. Default: C:\LocalCA
.PARAMETER AppName
    Application name used in certificate fields. Default: "MyApp"
.PARAMETER CaValidDays
    Root CA validity in days. Default: 3650
.PARAMETER ServerValidDays
    Server cert validity in days. Default: 825
.PARAMETER HttpsPort
    HTTPS port the application will listen on. Default: 443
.PARAMETER BundleDir
    Directory containing pre-staged installers for offline use.
    Default: .\bundle (relative to script location)
.PARAMETER OpenSSLExePath
    Explicit path to an openssl.exe binary. Overrides all detection/install logic.
.PARAMETER NetworkMode
    Force a network mode: Auto, Online, Offline. Default: Auto
.PARAMETER SkipTrustInstall
    Do not add the root CA to the Windows trust store.
.PARAMETER SkipFirewallRule
    Do not create a Windows Firewall inbound rule.
.PARAMETER Force
    Overwrite existing certificates.
.PARAMETER LogFile
    Log file path. Default: <RootDir>\install-ca.log
.EXAMPLE
    # Fully automatic — detects network, installs everything
    .\Install-LocalCA-Localhost.ps1

    # Offline with bundled MSI
    .\Install-LocalCA-Localhost.ps1 -BundleDir "D:\offline-pkg" -NetworkMode Offline

    # Point directly to a portable openssl.exe
    .\Install-LocalCA-Localhost.ps1 -OpenSSLExePath "C:\tools\openssl\openssl.exe"

    # Production example
    .\Install-LocalCA-Localhost.ps1 -AppName "OMNIS" -HttpsPort 5001 -BundleDir ".\bundle" -Force
#>

[CmdletBinding()]
param(
    [string]$RootDir          = "C:\LocalCA",
    [string]$AppName          = "MyApp",
    [int]   $CaValidDays      = 3650,
    [int]   $ServerValidDays  = 825,
    [int]   $HttpsPort        = 443,
    [string]$BundleDir        = "",
    [string]$OpenSSLExePath   = "",
    [ValidateSet("Auto","Online","Offline")]
    [string]$NetworkMode      = "Auto",
    [switch]$SkipTrustInstall,
    [switch]$SkipFirewallRule,
    [switch]$Force,
    [string]$LogFile          = ""
)

# ─────────────────────────────────────────────────────────────────────────────
#  STRICT MODE & GLOBALS
# ─────────────────────────────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CA_KEY_BITS         = 4096
$SERVER_KEY_BITS     = 2048
$OPENSSL_WINGET_ID   = "ShiningLight.OpenSSL"
$OPENSSL_CHOCO_ID    = "openssl"
$OPENSSL_MSI_URL     = "https://slproweb.com/download/Win64OpenSSL_Light-3_4_1.msi"
$OPENSSL_MSI_SHA256  = ""  # pin a hash for production; empty = skip verification

$LOCALHOST_SANS = @(
    "DNS.1 = localhost",
    "DNS.2 = $($env:COMPUTERNAME.ToLower())",
    "DNS.3 = $($env:COMPUTERNAME.ToLower()).local",
    "IP.1  = 127.0.0.1",
    "IP.2  = ::1"
)

$script:ExitCode      = 0
$script:StartTime     = Get-Date
$script:OpenSSLExe    = $null
$script:IsOnline      = $false
$script:ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:TempDir       = Join-Path $env:TEMP "localca-$([guid]::NewGuid().ToString('N').Substring(0,8))"

if ([string]::IsNullOrWhiteSpace($BundleDir))  { $BundleDir = Join-Path $script:ScriptDir "bundle" }
if ([string]::IsNullOrWhiteSpace($LogFile))     { $LogFile   = Join-Path $RootDir "install-ca.log" }

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────────────────────
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS","SECTION")]
        [string]$Level = "INFO"
    )
    $ts     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $prefix = switch ($Level) {
        "SECTION" { "════" }
        "SUCCESS" { " OK " }
        "ERROR"   { "FAIL" }
        "WARN"    { "WARN" }
        default   { "    " }
    }
    $line = "$ts [$($Level.PadRight(7))] $prefix  $Message"
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Write-Section {
    param([string]$Title, [int]$Phase)
    Write-Log "" "INFO"
    Write-Log ("-" * 72) "SECTION"
    Write-Log "PHASE $Phase — $Title" "SECTION"
    Write-Log ("-" * 72) "SECTION"
}

# ─────────────────────────────────────────────────────────────────────────────
#  UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-TempDir {
    if (-not (Test-Path $script:TempDir)) {
        New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null
    }
}

function Invoke-External {
    param(
        [string]$FilePath,
        [string]$Arguments,
        [string]$StepName,
        [int[]] $AcceptableExitCodes = @(0),
        [int]   $TimeoutSeconds = 600
    )
    Write-Log "exec: $FilePath $Arguments" "INFO"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $FilePath
    $psi.Arguments              = $Arguments
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $process = [System.Diagnostics.Process]::Start($psi)
    $stdout  = $process.StandardOutput.ReadToEnd()
    $stderr  = $process.StandardError.ReadToEnd()

    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill()
        Write-Log "$StepName TIMED OUT after ${TimeoutSeconds}s — killed." "ERROR"
        throw "$StepName timed out."
    }

    if ($stdout.Trim()) { foreach ($l in $stdout.Trim() -split "`n") { Write-Log "  [out] $l" "INFO" } }
    if ($stderr.Trim()) { foreach ($l in $stderr.Trim() -split "`n") { Write-Log "  [err] $l" "INFO" } }

    if ($process.ExitCode -notin $AcceptableExitCodes) {
        Write-Log "$StepName FAILED (exit $($process.ExitCode))" "ERROR"
        throw "$StepName failed (exit $($process.ExitCode))."
    }
    Write-Log "$StepName — done." "SUCCESS"
    return $stdout
}

function Invoke-OpenSSL {
    param([string]$Arguments, [string]$StepName)
    Invoke-External -FilePath $script:OpenSSLExe -Arguments $Arguments -StepName $StepName
}

function Remove-IfForce {
    param([string]$Path, [string]$Label)
    if ((Test-Path $Path) -and $Force) {
        Remove-Item $Path -Force
        Write-Log "Removed existing $Label (-Force): $Path" "WARN"
    }
}

function Get-FileFromWeb {
    param([string]$Url, [string]$OutPath, [string]$Label)
    Write-Log "Downloading $Label from $Url ..." "INFO"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($Url, $OutPath)
    $size = (Get-Item $OutPath).Length
    Write-Log "Downloaded $Label ($size bytes) -> $OutPath" "SUCCESS"
}

function Refresh-Path {
    Write-Log "Refreshing PATH from registry..." "INFO"
    $env:PATH = "$([Environment]::GetEnvironmentVariable('Path','Machine'));$([Environment]::GetEnvironmentVariable('Path','User'))"
}

# ─────────────────────────────────────────────────────────────────────────────
#  NETWORK DETECTION
# ─────────────────────────────────────────────────────────────────────────────
function Test-InternetConnectivity {
    <# Returns $true if outbound HTTPS is reachable. #>
    Write-Log "Testing internet connectivity..." "INFO"

    # Method 1: TCP to DNS
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $result = $tcp.BeginConnect("8.8.8.8", 443, $null, $null)
        $waited = $result.AsyncWaitHandle.WaitOne(3000, $false)
        if ($waited -and $tcp.Connected) {
            $tcp.Close()
            Write-Log "Internet reachable (TCP 8.8.8.8:443)." "SUCCESS"
            return $true
        }
        $tcp.Close()
    } catch {}

    # Method 2: HTTP HEAD to a known CDN
    try {
        $req = [System.Net.HttpWebRequest]::Create("https://www.google.com")
        $req.Method  = "HEAD"
        $req.Timeout = 4000
        $resp = $req.GetResponse()
        $resp.Close()
        Write-Log "Internet reachable (HTTPS HEAD google.com)." "SUCCESS"
        return $true
    } catch {}

    # Method 3: DNS resolution
    try {
        $dns = [System.Net.Dns]::GetHostAddresses("slproweb.com")
        if ($dns.Count -gt 0) {
            Write-Log "DNS works but TCP may be blocked." "WARN"
            return $true  # optimistic: DNS works, downloads might too
        }
    } catch {}

    Write-Log "Internet appears UNREACHABLE." "WARN"
    return $false
}

function Resolve-NetworkMode {
    <# Determines effective network mode: Online or Offline. #>
    switch ($NetworkMode) {
        "Online"  {
            Write-Log "Network mode forced: ONLINE" "INFO"
            return $true
        }
        "Offline" {
            Write-Log "Network mode forced: OFFLINE" "INFO"
            return $false
        }
        default {
            # Auto-detect
            $online = Test-InternetConnectivity
            if ($online) {
                Write-Log "Auto-detected: ONLINE" "SUCCESS"
            } else {
                Write-Log "Auto-detected: OFFLINE" "WARN"
            }
            return $online
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  OPENSSL DETECTION (works offline — filesystem only)
# ─────────────────────────────────────────────────────────────────────────────
function Find-OpenSSLOnDisk {
    <# Search for OpenSSL in PATH and well-known install locations. No network. #>
    $candidates = @(
        (Get-Command openssl -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\Program Files\OpenSSL\bin\openssl.exe",
        "C:\Program Files\Git\usr\bin\openssl.exe",
        "C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        "C:\tools\openssl\openssl.exe",
        "C:\OpenSSL-Win64\bin\openssl.exe",
        "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe"
    ) | Where-Object { $_ }

    foreach ($c in $candidates) {
        if (Test-Path $c) {
            Write-Log "Found on disk: $c" "SUCCESS"
            return $c
        }
    }

    # Deep scan of Program Files
    $found = Get-ChildItem "C:\Program Files*" -Recurse -Filter "openssl.exe" -ErrorAction SilentlyContinue |
             Select-Object -First 1 -ExpandProperty FullName
    if ($found) {
        Write-Log "Found via scan: $found" "SUCCESS"
        return $found
    }
    return $null
}

# ─────────────────────────────────────────────────────────────────────────────
#  OPENSSL INSTALLATION — OFFLINE STRATEGIES (bundle directory)
# ─────────────────────────────────────────────────────────────────────────────
function Install-OpenSSL-FromBundlePortable {
    <# Strategy: Use a pre-extracted portable openssl.exe from the bundle. #>
    $portablePaths = @(
        (Join-Path $BundleDir "openssl\bin\openssl.exe"),
        (Join-Path $BundleDir "openssl\openssl.exe"),
        (Join-Path $BundleDir "bin\openssl.exe"),
        (Join-Path $BundleDir "openssl.exe")
    )
    foreach ($p in $portablePaths) {
        if (Test-Path $p) {
            Write-Log "Portable OpenSSL found in bundle: $p" "SUCCESS"
            return $p
        }
    }
    Write-Log "No portable OpenSSL in bundle." "INFO"
    return $null
}

function Install-OpenSSL-FromBundleZip {
    <# Strategy: Extract openssl.zip from the bundle. #>
    $zipPath = Join-Path $BundleDir "openssl.zip"
    if (-not (Test-Path $zipPath)) {
        Write-Log "No openssl.zip in bundle." "INFO"
        return $null
    }

    Write-Log "Extracting openssl.zip from bundle..." "INFO"
    $extractDir = Join-Path $RootDir "tools\openssl"
    if (-not (Test-Path $extractDir)) { New-Item -ItemType Directory -Path $extractDir -Force | Out-Null }

    try {
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
        Write-Log "Extracted to $extractDir" "SUCCESS"

        # Search for openssl.exe inside the extraction
        $exe = Get-ChildItem $extractDir -Recurse -Filter "openssl.exe" -ErrorAction SilentlyContinue |
               Select-Object -First 1 -ExpandProperty FullName
        if ($exe) {
            Write-Log "Found after extraction: $exe" "SUCCESS"
            return $exe
        }
        Write-Log "openssl.exe not found inside ZIP." "WARN"
    } catch {
        Write-Log "ZIP extraction failed: $($_.Exception.Message)" "WARN"
    }
    return $null
}

function Install-OpenSSL-FromBundleMSI {
    <# Strategy: Run a pre-staged MSI from the bundle directory. #>
    $msiPath = Join-Path $BundleDir "openssl-installer.msi"
    if (-not (Test-Path $msiPath)) {
        Write-Log "No openssl-installer.msi in bundle." "INFO"
        return $false
    }

    Write-Log "Installing OpenSSL from bundled MSI: $msiPath" "INFO"
    try {
        Invoke-External -FilePath "msiexec.exe" `
            -Arguments "/i `"$msiPath`" /qn /norestart ADDLOCAL=ALL" `
            -StepName "Bundle MSI install" `
            -AcceptableExitCodes @(0, 3010) `
            -TimeoutSeconds 300
        Refresh-Path
        return $true
    } catch {
        Write-Log "Bundle MSI install failed: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Install-OpenSSL-FromBundleEXE {
    <# Strategy: Run a pre-staged EXE installer from the bundle. #>
    $exePath = Join-Path $BundleDir "openssl-installer.exe"
    if (-not (Test-Path $exePath)) {
        Write-Log "No openssl-installer.exe in bundle." "INFO"
        return $false
    }

    Write-Log "Installing OpenSSL from bundled EXE: $exePath" "INFO"
    try {
        Invoke-External -FilePath $exePath `
            -Arguments "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-" `
            -StepName "Bundle EXE install" `
            -AcceptableExitCodes @(0) `
            -TimeoutSeconds 300
        Refresh-Path
        return $true
    } catch {
        Write-Log "Bundle EXE install failed: $($_.Exception.Message)" "WARN"
        return $false
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  OPENSSL INSTALLATION — ONLINE STRATEGIES
# ─────────────────────────────────────────────────────────────────────────────
function Test-WingetAvailable {
    try { if (Get-Command winget -ErrorAction SilentlyContinue) { return $true } } catch {}
    return $false
}

function Test-ChocolateyAvailable {
    try { if (Get-Command choco -ErrorAction SilentlyContinue) { return $true } } catch {}
    return $false
}

function Install-Chocolatey {
    Write-Log "Installing Chocolatey..." "INFO"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $script = (New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
        $env:ChocolateyInstall = "$env:ProgramData\chocolatey"
        Invoke-Expression $script 2>&1 | ForEach-Object { Write-Log "  [choco-setup] $_" "INFO" }
        $chocoPath = "$env:ProgramData\chocolatey\bin"
        if (Test-Path $chocoPath) { $env:PATH = "$chocoPath;$env:PATH" }
        Write-Log "Chocolatey installed." "SUCCESS"
        return $true
    } catch {
        Write-Log "Chocolatey install failed: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Install-OpenSSL-ViaWinget {
    Write-Log "Online strategy: winget..." "INFO"
    try {
        Invoke-External -FilePath "winget" `
            -Arguments "install --id $OPENSSL_WINGET_ID --accept-package-agreements --accept-source-agreements --silent" `
            -StepName "winget install OpenSSL" `
            -AcceptableExitCodes @(0) `
            -TimeoutSeconds 300
        Refresh-Path
        return $true
    } catch {
        Write-Log "winget failed: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Install-OpenSSL-ViaChocolatey {
    Write-Log "Online strategy: Chocolatey..." "INFO"
    try {
        Invoke-External -FilePath "choco" `
            -Arguments "install $OPENSSL_CHOCO_ID -y --no-progress" `
            -StepName "choco install OpenSSL" `
            -AcceptableExitCodes @(0) `
            -TimeoutSeconds 300
        Refresh-Path
        return $true
    } catch {
        Write-Log "choco failed: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Install-OpenSSL-ViaDirectDownload {
    Write-Log "Online strategy: direct MSI download..." "INFO"
    try {
        Ensure-TempDir
        $msiPath = Join-Path $script:TempDir "openssl-installer.msi"
        Get-FileFromWeb -Url $OPENSSL_MSI_URL -OutPath $msiPath -Label "OpenSSL MSI"

        if ($OPENSSL_MSI_SHA256 -ne "") {
            $hash = (Get-FileHash -Path $msiPath -Algorithm SHA256).Hash
            if ($hash -ne $OPENSSL_MSI_SHA256) {
                Write-Log "SHA256 mismatch — expected: $OPENSSL_MSI_SHA256 got: $hash" "ERROR"
                throw "Hash verification failed."
            }
            Write-Log "SHA256 verified." "SUCCESS"
        }

        Invoke-External -FilePath "msiexec.exe" `
            -Arguments "/i `"$msiPath`" /qn /norestart ADDLOCAL=ALL" `
            -StepName "MSI install OpenSSL" `
            -AcceptableExitCodes @(0, 3010) `
            -TimeoutSeconds 300
        Refresh-Path
        return $true
    } catch {
        Write-Log "Direct download failed: $($_.Exception.Message)" "WARN"
        return $false
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  OPENSSL — MASTER RESOLVER
# ─────────────────────────────────────────────────────────────────────────────
function Resolve-OpenSSL {
    <#
    .SYNOPSIS
        Master resolution chain. Returns the path to a working openssl.exe.

        Resolution order:
          1. Explicit -OpenSSLExePath parameter
          2. Existing install on disk (PATH + well-known locations)
          3. Bundle — portable binary
          4. Bundle — ZIP archive
          5. Bundle — MSI installer
          6. Bundle — EXE installer
          7. (online only) winget
          8. (online only) Chocolatey (bootstrap if needed)
          9. (online only) Direct MSI download
    #>

    $strategyNum = 0

    # ── 1. Explicit path ─────────────────────────────────────────────────────
    $strategyNum++
    if ($OpenSSLExePath -ne "") {
        Write-Log "Strategy $strategyNum : Explicit path: $OpenSSLExePath" "INFO"
        if (Test-Path $OpenSSLExePath) {
            Write-Log "Explicit OpenSSL path valid." "SUCCESS"
            return $OpenSSLExePath
        }
        Write-Log "Explicit path does NOT exist: $OpenSSLExePath" "ERROR"
        throw "Specified -OpenSSLExePath not found."
    } else {
        Write-Log "Strategy $strategyNum : Explicit path — not provided, skipping." "INFO"
    }

    # ── 2. Existing install on disk ──────────────────────────────────────────
    $strategyNum++
    Write-Log "Strategy $strategyNum : Searching existing installs..." "INFO"
    $found = Find-OpenSSLOnDisk
    if ($found) { return $found }

    # ── 3. Bundle — portable ─────────────────────────────────────────────────
    $strategyNum++
    Write-Log "Strategy $strategyNum : Bundle — portable binary..." "INFO"
    if (Test-Path $BundleDir) {
        $portable = Install-OpenSSL-FromBundlePortable
        if ($portable) { return $portable }
    } else {
        Write-Log "Bundle directory not found: $BundleDir" "INFO"
    }

    # ── 4. Bundle — ZIP ──────────────────────────────────────────────────────
    $strategyNum++
    Write-Log "Strategy $strategyNum : Bundle — ZIP archive..." "INFO"
    if (Test-Path $BundleDir) {
        $fromZip = Install-OpenSSL-FromBundleZip
        if ($fromZip) { return $fromZip }
    }

    # ── 5. Bundle — MSI ──────────────────────────────────────────────────────
    $strategyNum++
    Write-Log "Strategy $strategyNum : Bundle — MSI installer..." "INFO"
    if (Test-Path $BundleDir) {
        if (Install-OpenSSL-FromBundleMSI) {
            $found = Find-OpenSSLOnDisk; if ($found) { return $found }
        }
    }

    # ── 6. Bundle — EXE ──────────────────────────────────────────────────────
    $strategyNum++
    Write-Log "Strategy $strategyNum : Bundle — EXE installer..." "INFO"
    if (Test-Path $BundleDir) {
        if (Install-OpenSSL-FromBundleEXE) {
            $found = Find-OpenSSLOnDisk; if ($found) { return $found }
        }
    }

    # ── ONLINE-ONLY strategies ───────────────────────────────────────────────
    if (-not $script:IsOnline) {
        Write-Log "OFFLINE mode — all offline strategies exhausted." "ERROR"
        Write-Log "" "ERROR"
        Write-Log "To run offline, prepare a bundle directory with one of:" "ERROR"
        Write-Log "  <BundleDir>\openssl.exe                  (portable binary)" "ERROR"
        Write-Log "  <BundleDir>\openssl\bin\openssl.exe      (extracted tree)" "ERROR"
        Write-Log "  <BundleDir>\openssl.zip                  (ZIP with bin\openssl.exe)" "ERROR"
        Write-Log "  <BundleDir>\openssl-installer.msi        (MSI installer)" "ERROR"
        Write-Log "  <BundleDir>\openssl-installer.exe        (EXE installer)" "ERROR"
        Write-Log "" "ERROR"
        Write-Log "Then run: .\Install-LocalCA-Localhost.ps1 -BundleDir `"<path>`"" "ERROR"
        throw "OpenSSL not available and no internet connection."
    }

    # ── 7. winget ────────────────────────────────────────────────────────────
    $strategyNum++
    Write-Log "Strategy $strategyNum : Online — winget..." "INFO"
    if (Test-WingetAvailable) {
        if (Install-OpenSSL-ViaWinget) {
            $found = Find-OpenSSLOnDisk; if ($found) { return $found }
        }
    } else {
        Write-Log "winget not available." "INFO"
    }

    # ── 8. Chocolatey ────────────────────────────────────────────────────────
    $strategyNum++
    Write-Log "Strategy $strategyNum : Online — Chocolatey..." "INFO"
    $chocoReady = Test-ChocolateyAvailable
    if (-not $chocoReady) {
        Write-Log "Chocolatey not installed — bootstrapping..." "INFO"
        $chocoReady = Install-Chocolatey
    }
    if ($chocoReady) {
        if (Install-OpenSSL-ViaChocolatey) {
            $found = Find-OpenSSLOnDisk; if ($found) { return $found }
        }
    }

    # ── 9. Direct download ───────────────────────────────────────────────────
    $strategyNum++
    Write-Log "Strategy $strategyNum : Online — direct MSI download..." "INFO"
    if (Install-OpenSSL-ViaDirectDownload) {
        $found = Find-OpenSSLOnDisk; if ($found) { return $found }
    }

    throw "All $strategyNum OpenSSL installation strategies exhausted."
}

function Test-OpenSSLFunctional {
    <# Quick sanity check: can OpenSSL actually generate a key? #>
    Ensure-TempDir
    $testKey = Join-Path $script:TempDir "sanity.key"
    try {
        Invoke-OpenSSL "genrsa -out `"$testKey`" 512" "Sanity test (throwaway 512-bit key)"
        Remove-Item $testKey -Force -ErrorAction SilentlyContinue
        Write-Log "OpenSSL is fully functional." "SUCCESS"
        return $true
    } catch {
        Write-Log "OpenSSL found but NOT functional: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════
try {

    Write-Log "================================================================" "INFO"
    Write-Log "  Local CA Installer — Localhost (Offline-Capable)" "INFO"
    Write-Log "  Started  : $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" "INFO"
    Write-Log "  Machine  : $env:COMPUTERNAME" "INFO"
    Write-Log "  User     : $env:USERNAME" "INFO"
    Write-Log "  OS       : $([Environment]::OSVersion.VersionString)" "INFO"
    Write-Log "  PS       : $($PSVersionTable.PSVersion)" "INFO"
    Write-Log "  App      : $AppName" "INFO"
    Write-Log "  Port     : $HttpsPort" "INFO"
    Write-Log "  Network  : $NetworkMode" "INFO"
    Write-Log "  Bundle   : $BundleDir" "INFO"
    Write-Log "  RootDir  : $RootDir" "INFO"
    Write-Log "================================================================" "INFO"

    # ── PHASE 0: PRE-FLIGHT ──────────────────────────────────────────────────
    Write-Section "PRE-FLIGHT CHECKS" 0

    # Admin
    if (-not (Test-Admin)) {
        if (-not $SkipTrustInstall) {
            Write-Log "Administrator privileges required." "ERROR"
            $script:ExitCode = 1; throw "Not elevated."
        }
        Write-Log "Not elevated — trust-store and firewall steps will be skipped." "WARN"
    } else {
        Write-Log "Running elevated." "SUCCESS"
    }

    # Network
    $script:IsOnline = Resolve-NetworkMode
    Write-Log "Effective mode: $(if ($script:IsOnline) { 'ONLINE' } else { 'OFFLINE' })" "INFO"

    # Bundle directory
    if (Test-Path $BundleDir) {
        Write-Log "Bundle directory found: $BundleDir" "SUCCESS"
        $bundleContents = Get-ChildItem $BundleDir -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        Write-Log "Bundle contents: $($bundleContents -join ', ')" "INFO"
    } else {
        Write-Log "Bundle directory not found: $BundleDir (will rely on installed tools or online install)" "INFO"
    }

    # Port
    $portInUse = Get-NetTCPConnection -LocalPort $HttpsPort -ErrorAction SilentlyContinue
    if ($portInUse) {
        $pid0  = ($portInUse | Select-Object -First 1).OwningProcess
        $name0 = (Get-Process -Id $pid0 -ErrorAction SilentlyContinue).ProcessName
        Write-Log "Port $HttpsPort in use by PID $pid0 ($name0)." "WARN"
    } else {
        Write-Log "Port $HttpsPort available." "SUCCESS"
    }

    # ── PHASE 1: PREREQUISITES ───────────────────────────────────────────────
    Write-Section "PREREQUISITES — OPENSSL" 1

    $script:OpenSSLExe = Resolve-OpenSSL
    Invoke-OpenSSL "version" "Version check"

    if (-not (Test-OpenSSLFunctional)) {
        $script:ExitCode = 2
        throw "OpenSSL is not functional."
    }

    # ── PHASE 2: DIRECTORY STRUCTURE ─────────────────────────────────────────
    Write-Section "DIRECTORY STRUCTURE" 2

    $dirs = @{
        root     = $RootDir
        private  = Join-Path $RootDir "private"
        certs    = Join-Path $RootDir "certs"
        server   = Join-Path $RootDir "server"
        newcerts = Join-Path $RootDir "newcerts"
    }
    foreach ($kv in $dirs.GetEnumerator()) {
        if (-not (Test-Path $kv.Value)) {
            New-Item -ItemType Directory -Path $kv.Value -Force | Out-Null
            Write-Log "Created: $($kv.Value)" "SUCCESS"
        } else {
            Write-Log "Exists:  $($kv.Value)" "INFO"
        }
    }

    $indexFile  = Join-Path $RootDir "index.txt"
    $serialFile = Join-Path $RootDir "serial"
    if (-not (Test-Path $indexFile))  { Set-Content $indexFile  "" -Encoding ASCII }
    if (-not (Test-Path $serialFile)) { Set-Content $serialFile "1000" -Encoding ASCII }

    # Lock down private/
    try {
        $acl = Get-Acl $dirs.private
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
        Set-Acl -Path $dirs.private -AclObject $acl
        Write-Log "ACL on private/ restricted." "SUCCESS"
    } catch {
        Write-Log "ACL failed: $($_.Exception.Message)" "WARN"
    }

    # ── PHASE 3: ROOT CA ─────────────────────────────────────────────────────
    Write-Section "ROOT CA GENERATION" 3

    $caKeyPath  = Join-Path $dirs.private "ca.key"
    $caCertPath = Join-Path $dirs.certs   "ca.crt"

    Remove-IfForce $caKeyPath  "CA key"
    Remove-IfForce $caCertPath "CA cert"

    if (Test-Path $caCertPath) {
        Write-Log "Root CA exists — skipping (use -Force)." "WARN"
        Invoke-OpenSSL "x509 -in `"$caCertPath`" -noout -subject -dates -fingerprint" "Existing CA info"
    } else {
        Invoke-OpenSSL "genrsa -out `"$caKeyPath`" $CA_KEY_BITS" "CA key ($CA_KEY_BITS-bit)"
        $caSubj = "/C=XX/O=$AppName/CN=$AppName Localhost Root CA"
        Invoke-OpenSSL "req -x509 -new -nodes -key `"$caKeyPath`" -sha256 -days $CaValidDays -out `"$caCertPath`" -subj `"$caSubj`"" "Root CA cert"
        Write-Log "Subject: $caSubj | Valid: $CaValidDays days" "INFO"
    }

    # ── PHASE 4: SERVER CERTIFICATE ──────────────────────────────────────────
    Write-Section "LOCALHOST SERVER CERTIFICATE" 4

    $srvKeyPath = Join-Path $dirs.server "localhost.key"
    $srvCsrPath = Join-Path $dirs.server "localhost.csr"
    $srvCrtPath = Join-Path $dirs.server "localhost.crt"
    $srvExtPath = Join-Path $dirs.server "localhost.ext"
    $srvPfxPath = Join-Path $dirs.server "localhost.pfx"
    $srvPemPath = Join-Path $dirs.server "localhost-fullchain.pem"

    Remove-IfForce $srvKeyPath "server key"
    Remove-IfForce $srvCsrPath "server CSR"
    Remove-IfForce $srvCrtPath "server cert"
    Remove-IfForce $srvPfxPath "server PFX"
    Remove-IfForce $srvPemPath "fullchain PEM"

    if (Test-Path $srvCrtPath) {
        Write-Log "Server cert exists — skipping (use -Force)." "WARN"
    } else {
        Invoke-OpenSSL "genrsa -out `"$srvKeyPath`" $SERVER_KEY_BITS" "Server key ($SERVER_KEY_BITS-bit)"

        $srvSubj = "/C=XX/O=$AppName/CN=localhost"
        Invoke-OpenSSL "req -new -key `"$srvKeyPath`" -out `"$srvCsrPath`" -subj `"$srvSubj`"" "Server CSR"

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
        Write-Log "SAN extension file:" "INFO"
        foreach ($s in $LOCALHOST_SANS) { Write-Log "  $($s.Trim())" "INFO" }

        Invoke-OpenSSL "x509 -req -in `"$srvCsrPath`" -CA `"$caCertPath`" -CAkey `"$caKeyPath`" -CAcreateserial -out `"$srvCrtPath`" -days $ServerValidDays -sha256 -extfile `"$srvExtPath`"" "Sign server cert"
        Write-Log "Server cert issued: CN=localhost, valid $ServerValidDays days." "SUCCESS"
    }

    # ── PHASE 5: EXPORT BUNDLES ──────────────────────────────────────────────
    Write-Section "EXPORT BUNDLES (PFX + fullchain PEM)" 5

    Remove-IfForce $srvPfxPath "PFX"
    if (Test-Path $srvPfxPath) {
        Write-Log "PFX exists — skipping." "WARN"
    } else {
        Invoke-OpenSSL "pkcs12 -export -out `"$srvPfxPath`" -inkey `"$srvKeyPath`" -in `"$srvCrtPath`" -certfile `"$caCertPath`" -passout pass:" "PFX export"
        Write-Log "PFX created: $srvPfxPath" "SUCCESS"
    }

    Remove-IfForce $srvPemPath "fullchain PEM"
    if (Test-Path $srvPemPath) {
        Write-Log "Fullchain PEM exists — skipping." "WARN"
    } else {
        $chain = (Get-Content $srvCrtPath -Raw) + "`n" + (Get-Content $caCertPath -Raw)
        Set-Content -Path $srvPemPath -Value $chain -Encoding ASCII -NoNewline
        Write-Log "Fullchain PEM created: $srvPemPath" "SUCCESS"
    }

    # ── PHASE 6: TRUST STORE ─────────────────────────────────────────────────
    Write-Section "WINDOWS TRUST STORE" 6

    if ($SkipTrustInstall) {
        Write-Log "Skipped (-SkipTrustInstall)." "WARN"
    } else {
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caCertPath)

            foreach ($loc in @("LocalMachine","CurrentUser")) {
                $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$loc
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                    [System.Security.Cryptography.X509Certificates.StoreName]::Root, $storeLocation)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $exists = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                if ($exists) {
                    Write-Log "Already in $loc\Root." "INFO"
                } else {
                    $store.Add($cert)
                    Write-Log "Added to $loc\Root." "SUCCESS"
                }
                $store.Close()
            }
            Write-Log "Thumbprint: $($cert.Thumbprint)" "INFO"
        } catch {
            Write-Log "Trust-store error: $($_.Exception.Message)" "ERROR"
            $script:ExitCode = 3
        }
    }

    # ── PHASE 7: FIREWALL ────────────────────────────────────────────────────
    Write-Section "FIREWALL RULE" 7

    if ($SkipFirewallRule) {
        Write-Log "Skipped (-SkipFirewallRule)." "WARN"
    } else {
        $ruleName = "$AppName HTTPS (localhost:$HttpsPort)"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "Rule exists: $ruleName" "INFO"
        } else {
            try {
                New-NetFirewallRule `
                    -DisplayName $ruleName `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort $HttpsPort `
                    -LocalAddress 127.0.0.1 `
                    -Action Allow `
                    -Profile Any `
                    -Description "Inbound HTTPS localhost — $AppName (auto-created)" | Out-Null
                Write-Log "Firewall rule created." "SUCCESS"
            } catch {
                Write-Log "Firewall rule failed: $($_.Exception.Message)" "WARN"
            }
        }
    }

    # ── PHASE 8: VERIFICATION ────────────────────────────────────────────────
    Write-Section "VERIFICATION" 8

    Invoke-OpenSSL "verify -CAfile `"$caCertPath`" `"$srvCrtPath`"" "Chain verification"
    Invoke-OpenSSL "x509 -in `"$srvCrtPath`" -noout -subject -issuer -dates -fingerprint -ext subjectAltName" "Cert details"

    Write-Log "" "INFO"
    Write-Log "=== INTEGRATION SNIPPETS ===" "INFO"
    Write-Log "" "INFO"
    Write-Log "  Kestrel appsettings.json:" "INFO"
    Write-Log "    `"Kestrel`": { `"Endpoints`": { `"Https`": {" "INFO"
    Write-Log "      `"Url`": `"https://localhost:$HttpsPort`"," "INFO"
    Write-Log "      `"Certificate`": { `"Path`": `"$($srvPfxPath -replace '\\','\\')`", `"Password`": `"`" }" "INFO"
    Write-Log "    }}}" "INFO"
    Write-Log "" "INFO"
    Write-Log "  Nginx:  ssl_certificate $srvPemPath;  ssl_certificate_key $srvKeyPath;" "INFO"
    Write-Log "  curl:   curl --cacert `"$caCertPath`" https://localhost:$HttpsPort" "INFO"

    # ── PHASE 9: SUMMARY ─────────────────────────────────────────────────────
    Write-Section "INSTALLATION COMPLETE" 9

    $elapsed = ((Get-Date) - $script:StartTime).TotalSeconds

    Write-Log "" "INFO"
    Write-Log "  Application ............. $AppName" "INFO"
    Write-Log "  Endpoint ................ https://localhost:$HttpsPort" "INFO"
    Write-Log "  Network mode ............ $(if ($script:IsOnline) { 'ONLINE' } else { 'OFFLINE' })" "INFO"
    Write-Log "" "INFO"
    Write-Log "  Root CA key ............. $caKeyPath" "INFO"
    Write-Log "  Root CA cert ............ $caCertPath" "INFO"
    Write-Log "  Server key .............. $srvKeyPath" "INFO"
    Write-Log "  Server cert ............. $srvCrtPath" "INFO"
    Write-Log "  Server PFX .............. $srvPfxPath" "INFO"
    Write-Log "  Fullchain PEM ........... $srvPemPath" "INFO"
    Write-Log "" "INFO"
    Write-Log "  Trust installed ......... $(-not $SkipTrustInstall)" "INFO"
    Write-Log "  Firewall rule ........... $(-not $SkipFirewallRule)" "INFO"
    Write-Log "  OpenSSL ................. $($script:OpenSSLExe)" "INFO"
    Write-Log "  Log ..................... $LogFile" "INFO"
    Write-Log "  Duration ................ $([math]::Round($elapsed, 2))s" "INFO"
    Write-Log "  Exit code ............... $($script:ExitCode)" "INFO"

} catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack: $($_.ScriptStackTrace)" "ERROR"
    if ($script:ExitCode -eq 0) { $script:ExitCode = 99 }
} finally {
    if (Test-Path $script:TempDir) {
        Remove-Item $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Cleaned temp: $($script:TempDir)" "INFO"
    }
    Write-Log "Exit code $script:ExitCode." "INFO"
    exit $script:ExitCode
}
