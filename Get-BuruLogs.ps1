#Requires -Version 5.1

<#
.SYNOPSIS
    BuruGuru - Rebex Buru SFTP Server forensic analysis and incident response tool.

.DESCRIPTION
    BuruGuru is a comprehensive forensic analysis tool for Rebex Buru SFTP Server.
    Performs session reconstruction, file transfer auditing, brute-force detection,
    credential stuffing identification, SSH algorithm assessment, user database
    enumeration, and generates a full IR report, HTML dashboard, and CSV artifact set.

    Auto-detects dev mode when a sibling BuruServer\ folder is present, allowing
    analysis against local log copies without modifying any paths.

.PARAMETER Mode
    live    - Query live server (services, burusftp.exe CLI, live paths/users)
    offline - Process log files only; no live server interaction required

.PARAMETER SkipTimestampConversion
    Skip converting audit log timestamps from Buru native format to ISO 8601.
    Conversion is recommended for timeline correlation with other log sources.

.PARAMETER TimezoneOffsetHours
    UTC offset of the server generating the logs (e.g. -5 for US Central).
    Applied during timestamp conversion. Default: -5

.PARAMETER DateFrom
    Filter analysis to events on or after this date (yyyy-MM-dd).

.PARAMETER DateTo
    Filter analysis to events on or before this date (yyyy-MM-dd).

.PARAMETER UserFilter
    Filter audit analysis to a specific username (exact match).

.PARAMETER AfterHoursStart
    Hour (0-23) defining start of business hours. Events outside the window
    are flagged as after-hours. Default: 6 (6 AM)

.PARAMETER AfterHoursEnd
    Hour (0-23) defining end of business hours. Default: 20 (8 PM)

.PARAMETER BruteForceThreshold
    Minimum failed login attempts from a single IP to flag as brute force. Default: 10

.PARAMETER LargeTransferThresholdMB
    File transfers above this size (MB) are flagged for review. Default: 100

.EXAMPLE
    .\Get-BuruLogs.ps1
    Full analysis against live server (or dev BuruServer\ folder if present).

.EXAMPLE
    .\Get-BuruLogs.ps1 -Mode offline -DateFrom 2023-01-10 -DateTo 2023-03-31
    Offline analysis restricted to Q1 2023.

.EXAMPLE
    .\Get-BuruLogs.ps1 -Mode offline -UserFilter presswise
    Audit trail for a single user.

.NOTES
    Author:   Geoff Tankersley
    Requires: PowerShell 5.1+
    Optional: powershell-yaml module (for config.yaml analysis)
              LiteDB.dll in BuruServer root (for users.ldb analysis)
#>

[CmdletBinding()]
param (
    [ValidateSet("live", "offline", IgnoreCase = $true)]
    [string]$Mode = "live",

    [switch]$SkipTimestampConversion,

    [ValidateRange(-12, 14)]
    [int]$TimezoneOffsetHours = -5,

    [string]$DateFrom,
    [string]$DateTo,
    [string]$UserFilter,

    [ValidateRange(0, 23)]
    [int]$AfterHoursStart = 6,

    [ValidateRange(0, 23)]
    [int]$AfterHoursEnd = 20,

    [int]$BruteForceThreshold = 10,

    [double]$LargeTransferThresholdMB = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ============================================================
# PATHS - auto-detect dev vs. production
# ============================================================
$script:ScriptRoot  = $PSScriptRoot
$script:IsDevMode   = Test-Path (Join-Path $script:ScriptRoot "BuruServer")

if ($script:IsDevMode) {
    $script:BuruRoot      = Join-Path $script:ScriptRoot "BuruServer"
    $script:AuditLogDir   = Join-Path $script:BuruRoot "logs"
    $script:ServerLogDir  = Join-Path $script:BuruRoot "serverlogs"
    $script:ConfigDir     = "C:\ProgramData\Rebex\BuruSftp"
} else {
    $script:BuruRoot      = "C:\Program Files\BuruServer"
    $script:AuditLogDir   = Join-Path $script:BuruRoot "logs"
    $script:ServerLogDir  = Join-Path $script:BuruRoot "serverlogs"
    $script:ConfigDir     = "C:\ProgramData\Rebex\BuruSftp"
}

$script:LiteDbDllPath = Join-Path $script:BuruRoot "LiteDB.dll"
$script:LdbFilePath   = Join-Path $script:ConfigDir "users.ldb"
$script:BuruExe       = Join-Path $script:BuruRoot "burusftp.exe"

$script:OutputDir     = Join-Path $script:ScriptRoot "BuruAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $script:OutputDir -Force | Out-Null

$script:CombinedAuditLog   = Join-Path $script:OutputDir "combined-audit.log"
$script:CombinedServerLog  = Join-Path $script:OutputDir "combined-server.log"
$script:ConvertedAuditLog  = Join-Path $script:OutputDir "converted-audit.log"
$script:ReportPath         = Join-Path $script:OutputDir "BuruAnalysisReport.txt"

# Parse date filters
$script:FilterFrom = $null
$script:FilterTo   = $null
if ($DateFrom) {
    try { $script:FilterFrom = [datetime]::ParseExact($DateFrom, "yyyy-MM-dd", $null) }
    catch { Write-Warning "Invalid DateFrom '$DateFrom'  ignoring filter." }
}
if ($DateTo) {
    try { $script:FilterTo = [datetime]::ParseExact($DateTo, "yyyy-MM-dd", $null).AddDays(1).AddMilliseconds(-1) }
    catch { Write-Warning "Invalid DateTo '$DateTo'  ignoring filter." }
}

$script:TZOffset = [timespan]::FromHours($TimezoneOffsetHours)
$script:TZLabel  = if ($TimezoneOffsetHours -ge 0) { "+{0:00}:00" -f $TimezoneOffsetHours } else { "-{0:00}:00" -f [Math]::Abs($TimezoneOffsetHours) }

# ============================================================
# BURU VERSION TABLE
# ============================================================
$script:VersionTable = @{
    "2.15.6"="2024-11-08"; "2.15.5"="2024-10-31"; "2.15.4"="2024-10-01"
    "2.15.3"="2024-10-01"; "2.15.2"="2024-09-19"; "2.15.1"="2024-09-17"
    "2.15.0"="2024-09-13"; "2.14.5"="2024-08-01"; "2.14.4"="2024-06-07"
    "2.14.3"="2024-06-25"; "2.14.2"="2024-06-21"; "2.14.1"="2024-06-10"
    "2.14.0"="2024-05-21"; "2.13.0"="2024-04-25"; "2.12.1"="2024-04-23"
    "2.12.0"="2024-04-15"; "2.11.4"="2024-03-18"; "2.11.3"="2024-01-18"
    "2.11.2"="2024-01-04"; "2.11.1"="2023-11-22"; "2.11.0"="2023-11-21"
    "2.10.2"="2023-08-11"; "2.10.1"="2023-07-31"; "2.10.0"="2023-07-26"
    "2.9.2" ="2023-06-28"; "2.9.1" ="2023-05-30"; "2.9.0" ="2023-05-09"
    "2.8.3" ="2023-03-30"; "2.8.2" ="2023-03-07"; "2.8.1" ="2023-02-09"
    "2.8.0" ="2023-01-17"; "2.7.2" ="2022-12-15"; "2.7.1" ="2022-11-10"
    "2.7.0" ="2022-10-05"; "2.6.2" ="2022-08-18"; "2.6.1" ="2022-07-07"
}

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

function Write-Section {
    param([string]$Title)
    $line = "=" * 72
    Write-Host "`n$line" -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkCyan
}

function Get-IPCategory {
    param([string]$IP)
    if ($IP -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.)') { return "Internal" }
    if ($IP -match '^(8\.8\.|8\.8\.4\.|1\.1\.1\.|1\.0\.0\.|208\.67\.)') { return "DNS" }
    return "External"
}

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:F2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:F2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:F2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Get-BuruVersionInfo {
    param([string]$Version)
    if ($script:VersionTable.ContainsKey($Version)) {
        $releaseDate = $script:VersionTable[$Version]
        $age = ((Get-Date) - [datetime]::Parse($releaseDate)).Days
        return [PSCustomObject]@{
            Version     = $Version
            ReleaseDate = $releaseDate
            AgeInDays   = $age
            IsCurrent   = $age -lt 90
        }
    }
    return [PSCustomObject]@{ Version = $Version; ReleaseDate = "Unknown"; AgeInDays = -1; IsCurrent = $false }
}

# ============================================================
# MODULE CHECK (powershell-yaml  optional)
# ============================================================
function Test-YamlModule {
    if (Get-Module -ListAvailable -Name powershell-yaml) {
        try { Import-Module powershell-yaml -Force; return $true } catch {}
    }
    Write-Warning "powershell-yaml not installed. Config analysis will be skipped."
    Write-Host "  Install with: Install-Module powershell-yaml -Scope CurrentUser" -ForegroundColor DarkYellow
    return $false
}

# ============================================================
# ENVIRONMENT ASSESSMENT
# ============================================================
function Test-BuruEnvironment {
    Write-Section "ENVIRONMENT ASSESSMENT"

    if ($script:IsDevMode) {
        Write-Host "  [DEV MODE] Using local BuruServer folder: $script:BuruRoot" -ForegroundColor Yellow
    }

    $env = [PSCustomObject]@{
        InstallPath      = $script:BuruRoot
        ConfigPath       = $script:ConfigDir
        BuruVersion      = "Unknown"
        VersionInfo      = $null
        ServicesRunning  = $false
        ProcessesRunning = $false
        AuditLogsPresent = Test-Path $script:AuditLogDir
        ServerLogsPresent= Test-Path $script:ServerLogDir
        ConfigPresent    = Test-Path (Join-Path $script:ConfigDir "config.yaml")
        LiteDbPresent    = Test-Path $script:LdbFilePath
        IsDevMode        = $script:IsDevMode
    }

    # Services
    $services = Get-Service -Name "RebexBuruSftpWA","RebexBuruSftp" -ErrorAction SilentlyContinue
    if ($services) {
        $running = @($services | Where-Object { $_.Status -eq 'Running' })
        $env.ServicesRunning = $running.Count -gt 0
        foreach ($svc in $services) {
            $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Yellow' }
            Write-Host "  Service: $($svc.Name) [$($svc.Status)]" -ForegroundColor $color
        }
    } else {
        Write-Host "  Services: None found (portable or dev mode)" -ForegroundColor Yellow
    }

    # Processes
    $procs = Get-Process -Name "burusftp*" -ErrorAction SilentlyContinue
    if ($procs) {
        $env.ProcessesRunning = $true
        Write-Host "  Processes: $($procs.Count) Buru process(es) running" -ForegroundColor Green
    }

    # Version
    if (Test-Path $script:BuruExe) {
        try {
            $ver = (& $script:BuruExe --version 2>$null)
            if ($ver) {
                $env.BuruVersion = $ver.Trim() -replace '^.*?(\d+\.\d+\.\d+).*$','$1'
                $env.VersionInfo = Get-BuruVersionInfo -Version $env.BuruVersion
            }
        } catch {}
    }

    # Print status
    $present = { param($b) if ($b) { Write-Host "  [FOUND]  " -NoNewline -ForegroundColor Green } else { Write-Host "  [MISSING]" -NoNewline -ForegroundColor Red } }
    & $present $env.AuditLogsPresent;  Write-Host " Audit logs:  $script:AuditLogDir"
    & $present $env.ServerLogsPresent; Write-Host " Server logs: $script:ServerLogDir"
    & $present $env.ConfigPresent;     Write-Host " Config:      $($script:ConfigDir)\config.yaml"
    & $present $env.LiteDbPresent;     Write-Host " User DB:     $script:LdbFilePath"

    Write-Host "  Version: $($env.BuruVersion)" -ForegroundColor Cyan
    if ($env.VersionInfo -and $env.VersionInfo.ReleaseDate -ne "Unknown") {
        $ageColor = if ($env.VersionInfo.IsCurrent) { 'Green' } else { 'Red' }
        Write-Host "  Released: $($env.VersionInfo.ReleaseDate) ($($env.VersionInfo.AgeInDays) days ago)" -ForegroundColor $ageColor
        if (-not $env.VersionInfo.IsCurrent) {
            Write-Host "  [!] Version is older than 90 days  check for updates" -ForegroundColor Red
        }
    }

    return $env
}

# ============================================================
# CONFIGURATION ANALYSIS
# ============================================================
function Get-ConfigurationAnalysis {
    Write-Section "CONFIGURATION ANALYSIS"

    $result = [PSCustomObject]@{
        ConfigFound    = $false
        WebConfigFound = $false
        LicenseFound   = $false
        SSHAlgorithms  = $null
        IPFilters      = $null
        LoggingConfig  = $null
        SecurityIssues = [System.Collections.Generic.List[string]]::new()
        Recommendations= [System.Collections.Generic.List[string]]::new()
        RawConfig      = $null
    }

    $configFile    = Join-Path $script:ConfigDir "config.yaml"
    $webConfigFile = Join-Path $script:ConfigDir "webconfig.yaml"
    $licenseFile   = Join-Path $script:ConfigDir "license.key"

    $hasYaml = Test-YamlModule

    # Main config
    if (Test-Path $configFile) {
        $result.ConfigFound = $true
        Write-Host "  Parsing config.yaml..." -ForegroundColor Gray
        if ($hasYaml) {
            try {
                $raw = Get-Content $configFile -Raw
                $cfg = ConvertFrom-Yaml $raw
                $result.RawConfig = $cfg

                # SSH algorithm assessment
                $result.SSHAlgorithms = Measure-SSHAlgorithms -Config $cfg

                if ($result.SSHAlgorithms.InsecureFound.Count -gt 0) {
                    $result.SecurityIssues.Add("Insecure SSH algorithms configured: $($result.SSHAlgorithms.InsecureFound -join ', ')")
                    $result.Recommendations.Add("Remove insecure algorithms: $($result.SSHAlgorithms.InsecureFound -join ', ')")
                }
                if ($result.SSHAlgorithms.WeakFound.Count -gt 0) {
                    $result.SecurityIssues.Add("Weak SSH algorithms configured: $($result.SSHAlgorithms.WeakFound -join ', ')")
                    $result.Recommendations.Add("Replace weak algorithms with CTR-mode and ETM-MAC variants")
                }

                # IP filtering
                if ($cfg.ipFilter) {
                    $allow = @(if ($cfg.ipFilter.allow) { $cfg.ipFilter.allow } else { @() })
                    $deny  = @(if ($cfg.ipFilter.deny)  { $cfg.ipFilter.deny  } else { @() })
                    $result.IPFilters = [PSCustomObject]@{
                        HasFiltering = ($allow.Count -gt 0 -or $deny.Count -gt 0)
                        AllowRules   = $allow
                        DenyRules    = $deny
                    }
                    if (-not $result.IPFilters.HasFiltering) {
                        $result.SecurityIssues.Add("IP filtering is not configured  all source IPs permitted")
                        $result.Recommendations.Add("Configure ipFilter allow/deny rules to restrict access by IP")
                    }
                } else {
                    $result.SecurityIssues.Add("No ipFilter section found in config  all IPs permitted")
                    $result.Recommendations.Add("Add ipFilter configuration to restrict access")
                }

                # Logging
                if ($cfg.logging) {
                    $result.LoggingConfig = [PSCustomObject]@{
                        ServerLocation   = if ($cfg.logging.server) { $cfg.logging.server.location } else { $null }
                        AccessLocation   = if ($cfg.logging.access) { $cfg.logging.access.location } else { $null }
                        MaxFileCount     = if ($cfg.logging.server) { $cfg.logging.server.maxFileCount } else { $null }
                    }
                    if (-not $result.LoggingConfig.MaxFileCount) {
                        $result.Recommendations.Add("Set logging.server.maxFileCount to prevent unbounded log growth")
                    }
                }

                Write-Host "  config.yaml: parsed OK" -ForegroundColor Green
                Write-Host "    SSH security: $($result.SSHAlgorithms.OverallSecurity)" -ForegroundColor $(
                    switch ($result.SSHAlgorithms.OverallSecurity) { 'Good'{'Green'} 'Weak'{'Yellow'} default{'Red'} }
                )
                if ($result.IPFilters) {
                    Write-Host "    IP filtering: Allow=$($result.IPFilters.AllowRules.Count)  Deny=$($result.IPFilters.DenyRules.Count)"
                }
            } catch {
                Write-Warning "  Failed to parse config.yaml: $_"
                $result.SecurityIssues.Add("config.yaml parse error: $_")
            }
        } else {
            Write-Host "  config.yaml found but powershell-yaml unavailable  skipping parse" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  config.yaml not found at $configFile" -ForegroundColor Red
        $result.SecurityIssues.Add("Main configuration file not found")
    }

    # Web config
    if (Test-Path $webConfigFile) {
        $result.WebConfigFound = $true
        if ($hasYaml) {
            try {
                $webCfg = ConvertFrom-Yaml (Get-Content $webConfigFile -Raw)
                if ($webCfg.bindings) {
                    $httpsBindings = @($webCfg.bindings | Where-Object { $_.certificateFromFile -or $_.port -eq 443 })
                    if ($httpsBindings.Count -eq 0) {
                        $result.SecurityIssues.Add("Web admin interface not configured for HTTPS")
                        $result.Recommendations.Add("Configure HTTPS (port 443 + certificate) for web administration")
                    }
                }
                Write-Host "  webconfig.yaml: parsed OK" -ForegroundColor Green
            } catch {
                Write-Warning "  Failed to parse webconfig.yaml: $_"
            }
        }
    }

    # License
    if (Test-Path $licenseFile) {
        $result.LicenseFound = $true
        Write-Host "  license.key: found" -ForegroundColor Green
    }

    if ($result.SecurityIssues.Count -gt 0) {
        Write-Host "`n  Security Issues:" -ForegroundColor Red
        $result.SecurityIssues | ForEach-Object { Write-Host "    [!] $_" -ForegroundColor Red }
    }
    if ($result.Recommendations.Count -gt 0) {
        Write-Host "  Recommendations:" -ForegroundColor Yellow
        $result.Recommendations | ForEach-Object { Write-Host "    [-] $_" -ForegroundColor Yellow }
    }

    return $result
}

function Measure-SSHAlgorithms {
    param($Config)

    $weak = @{
        kexAlgorithms        = @('diffie-hellman-group14-sha1','diffie-hellman-group-exchange-sha1','diffie-hellman-group1-sha1')
        hostKeyAlgorithms    = @('ssh-dss')
        encryptionAlgorithms = @('aes256-cbc','aes192-cbc','aes128-cbc','3des-cbc','3des-ctr','twofish-cbc','twofish256-cbc','twofish192-cbc','twofish128-cbc')
        macAlgorithms        = @('hmac-sha1','hmac-sha1-96')
    }
    $insecure = @{
        kexAlgorithms        = @()
        hostKeyAlgorithms    = @('ssh-rsa')
        encryptionAlgorithms = @()
        macAlgorithms        = @('hmac-md5','hmac-md5-96')
    }
    $recommended = @{
        kexAlgorithms        = @('curve25519-sha256','curve25519-sha256@libssh.org','ecdh-sha2-nistp521','ecdh-sha2-nistp384','ecdh-sha2-nistp256')
        hostKeyAlgorithms    = @('ssh-ed25519','ecdsa-sha2-nistp521','ecdsa-sha2-nistp384','ecdsa-sha2-nistp256','rsa-sha2-512','rsa-sha2-256')
        encryptionAlgorithms = @('aes256-ctr','aes192-ctr','aes128-ctr','chacha20-poly1305@openssh.com')
        macAlgorithms        = @('hmac-sha2-512-etm@openssh.com','hmac-sha2-256-etm@openssh.com','hmac-sha2-512','hmac-sha2-256')
    }

    $result = [PSCustomObject]@{
        WeakFound       = [System.Collections.Generic.List[string]]::new()
        InsecureFound   = [System.Collections.Generic.List[string]]::new()
        RecommendedUsed = [System.Collections.Generic.List[string]]::new()
        OverallSecurity = "Good"
    }

    if (-not $Config.ssh) { return $result }

    foreach ($cat in @('kexAlgorithms','hostKeyAlgorithms','encryptionAlgorithms','macAlgorithms')) {
        if (-not $Config.ssh.$cat) { continue }
        foreach ($alg in $Config.ssh.$cat) {
            if ($weak[$cat] -contains $alg)      { $result.WeakFound.Add("${cat}: $alg");     $result.OverallSecurity = "Weak" }
            elseif ($insecure[$cat] -contains $alg) { $result.InsecureFound.Add("${cat}: $alg"); if ($result.OverallSecurity -eq "Good") { $result.OverallSecurity = "Poor" } }
            elseif ($recommended[$cat] -contains $alg) { $result.RecommendedUsed.Add("${cat}: $alg") }
        }
    }

    return $result
}

# ============================================================
# LOG COMBINATION
# ============================================================
function Invoke-LogCombination {
    Write-Section "LOG COMBINATION"

    function Merge-Logs {
        param([string]$SourceDir, [string]$Pattern, [string]$OutputFile)
        if (-not (Test-Path $SourceDir)) {
            Write-Host "  [SKIP] Folder not found: $SourceDir" -ForegroundColor Yellow
            return 0
        }
        $files = @(Get-ChildItem -Path $SourceDir -Filter $Pattern | Sort-Object Name)
        if ($files.Count -eq 0) {
            Write-Host "  [SKIP] No files matching $Pattern in $SourceDir" -ForegroundColor Yellow
            return 0
        }
        if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }
        $writer = [System.IO.StreamWriter]::new($OutputFile, $false, [System.Text.Encoding]::UTF8)
        $totalLines = 0
        $cloudErrors = 0
        try {
            foreach ($f in $files) {
                try {
                    $reader = [System.IO.StreamReader]::new($f.FullName, [System.Text.Encoding]::UTF8)
                    try {
                        while ($null -ne ($line = $reader.ReadLine())) {
                            $writer.WriteLine($line)
                            $totalLines++
                        }
                    } finally { $reader.Close() }
                } catch {
                    $msg = $_.Exception.Message
                    if ($msg -match 'cloud|time.out|sync') {
                        $cloudErrors++
                        Write-Warning "  Cloud sync timeout on $($f.Name) - trying Get-Content fallback..."
                        try {
                            $lines = Get-Content -LiteralPath $f.FullName -Encoding UTF8
                            foreach ($line in $lines) { $writer.WriteLine($line); $totalLines++ }
                        } catch {
                            Write-Warning "  Fallback also failed for $($f.Name): skipping. Run 'attrib -U `"$($f.FullName)`"' or sync via OneDrive first."
                        }
                    } else {
                        Write-Warning "  Error reading $($f.Name): $msg"
                    }
                }
            }
        } finally { $writer.Close() }
        if ($cloudErrors -gt 0) {
            Write-Warning "  $cloudErrors file(s) had cloud sync issues. To fix: right-click the logs folder in OneDrive and choose 'Always keep on this device'."
        }
        Write-Host "  Merged $($files.Count) files -> $(Split-Path $OutputFile -Leaf)  ($totalLines lines)" -ForegroundColor $(if ($cloudErrors -gt 0) {'Yellow'} else {'Green'})
        return $totalLines
    }

    $auditLines  = Merge-Logs -SourceDir $script:AuditLogDir  -Pattern "burusftp-audit-*.log"  -OutputFile $script:CombinedAuditLog
    $serverLines = Merge-Logs -SourceDir $script:ServerLogDir -Pattern "burusftp-server-*.log" -OutputFile $script:CombinedServerLog

    return [PSCustomObject]@{ AuditLines = $auditLines; ServerLines = $serverLines }
}

# ============================================================
# TIMESTAMP CONVERSION  (Buru YYYYMMDD_HHmmss.fff -> ISO 8601)
# ============================================================
function Convert-AuditTimestamps {
    if (-not (Test-Path $script:CombinedAuditLog)) { return }
    Write-Host "  Converting audit timestamps to ISO 8601 (UTC$script:TZLabel)..." -ForegroundColor Gray

    $reader = [System.IO.StreamReader]::new($script:CombinedAuditLog, [System.Text.Encoding]::UTF8)
    $writer = [System.IO.StreamWriter]::new($script:ConvertedAuditLog, $false, [System.Text.Encoding]::UTF8)
    $n = 0
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $n++
            if ($n % 100000 -eq 0) { Write-Progress -Activity "Converting timestamps" -Status "$n lines" -PercentComplete -1 }
            # Pattern: 20230110_080633.522 (always first 19 chars, no quotes)
            if ($line.Length -ge 19 -and $line[8] -eq '_') {
                $ts = $line.Substring(0, 19)
                $rest = $line.Substring(19)
                # Fast string-based conversion (avoids DateTime parsing overhead)
                $converted = "$($ts.Substring(0,4))-$($ts.Substring(4,2))-$($ts.Substring(6,2)) " +
                             "$($ts.Substring(9,2)):$($ts.Substring(11,2)):$($ts.Substring(13,6)) " +
                             $script:TZLabel + $rest
                $writer.WriteLine($converted)
            } else {
                $writer.WriteLine($line)
            }
        }
    } finally {
        $reader.Close()
        $writer.Close()
        Write-Progress -Activity "Converting timestamps" -Completed
    }
    Write-Host "  Converted $n lines -> $(Split-Path $script:ConvertedAuditLog -Leaf)" -ForegroundColor Green
}

# ============================================================
# AUDIT LOG ANALYSIS  (single-pass, full session reconstruction)
# ============================================================
function Get-AuditLogAnalysis {
    Write-Section "AUDIT LOG ANALYSIS"

    $sourceFile = if ((Test-Path $script:ConvertedAuditLog) -and (-not $SkipTimestampConversion)) {
        $script:ConvertedAuditLog
    } else {
        $script:CombinedAuditLog
    }

    if (-not (Test-Path $sourceFile)) {
        Write-Warning "Audit log not found: $sourceFile"
        return $null
    }

    # Data structures
    $sessions      = @{}   # sessionId -> session object
    $userStats     = @{}   # username  -> stats
    $ipStats       = @{}   # ip        -> stats
    $ipUserMap     = @{}   # ip        -> {username -> $true}
    $dailyStats    = @{}   # date      -> stats
    $hourlyMatrix  = @{}   # date -> hour -> count
    $fileTransfers = [System.Collections.Generic.List[PSCustomObject]]::new()
    $nullSessions  = [System.Collections.Generic.List[PSCustomObject]]::new()  # credential stuffing
    $afterHoursEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
    $largeTransfers   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timeRange     = @{ Start = $null; End = $null }
    $totalLines    = 0
    $skippedLines  = 0

    $reader = [System.IO.StreamReader]::new($sourceFile, [System.Text.Encoding]::UTF8)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $totalLines++
            if ($totalLines % 100000 -eq 0) {
                Write-Progress -Activity "Parsing audit log" -Status "$totalLines lines processed"
            }

            # Parse line: timestamp,"ip",sessionId,"username","action",[data]
            # Timestamp may be Buru native (YYYYMMDD_HHmmss.fff) or converted ISO
            # Split on comma with limit 6 to preserve data array
            $parts = $line -split ',', 6
            if ($parts.Count -lt 5) { $skippedLines++; continue }

            $tsRaw     = $parts[0].Trim('"')
            $ip        = $parts[1].Trim('"')
            $sessionId = $parts[2].Trim()
            $username  = $parts[3].Trim('"')
            if ($username -eq 'null' -or $username -eq '') { $username = $null }
            $action    = $parts[4].Trim('"')
            $dataField = if ($parts.Count -gt 5) { $parts[5].Trim() } else { "[]" }

            # Parse timestamp
            $timestamp = $null
            # Try ISO converted format first: "2023-01-10 08:06:33.522 -05:00"
            if ($tsRaw -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})') {
                try { $timestamp = [datetime]::ParseExact($matches[1], "yyyy-MM-dd HH:mm:ss.fff", $null) } catch {}
            }
            # Fall back to Buru native: "20230110_080633.522"
            if (-not $timestamp -and $tsRaw -match '^(\d{8}_\d{6}\.\d{3})') {
                try { $timestamp = [datetime]::ParseExact($matches[1], "yyyyMMdd_HHmmss.fff", $null) } catch {}
            }
            if (-not $timestamp) { $skippedLines++; continue }

            # Date filter
            if ($script:FilterFrom -and $timestamp -lt $script:FilterFrom) { continue }
            if ($script:FilterTo   -and $timestamp -gt $script:FilterTo)   { continue }

            # Username filter
            if ($UserFilter -and $username -ne $UserFilter) { continue }

            # Update time range
            if ($null -eq $timeRange.Start -or $timestamp -lt $timeRange.Start) { $timeRange.Start = $timestamp }
            if ($null -eq $timeRange.End   -or $timestamp -gt $timeRange.End)   { $timeRange.End   = $timestamp }

            $dateKey = $timestamp.ToString("yyyy-MM-dd")
            $hour    = $timestamp.Hour

            # Daily stats
            if (-not $dailyStats.ContainsKey($dateKey)) {
                $dailyStats[$dateKey] = @{ Logins=0; Logouts=0; Uploads=0; Downloads=0; UploadBytes=0L; DownloadBytes=0L; UniqueUsers=@{}; UniqueIPs=@{} }
            }
            $dailyStats[$dateKey].UniqueIPs[$ip]        = $true
            if ($username) { $dailyStats[$dateKey].UniqueUsers[$username] = $true }

            # Hourly matrix
            if (-not $hourlyMatrix.ContainsKey($dateKey)) { $hourlyMatrix[$dateKey] = @{} }
            $hourlyMatrix[$dateKey][$hour] = ($hourlyMatrix[$dateKey][$hour] -as [int]) + 1

            # IP stats
            if (-not $ipStats.ContainsKey($ip)) {
                $ipStats[$ip] = @{ Category=(Get-IPCategory $ip); Logins=0; FailedLogins=0; Uploads=0; Downloads=0; UploadBytes=0L; DownloadBytes=0L; Usernames=@{} }
            }
            if ($username) { $ipStats[$ip].Usernames[$username] = $true }

            # User stats
            if ($username) {
                if (-not $userStats.ContainsKey($username)) {
                    $userStats[$username] = @{ IPs=@{}; Logins=0; Uploads=0; Downloads=0; UploadBytes=0L; DownloadBytes=0L; FirstSeen=$timestamp; LastSeen=$timestamp }
                }
                $userStats[$username].IPs[$ip] = $true
                if ($timestamp -lt $userStats[$username].FirstSeen) { $userStats[$username].FirstSeen = $timestamp }
                if ($timestamp -gt $userStats[$username].LastSeen)  { $userStats[$username].LastSeen  = $timestamp }
            }

            # IP->username map (for multi-username detection)
            if ($username) {
                if (-not $ipUserMap.ContainsKey($ip)) { $ipUserMap[$ip] = @{} }
                $ipUserMap[$ip][$username] = $true
            }

            # Session tracking
            if (-not $sessions.ContainsKey($sessionId)) {
                $sessions[$sessionId] = @{
                    SessionId    = $sessionId
                    IP           = $ip
                    Username     = $username
                    LoginTime    = $null
                    LogoutTime   = $null
                    UploadCount  = 0
                    DownloadCount= 0
                    UploadBytes  = 0L
                    DownloadBytes= 0L
                    Files        = [System.Collections.Generic.List[string]]::new()
                }
            }
            if ($username -and -not $sessions[$sessionId].Username) { $sessions[$sessionId].Username = $username }

            # Process by action
            switch ($action) {
                "login" {
                    $sessions[$sessionId].LoginTime = $timestamp
                    $dailyStats[$dateKey].Logins++
                    $ipStats[$ip].Logins++
                    if ($username) { $userStats[$username].Logins++ }

                    # Null-username login = credential stuffing attempt
                    if (-not $username) {
                        $nullSessions.Add([PSCustomObject]@{
                            Timestamp = $timestamp; IP = $ip; SessionId = $sessionId
                        })
                        $ipStats[$ip].FailedLogins++
                    }

                    # After-hours check
                    if ($hour -lt $AfterHoursStart -or $hour -ge $AfterHoursEnd) {
                        $afterHoursEvents.Add([PSCustomObject]@{
                            Timestamp = $timestamp; IP = $ip; Username = $username
                            SessionId = $sessionId; Action = "login"
                        })
                    }
                }
                "logout" {
                    $sessions[$sessionId].LogoutTime = $timestamp
                    $dailyStats[$dateKey].Logouts++
                }
                "upload" {
                    # dataField: ["/mount\file.pdf", 12345]
                    $filePath = $null; $bytes = 0L
                    if ($dataField -match '"([^"]+)"') { $filePath = $matches[1] }
                    if ($dataField -match ',\s*(\d+)\s*\]') { $bytes = [long]$matches[1] }

                    $sessions[$sessionId].UploadCount++
                    $sessions[$sessionId].UploadBytes += $bytes
                    if ($filePath) { $sessions[$sessionId].Files.Add("UP:$filePath") }
                    $dailyStats[$dateKey].Uploads++
                    $dailyStats[$dateKey].UploadBytes += $bytes
                    $ipStats[$ip].Uploads++
                    $ipStats[$ip].UploadBytes += $bytes
                    if ($username) {
                        $userStats[$username].Uploads++
                        $userStats[$username].UploadBytes += $bytes
                    }

                    $transfer = [PSCustomObject]@{
                        Timestamp = $timestamp; Direction = "Upload"; IP = $ip
                        Username  = $username; SessionId = $sessionId
                        FilePath  = $filePath; Bytes = $bytes
                        SizeFmt   = Format-Bytes $bytes
                    }
                    $fileTransfers.Add($transfer)

                    if ($bytes -ge ($LargeTransferThresholdMB * 1MB)) {
                        $largeTransfers.Add($transfer)
                    }
                }
                "download" {
                    $filePath = $null; $bytes = 0L
                    if ($dataField -match '"([^"]+)"') { $filePath = $matches[1] }
                    if ($dataField -match ',\s*(\d+)\s*\]') { $bytes = [long]$matches[1] }

                    $sessions[$sessionId].DownloadCount++
                    $sessions[$sessionId].DownloadBytes += $bytes
                    if ($filePath) { $sessions[$sessionId].Files.Add("DN:$filePath") }
                    $dailyStats[$dateKey].Downloads++
                    $dailyStats[$dateKey].DownloadBytes += $bytes
                    $ipStats[$ip].Downloads++
                    $ipStats[$ip].DownloadBytes += $bytes
                    if ($username) {
                        $userStats[$username].Downloads++
                        $userStats[$username].DownloadBytes += $bytes
                    }

                    $transfer = [PSCustomObject]@{
                        Timestamp = $timestamp; Direction = "Download"; IP = $ip
                        Username  = $username; SessionId = $sessionId
                        FilePath  = $filePath; Bytes = $bytes
                        SizeFmt   = Format-Bytes $bytes
                    }
                    $fileTransfers.Add($transfer)

                    if ($bytes -ge ($LargeTransferThresholdMB * 1MB)) {
                        $largeTransfers.Add($transfer)
                    }
                }
            }
        }
    } finally {
        $reader.Close()
        Write-Progress -Activity "Parsing audit log" -Completed
    }

    # Compute IPs with multiple usernames (credential stuffing / shared egress)
    $multiUserIPs = @($ipUserMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 })

    # ---- Print summary ----
    Write-Host "  Total lines processed : $totalLines" -ForegroundColor White
    Write-Host "  Lines skipped (parse) : $skippedLines" -ForegroundColor $(if ($skippedLines -gt 0) {'Yellow'} else {'Gray'})
    if ($timeRange.Start) {
        Write-Host "  Log time range        : $($timeRange.Start) to $($timeRange.End)" -ForegroundColor White
        Write-Host "  Duration              : $(($timeRange.End - $timeRange.Start).Days) days" -ForegroundColor White
    }
    Write-Host "  Unique IPs            : $($ipStats.Count)" -ForegroundColor White
    Write-Host "  Unique users          : $($userStats.Count)" -ForegroundColor White
    Write-Host "  Total sessions        : $($sessions.Count)" -ForegroundColor White
    Write-Host "  File transfers        : $($fileTransfers.Count) ($(($fileTransfers | Where-Object Direction -eq 'Upload' | Measure-Object).Count) up / $(($fileTransfers | Where-Object Direction -eq 'Download' | Measure-Object).Count) dn)" -ForegroundColor White

    $totalUpBytes   = ($fileTransfers | Where-Object Direction -eq 'Upload'   | Measure-Object Bytes -Sum).Sum
    $totalDnBytes   = ($fileTransfers | Where-Object Direction -eq 'Download' | Measure-Object Bytes -Sum).Sum
    Write-Host "  Data uploaded         : $(Format-Bytes ([long]$totalUpBytes))" -ForegroundColor Cyan
    Write-Host "  Data downloaded       : $(Format-Bytes ([long]$totalDnBytes))" -ForegroundColor Cyan

    if ($nullSessions.Count -gt 0) {
        Write-Host "`n  [!] Auth failures (null sessions): $($nullSessions.Count)" -ForegroundColor Red
        $nullIPs = @($nullSessions | Group-Object IP | Sort-Object Count -Descending | Select-Object -First 10)
        foreach ($g in $nullIPs) {
            Write-Host "      $($g.Name): $($g.Count) failed attempts [$(Get-IPCategory $g.Name)]" -ForegroundColor Red
        }
    }

    if ($multiUserIPs.Count -gt 0) {
        Write-Host "`n  [!] IPs using multiple usernames (possible credential stuffing / shared NAT):" -ForegroundColor Yellow
        foreach ($entry in ($multiUserIPs | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 10)) {
            Write-Host "      $($entry.Key): $($entry.Value.Keys -join ', ')" -ForegroundColor Yellow
        }
    }

    if ($afterHoursEvents.Count -gt 0) {
        Write-Host "`n  [!] After-hours logins (outside $AfterHoursStart:00-$AfterHoursEnd:00): $($afterHoursEvents.Count)" -ForegroundColor Yellow
        $ahUsers = @($afterHoursEvents | Group-Object Username | Sort-Object Count -Descending | Select-Object -First 5)
        foreach ($g in $ahUsers) { Write-Host "      $($g.Name): $($g.Count) after-hours events" -ForegroundColor Yellow }
    }

    if ($largeTransfers.Count -gt 0) {
        Write-Host "`n  [!] Large transfers (>$($LargeTransferThresholdMB) MB): $($largeTransfers.Count)" -ForegroundColor Yellow
        foreach ($t in ($largeTransfers | Sort-Object Bytes -Descending | Select-Object -First 5)) {
            Write-Host "      $($t.Timestamp) | $($t.Username) @ $($t.IP) | $($t.Direction) | $($t.SizeFmt) | $($t.FilePath)" -ForegroundColor Yellow
        }
    }

    # ---- Volume spike detection (statistical) ----
    $dailyCounts = @($dailyStats.GetEnumerator() | ForEach-Object {
        $d = $_.Value
        $events = $d.Logins + $d.Logouts + $d.Uploads + $d.Downloads
        [PSCustomObject]@{ Date = $_.Key; Events = $events }
    } | Sort-Object Date)

    $volumeAnomalies = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($dailyCounts.Count -ge 5) {
        $mean  = ($dailyCounts | Measure-Object Events -Average).Average
        $variance = ($dailyCounts | ForEach-Object { [Math]::Pow($_.Events - $mean, 2) } | Measure-Object -Sum).Sum / $dailyCounts.Count
        $stdev = [Math]::Sqrt($variance)
        $threshold = $mean + (2 * $stdev)

        Write-Host "`n  Daily volume baseline: avg=$([int]$mean)  stdev=$([int]$stdev)  spike threshold=$([int]$threshold)" -ForegroundColor Gray

        foreach ($day in $dailyCounts) {
            if ($day.Events -ge $threshold) {
                $ratio = [Math]::Round($day.Events / $mean, 1)
                $volumeAnomalies.Add([PSCustomObject]@{
                    Date      = $day.Date
                    Events    = $day.Events
                    Mean      = [int]$mean
                    StdevAbove= [Math]::Round(($day.Events - $mean) / $stdev, 1)
                    Ratio     = $ratio
                })
                Write-Host "  [!] VOLUME SPIKE  $($day.Date): $($day.Events) events ($ratio x normal)" -ForegroundColor Red
            }
        }

        Write-Host "`n  Top 10 busiest days:" -ForegroundColor Cyan
        $dailyCounts | Sort-Object Events -Descending | Select-Object -First 10 | ForEach-Object {
            $marker = if ($_.Events -ge $threshold) { " [SPIKE]" } else { "" }
            Write-Host "    $($_.Date)  $($_.Events) events$marker" -ForegroundColor $(if ($_.Events -ge $threshold) { 'Red' } else { 'Gray' })
        }
    }

    # ---- Session velocity detection (many rapid sessions = scanner/bot) ----
    $sessionVelocity = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ipSessionList = @{}
    foreach ($s in $sessions.Values) {
        if ($null -eq $s.LoginTime) { continue }
        if (-not $ipSessionList.ContainsKey($s.IP)) { $ipSessionList[$s.IP] = [System.Collections.Generic.List[datetime]]::new() }
        $ipSessionList[$s.IP].Add($s.LoginTime)
    }
    foreach ($entry in $ipSessionList.GetEnumerator()) {
        $times = @($entry.Value | Sort-Object)
        if ($times.Count -lt 5) { continue }
        # Find densest 10-minute window
        $maxInWindow = 0
        for ($i = 0; $i -lt $times.Count; $i++) {
            $windowEnd = $times[$i].AddMinutes(10)
            $inWindow = 0
            for ($j = $i; $j -lt $times.Count -and $times[$j] -le $windowEnd; $j++) { $inWindow++ }
            if ($inWindow -gt $maxInWindow) { $maxInWindow = $inWindow }
        }
        if ($maxInWindow -ge 20) {
            $sessionVelocity.Add([PSCustomObject]@{
                IP               = $entry.Key
                Category         = Get-IPCategory $entry.Key
                TotalSessions    = $times.Count
                MaxSessionsPer10m= $maxInWindow
                Usernames        = ($ipStats[$entry.Key].Usernames.Keys -join '; ')
            })
        }
    }
    if ($sessionVelocity.Count -gt 0) {
        Write-Host "`n  [!] High-velocity session IPs (>=20 sessions/10 min = automated scanning):" -ForegroundColor Red
        foreach ($sv in ($sessionVelocity | Sort-Object MaxSessionsPer10m -Descending | Select-Object -First 10)) {
            Write-Host "      $($sv.IP.PadRight(18)) $($sv.MaxSessionsPer10m)/10min  total=$($sv.TotalSessions)  users=$($sv.Usernames)" -ForegroundColor Red
        }
    }

    # ---- Hourly heatmap summary ----
    $hourTotals = @{}
    foreach ($dayMatrix in $hourlyMatrix.Values) {
        foreach ($h in $dayMatrix.GetEnumerator()) {
            $hourTotals[$h.Key] = ($hourTotals[$h.Key] -as [int]) + $h.Value
        }
    }
    Write-Host "`n  Hourly activity heatmap (all days):" -ForegroundColor Cyan
    $hourRow = ""
    0..23 | ForEach-Object { $hourRow += "{0,5}" -f $_ }
    Write-Host "    $hourRow" -ForegroundColor DarkGray
    $countRow = ""
    0..23 | ForEach-Object {
        $v = ($hourTotals[$_] -as [int])
        $countRow += "{0,5}" -f [int]($v / [Math]::Max(1, $dailyCounts.Count))
    }
    Write-Host "    $countRow  (avg events/day/hour)" -ForegroundColor Gray

    Write-Host "`n  Top 10 users by upload volume:" -ForegroundColor Cyan
    $userStats.GetEnumerator() | Sort-Object { $_.Value.UploadBytes } -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Host "    $($_.Key.PadRight(20)) uploads=$($_.Value.Uploads)  $(Format-Bytes $_.Value.UploadBytes)  from $($_.Value.IPs.Count) IP(s)" -ForegroundColor Gray
    }

    Write-Host "`n  Top 10 IPs by session count:" -ForegroundColor Cyan
    $ipStats.GetEnumerator() | Sort-Object { $_.Value.Logins } -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Host "    $($_.Key.PadRight(18)) [$($_.Value.Category.PadRight(8))]  logins=$($_.Value.Logins)  uploads=$(Format-Bytes $_.Value.UploadBytes)" -ForegroundColor Gray
    }

    return [PSCustomObject]@{
        TotalLines        = $totalLines
        TimeRange         = $timeRange
        Sessions          = $sessions
        UserStats         = $userStats
        IPStats           = $ipStats
        IPUserMap         = $ipUserMap
        DailyStats        = $dailyStats
        HourlyMatrix      = $hourlyMatrix
        FileTransfers     = $fileTransfers
        NullSessions      = $nullSessions
        MultiUserIPs      = $multiUserIPs
        AfterHoursEvents  = $afterHoursEvents
        LargeTransfers    = $largeTransfers
        TotalUploadBytes  = [long]$totalUpBytes
        TotalDownloadBytes= [long]$totalDnBytes
        VolumeAnomalies   = $volumeAnomalies
        SessionVelocity   = $sessionVelocity
        DailyCounts       = $dailyCounts
        HourTotals        = $hourTotals
    }
}

# ============================================================
# SERVER LOG ANALYSIS
# ============================================================
function Get-ServerLogAnalysis {
    Write-Section "SERVER LOG ANALYSIS"

    if (-not (Test-Path $script:CombinedServerLog)) {
        Write-Warning "Server log not found: $script:CombinedServerLog"
        return $null
    }

    # Patterns
    $failedPwPattern  = [regex]'Session \d+: "([^@"]+)@([^"]+)" supplied a password but the password doesn''t match'
    $failedKeyPattern = [regex]'Session \d+: "([^@"]+)@([^"]+)" supplied a public key but'
    $timestampPat     = [regex]'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}'
    $ipPat            = [regex]'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    $failedPassByIP   = @{}
    $failedPassByUser = @{}
    $failedKeyByIP    = @{}
    $allIPCounts      = @{}
    $dailyEvents      = @{}
    $timeRange        = @{ Start = $null; End = $null }
    $totalLines       = 0

    $reader = [System.IO.StreamReader]::new($script:CombinedServerLog, [System.Text.Encoding]::UTF8)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $totalLines++
            if ($totalLines % 100000 -eq 0) { Write-Progress -Activity "Parsing server log" -Status "$totalLines lines" }

            # Timestamp
            $tsMatch = $timestampPat.Match($line)
            if ($tsMatch.Success) {
                try {
                    $ts = [datetime]::ParseExact($tsMatch.Value, "yyyy-MM-dd HH:mm:ss.fff", $null)
                    if ($null -eq $timeRange.Start -or $ts -lt $timeRange.Start) { $timeRange.Start = $ts }
                    if ($null -eq $timeRange.End   -or $ts -gt $timeRange.End)   { $timeRange.End   = $ts }
                    $dk = $ts.ToString("yyyy-MM-dd")
                    $dailyEvents[$dk] = ($dailyEvents[$dk] -as [int]) + 1
                } catch {}
            }

            # Failed password
            $m = $failedPwPattern.Match($line)
            if ($m.Success) {
                $user = $m.Groups[1].Value; $ip = $m.Groups[2].Value
                $failedPassByIP[$ip]     = ($failedPassByIP[$ip]     -as [int]) + 1
                $failedPassByUser[$user] = ($failedPassByUser[$user] -as [int]) + 1
            }

            # Failed public key
            $mk = $failedKeyPattern.Match($line)
            if ($mk.Success) {
                $ip = $mk.Groups[2].Value
                $failedKeyByIP[$ip] = ($failedKeyByIP[$ip] -as [int]) + 1
            }

            # All IPs
            foreach ($im in $ipPat.Matches($line)) {
                $allIPCounts[$im.Value] = ($allIPCounts[$im.Value] -as [int]) + 1
            }
        }
    } finally {
        $reader.Close()
        Write-Progress -Activity "Parsing server log" -Completed
    }

    $totalFailed = ($failedPassByIP.Values | Measure-Object -Sum).Sum -as [int]
    $bruteForceIPs = @($failedPassByIP.GetEnumerator() | Where-Object { $_.Value -ge $BruteForceThreshold } | Sort-Object Value -Descending)

    Write-Host "  Total lines processed  : $totalLines" -ForegroundColor White
    if ($timeRange.Start) {
        Write-Host "  Log time range         : $($timeRange.Start) to $($timeRange.End)" -ForegroundColor White
    }
    Write-Host "  Total failed passwords : $totalFailed from $($failedPassByIP.Count) unique IPs" -ForegroundColor $(if ($totalFailed -gt 0) {'Red'} else {'Green'})
    Write-Host "  Unique IPs in logs     : $($allIPCounts.Count)" -ForegroundColor White

    if ($bruteForceIPs.Count -gt 0) {
        Write-Host "`n  [!] Brute-force IPs (>=$BruteForceThreshold failed passwords):" -ForegroundColor Red
        foreach ($entry in ($bruteForceIPs | Select-Object -First 20)) {
            Write-Host "      $($entry.Key.PadRight(18)) $($entry.Value) attempts [$(Get-IPCategory $entry.Key)]" -ForegroundColor Red
        }
    }

    if ($failedPassByUser.Count -gt 0) {
        Write-Host "`n  Top targeted usernames:" -ForegroundColor Yellow
        $failedPassByUser.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
            Write-Host "      $($_.Key.PadRight(20)) $($_.Value) attempts" -ForegroundColor Yellow
        }
    }

    $internalIPs = @($allIPCounts.Keys | Where-Object { (Get-IPCategory $_) -eq 'Internal' })
    $externalIPs = @($allIPCounts.Keys | Where-Object { (Get-IPCategory $_) -eq 'External' })
    Write-Host "`n  IP breakdown: $($internalIPs.Count) internal, $($externalIPs.Count) external" -ForegroundColor Cyan

    return [PSCustomObject]@{
        TotalLines      = $totalLines
        TimeRange       = $timeRange
        FailedPassByIP  = $failedPassByIP
        FailedPassByUser= $failedPassByUser
        FailedKeyByIP   = $failedKeyByIP
        AllIPCounts     = $allIPCounts
        BruteForceIPs   = $bruteForceIPs
        DailyEvents     = $dailyEvents
        InternalIPs     = $internalIPs
        ExternalIPs     = $externalIPs
    }
}

# ============================================================
# LITEDB USER DATABASE ANALYSIS
# ============================================================
function Get-LiteDBAnalysis {
    Write-Section "USER DATABASE ANALYSIS (LiteDB)"

    if (-not (Test-Path $script:LiteDbDllPath)) {
        Write-Host "  LiteDB.dll not found at: $script:LiteDbDllPath" -ForegroundColor Yellow
        Write-Host "  Skipping user database analysis." -ForegroundColor Yellow
        return $null
    }
    if (-not (Test-Path $script:LdbFilePath)) {
        Write-Host "  users.ldb not found at: $script:LdbFilePath" -ForegroundColor Yellow
        return $null
    }

    try {
        Add-Type -Path $script:LiteDbDllPath

        $db = [LiteDB.LiteDatabase]::new("Filename=$script:LdbFilePath;ReadOnly=true")
        $result = [PSCustomObject]@{
            Collections      = @()
            UserCount        = 0
            Users            = @()
            LoginHistoryCount= 0
            RecentLogins     = @()
        }

        try {
            $result.Collections = @($db.GetCollectionNames())
            Write-Host "  Collections: $($result.Collections -join ', ')" -ForegroundColor Cyan

            if ($result.Collections -contains "User") {
                $col = $db.GetCollection("User")
                $result.UserCount = $col.Count()
                $result.Users = @($col.FindAll() | Select-Object -First 100)
                Write-Host "  User accounts: $($result.UserCount)" -ForegroundColor Green
                $result.Users | Select-Object -First 20 | ForEach-Object {
                    Write-Host "    $($_.Name)" -ForegroundColor Gray
                }
            }

            if ($result.Collections -contains "UserLoginHistory") {
                $col = $db.GetCollection("UserLoginHistory")
                $result.LoginHistoryCount = $col.Count()
                $result.RecentLogins = @($col.FindAll() | Select-Object -Last 20)
                Write-Host "  Login history records: $($result.LoginHistoryCount)" -ForegroundColor Green
            }
        } finally {
            $db.Dispose()
        }

        return $result
    } catch {
        Write-Warning "LiteDB analysis failed: $_"
        return $null
    }
}

# ============================================================
# LIVE SYSTEM INFO
# ============================================================
function Get-LiveSystemInfo {
    if ($Mode -ne "live") { return $null }
    Write-Section "LIVE SYSTEM INFORMATION"

    if (-not (Test-Path $script:BuruExe)) {
        Write-Warning "burusftp.exe not found at: $script:BuruExe"
        return $null
    }

    $info = [PSCustomObject]@{ Version="Unknown"; Users=@(); Paths=@(); Services=@() }

    try {
        $ver = & $script:BuruExe --version 2>$null
        if ($ver) { $info.Version = $ver.Trim(); Write-Host "  Version: $($info.Version)" -ForegroundColor Green }

        try {
            $users = & $script:BuruExe user list -v 2>$null
            if ($users) { $info.Users = @($users); Write-Host "  Users: $($info.Users.Count)" -ForegroundColor Green }
        } catch {}

        try {
            $paths = & $script:BuruExe path list --format csv 2>$null
            if ($paths) { $info.Paths = @($paths); Write-Host "  Configured paths: $($info.Paths.Count)" -ForegroundColor Green }
        } catch {}
    } catch { Write-Warning "Error querying burusftp.exe: $_" }

    $info.Services = @(Get-Service -Name "RebexBuru*" -ErrorAction SilentlyContinue)
    foreach ($svc in $info.Services) {
        $c = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
        Write-Host "  $($svc.Name): $($svc.Status)" -ForegroundColor $c
    }

    return $info
}

# ============================================================
# CSV EXPORTS
# ============================================================
function Export-AnalysisArtifacts {
    param(
        [object]$Audit,
        [object]$Server
    )

    Write-Section "EXPORTING CSV ARTIFACTS"

    if ($Audit) {
        # Sessions
        $sessionRows = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($s in $Audit.Sessions.Values) {
            $duration = if ($s.LoginTime -and $s.LogoutTime) {
                [int]($s.LogoutTime - $s.LoginTime).TotalSeconds
            } else { $null }
            $sessionRows.Add([PSCustomObject]@{
                SessionId     = $s.SessionId
                Username      = $s.Username
                IP            = $s.IP
                Category      = Get-IPCategory $s.IP
                LoginTime     = $s.LoginTime
                LogoutTime    = $s.LogoutTime
                DurationSec   = $duration
                UploadCount   = $s.UploadCount
                DownloadCount = $s.DownloadCount
                UploadBytes   = $s.UploadBytes
                DownloadBytes = $s.DownloadBytes
                UploadFmt     = Format-Bytes $s.UploadBytes
                DownloadFmt   = Format-Bytes $s.DownloadBytes
            })
        }
        $sessionRows | Sort-Object LoginTime | Export-Csv (Join-Path $script:OutputDir "Sessions.csv") -NoTypeInformation
        Write-Host "  Sessions.csv          ($($sessionRows.Count) rows)" -ForegroundColor Green

        # File transfers
        if ($Audit.FileTransfers.Count -gt 0) {
            $Audit.FileTransfers | Sort-Object Timestamp | Export-Csv (Join-Path $script:OutputDir "FileTransfers.csv") -NoTypeInformation
            Write-Host "  FileTransfers.csv     ($($Audit.FileTransfers.Count) rows)" -ForegroundColor Green
        }

        # User activity
        $userRows = $Audit.UserStats.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{
                Username      = $_.Key
                Logins        = $_.Value.Logins
                Uploads       = $_.Value.Uploads
                Downloads     = $_.Value.Downloads
                UploadBytes   = $_.Value.UploadBytes
                DownloadBytes = $_.Value.DownloadBytes
                UploadFmt     = Format-Bytes $_.Value.UploadBytes
                DownloadFmt   = Format-Bytes $_.Value.DownloadBytes
                UniqueIPs     = $_.Value.IPs.Count
                IPs           = ($_.Value.IPs.Keys -join '; ')
                FirstSeen     = $_.Value.FirstSeen
                LastSeen      = $_.Value.LastSeen
            }
        } | Sort-Object UploadBytes -Descending
        $userRows | Export-Csv (Join-Path $script:OutputDir "UserActivity.csv") -NoTypeInformation
        Write-Host "  UserActivity.csv      ($($userRows.Count) rows)" -ForegroundColor Green

        # IP summary
        $ipRows = $Audit.IPStats.GetEnumerator() | ForEach-Object {
            $failedPwCount = if ($Server -and $Server.FailedPassByIP.ContainsKey($_.Key)) { $Server.FailedPassByIP[$_.Key] } else { 0 }
            [PSCustomObject]@{
                IP              = $_.Key
                Category        = $_.Value.Category
                Logins          = $_.Value.Logins
                AuditFailedAuth = $_.Value.FailedLogins
                ServerFailedPw  = $failedPwCount
                Uploads         = $_.Value.Uploads
                Downloads       = $_.Value.Downloads
                UploadBytes     = $_.Value.UploadBytes
                DownloadBytes   = $_.Value.DownloadBytes
                UploadFmt       = Format-Bytes $_.Value.UploadBytes
                UniqueUsernames = $_.Value.Usernames.Count
                Usernames       = ($_.Value.Usernames.Keys -join '; ')
            }
        } | Sort-Object ServerFailedPw -Descending
        $ipRows | Export-Csv (Join-Path $script:OutputDir "IPSummary.csv") -NoTypeInformation
        Write-Host "  IPSummary.csv         ($($ipRows.Count) rows)" -ForegroundColor Green

        # Daily stats
        $dailyRows = $Audit.DailyStats.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{
                Date          = $_.Key
                Logins        = $_.Value.Logins
                Logouts       = $_.Value.Logouts
                Uploads       = $_.Value.Uploads
                Downloads     = $_.Value.Downloads
                UploadBytes   = $_.Value.UploadBytes
                DownloadBytes = $_.Value.DownloadBytes
                UploadFmt     = Format-Bytes $_.Value.UploadBytes
                UniqueIPs     = $_.Value.UniqueIPs.Count
                UniqueUsers   = $_.Value.UniqueUsers.Count
            }
        } | Sort-Object Date
        $dailyRows | Export-Csv (Join-Path $script:OutputDir "DailyStats.csv") -NoTypeInformation
        Write-Host "  DailyStats.csv        ($($dailyRows.Count) rows)" -ForegroundColor Green

        # Null sessions (credential stuffing)
        if ($Audit.NullSessions.Count -gt 0) {
            $Audit.NullSessions | Sort-Object Timestamp | Export-Csv (Join-Path $script:OutputDir "CredentialStuffing.csv") -NoTypeInformation
            Write-Host "  CredentialStuffing.csv ($($Audit.NullSessions.Count) rows)" -ForegroundColor Red
        }

        # After-hours events
        if ($Audit.AfterHoursEvents.Count -gt 0) {
            $Audit.AfterHoursEvents | Sort-Object Timestamp | Export-Csv (Join-Path $script:OutputDir "AfterHoursActivity.csv") -NoTypeInformation
            Write-Host "  AfterHoursActivity.csv ($($Audit.AfterHoursEvents.Count) rows)" -ForegroundColor Yellow
        }

        # Large transfers
        if ($Audit.LargeTransfers.Count -gt 0) {
            $Audit.LargeTransfers | Sort-Object Bytes -Descending | Export-Csv (Join-Path $script:OutputDir "LargeTransfers.csv") -NoTypeInformation
            Write-Host "  LargeTransfers.csv    ($($Audit.LargeTransfers.Count) rows)" -ForegroundColor Yellow
        }

        # Volume anomaly days
        if ($Audit.VolumeAnomalies.Count -gt 0) {
            $Audit.VolumeAnomalies | Sort-Object Events -Descending | Export-Csv (Join-Path $script:OutputDir "VolumeAnomalies.csv") -NoTypeInformation
            Write-Host "  VolumeAnomalies.csv   ($($Audit.VolumeAnomalies.Count) spike days)" -ForegroundColor Red
        }

        # Session velocity (automated scanners)
        if ($Audit.SessionVelocity.Count -gt 0) {
            $Audit.SessionVelocity | Sort-Object MaxSessionsPer10m -Descending | Export-Csv (Join-Path $script:OutputDir "SessionVelocity.csv") -NoTypeInformation
            Write-Host "  SessionVelocity.csv   ($($Audit.SessionVelocity.Count) high-velocity IPs)" -ForegroundColor Red
        }

        # Full daily counts for charting
        $Audit.DailyCounts | Export-Csv (Join-Path $script:OutputDir "DailyEventCounts.csv") -NoTypeInformation
        Write-Host "  DailyEventCounts.csv  ($($Audit.DailyCounts.Count) days)" -ForegroundColor Green

        # Hourly heatmap
        $heatmapRows = 0..23 | ForEach-Object {
            [PSCustomObject]@{ Hour = $_; TotalEvents = ($Audit.HourTotals[$_] -as [int]) }
        }
        $heatmapRows | Export-Csv (Join-Path $script:OutputDir "HourlyHeatmap.csv") -NoTypeInformation
        Write-Host "  HourlyHeatmap.csv     (24 rows)" -ForegroundColor Green
    }

    # Failed logins from server logs
    if ($Server -and $Server.FailedPassByIP.Count -gt 0) {
        $Server.FailedPassByIP.GetEnumerator() |
            Select-Object @{N='IP';E={$_.Key}}, @{N='FailedPasswords';E={$_.Value}}, @{N='Category';E={Get-IPCategory $_.Key}} |
            Sort-Object FailedPasswords -Descending |
            Export-Csv (Join-Path $script:OutputDir "FailedLogins.csv") -NoTypeInformation
        Write-Host "  FailedLogins.csv      ($($Server.FailedPassByIP.Count) rows)" -ForegroundColor Green
    }

    # IOC / Threat indicators - consolidated suspicious IPs
    $iocList = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($Audit) {
        foreach ($s in @($Audit.NullSessions | Group-Object IP)) {
            $iocList.Add([PSCustomObject]@{
                IP = $s.Name; Category = Get-IPCategory $s.Name
                Indicator = "CredentialStuffing"
                Detail = "$($s.Count) failed auth (null session) attempts from audit log"
            })
        }
        foreach ($sv in $Audit.SessionVelocity) {
            $iocList.Add([PSCustomObject]@{
                IP = $sv.IP; Category = $sv.Category
                Indicator = "HighVelocityScanning"
                Detail = "$($sv.MaxSessionsPer10m) sessions/10min, $($sv.TotalSessions) total sessions"
            })
        }
        foreach ($entry in $Audit.MultiUserIPs) {
            $iocList.Add([PSCustomObject]@{
                IP = $entry.Key; Category = Get-IPCategory $entry.Key
                Indicator = "MultipleUsernames"
                Detail = "Used $($entry.Value.Count) distinct usernames: $($entry.Value.Keys -join ', ')"
            })
        }
    }
    if ($Server) {
        foreach ($entry in $Server.BruteForceIPs) {
            $iocList.Add([PSCustomObject]@{
                IP = $entry.Key; Category = Get-IPCategory $entry.Key
                Indicator = "BruteForce"
                Detail = "$($entry.Value) failed password attempts in server log"
            })
        }
    }
    if ($iocList.Count -gt 0) {
        $iocList | Sort-Object Indicator, IP | Export-Csv (Join-Path $script:OutputDir "ThreatIndicators.csv") -NoTypeInformation
        Write-Host "  ThreatIndicators.csv  ($($iocList.Count) indicators)" -ForegroundColor Red
    }

    Write-Host "`n  All artifacts saved to: $script:OutputDir" -ForegroundColor Cyan
}

# ============================================================
# FINAL REPORT
# ============================================================
function New-AnalysisReport {
    param(
        [object]$Env,
        [object]$Config,
        [object]$Audit,
        [object]$Server,
        [object]$Database,
        [object]$Live
    )

    Write-Section "GENERATING REPORT"

    $sb = [System.Text.StringBuilder]::new()

    $header = @"
================================================================================
                   BURU SFTP SECURITY ANALYSIS REPORT
================================================================================
Generated     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Mode          : $Mode
Dev Mode      : $($Env.IsDevMode)
Date Filter   : $(if ($script:FilterFrom) { $script:FilterFrom.ToString('yyyy-MM-dd') } else { 'none' }) to $(if ($script:FilterTo) { $script:FilterTo.ToString('yyyy-MM-dd') } else { 'none' })
User Filter   : $(if ($UserFilter) { $UserFilter } else { 'none' })
Script Version: BuruGuru v1.0
Output Dir    : $script:OutputDir

"@
    [void]$sb.Append($header)

    # Environment
    [void]$sb.AppendLine("================================================================================")
    [void]$sb.AppendLine("ENVIRONMENT")
    [void]$sb.AppendLine("================================================================================")
    [void]$sb.AppendLine("Install Path   : $($Env.InstallPath)")
    [void]$sb.AppendLine("Config Path    : $($Env.ConfigPath)")
    [void]$sb.AppendLine("Version        : $($Env.BuruVersion)")
    if ($Env.VersionInfo -and $Env.VersionInfo.ReleaseDate -ne "Unknown") {
        [void]$sb.AppendLine("Released       : $($Env.VersionInfo.ReleaseDate) ($($Env.VersionInfo.AgeInDays) days ago)$(if (-not $Env.VersionInfo.IsCurrent) { ' [OUTDATED]' })")
    }
    [void]$sb.AppendLine("Services       : $(if ($Env.ServicesRunning) { 'Running' } else { 'Not running' })")
    [void]$sb.AppendLine("Audit Logs     : $(if ($Env.AuditLogsPresent) { 'Present' } else { 'MISSING' })")
    [void]$sb.AppendLine("Server Logs    : $(if ($Env.ServerLogsPresent) { 'Present' } else { 'MISSING' })")
    [void]$sb.AppendLine("Config File    : $(if ($Env.ConfigPresent) { 'Present' } else { 'MISSING' })")
    [void]$sb.AppendLine("User DB (LDB)  : $(if ($Env.LiteDbPresent) { 'Present' } else { 'MISSING' })")
    [void]$sb.AppendLine("")

    # Config
    if ($Config) {
        [void]$sb.AppendLine("================================================================================")
        [void]$sb.AppendLine("CONFIGURATION ANALYSIS")
        [void]$sb.AppendLine("================================================================================")
        [void]$sb.AppendLine("config.yaml    : $(if ($Config.ConfigFound) { 'Found' } else { 'NOT FOUND' })")
        [void]$sb.AppendLine("webconfig.yaml : $(if ($Config.WebConfigFound) { 'Found' } else { 'NOT FOUND' })")
        [void]$sb.AppendLine("license.key    : $(if ($Config.LicenseFound) { 'Found' } else { 'NOT FOUND' })")
        if ($Config.SSHAlgorithms) {
            [void]$sb.AppendLine("SSH Security   : $($Config.SSHAlgorithms.OverallSecurity)")
            if ($Config.SSHAlgorithms.WeakFound.Count -gt 0) {
                [void]$sb.AppendLine("  Weak algos   : $($Config.SSHAlgorithms.WeakFound -join ', ')")
            }
            if ($Config.SSHAlgorithms.InsecureFound.Count -gt 0) {
                [void]$sb.AppendLine("  Insecure alg : $($Config.SSHAlgorithms.InsecureFound -join ', ')")
            }
        }
        if ($Config.IPFilters) {
            [void]$sb.AppendLine("IP Filtering   : Allow=$($Config.IPFilters.AllowRules.Count)  Deny=$($Config.IPFilters.DenyRules.Count)")
        }
        if ($Config.SecurityIssues.Count -gt 0) {
            [void]$sb.AppendLine("`nSecurity Issues:")
            $Config.SecurityIssues | ForEach-Object { [void]$sb.AppendLine("  [!] $_") }
        }
        if ($Config.Recommendations.Count -gt 0) {
            [void]$sb.AppendLine("`nRecommendations:")
            $Config.Recommendations | ForEach-Object { [void]$sb.AppendLine("  [-] $_") }
        }
        [void]$sb.AppendLine("")
    }

    # Audit
    if ($Audit) {
        [void]$sb.AppendLine("================================================================================")
        [void]$sb.AppendLine("AUDIT LOG ANALYSIS")
        [void]$sb.AppendLine("================================================================================")
        if ($Audit.TimeRange.Start) {
            [void]$sb.AppendLine("Time Range     : $($Audit.TimeRange.Start) -> $($Audit.TimeRange.End)")
            [void]$sb.AppendLine("Duration       : $(($Audit.TimeRange.End - $Audit.TimeRange.Start).Days) days")
        }
        [void]$sb.AppendLine("Lines Parsed   : $($Audit.TotalLines)")
        [void]$sb.AppendLine("Sessions       : $($Audit.Sessions.Count)")
        [void]$sb.AppendLine("Unique IPs     : $($Audit.IPStats.Count)")
        [void]$sb.AppendLine("Unique Users   : $($Audit.UserStats.Count)")
        [void]$sb.AppendLine("File Transfers : $($Audit.FileTransfers.Count)")
        [void]$sb.AppendLine("Data Uploaded  : $(Format-Bytes $Audit.TotalUploadBytes)")
        [void]$sb.AppendLine("Data Downloaded: $(Format-Bytes $Audit.TotalDownloadBytes)")
        [void]$sb.AppendLine("")

        if ($Audit.NullSessions.Count -gt 0) {
            [void]$sb.AppendLine("[!] CREDENTIAL STUFFING (null sessions): $($Audit.NullSessions.Count) events")
            $Audit.NullSessions | Group-Object IP | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
                [void]$sb.AppendLine("    $($_.Name): $($_.Count) attempts")
            }
            [void]$sb.AppendLine("")
        }

        if ($Audit.MultiUserIPs.Count -gt 0) {
            [void]$sb.AppendLine("[!] IPs WITH MULTIPLE USERNAMES:")
            foreach ($e in ($Audit.MultiUserIPs | Sort-Object { $_.Value.Count } -Descending)) {
                [void]$sb.AppendLine("    $($e.Key): $($e.Value.Keys -join ', ')")
            }
            [void]$sb.AppendLine("")
        }

        [void]$sb.AppendLine("TOP USERS BY UPLOAD VOLUME:")
        $Audit.UserStats.GetEnumerator() | Sort-Object { $_.Value.UploadBytes } -Descending | Select-Object -First 10 | ForEach-Object {
            [void]$sb.AppendLine("  $($_.Key.PadRight(20)) $(Format-Bytes $_.Value.UploadBytes)  ($($_.Value.Uploads) files)  from $($_.Value.IPs.Count) IP(s)")
        }
        [void]$sb.AppendLine("")

        if ($Audit.VolumeAnomalies.Count -gt 0) {
            [void]$sb.AppendLine("[!] VOLUME SPIKE DAYS (>2 stdev above mean):")
            foreach ($va in ($Audit.VolumeAnomalies | Sort-Object Events -Descending)) {
                [void]$sb.AppendLine("  $($va.Date)  $($va.Events) events  ($($va.Ratio)x normal, $($va.StdevAbove) stdev above mean)")
            }
            [void]$sb.AppendLine("")
        }

        if ($Audit.SessionVelocity.Count -gt 0) {
            [void]$sb.AppendLine("[!] HIGH-VELOCITY SESSION IPs (automated scanning):")
            foreach ($sv in ($Audit.SessionVelocity | Sort-Object MaxSessionsPer10m -Descending | Select-Object -First 20)) {
                [void]$sb.AppendLine("  $($sv.IP.PadRight(18)) $($sv.MaxSessionsPer10m)/10min  total=$($sv.TotalSessions)  [$($sv.Category)]")
            }
            [void]$sb.AppendLine("")
        }

        [void]$sb.AppendLine("DAILY ACTIVITY (top 30 by volume):")
        $Audit.DailyCounts | Sort-Object Events -Descending | Select-Object -First 30 | ForEach-Object {
            $spike = if ($Audit.VolumeAnomalies | Where-Object Date -eq $_.Date) { " [SPIKE]" } else { "" }
            [void]$sb.AppendLine("  $($_.Date)  $($_.Events) events$spike")
        }
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("HOURLY HEATMAP (avg events/day by hour):")
        $heatLine = (0..23 | ForEach-Object {
            $avg = [int](($Audit.HourTotals[$_] -as [int]) / [Math]::Max(1, $Audit.DailyCounts.Count))
            "  {0:00}h={1}" -f $_, $avg
        }) -join "  "
        [void]$sb.AppendLine($heatLine)
        [void]$sb.AppendLine("")
    }

    # Server log
    if ($Server) {
        [void]$sb.AppendLine("================================================================================")
        [void]$sb.AppendLine("SERVER LOG ANALYSIS")
        [void]$sb.AppendLine("================================================================================")
        [void]$sb.AppendLine("Lines Parsed   : $($Server.TotalLines)")
        if ($Server.TimeRange.Start) {
            [void]$sb.AppendLine("Time Range     : $($Server.TimeRange.Start) -> $($Server.TimeRange.End)")
        }
        [void]$sb.AppendLine("Failed Passwords: $(($Server.FailedPassByIP.Values | Measure-Object -Sum).Sum) from $($Server.FailedPassByIP.Count) IPs")
        [void]$sb.AppendLine("Unique IPs     : $($Server.AllIPCounts.Count) ($($Server.InternalIPs.Count) internal, $($Server.ExternalIPs.Count) external)")
        if ($Server.BruteForceIPs.Count -gt 0) {
            [void]$sb.AppendLine("`n[!] BRUTE-FORCE IPs (>=$BruteForceThreshold failures):")
            foreach ($e in $Server.BruteForceIPs) {
                [void]$sb.AppendLine("    $($e.Key.PadRight(18)) $($e.Value) attempts [$(Get-IPCategory $e.Key)]")
            }
        }
        if ($Server.FailedPassByUser.Count -gt 0) {
            [void]$sb.AppendLine("`nTOP TARGETED USERNAMES:")
            $Server.FailedPassByUser.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
                [void]$sb.AppendLine("  $($_.Key.PadRight(20)) $($_.Value) attempts")
            }
        }
        [void]$sb.AppendLine("")
    }

    # LiteDB
    if ($Database) {
        [void]$sb.AppendLine("================================================================================")
        [void]$sb.AppendLine("USER DATABASE (LiteDB)")
        [void]$sb.AppendLine("================================================================================")
        [void]$sb.AppendLine("Collections    : $($Database.Collections -join ', ')")
        [void]$sb.AppendLine("User Count     : $($Database.UserCount)")
        [void]$sb.AppendLine("Login History  : $($Database.LoginHistoryCount) records")
        [void]$sb.AppendLine("")
    }

    # Live
    if ($Live) {
        [void]$sb.AppendLine("================================================================================")
        [void]$sb.AppendLine("LIVE SYSTEM")
        [void]$sb.AppendLine("================================================================================")
        [void]$sb.AppendLine("Version        : $($Live.Version)")
        [void]$sb.AppendLine("Active Users   : $($Live.Users.Count)")
        [void]$sb.AppendLine("Configured Paths: $($Live.Paths.Count)")
        foreach ($svc in $Live.Services) {
            [void]$sb.AppendLine("Service        : $($svc.Name) [$($svc.Status)]")
        }
        [void]$sb.AppendLine("")
    }

    $footer = @"
================================================================================
OUTPUT FILES
================================================================================
Directory      : $script:OutputDir
Report         : $(Split-Path $script:ReportPath -Leaf)
Sessions.csv             User/IP/transfer stats per session
FileTransfers.csv        Every upload and download event
UserActivity.csv         Per-user aggregate stats
IPSummary.csv            Per-IP aggregate + threat data
DailyStats.csv           Day-by-day activity
FailedLogins.csv         Failed password attempts (server log)
CredentialStuffing.csv   Null-session auth failures (audit log)
AfterHoursActivity.csv   Events outside business hours
LargeTransfers.csv       Transfers above threshold
ThreatIndicators.csv     Consolidated IOC list
VolumeAnomalies.csv      Days with statistically anomalous event counts
SessionVelocity.csv      IPs with automated/scanning-speed session rates
DailyEventCounts.csv     Raw daily event totals for charting
HourlyHeatmap.csv        Activity by hour of day (pivot for Excel)
================================================================================
BuruGuru v1.0
================================================================================
"@
    [void]$sb.Append($footer)

    $reportText = $sb.ToString()
    $reportText | Out-File -FilePath $script:ReportPath -Encoding UTF8
    Write-Host "  Report saved: $script:ReportPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host $reportText -ForegroundColor White
}

# ============================================================
# HTML REPORT
# ============================================================
function New-HtmlReport {
    param(
        [object]$Env,
        [object]$Config,
        [object]$Audit,
        [object]$Server,
        [object]$Database,
        [object]$Live
    )

    Write-Host "  Generating HTML report..." -ForegroundColor Gray

    # Helpers
    function Enc([string]$s) {
        $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
    }

    function HCard([string]$label, [string]$val, [string]$cls = '') {
        "<div class='card $cls'><div class='cv'>$(Enc $val)</div><div class='cl'>$(Enc $label)</div></div>"
    }

    function NavLink([string]$icon, [string]$label, [string]$sec) {
        "<a data-s='$sec' onclick='show(""$sec"")'>$icon&ensp;$(Enc $label)</a>"
    }

    function Get-HtmlTable([object[]]$Rows, [string]$Id, [int]$Limit = 0, [string]$Csv = '', [scriptblock]$ClassFn = $null) {
        if (-not $Rows -or $Rows.Count -eq 0) { return "<p class='empty'>No data.</p>" }
        $total = $Rows.Count
        $shown = if ($Limit -gt 0 -and $total -gt $Limit) { $Rows | Select-Object -First $Limit } else { $Rows }
        $props = $shown[0] | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
        $sb = [System.Text.StringBuilder]::new()
        $meta = "Showing $($shown.Count) of $total rows"
        if ($Csv -and (Test-Path (Join-Path $script:OutputDir $Csv))) {
            $meta += " &nbsp;&bull;&nbsp; <a class='csv-btn' href='$Csv'>Download full CSV</a>"
        }
        [void]$sb.AppendLine("<div class='tmeta'>$meta</div>")
        [void]$sb.AppendLine("<input class='srch' placeholder='Filter...' oninput='ft(this,""$Id"")'>")
        [void]$sb.AppendLine("<div class='tw'><table id='$Id'>")
        [void]$sb.AppendLine("<thead><tr>")
        $ci = 0
        foreach ($p in $props) {
            [void]$sb.AppendLine("<th onclick='st(this.closest(""table""),$ci)'>$(Enc $p)</th>")
            $ci++
        }
        [void]$sb.AppendLine("</tr></thead><tbody>")
        foreach ($row in $shown) {
            $cls = if ($ClassFn) { & $ClassFn $row } else { '' }
            $attr = if ($cls) { " class='$cls'" } else { '' }
            [void]$sb.AppendLine("<tr$attr>")
            foreach ($p in $props) {
                $v = $row.$p; if ($null -eq $v) { $v = '' }
                [void]$sb.AppendLine("<td>$(Enc $v.ToString())</td>")
            }
            [void]$sb.AppendLine("</tr>")
        }
        [void]$sb.AppendLine("</tbody></table></div>")
        return $sb.ToString()
    }

    function SectionOpen([string]$id, [string]$title, [string]$sub = '') {
        $subHtml = if ($sub) { "<span class='subtitle'>$sub</span>" } else { '' }
        return "<section id='$id'>`n<div class='section-hdr'><h2>$(Enc $title) $subHtml</h2></div>"
    }

    # ---- CSS (single-quoted - no PS variable expansion needed) ----
    $css = @'
*{box-sizing:border-box;margin:0;padding:0}
body{display:flex;font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;background:#0d1117;color:#c9d1d9;height:100vh;overflow:hidden}
nav{width:215px;min-width:215px;background:#161b22;border-right:1px solid #30363d;display:flex;flex-direction:column;overflow-y:auto;padding:12px 0}
.logo{padding:12px 16px 18px;font-size:14px;font-weight:700;color:#58a6ff;border-bottom:1px solid #30363d;margin-bottom:6px}
.logo small{display:block;font-size:10px;font-weight:400;color:#8b949e;margin-top:3px}
nav a{display:flex;align-items:center;gap:7px;padding:6px 16px;color:#8b949e;cursor:pointer;border-left:3px solid transparent;font-size:12px;text-decoration:none}
nav a:hover{background:#21262d;color:#c9d1d9}
nav a.active{background:#21262d;color:#58a6ff;border-left-color:#58a6ff;font-weight:600}
.ng{padding:12px 16px 3px;font-size:10px;font-weight:600;color:#484f58;text-transform:uppercase;letter-spacing:.08em}
main{flex:1;overflow-y:auto;padding:24px}
section{display:none}section.active{display:block}
h2{font-size:18px;font-weight:600;color:#e6edf3;margin-bottom:4px}
.subtitle{font-size:12px;font-weight:400;color:#8b949e;margin-left:6px}
.section-hdr{margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid #21262d}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:0 0 22px}
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px 18px;min-width:130px}
.card.danger{border-color:#f8514960}.card.warn{border-color:#d2992260}.card.good{border-color:#3fb95060}
.cv{font-size:22px;font-weight:700;color:#e6edf3}
.cl{font-size:11px;color:#8b949e;margin-top:2px}
.card.danger .cv{color:#f85149}.card.warn .cv{color:#d29922}.card.good .cv{color:#3fb950}
.tmeta{font-size:12px;color:#8b949e;margin-bottom:6px}
.csv-btn{color:#58a6ff;text-decoration:none;font-weight:500}.csv-btn:hover{text-decoration:underline}
.srch{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:5px 10px;border-radius:4px;width:280px;margin-bottom:8px;font-size:12px}
.srch::placeholder{color:#484f58}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:12px}
thead th{background:#161b22;color:#8b949e;font-weight:600;text-align:left;padding:7px 10px;border-bottom:2px solid #30363d;white-space:nowrap;cursor:pointer;user-select:none}
thead th:hover{color:#c9d1d9}
tbody tr:hover{background:#161b22}
td{padding:5px 10px;border-bottom:1px solid #21262d;color:#c9d1d9;white-space:nowrap;max-width:420px;overflow:hidden;text-overflow:ellipsis}
tr.danger td{background:#f8514912}tr.warn td{background:#d2992215}tr.spike td{background:#f8514922}
.empty{color:#484f58;font-style:italic;padding:10px 0}
.heatmap{display:grid;grid-template-columns:repeat(24,1fr);gap:3px;margin-top:10px;margin-bottom:20px}
.hm-cell{border-radius:3px;padding:8px 4px;text-align:center;font-size:11px}
.hm-hour{font-size:9px;color:#8b949e;margin-bottom:3px}.hm-val{color:#fff;font-weight:600}
.stat-row{display:flex;gap:8px;margin-bottom:4px;font-size:12px;color:#8b949e}
.stat-row strong{color:#c9d1d9}
'@

    # ---- JS (single-quoted - $ chars are literal JS, not PS vars) ----
    $js = @'
function show(id){
  document.querySelectorAll('section').forEach(function(s){s.classList.remove('active');});
  document.querySelectorAll('nav a[data-s]').forEach(function(a){a.classList.remove('active');});
  var s=document.getElementById(id); if(s) s.classList.add('active');
  var a=document.querySelector('nav a[data-s="'+id+'"]'); if(a) a.classList.add('active');
}
function st(tbl,ci){
  var tb=tbl.tBodies[0], rs=Array.from(tb.rows);
  var asc=tbl.dataset.sc==ci && tbl.dataset.sd=='1';
  rs.sort(function(a,b){
    var av=a.cells[ci]?a.cells[ci].textContent.trim():'';
    var bv=b.cells[ci]?b.cells[ci].textContent.trim():'';
    var an=parseFloat(av.replace(/[^0-9.\-]/g,'')), bn=parseFloat(bv.replace(/[^0-9.\-]/g,''));
    if(!isNaN(an)&&!isNaN(bn)) return asc?bn-an:an-bn;
    return asc?bv.localeCompare(av):av.localeCompare(bv);
  });
  rs.forEach(function(r){tb.appendChild(r);});
  tbl.dataset.sc=ci; tbl.dataset.sd=asc?'0':'1';
}
function ft(inp,tid){
  var q=inp.value.toLowerCase();
  document.querySelectorAll('#'+tid+' tbody tr').forEach(function(r){
    r.style.display=r.textContent.toLowerCase().indexOf(q)>=0?'':'none';
  });
}
window.onload=function(){ show('summary'); };
'@

    $body = [System.Text.StringBuilder]::new()

    # ---- SUMMARY ----
    $threatCount = 0; $spikeCount = 0; $scannerCount = 0; $stuffCount = 0
    if ($Audit) {
        $spikeCount   = $Audit.VolumeAnomalies.Count
        $scannerCount = $Audit.SessionVelocity.Count
        $stuffCount   = ($Audit.NullSessions | Group-Object IP).Count
        $threatCount  = $spikeCount + $scannerCount + $stuffCount + $Audit.MultiUserIPs.Count
    }
    if ($Server) { $threatCount += $Server.BruteForceIPs.Count }

    $heatmapHtml = ''
    if ($Audit -and $Audit.HourTotals -and $Audit.DailyCounts.Count -gt 0) {
        $dayCount = $Audit.DailyCounts.Count
        $maxHour  = ($Audit.HourTotals.Values | Measure-Object -Maximum).Maximum
        $maxHour  = [Math]::Max(1, $maxHour / $dayCount)
        $hmSb = [System.Text.StringBuilder]::new()
        [void]$hmSb.AppendLine("<div class='heatmap'>")
        for ($h = 0; $h -lt 24; $h++) {
            $avg = [int](($Audit.HourTotals[$h] -as [int]) / $dayCount)
            $intensity = [Math]::Min(1.0, ($avg / $maxHour))
            $r = [int](88  * $intensity + 13  * (1 - $intensity))
            $g = [int](166 * $intensity + 17  * (1 - $intensity))
            $b = [int](255 * $intensity + 23  * (1 - $intensity))
            $a = [Math]::Round(0.15 + $intensity * 0.85, 2)
            [void]$hmSb.AppendLine("<div class='hm-cell' style='background:rgba($r,$g,$b,$a)'><div class='hm-hour'>${h}h</div><div class='hm-val'>$avg</div></div>")
        }
        [void]$hmSb.AppendLine("</div>")
        $heatmapHtml = $hmSb.ToString()
    }

    [void]$body.AppendLine($(SectionOpen "summary" "Summary" "Executive Overview"))
    if ($Audit -and $Audit.TimeRange.Start) {
        $dur = ($Audit.TimeRange.End - $Audit.TimeRange.Start).Days
        [void]$body.AppendLine("<p class='stat-row'>Time range: <strong>$($Audit.TimeRange.Start.ToString('yyyy-MM-dd'))</strong>&ensp;to&ensp;<strong>$($Audit.TimeRange.End.ToString('yyyy-MM-dd'))</strong>&ensp;($dur days)</p>")
    }
    [void]$body.AppendLine("<div class='cards'>")
    if ($Audit) {
        [void]$body.AppendLine($(HCard "Total Events"    ([string]::Format('{0:N0}', $Audit.TotalLines))))
        [void]$body.AppendLine($(HCard "Sessions"        ([string]::Format('{0:N0}', $Audit.Sessions.Count))))
        [void]$body.AppendLine($(HCard "Unique IPs"      ([string]::Format('{0:N0}', $Audit.IPStats.Count))))
        [void]$body.AppendLine($(HCard "Unique Users"    ([string]::Format('{0:N0}', $Audit.UserStats.Count))))
        [void]$body.AppendLine($(HCard "File Transfers"  ([string]::Format('{0:N0}', $Audit.FileTransfers.Count))))
        [void]$body.AppendLine($(HCard "Data Uploaded"   (Format-Bytes $Audit.TotalUploadBytes) "warn"))
        [void]$body.AppendLine($(HCard "Data Downloaded" (Format-Bytes $Audit.TotalDownloadBytes)))
        [void]$body.AppendLine($(HCard "Spike Days"      $spikeCount   $(if ($spikeCount   -gt 0) { 'danger' } else { 'good' })))
        [void]$body.AppendLine($(HCard "Scanners"        $scannerCount $(if ($scannerCount -gt 0) { 'danger' } else { 'good' })))
    }
    [void]$body.AppendLine($(HCard "Threat Indicators" $threatCount  $(if ($threatCount  -gt 0) { 'danger' } else { 'good' })))
    [void]$body.AppendLine("</div>")
    if ($heatmapHtml) {
        [void]$body.AppendLine("<div class='ng' style='padding-left:0;margin-bottom:8px'>Hourly Activity Heatmap (avg events / day)</div>")
        [void]$body.AppendLine($heatmapHtml)
    }
    [void]$body.AppendLine("</section>")

    # ---- THREAT INDICATORS ----
    $iocRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($Audit) {
        foreach ($s in @($Audit.NullSessions | Group-Object IP)) {
            $iocRows.Add([PSCustomObject]@{ IP=$s.Name; Category=Get-IPCategory $s.Name; Indicator="CredentialStuffing"; Detail="$($s.Count) null-session auth failures" })
        }
        foreach ($sv in $Audit.SessionVelocity) {
            $iocRows.Add([PSCustomObject]@{ IP=$sv.IP; Category=$sv.Category; Indicator="HighVelocityScanning"; Detail="$($sv.MaxSessionsPer10m) sessions/10min, $($sv.TotalSessions) total" })
        }
        foreach ($entry in $Audit.MultiUserIPs) {
            $ul = ($entry.Value.Keys | Select-Object -First 8) -join ', '
            if ($entry.Value.Count -gt 8) { $ul += " +$($entry.Value.Count - 8) more" }
            $iocRows.Add([PSCustomObject]@{ IP=$entry.Key; Category=Get-IPCategory $entry.Key; Indicator="MultipleUsernames"; Detail="$($entry.Value.Count) distinct usernames: $ul" })
        }
    }
    if ($Server) {
        foreach ($entry in $Server.BruteForceIPs) {
            $iocRows.Add([PSCustomObject]@{ IP=$entry.Key; Category=Get-IPCategory $entry.Key; Indicator="BruteForce"; Detail="$($entry.Value) failed password attempts" })
        }
    }
    $iocClassFn = { param($r)
        switch ($r.Indicator) {
            'HighVelocityScanning' { 'danger' }
            'BruteForce'           { 'danger' }
            'CredentialStuffing'   { 'warn'   }
            default                { ''       }
        }
    }
    [void]$body.AppendLine($(SectionOpen "threats" "Threat Indicators" "Consolidated IOC list"))
    [void]$body.AppendLine($(Get-HtmlTable ($iocRows | Sort-Object Indicator, IP) "tbl-threats" 0 "ThreatIndicators.csv" $iocClassFn))
    [void]$body.AppendLine("</section>")

    # ---- CREDENTIAL STUFFING ----
    [void]$body.AppendLine($(SectionOpen "stuffing" "Credential Stuffing" "Null-session auth failures; username never established"))
    if ($Audit -and $Audit.NullSessions.Count -gt 0) {
        [void]$body.AppendLine($(Get-HtmlTable ($Audit.NullSessions | Sort-Object Timestamp) "tbl-stuffing" 0 "CredentialStuffing.csv"))
    } else { [void]$body.AppendLine("<p class='empty'>No credential stuffing events detected.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- BRUTE FORCE ----
    [void]$body.AppendLine($(SectionOpen "bruteforce" "Brute Force" "Failed password attempts from server log"))
    if ($Server -and $Server.FailedPassByIP.Count -gt 0) {
        $bfRows = $Server.FailedPassByIP.GetEnumerator() |
            Select-Object @{N='IP';E={$_.Key}}, @{N='FailedPasswords';E={$_.Value}}, @{N='Category';E={Get-IPCategory $_.Key}} |
            Sort-Object FailedPasswords -Descending
        $bfThresh = $BruteForceThreshold
        $bfClassFn = { param($r) if ($r.FailedPasswords -ge 100) { 'danger' } elseif ($r.FailedPasswords -ge $bfThresh) { 'warn' } else { '' } }
        [void]$body.AppendLine($(Get-HtmlTable $bfRows "tbl-brute" 300 "FailedLogins.csv" $bfClassFn))
    } else { [void]$body.AppendLine("<p class='empty'>No failed password data available.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- SCANNERS ----
    [void]$body.AppendLine($(SectionOpen "scanners" "High-Velocity Scanners" "IPs with automated session rates (20+ sessions / 10 min)"))
    if ($Audit -and $Audit.SessionVelocity.Count -gt 0) {
        $svClassFn = { param($r) if ($r.MaxSessionsPer10m -ge 100) { 'danger' } else { 'warn' } }
        [void]$body.AppendLine($(Get-HtmlTable ($Audit.SessionVelocity | Sort-Object MaxSessionsPer10m -Descending) "tbl-scanners" 0 "SessionVelocity.csv" $svClassFn))
    } else { [void]$body.AppendLine("<p class='empty'>No high-velocity scanning IPs detected.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- MULTI-USERNAME IPs ----
    [void]$body.AppendLine($(SectionOpen "multiuser" "Multi-Username IPs" "Single IP used more than one distinct username"))
    if ($Audit -and $Audit.MultiUserIPs.Count -gt 0) {
        $muRows = $Audit.MultiUserIPs | Sort-Object { $_.Value.Count } -Descending | ForEach-Object {
            [PSCustomObject]@{
                IP        = $_.Key
                Category  = Get-IPCategory $_.Key
                UserCount = $_.Value.Count
                Usernames = (($_.Value.Keys | Select-Object -First 20) -join ', ') + $(if ($_.Value.Count -gt 20) { " +$($_.Value.Count - 20) more" } else { '' })
            }
        }
        $muClassFn = { param($r) if ($r.UserCount -ge 50) { 'danger' } elseif ($r.UserCount -ge 5) { 'warn' } else { '' } }
        [void]$body.AppendLine($(Get-HtmlTable $muRows "tbl-multiuser" 0 "" $muClassFn))
    } else { [void]$body.AppendLine("<p class='empty'>No multi-username IPs detected.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- VOLUME ANOMALIES ----
    [void]$body.AppendLine($(SectionOpen "anomalies" "Volume Anomalies" "Days more than 2 standard deviations above the daily mean"))
    if ($Audit -and $Audit.VolumeAnomalies.Count -gt 0) {
        $vaClassFn = { param($r) if ($r.Ratio -ge 5) { 'spike' } else { 'warn' } }
        [void]$body.AppendLine($(Get-HtmlTable ($Audit.VolumeAnomalies | Sort-Object Events -Descending) "tbl-anomalies" 0 "VolumeAnomalies.csv" $vaClassFn))
    } else { [void]$body.AppendLine("<p class='empty'>No volume anomalies detected.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- USER ACTIVITY ----
    [void]$body.AppendLine($(SectionOpen "users" "User Activity" "Per-user aggregate stats"))
    if ($Audit -and $Audit.UserStats.Count -gt 0) {
        $userRows = $Audit.UserStats.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{
                Username      = $_.Key
                Logins        = $_.Value.Logins
                Uploads       = $_.Value.Uploads
                Downloads     = $_.Value.Downloads
                Uploaded      = Format-Bytes $_.Value.UploadBytes
                Downloaded    = Format-Bytes $_.Value.DownloadBytes
                UploadBytes   = $_.Value.UploadBytes
                UniqueIPs     = $_.Value.IPs.Count
                FirstSeen     = $_.Value.FirstSeen
                LastSeen      = $_.Value.LastSeen
            }
        } | Sort-Object UploadBytes -Descending |
            Select-Object Username, Logins, Uploads, Downloads, Uploaded, Downloaded, UniqueIPs, FirstSeen, LastSeen
        [void]$body.AppendLine($(Get-HtmlTable $userRows "tbl-users" 200 "UserActivity.csv"))
    } else { [void]$body.AppendLine("<p class='empty'>No user data available.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- IP SUMMARY ----
    [void]$body.AppendLine($(SectionOpen "ips" "IP Summary" "Per-IP aggregate with threat data"))
    if ($Audit -and $Audit.IPStats.Count -gt 0) {
        $ipHRows = $Audit.IPStats.GetEnumerator() | ForEach-Object {
            $failedPw = if ($Server -and $Server.FailedPassByIP.ContainsKey($_.Key)) { $Server.FailedPassByIP[$_.Key] } else { 0 }
            [PSCustomObject]@{
                IP             = $_.Key
                Category       = $_.Value.Category
                Logins         = $_.Value.Logins
                AuditFailedAuth= $_.Value.FailedLogins
                ServerFailedPw = $failedPw
                Uploads        = $_.Value.Uploads
                Downloads      = $_.Value.Downloads
                Uploaded       = Format-Bytes $_.Value.UploadBytes
                Downloaded     = Format-Bytes $_.Value.DownloadBytes
                UploadBytes    = $_.Value.UploadBytes
                UniqueUsers    = $_.Value.Usernames.Count
            }
        } | Sort-Object ServerFailedPw -Descending |
            Select-Object IP, Category, Logins, AuditFailedAuth, ServerFailedPw, Uploads, Downloads, Uploaded, Downloaded, UniqueUsers
        $ipClassFn = { param($r) if ($r.ServerFailedPw -ge 100 -or $r.AuditFailedAuth -ge 50) { 'danger' } elseif ($r.ServerFailedPw -ge 10) { 'warn' } else { '' } }
        [void]$body.AppendLine($(Get-HtmlTable $ipHRows "tbl-ips" 500 "IPSummary.csv" $ipClassFn))
    } else { [void]$body.AppendLine("<p class='empty'>No IP data available.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- DAILY STATS ----
    [void]$body.AppendLine($(SectionOpen "daily" "Daily Statistics" "Day-by-day activity breakdown"))
    if ($Audit -and $Audit.DailyStats.Count -gt 0) {
        $spikeSet = @{}; $Audit.VolumeAnomalies | ForEach-Object { $spikeSet[$_.Date] = $true }
        $dailyHRows = $Audit.DailyStats.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{
                Date        = $_.Key
                Logins      = $_.Value.Logins
                Uploads     = $_.Value.Uploads
                Downloads   = $_.Value.Downloads
                Uploaded    = Format-Bytes $_.Value.UploadBytes
                Downloaded  = Format-Bytes $_.Value.DownloadBytes
                UniqueIPs   = $_.Value.UniqueIPs.Count
                UniqueUsers = $_.Value.UniqueUsers.Count
                VolumeSpike = if ($spikeSet.ContainsKey($_.Key)) { 'YES' } else { '' }
            }
        } | Sort-Object Date
        $dayClassFn = { param($r) if ($r.VolumeSpike -eq 'YES') { 'spike' } else { '' } }
        [void]$body.AppendLine($(Get-HtmlTable $dailyHRows "tbl-daily" 0 "DailyStats.csv" $dayClassFn))
    } else { [void]$body.AppendLine("<p class='empty'>No daily stats available.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- AFTER HOURS ----
    $ahLabel = "After-Hours Activity"
    $ahSub   = "Events outside business hours (${AfterHoursStart}:00 - ${AfterHoursEnd}:00)"
    [void]$body.AppendLine($(SectionOpen "afterhours" $ahLabel $ahSub))
    if ($Audit -and $Audit.AfterHoursEvents.Count -gt 0) {
        [void]$body.AppendLine($(Get-HtmlTable ($Audit.AfterHoursEvents | Sort-Object Timestamp) "tbl-afterhours" 500 "AfterHoursActivity.csv"))
    } else { [void]$body.AppendLine("<p class='empty'>No after-hours events detected.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- FILE TRANSFERS ----
    [void]$body.AppendLine($(SectionOpen "filetransfers" "File Transfers" "Individual upload and download events (top 500 by size; download CSV for full dataset)"))
    if ($Audit -and $Audit.FileTransfers.Count -gt 0) {
        [void]$body.AppendLine($(Get-HtmlTable ($Audit.FileTransfers | Sort-Object Bytes -Descending) "tbl-ft" 500 "FileTransfers.csv"))
    } else { [void]$body.AppendLine("<p class='empty'>No file transfer data available.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- LARGE TRANSFERS ----
    $ltSub = "File transfers above $LargeTransferThresholdMB MB"
    [void]$body.AppendLine($(SectionOpen "largetx" "Large Transfers" $ltSub))
    if ($Audit -and $Audit.LargeTransfers.Count -gt 0) {
        $ltClassFn = { param($r) 'warn' }
        [void]$body.AppendLine($(Get-HtmlTable ($Audit.LargeTransfers | Sort-Object Bytes -Descending) "tbl-largetx" 0 "LargeTransfers.csv" $ltClassFn))
    } else { [void]$body.AppendLine("<p class='empty'>No large transfers detected.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- SESSIONS ----
    [void]$body.AppendLine($(SectionOpen "sessions" "Sessions" "Reconstructed sessions (top 500 by upload size; download CSV for full dataset)"))
    if ($Audit -and $Audit.Sessions.Count -gt 0) {
        $sessionHRows = $Audit.Sessions.Values | ForEach-Object {
            $dur = if ($_.LoginTime -and $_.LogoutTime) { [int]($_.LogoutTime - $_.LoginTime).TotalSeconds } else { $null }
            [PSCustomObject]@{
                SessionId     = $_.SessionId
                Username      = $_.Username
                IP            = $_.IP
                Category      = Get-IPCategory $_.IP
                LoginTime     = $_.LoginTime
                DurationSec   = $dur
                UploadCount   = $_.UploadCount
                DownloadCount = $_.DownloadCount
                Uploaded      = Format-Bytes $_.UploadBytes
                Downloaded    = Format-Bytes $_.DownloadBytes
                UploadBytes   = $_.UploadBytes
            }
        } | Sort-Object UploadBytes -Descending |
            Select-Object SessionId, Username, IP, Category, LoginTime, DurationSec, UploadCount, DownloadCount, Uploaded, Downloaded
        [void]$body.AppendLine($(Get-HtmlTable $sessionHRows "tbl-sessions" 500 "Sessions.csv"))
    } else { [void]$body.AppendLine("<p class='empty'>No session data available.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- SERVER LOG ----
    [void]$body.AppendLine($(SectionOpen "serverlog" "Server Log" "Failed password attempts and brute-force detection"))
    if ($Server -and $Server.FailedPassByIP.Count -gt 0) {
        $totalFailed = ($Server.FailedPassByIP.Values | Measure-Object -Sum).Sum -as [int]
        [void]$body.AppendLine("<div class='cards'>")
        [void]$body.AppendLine($(HCard "Total Failed Passwords" ([string]::Format('{0:N0}', $totalFailed))  $(if ($totalFailed -gt 1000) { 'danger' } else { 'warn' })))
        [void]$body.AppendLine($(HCard "Attacking IPs"          ([string]::Format('{0:N0}', $Server.FailedPassByIP.Count))))
        [void]$body.AppendLine($(HCard "Brute-Force IPs"        $Server.BruteForceIPs.Count $(if ($Server.BruteForceIPs.Count -gt 0) { 'danger' } else { 'good' })))
        [void]$body.AppendLine("</div>")
        if ($Server.FailedPassByUser.Count -gt 0) {
            [void]$body.AppendLine("<div class='ng' style='padding-left:0;margin-bottom:8px'>Top Targeted Usernames</div><div class='cards'>")
            $Server.FailedPassByUser.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
                [void]$body.AppendLine($(HCard (Enc $_.Key) ([string]::Format('{0:N0}', $_.Value)) 'warn'))
            }
            [void]$body.AppendLine("</div>")
        }
        $slRows = $Server.FailedPassByIP.GetEnumerator() |
            Select-Object @{N='IP';E={$_.Key}}, @{N='FailedPasswords';E={$_.Value}}, @{N='Category';E={Get-IPCategory $_.Key}} |
            Sort-Object FailedPasswords -Descending
        $slClassFn = { param($r) if ($r.FailedPasswords -ge 100) { 'danger' } elseif ($r.FailedPasswords -ge 10) { 'warn' } else { '' } }
        [void]$body.AppendLine($(Get-HtmlTable $slRows "tbl-serverlog" 300 "FailedLogins.csv" $slClassFn))
    } else { [void]$body.AppendLine("<p class='empty'>No server log data available.</p>") }
    [void]$body.AppendLine("</section>")

    # ---- NAV ----
    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $nav = @"
<nav>
<div class='logo'>BuruGuru<small>v1.0 &bull; $generated</small></div>
<div class='ng'>Overview</div>
$(NavLink "&#128202;" "Summary"             "summary")
$(NavLink "&#9888;"   "Threat Indicators"   "threats")
<div class='ng'>Authentication</div>
$(NavLink "&#128100;" "Credential Stuffing"  "stuffing")
$(NavLink "&#128308;" "Brute Force"          "bruteforce")
$(NavLink "&#128246;" "High-Velocity Scanners" "scanners")
$(NavLink "&#128101;" "Multi-Username IPs"   "multiuser")
<div class='ng'>Activity</div>
$(NavLink "&#128104;" "User Activity"        "users")
$(NavLink "&#127760;" "IP Summary"           "ips")
$(NavLink "&#128197;" "Daily Statistics"     "daily")
$(NavLink "&#128336;" "After-Hours Activity" "afterhours")
$(NavLink "&#128200;" "Volume Anomalies"     "anomalies")
<div class='ng'>Transfers</div>
$(NavLink "&#128196;" "File Transfers"       "filetransfers")
$(NavLink "&#128228;" "Large Transfers"      "largetx")
$(NavLink "&#128193;" "Sessions"             "sessions")
<div class='ng'>Infrastructure</div>
$(NavLink "&#128220;" "Server Log"           "serverlog")
</nav>
"@

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Buru SFTP Analysis - $generated</title>
<style>
$css
</style>
</head>
<body>
$nav
<main>
$($body.ToString())
</main>
<script>
$js
</script>
</body>
</html>
"@

    $htmlPath = Join-Path $script:OutputDir "BuruAnalysisReport.html"
    [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.Encoding]::UTF8)
    Write-Host "  HTML report: $htmlPath" -ForegroundColor Cyan
}

# ============================================================
# MAIN
# ============================================================
function Invoke-BuruAnalysis {
    Write-Host @"

================================================================================
                     BURUGURU  v1.0
================================================================================
Mode     : $Mode
Dev Mode : $($script:IsDevMode)
Output   : $script:OutputDir
================================================================================
"@ -ForegroundColor Cyan

    # 1. Environment
    $envResult = Test-BuruEnvironment

    # 2. Config
    $configResult = Get-ConfigurationAnalysis

    # 3. Combine logs
    $combineResult = Invoke-LogCombination

    # 4. Convert timestamps
    if ($combineResult.AuditLines -gt 0 -and -not $SkipTimestampConversion) {
        Convert-AuditTimestamps
    }

    # 5. Audit analysis
    $auditResult = $null
    if ($combineResult.AuditLines -gt 0) {
        $auditResult = Get-AuditLogAnalysis
    }

    # 6. Server log analysis
    $serverResult = $null
    if ($combineResult.ServerLines -gt 0) {
        $serverResult = Get-ServerLogAnalysis
    }

    # 7. LiteDB
    $dbResult = Get-LiteDBAnalysis

    # 8. Live info
    $liveResult = Get-LiveSystemInfo

    # 9. Exports
    Export-AnalysisArtifacts -Audit $auditResult -Server $serverResult

    # 10. Text report
    New-AnalysisReport -Env $envResult -Config $configResult -Audit $auditResult `
        -Server $serverResult -Database $dbResult -Live $liveResult

    # 11. HTML report
    New-HtmlReport -Env $envResult -Config $configResult -Audit $auditResult `
        -Server $serverResult -Database $dbResult -Live $liveResult

    Write-Host "Done. Output: $script:OutputDir" -ForegroundColor Green
}

try {
    Invoke-BuruAnalysis
} catch {
    Write-Error "Analysis failed: $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}

