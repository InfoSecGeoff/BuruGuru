# BuruGuru

> The definitive forensic analysis and incident response tool for [Rebex Buru SFTP Server](https://www.rebex.net/buru-sftp-server/).

BuruGuru ingests Buru's audit and server logs, reconstructs sessions, identifies threat actors, detects anomalies, and produces a self-contained HTML dashboard plus a full CSV artifact set — all from a single PowerShell script you can drop on any Windows box.

---

## Requirements

- PowerShell 5.1+ (Windows PowerShell or PowerShell Core)
- Read access to Buru log directories
- **Optional:** `powershell-yaml` module — enables `config.yaml` security assessment
  ```powershell
  Install-Module powershell-yaml
  ```
- **Optional:** `LiteDB.dll` placed in the script directory — enables `users.ldb` credential store enumeration

---

## Quick Start

```powershell
# Full live analysis against a running Buru server
.\Get-BuruLogs.ps1

# Offline analysis (no live server required)
.\Get-BuruLogs.ps1 -Mode offline

# Scope to a date range
.\Get-BuruLogs.ps1 -Mode offline -DateFrom 2024-01-01 -DateTo 2024-03-31

# Pull the full audit trail for a single user
.\Get-BuruLogs.ps1 -Mode offline -UserFilter jsmith

# Adjust for a server in a different timezone
.\Get-BuruLogs.ps1 -Mode offline -TimezoneOffsetHours -8
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `Mode` | `live` / `offline` | `live` | `live` queries the running server for service state, version, and connected users. `offline` processes log files only — safe to run on a copy. |
| `TimezoneOffsetHours` | int (-12 to 14) | `-5` | UTC offset of the server that generated the logs. Applied during timestamp normalization. |
| `SkipTimestampConversion` | switch | off | Skip converting Buru's native timestamp format to ISO 8601. Not recommended — conversion is needed for timeline correlation with other log sources. |
| `DateFrom` | string | none | Restrict analysis to events on or after this date (`yyyy-MM-dd`). |
| `DateTo` | string | none | Restrict analysis to events on or before this date (`yyyy-MM-dd`). |
| `UserFilter` | string | none | Restrict audit analysis to a single username (exact match). Useful for targeted user investigations. |
| `AfterHoursStart` | int (0-23) | `6` | Start of business hours. Events before this hour are flagged as after-hours. |
| `AfterHoursEnd` | int (0-23) | `20` | End of business hours. Events after this hour are flagged as after-hours. |
| `BruteForceThreshold` | int | `10` | Minimum failed password attempts from a single IP to flag as brute force in the server log analysis. |
| `LargeTransferThresholdMB` | double | `100` | File transfers above this size (MB) are flagged for review. |

---

## Log File Locations

Buru SFTP stores its logs in two locations by default:

| Log Type | Default Path |
|---|---|
| Audit logs | `C:\Program Files\BuruServer\logs\burusftp-audit-*.log` |
| Server logs | `C:\Program Files\BuruServer\serverlogs\burusftp-*.log` |
| Configuration | `C:\ProgramData\Rebex\BuruSftp\config.yaml` |
| User database | `C:\ProgramData\Rebex\BuruSftp\users.ldb` |

### Audit Log Format

Buru writes one audit log per day in CSV-like format:

```
20230110_080633.522,"74.138.59.94",1,"jsmith","login",[]
20230110_080634.101,"74.138.59.94",1,"jsmith","access",["/files","Read"]
20230110_080701.443,"74.138.59.94",1,"jsmith","upload",["/files/report.pdf",204800]
20230110_080702.019,"74.138.59.94",1,"jsmith","logout",[]
```

Fields: `timestamp, ip, sessionId, username, action, [data]`

A `null` username on a `login` event indicates a failed authentication attempt before a session was established — a credential stuffing indicator.

---

## Dev / Testing Mode

If a `BuruServer\` folder exists in the same directory as the script, BuruGuru automatically operates in **dev mode** — using that folder as the Buru root instead of `C:\Program Files\BuruServer`. This allows offline analysis against a local copy of logs without modifying any paths.

```
BuruGuru/
  Get-BuruLogs.ps1
  BuruServer/          <-- triggers dev mode
    logs/
      burusftp-audit-20240101.log
      ...
    serverlogs/
      burusftp-20240101.log
      ...
```

---

## What It Analyzes

### Environment Assessment
- Buru service state and version
- Presence of audit logs, server logs, config file, and user database
- SSH algorithm security classification (weak CBC/SHA1, insecure ssh-rsa/MD5, recommended CTR/ETM/ed25519)

### Configuration Analysis
- `config.yaml` security review (requires `powershell-yaml`)
- `webconfig.yaml` web interface settings
- License information

### Audit Log Analysis
Single-pass, full session reconstruction across all daily log files:

- **Session reconstruction** — correlates login, file access, upload, download, and logout events by session ID
- **Transfer accounting** — total uploaded/downloaded bytes per user, per IP, per session
- **After-hours activity** — all events outside configured business hours
- **Credential stuffing detection** — null-session login attempts (auth failures before session establishment)
- **Multi-username IPs** — IPs that authenticated or attempted with more than one username
- **Large transfer flagging** — individual file transfers above threshold
- **Volume anomaly detection** — days with event counts more than 2 standard deviations above the daily mean
- **Session velocity detection** — IPs with 20+ sessions in any 10-minute window (automated scanner behavior)
- **Hourly heatmap** — average events per hour of day across the full dataset

### Server Log Analysis
- Failed password attempt aggregation by IP
- Brute-force IP identification (configurable threshold)
- Top targeted usernames
- Internal vs. external IP classification

### User Database Analysis
- LiteDB user enumeration (requires `LiteDB.dll`)
- Account listing with roles and permissions

### Live Mode (requires running server)
- Active connected sessions
- `burusftp.exe` CLI version query

---

## Output

Each run creates a timestamped output directory (`BuruAnalysis_YYYYMMDD_HHmmss\`) containing:

| File | Contents |
|---|---|
| `BuruAnalysisReport.html` | Self-contained HTML dashboard with sidebar navigation, sortable tables, and CSV download links |
| `BuruAnalysisReport.txt` | Plain-text IR report |
| `Sessions.csv` | Per-session detail: user, IP, duration, bytes transferred |
| `FileTransfers.csv` | Every upload and download event with filename, size, timestamp |
| `UserActivity.csv` | Per-user aggregate: session count, bytes up/down, IP count |
| `IPSummary.csv` | Per-IP aggregate with threat indicators and category |
| `DailyStats.csv` | Day-by-day session and transfer counts |
| `FailedLogins.csv` | Failed password attempts from server log, by IP |
| `CredentialStuffing.csv` | Null-session auth failures from audit log |
| `AfterHoursActivity.csv` | All events outside business hours |
| `LargeTransfers.csv` | File transfers above the size threshold |
| `ThreatIndicators.csv` | Consolidated IOC list (credential stuffing, scanning, multi-user) |
| `VolumeAnomalies.csv` | Days with statistically anomalous event volumes |
| `SessionVelocity.csv` | IPs with automated/scanning-speed session rates |
| `DailyEventCounts.csv` | Raw daily event totals (suitable for charting) |
| `HourlyHeatmap.csv` | Activity pivot by hour of day (suitable for Excel) |

The working files `combined-audit.log`, `combined-server.log`, and `converted-audit.log` are also written to the output directory. These merge all daily log files and normalize timestamps — useful for importing into a SIEM or running additional analysis.

---

## HTML Dashboard

The HTML report is fully self-contained — open it in any browser directly from the filesystem, no web server needed. Works air-gapped.

- **15-section sidebar navigation** grouped by category
- **Sortable, filterable tables** in every section (pure JS, no external dependencies)
- **Color-coded rows** — red for high-severity indicators, amber for medium
- **Hourly heatmap** with intensity shading on the summary page
- **CSV download links** on every table for the full dataset

---

## OneDrive / Cloud-Synced Log Files

If Buru logs are stored in a OneDrive-synced folder and files are in online-only state, BuruGuru automatically falls back to `Get-Content` when `StreamReader` encounters a cloud sync error. No manual intervention required.

---

## Example Findings

From a 693-day production dataset (Jan 2023 - Dec 2024, 5.4M audit events):

- **21,191 unique source IPs** attempted connections
- **6,988 unique usernames** used in auth attempts
- **`admin`** targeted 27,121 times for brute-force password attacks
- **`141.98.11.161`** attempted 600+ distinct usernames — mass credential stuffing
- **`128.199.212.108`** reached 624 sessions in a single 10-minute window — pure scanner
- **2024-11-20** was the highest-volume anomaly day at 87,554 events (16x the daily mean)
- **792 GB uploaded** across 87,407 file transfer events

---

## Threat Indicator Categories

| Indicator | Detection Method |
|---|---|
| `CredentialStuffing` | `null` username on login event in audit log |
| `HighVelocityScanning` | 20+ sessions in any 10-minute window |
| `MultipleUsernames` | Single IP authenticating with 2+ distinct usernames |
| `BruteForce` | IP exceeds failed password threshold in server log |
| `VolumeAnomaly` | Day exceeds mean + 2 standard deviations of daily event count |

---

## Notes

- BuruGuru is read-only — it does not modify any Buru configuration or log files.
- Timestamp conversion adds a `converted-audit.log` to the output directory; original logs are never touched.
- Each run creates a new timestamped output directory; re-running never overwrites previous results.
- PS5.1 (Windows PowerShell) and PS7+ (PowerShell Core) are both supported.

---

## Author

**Geoff Tankersley**
