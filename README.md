# Windows Security Sweep

A modular, colour-coded security sweep script for Windows home machines.

---

## Quick Start

### 1. Install dependencies
```
pip install -r requirements.txt
```

### 2. Run the sweep (as Administrator for full results)
```
python security_sweep.py
```

### 3. Save a report
```
python security_sweep.py --output json
python security_sweep.py --output txt
```

### 4. Run only specific checks
```
python security_sweep.py --only ports,firewall,logins
```

### 5. Disable specific checks
```
python security_sweep.py --disable packages,writable
```

---

## Checks

| Flag        | What it does                                                  | Severity range |
|-------------|---------------------------------------------------------------|----------------|
| `ports`     | Scans listening ports, flags known-risky ones                 | MEDIUM / HIGH  |
| `processes` | Lists processes, flags malware names and resource hogs        | LOW – HIGH     |
| `packages`  | Checks pip + winget for outdated packages                     | LOW            |
| `tasks`     | Inspects scheduled tasks for suspicious paths / recent adds   | MEDIUM / HIGH  |
| `writable`  | Finds world-writable files and directories                    | MEDIUM / HIGH  |
| `logins`    | Summarises failed login events from the Security event log    | MEDIUM / HIGH  |
| `firewall`  | Reports firewall profile status and broad inbound rules       | MEDIUM / HIGH  |

---

## Severity colours

| Colour       | Level  | Meaning                              |
|--------------|--------|--------------------------------------|
| 🔴 Red       | HIGH   | Act immediately                      |
| 🟡 Yellow    | MEDIUM | Review soon                          |
| 🔵 Cyan      | LOW    | Informational / low risk             |
| 🟢 Green     | INFO   | All clear / normal finding           |

---

## Scheduling with Task Scheduler (weekly, with email alerts)

### 1. Edit `run_sweep.ps1`
Open the file and fill in the `$Config` block at the top:
- `SmtpUser` / `SmtpPassword` — your email credentials  
  (For Gmail, generate an **App Password** at myaccount.google.com/apppasswords)
- `EmailFrom` / `EmailTo` — sender and recipient addresses

### 2. Register the scheduled task (run PowerShell as Administrator)
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\run_sweep.ps1 -Register
```
This creates a task that runs every **Sunday at 08:00**.  
Change `TaskTriggerDay` and `TaskTriggerTime` in `$Config` to adjust.

### 3. Test it manually
```powershell
.\run_sweep.ps1
```
Or trigger via Task Scheduler:
```powershell
Start-ScheduledTask -TaskName "WeeklySecuritySweep"
```

### 4. Email behaviour
The wrapper only sends an email when the sweep exits with code `1`,  
which happens only when **HIGH severity findings** are present.  
No HIGH findings = no email noise.

---

## Notes

- Run as **Administrator** for full access to the Security event log, firewall rules, and all process details.
- The world-writable scan is capped at 500 files per run to keep it fast. Increase `MAX_FILES` in `security_sweep.py` for deeper scans.
- `winget` must be installed for system package update checks (comes with Windows 10 1809+ / Windows 11).
- The script exits with code `0` (clean) or `1` (HIGH findings), making it easy to chain with other tools.
