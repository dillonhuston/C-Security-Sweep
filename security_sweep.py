"""
security_sweep.py
=================
Windows home-machine security sweep script.
Checks: open ports, running processes, outdated packages, scheduled tasks,
world-writable files, failed logins, and firewall status.

Usage:
    python security_sweep.py [--output txt|json] [--disable <check1,check2,...>]

Requires:
    pip install colorama psutil
    Run as Administrator for full results (firewall, event log, etc.)
"""

import argparse
import datetime
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Third-party imports (install via: pip install colorama psutil)
# ---------------------------------------------------------------------------
try:
    import psutil
except ImportError:
    sys.exit("[ERROR] psutil not installed. Run: pip install psutil")

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    sys.exit("[ERROR] colorama not installed. Run: pip install colorama")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ports commonly associated with vulnerabilities or remote-access abuse
SUSPICIOUS_PORTS = {
    21: "FTP (plaintext)",
    22: "SSH",
    23: "Telnet (plaintext)",
    25: "SMTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    445: "SMB (EternalBlue target)",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    4444: "Metasploit default",
    5900: "VNC",
    6666: "IRC / malware C2",
    6667: "IRC",
    8080: "Alt HTTP",
    8443: "Alt HTTPS",
    9200: "Elasticsearch (often unauth)",
    27017: "MongoDB (often unauth)",
}

# Process names commonly associated with malware or unwanted tools
SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "pwdump.exe", "fgdump.exe", "wce.exe",
    "nc.exe", "ncat.exe", "netcat.exe",
    "meterpreter", "payload.exe", "rat.exe",
    "keylogger.exe", "spyware.exe",
    "cryptominer.exe", "xmrig.exe", "minerd.exe",
}

# CPU / memory thresholds that flag a process as resource-hungry
CPU_THRESHOLD_PCT = 50.0   # % CPU over a sample window
MEM_THRESHOLD_MB  = 1024   # MB resident set size

# Directories to scan for world-writable files
WRITABLE_SCAN_DIRS = [
    os.environ.get("TEMP", "C:\\Windows\\Temp"),
    os.environ.get("TMP",  "C:\\Windows\\Temp"),
    "C:\\Windows\\Temp",
    "C:\\Temp",
    str(Path.home()),                    # user home
    str(Path.home() / "AppData"),
]

# How many days back to look for recently-added scheduled tasks
TASK_RECENT_DAYS = 14

# How many failed login events to summarise
MAX_FAILED_LOGIN_EVENTS = 200

# ---------------------------------------------------------------------------
# Colour helpers  (dyspraxia-friendly: high contrast, consistent palette)
# ---------------------------------------------------------------------------

def sev_colour(severity: str) -> str:
    """Return a coloured severity badge."""
    colours = {
        "HIGH":   Fore.RED    + Style.BRIGHT,
        "MEDIUM": Fore.YELLOW + Style.BRIGHT,
        "LOW":    Fore.CYAN   + Style.BRIGHT,
        "INFO":   Fore.GREEN  + Style.BRIGHT,
    }
    colour = colours.get(severity.upper(), Fore.WHITE)
    return f"{colour}[{severity.upper()}]{Style.RESET_ALL}"


def section_header(title: str) -> str:
    """Bold white section header with a separator line."""
    line = "=" * 60
    return f"\n{Fore.WHITE}{Style.BRIGHT}{line}\n  {title}\n{line}{Style.RESET_ALL}"


def finding(severity: str, message: str, check: str = "") -> dict:
    """Create a structured finding dict and print it immediately."""
    entry = {
        "severity":  severity.upper(),
        "message":   message,
        "check":     check,
        "timestamp": datetime.datetime.now().isoformat(),
    }
    print(f"  {sev_colour(severity)}  {message}")
    return entry


def info_line(message: str):
    """Print a plain informational line (no severity)."""
    print(f"  {Fore.GREEN}•{Style.RESET_ALL} {message}")


# ---------------------------------------------------------------------------
# Helper: run a shell command and return stdout (empty string on failure)
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], timeout: int = 30) -> str:
    """Run a subprocess command and return decoded stdout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""


# ===========================================================================
# CHECK 1 — Open Ports
# ===========================================================================

def check_open_ports() -> list[dict]:
    """
    Enumerate all listening TCP/UDP ports using psutil.
    Flag any port in the SUSPICIOUS_PORTS dictionary as HIGH or MEDIUM.
    Unknown high-numbered ports are flagged LOW.
    """
    print(section_header("CHECK 1 — Open Ports"))
    findings = []

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        findings.append(finding("MEDIUM", "Access denied reading network connections — run as Administrator", "ports"))
        return findings

    listening_ports = {}
    for conn in connections:
        # Only care about LISTEN state (TCP) or unconnected UDP (laddr set, raddr empty)
        if conn.status in ("LISTEN", "NONE", "") and conn.laddr:
            port = conn.laddr.port
            pid  = conn.pid
            try:
                proc_name = psutil.Process(pid).name() if pid else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "unknown"
            listening_ports[port] = proc_name

    if not listening_ports:
        info_line("No listening ports found.")
        return findings

    for port, proc in sorted(listening_ports.items()):
        label = SUSPICIOUS_PORTS.get(port)
        if label:
            # RDP and SMB on a home machine are HIGH; others MEDIUM
            sev = "HIGH" if port in (3389, 445, 4444, 6666, 6667) else "MEDIUM"
            findings.append(finding(sev, f"Port {port} open — {label} (process: {proc})", "ports"))
        else:
            info_line(f"Port {port} open — process: {proc}")

    if not findings:
        info_line("No suspicious ports detected.")

    return findings


# ===========================================================================
# CHECK 2 — Running Processes
# ===========================================================================

def check_running_processes() -> list[dict]:
    """
    Iterate all running processes.
    Flag: known-malware names (HIGH), excessive CPU/RAM (MEDIUM),
    processes with no executable path (LOW).
    """
    print(section_header("CHECK 2 — Running Processes"))
    findings = []

    # Sample CPU usage over a short window for accuracy
    for proc in psutil.process_iter(["pid", "name", "exe", "memory_info", "cpu_percent"]):
        try:
            proc.cpu_percent(interval=None)   # prime the counter
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    import time
    time.sleep(1)   # wait 1 s then read CPU %

    for proc in psutil.process_iter(["pid", "name", "exe", "memory_info", "cpu_percent"]):
        try:
            name   = (proc.info["name"] or "").lower()
            exe    = proc.info["exe"] or ""
            pid    = proc.info["pid"]
            mem_mb = (proc.info["memory_info"].rss / 1024 / 1024
                      if proc.info["memory_info"] else 0)
            cpu    = proc.info["cpu_percent"] or 0.0

            # Known malware name match
            if name in SUSPICIOUS_PROCESS_NAMES:
                findings.append(finding("HIGH",
                    f"Suspicious process: {name} (PID {pid}) — matches known malware name", "processes"))

            # Excessive resource use
            elif cpu > CPU_THRESHOLD_PCT:
                findings.append(finding("MEDIUM",
                    f"High CPU: {name} (PID {pid}) using {cpu:.1f}% CPU", "processes"))

            elif mem_mb > MEM_THRESHOLD_MB:
                findings.append(finding("MEDIUM",
                    f"High memory: {name} (PID {pid}) using {mem_mb:.0f} MB RAM", "processes"))

            # No executable path (could be injected / hollow process)
            elif not exe and name not in ("system", "registry", "smss.exe",
                                          "csrss.exe", "wininit.exe"):
                findings.append(finding("LOW",
                    f"Process with no exe path: {name} (PID {pid})", "processes"))

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not findings:
        info_line("No suspicious processes detected.")

    return findings


# ===========================================================================
# CHECK 3 — Outdated Packages
# ===========================================================================

def check_outdated_packages() -> list[dict]:
    """
    Check pip for outdated Python packages.
    Each outdated package is a LOW finding (could have security patches).
    Also attempts winget upgrade --include-unknown for system packages.
    """
    print(section_header("CHECK 3 — Outdated Packages"))
    findings = []

    # --- pip ---
    info_line("Checking pip packages (this may take a moment)…")
    pip_out = run_cmd([sys.executable, "-m", "pip", "list", "--outdated",
                       "--format=columns"], timeout=60)
    if pip_out:
        lines = [l for l in pip_out.splitlines() if l and not l.startswith(("Package", "---"))]
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                pkg, current, latest = parts[0], parts[1], parts[2]
                findings.append(finding("LOW",
                    f"pip: {pkg} {current} → {latest} available", "packages"))
    else:
        info_line("pip check returned no results or pip not available.")

    # --- winget (Windows Package Manager) ---
    info_line("Checking winget for system package updates…")
    winget_out = run_cmd(["winget", "upgrade", "--include-unknown"], timeout=60)
    if winget_out:
        # winget output has a header; skip until we hit package lines
        in_packages = False
        for line in winget_out.splitlines():
            if re.match(r"^-+", line):
                in_packages = True
                continue
            if in_packages and line.strip():
                # Each line: Name  Id  Version  Available  Source
                parts = line.split()
                if len(parts) >= 4:
                    findings.append(finding("LOW",
                        f"winget: {parts[0]} — update available ({parts[3]})", "packages"))
    else:
        info_line("winget not available or no updates found.")

    if not findings:
        info_line("All checked packages appear up to date.")

    return findings


# ===========================================================================
# CHECK 4 — Suspicious Scheduled Tasks
# ===========================================================================

def check_scheduled_tasks() -> list[dict]:
    """
    Query Windows Task Scheduler via schtasks.
    Flag tasks that:
      - Run from TEMP / AppData / unusual paths (HIGH)
      - Were created/modified within the last TASK_RECENT_DAYS days (MEDIUM)
      - Run as SYSTEM or with highest privileges (LOW, informational)
    """
    print(section_header("CHECK 4 — Scheduled Tasks"))
    findings = []

    raw = run_cmd(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=30)
    if not raw:
        findings.append(finding("LOW", "Could not query scheduled tasks — try running as Administrator", "tasks"))
        return findings

    suspicious_path_patterns = [
        r"\\temp\\", r"\\tmp\\", r"\\appdata\\roaming\\",
        r"\\appdata\\local\\temp\\", r"\\users\\public\\",
        r"\.vbs$", r"\.ps1$", r"\.bat$", r"\.cmd$",
    ]

    cutoff = datetime.datetime.now() - datetime.timedelta(days=TASK_RECENT_DAYS)
    seen_tasks = set()

    lines = raw.splitlines()
    headers = []
    for line in lines:
        if not line.strip():
            continue
        parts = [p.strip('"') for p in line.split('","')]

        # First non-empty line is the header row
        if not headers:
            headers = [h.lower() for h in parts]
            continue

        if len(parts) < len(headers):
            continue

        row = dict(zip(headers, parts))
        task_name  = row.get("taskname", "")
        task_to_run = row.get("task to run", "")
        run_as     = row.get("run as user", "")
        last_run   = row.get("last run time", "")
        next_run   = row.get("next run time", "")

        if task_name in seen_tasks:
            continue
        seen_tasks.add(task_name)

        task_to_run_lower = task_to_run.lower()

        # Flag tasks pointing to suspicious locations
        for pattern in suspicious_path_patterns:
            if re.search(pattern, task_to_run_lower):
                findings.append(finding("HIGH",
                    f"Task '{task_name}' runs from suspicious path: {task_to_run}", "tasks"))
                break

        # Flag recently-created/modified tasks (use next_run as a proxy when
        # last_run is N/A — not perfect but catches newly registered tasks)
        for date_str in (last_run, next_run):
            try:
                dt = datetime.datetime.strptime(date_str, "%d/%m/%Y %H:%M:%S")
                if dt > cutoff:
                    findings.append(finding("MEDIUM",
                        f"Task '{task_name}' has recent activity ({date_str})", "tasks"))
                    break
            except ValueError:
                pass

        # Informational: tasks running as SYSTEM
        if "system" in run_as.lower():
            info_line(f"SYSTEM task: {task_name} → {task_to_run[:80]}")

    if not findings:
        info_line("No obviously suspicious scheduled tasks found.")

    return findings


# ===========================================================================
# CHECK 5 — World-Writable Files and Directories
# ===========================================================================

def check_world_writable() -> list[dict]:
    """
    Walk common directories and flag files/folders that are writable by
    Everyone or Users groups using icacls.
    Limits scan depth to avoid very long runtimes.
    """
    print(section_header("CHECK 5 — World-Writable Files & Directories"))
    findings = []
    MAX_DEPTH = 3
    MAX_FILES = 500   # cap to keep runtime reasonable

    scanned = 0
    flagged_paths = set()

    for base_dir in WRITABLE_SCAN_DIRS:
        if not os.path.isdir(base_dir):
            continue
        info_line(f"Scanning: {base_dir}")

        for root, dirs, files in os.walk(base_dir):
            # Limit depth
            depth = root.replace(base_dir, "").count(os.sep)
            if depth >= MAX_DEPTH:
                dirs.clear()
                continue

            targets = [root] + [os.path.join(root, f) for f in files]
            for target in targets:
                if scanned >= MAX_FILES:
                    break
                if target in flagged_paths:
                    continue
                scanned += 1

                # icacls returns permission lines; look for (W) or (F) for Everyone/Users
                out = run_cmd(["icacls", target], timeout=5)
                if re.search(r"(Everyone|BUILTIN\\Users).*(\\(W\\)|\\(F\\)|\\(M\\))", out, re.IGNORECASE):
                    flagged_paths.add(target)
                    is_dir = os.path.isdir(target)
                    sev = "HIGH" if is_dir else "MEDIUM"
                    findings.append(finding(sev,
                        f"World-writable {'directory' if is_dir else 'file'}: {target}", "writable"))

            if scanned >= MAX_FILES:
                info_line(f"Scan cap ({MAX_FILES} items) reached — increase MAX_FILES for deeper scan.")
                break

    if not findings:
        info_line("No world-writable paths found in scanned locations.")

    return findings


# ===========================================================================
# CHECK 6 — Failed Login Attempts
# ===========================================================================

def check_failed_logins() -> list[dict]:
    """
    Query the Windows Security Event Log for Event ID 4625 (failed logon).
    Summarises by source IP / username and flags repeated attempts.
    Requires Administrator privileges.
    """
    print(section_header("CHECK 6 — Failed Login Attempts"))
    findings = []

    # Use PowerShell to query the Security event log
    ps_script = (
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} "
        f"-MaxEvents {MAX_FAILED_LOGIN_EVENTS} -ErrorAction SilentlyContinue | "
        "Select-Object TimeCreated, "
        "@{n='User';e={$_.Properties[5].Value}}, "
        "@{n='IP';e={$_.Properties[19].Value}} | "
        "ConvertTo-Csv -NoTypeInformation"
    )

    raw = run_cmd(["powershell", "-NoProfile", "-Command", ps_script], timeout=30)

    if not raw.strip():
        findings.append(finding("LOW",
            "Could not read Security event log — run as Administrator for failed login data", "logins"))
        return findings

    from collections import Counter
    ip_counter   = Counter()
    user_counter = Counter()
    total        = 0

    for line in raw.splitlines()[1:]:   # skip CSV header
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) < 3:
            continue
        _time, user, ip = parts[0], parts[1], parts[2]
        if ip and ip not in ("-", ""):
            ip_counter[ip] += 1
        if user and user not in ("-", ""):
            user_counter[user] += 1
        total += 1

    if total == 0:
        info_line("No failed login events found in the last log window.")
        return findings

    info_line(f"Total failed login events found: {total}")

    # Flag IPs with >= 5 failures as MEDIUM, >= 20 as HIGH
    for ip, count in ip_counter.most_common(10):
        sev = "HIGH" if count >= 20 else "MEDIUM"
        findings.append(finding(sev,
            f"Failed logins from IP {ip}: {count} attempts", "logins"))

    # Flag usernames with repeated failures
    for user, count in user_counter.most_common(10):
        if count >= 5:
            findings.append(finding("MEDIUM",
                f"Repeated failed logins for user '{user}': {count} attempts", "logins"))

    return findings


# ===========================================================================
# CHECK 7 — Firewall Status
# ===========================================================================

def check_firewall() -> list[dict]:
    """
    Check Windows Defender Firewall status for all three profiles
    (Domain, Private, Public) using netsh.
    Flag if any profile is OFF (HIGH) or if inbound rules allow broad access (MEDIUM).
    """
    print(section_header("CHECK 7 — Firewall Status"))
    findings = []

    # --- Profile status ---
    raw = run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
    if not raw:
        findings.append(finding("HIGH", "Could not query firewall — run as Administrator", "firewall"))
        return findings

    for line in raw.splitlines():
        m = re.match(r"^(Domain|Private|Public)\s+Profile.*", line, re.IGNORECASE)
        if m:
            profile = m.group(1)
        if "state" in line.lower():
            if "off" in line.lower():
                findings.append(finding("HIGH",
                    f"Firewall {profile} profile is DISABLED", "firewall"))
            else:
                info_line(f"Firewall {profile} profile: ON")

    # --- Inbound rules that allow all traffic ---
    rules_raw = run_cmd(
        ["netsh", "advfirewall", "firewall", "show", "rule",
         "name=all", "dir=in", "action=allow"], timeout=20)

    broad_rules = []
    current_rule = {}
    for line in rules_raw.splitlines():
        line = line.strip()
        if line.startswith("Rule Name:"):
            current_rule = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("LocalPort:"):
            current_rule["port"] = line.split(":", 1)[1].strip()
        elif line.startswith("RemoteIP:"):
            current_rule["remote_ip"] = line.split(":", 1)[1].strip()
            # If remote IP is Any and port is Any — very broad
            if (current_rule.get("remote_ip", "").lower() in ("any", "") and
                    current_rule.get("port", "").lower() in ("any", "")):
                broad_rules.append(current_rule.get("name", "unknown"))

    for rule_name in broad_rules[:10]:   # cap output
        findings.append(finding("MEDIUM",
            f"Broad inbound allow rule: '{rule_name}' (Any IP, Any Port)", "firewall"))

    if not findings:
        info_line("Firewall appears properly configured.")

    return findings


# ===========================================================================
# Report assembly and output
# ===========================================================================

def print_summary(all_findings: list[dict]):
    """Print a colour-coded summary table at the end of the report."""
    from collections import Counter
    counts = Counter(f["severity"] for f in all_findings)

    print(section_header("SUMMARY"))
    total = len(all_findings)
    print(f"  Total findings: {Style.BRIGHT}{total}{Style.RESET_ALL}")
    for sev in ("HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev, 0)
        print(f"  {sev_colour(sev)}  {n} finding(s)")

    if counts.get("HIGH", 0) > 0:
        print(f"\n  {Fore.RED}{Style.BRIGHT}⚠  HIGH severity issues found — review immediately.{Style.RESET_ALL}")
    elif counts.get("MEDIUM", 0) > 0:
        print(f"\n  {Fore.YELLOW}{Style.BRIGHT}⚠  MEDIUM severity issues found — review soon.{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.GREEN}{Style.BRIGHT}✔  No high/medium issues detected.{Style.RESET_ALL}")


def save_report(all_findings: list[dict], fmt: str, checks_run: list[str]):
    """
    Save the report to a timestamped file.
    txt format mirrors the terminal layout exactly (section headers, bullet points).
    json format saves structured data for scripting / email attachments.
    """
    from collections import Counter
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    now  = datetime.datetime.now()

    # Resolve the script's own directory so the report lands next to the script,
    # not wherever the terminal's working directory happens to be.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, f"security_report_{ts}.{fmt}")

    if fmt == "json":
        report = {
            "generated":   now.isoformat(),
            "checks_run":  checks_run,
            "findings":    all_findings,
            "summary": {
                "total":  len(all_findings),
                "high":   sum(1 for f in all_findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
                "low":    sum(1 for f in all_findings if f["severity"] == "LOW"),
            }
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)

    else:
        # ----------------------------------------------------------------
        # Plain-text format — mirrors the terminal output layout
        # ----------------------------------------------------------------
        SEP  = "=" * 60
        SEP2 = "-" * 60

        # Group findings by check section for structured output
        CHECK_TITLES = {
            "ports":     "CHECK 1 — Open Ports",
            "processes": "CHECK 2 — Running Processes",
            "packages":  "CHECK 3 — Outdated Packages",
            "tasks":     "CHECK 4 — Scheduled Tasks",
            "writable":  "CHECK 5 — World-Writable Files & Directories",
            "logins":    "CHECK 6 — Failed Login Attempts",
            "firewall":  "CHECK 7 — Firewall Status",
        }

        # Severity badge without colour codes (plain text file)
        def plain_badge(sev: str) -> str:
            return f"[{sev.upper()}]"

        counts = Counter(f["severity"] for f in all_findings)

        with open(path, "w", encoding="utf-8") as fh:
            # Header banner
            fh.write(f"{SEP}\n")
            fh.write(f"  SECURITY SWEEP REPORT\n")
            fh.write(f"  Generated : {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
            fh.write(f"  Machine   : {os.environ.get('COMPUTERNAME', 'unknown')}\n")
            fh.write(f"  Checks    : {', '.join(checks_run)}\n")
            fh.write(f"{SEP}\n\n")

            # One section per check
            for check_name in checks_run:
                title = CHECK_TITLES.get(check_name, check_name.upper())
                section_findings = [
                    f for f in all_findings
                    if f.get("check") == check_name
                ]
                fh.write(f"{SEP2}\n")
                fh.write(f"  {title}\n")
                fh.write(f"{SEP2}\n")
                if section_findings:
                    for f in section_findings:
                        fh.write(f"  {plain_badge(f['severity'])}  {f['message']}\n")
                else:
                    fh.write("  • No findings.\n")
                fh.write("\n")

            # All findings in one flat list (easy to grep)
            fh.write(f"{SEP}\n")
            fh.write("  ALL FINDINGS\n")
            fh.write(f"{SEP}\n")
            if all_findings:
                for f in all_findings:
                    fh.write(f"  {plain_badge(f['severity'])}  {f['message']}\n")
            else:
                fh.write("  No findings.\n")
            fh.write("\n")

            # Summary
            fh.write(f"{SEP}\n")
            fh.write("  SUMMARY\n")
            fh.write(f"{SEP}\n")
            fh.write(f"  Total findings : {len(all_findings)}\n")
            fh.write(f"  [HIGH]         : {counts.get('HIGH', 0)}\n")
            fh.write(f"  [MEDIUM]       : {counts.get('MEDIUM', 0)}\n")
            fh.write(f"  [LOW]          : {counts.get('LOW', 0)}\n")
            fh.write(f"{SEP}\n")

            if counts.get("HIGH", 0) > 0:
                fh.write("\n  ⚠  HIGH severity issues found — review immediately.\n")
            elif counts.get("MEDIUM", 0) > 0:
                fh.write("\n  ⚠  MEDIUM severity issues found — review soon.\n")
            else:
                fh.write("\n  ✔  No high/medium issues detected.\n")

    print(f"\n  {Fore.GREEN}Report saved → {path}{Style.RESET_ALL}")
    return path


# ===========================================================================
# Entry point
# ===========================================================================

# Map of check names to their functions
ALL_CHECKS = {
    "ports":      check_open_ports,
    "processes":  check_running_processes,
    "packages":   check_outdated_packages,
    "tasks":      check_scheduled_tasks,
    "writable":   check_world_writable,
    "logins":     check_failed_logins,
    "firewall":   check_firewall,
}


def main():
    parser = argparse.ArgumentParser(
        description="Windows home-machine security sweep",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_sweep.py
  python security_sweep.py --output json
  python security_sweep.py --disable packages,writable
  python security_sweep.py --only ports,firewall,logins
        """
    )
    parser.add_argument(
        "--output", choices=["txt", "json"],
        help="Save report to a timestamped file (txt or json)"
    )
    parser.add_argument(
        "--disable", metavar="CHECK1,CHECK2",
        help=f"Comma-separated checks to skip. Available: {', '.join(ALL_CHECKS)}"
    )
    parser.add_argument(
        "--only", metavar="CHECK1,CHECK2",
        help="Run only these checks (comma-separated)"
    )
    args = parser.parse_args()

    # Determine which checks to run
    if args.only:
        checks_to_run = [c.strip() for c in args.only.split(",") if c.strip() in ALL_CHECKS]
    else:
        checks_to_run = list(ALL_CHECKS.keys())

    if args.disable:
        disabled = {c.strip() for c in args.disable.split(",")}
        checks_to_run = [c for c in checks_to_run if c not in disabled]

    # Header banner
    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'#' * 60}")
    print(f"#  SECURITY SWEEP — {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"#  Checks: {', '.join(checks_to_run)}")
    print(f"{'#' * 60}{Style.RESET_ALL}")

    all_findings: list[dict] = []

    for check_name in checks_to_run:
        fn = ALL_CHECKS[check_name]
        try:
            results = fn()
            all_findings.extend(results)
        except Exception as exc:
            all_findings.append(finding("MEDIUM",
                f"Check '{check_name}' raised an unexpected error: {exc}", check_name))

    print_summary(all_findings)

    # Always save a txt report automatically.
    # Pass --output json to save as JSON instead (txt is still saved alongside it).
    save_report(all_findings, "txt", checks_to_run)
    if args.output == "json":
        save_report(all_findings, "json", checks_to_run)

    # Exit with code 1 if any HIGH findings — useful for scripting / email triggers
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    sys.exit(1 if high_count > 0 else 0)


if __name__ == "__main__":
    main()
