import datetime
from collections import Counter
from utils.helpers import run_cmd
from config.constants import MAX_FAILED_LOGIN_EVENTS
from models.finding import Finding

def failed_logins():
    findings = []

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
        finding = Finding(
            title="Failed Logins Unavailable",
            severity="LOW",
            message="Could not read Security event log — run as Administrator for failed login data",
            check="failed_logins"
        )
        findings.append(finding.to_dict())
        return findings

    ip_counter = Counter()
    user_counter = Counter()
    total = 0

    for line in raw.splitlines()[1:]:
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
        return findings

    for ip, count in ip_counter.most_common(10):
        sev = "HIGH" if count >= 20 else "MEDIUM"
        finding = Finding(
            title="Failed Login Attempts",
            severity=sev,
            message=f"Failed logins from IP {ip}: {count} attempts",
            check="failed_logins"
        )
        findings.append(finding.to_dict())

    for user, count in user_counter.most_common(10):
        if count >= 5:
            finding = Finding(
                title="Repeated Failed Logins",
                severity="MEDIUM",
                message=f"Repeated failed logins for user '{user}': {count} attempts",
                check="failed_logins"
            )
            findings.append(finding.to_dict())

    return findings