import re
import datetime
from utils.helpers import run_cmd
from config.constants import TASK_RECENT_DAYS
from models.finding import Finding

def scheduled_tasks():
    findings = []

    raw = run_cmd(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=30)
    if not raw:
        finding = Finding(
            title="Scheduled Tasks Unavailable",
            severity="LOW",
            message="Could not query scheduled tasks — try running as Administrator",
            check="scheduled_tasks"
        )
        findings.append(finding.to_dict())
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

        if not headers:
            headers = [h.lower() for h in parts]
            continue

        if len(parts) < len(headers):
            continue

        row = dict(zip(headers, parts))
        task_name = row.get("taskname", "")
        task_to_run = row.get("task to run", "")
        last_run = row.get("last run time", "")
        next_run = row.get("next run time", "")

        if task_name in seen_tasks:
            continue
        seen_tasks.add(task_name)

        task_to_run_lower = task_to_run.lower()

        for pattern in suspicious_path_patterns:
            if re.search(pattern, task_to_run_lower):
                finding = Finding(
                    title="Suspicious Scheduled Task",
                    severity="HIGH",
                    message=f"Task '{task_name}' runs from suspicious path: {task_to_run}",
                    check="scheduled_tasks"
                )
                findings.append(finding.to_dict())
                break

        for date_str in (last_run, next_run):
            try:
                dt = datetime.datetime.strptime(date_str, "%d/%m/%Y %H:%M:%S")
                if dt > cutoff:
                    finding = Finding(
                        title="Recent Scheduled Task Activity",
                        severity="MEDIUM",
                        message=f"Task '{task_name}' has recent activity ({date_str})",
                        check="scheduled_tasks"
                    )
                    findings.append(finding.to_dict())
                    break
            except ValueError:
                pass

    return findings