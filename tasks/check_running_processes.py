import psutil
import datetime
import time
from config.constants import SUSPICIOUS_PROCESS_NAMES, CPU_THRESHOLD_PCT, MEM_THRESHOLD_MB
from models.finding import Finding

def running_processes() -> list[dict]:
    findings = []

    for proc in psutil.process_iter(["pid", "name", "exe", "memory_info", "cpu_percent"]):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    time.sleep(1)

    for proc in psutil.process_iter(["pid", "name", "exe", "memory_info", "cpu_percent"]):
        try:
            name = (proc.info["name"] or "").lower()
            exe = proc.info["exe"] or ""
            pid = proc.info["pid"]
            mem_mb = (proc.info["memory_info"].rss / 1024 / 1024
                      if proc.info["memory_info"] else 0)
            cpu = proc.info["cpu_percent"] or 0.0

            if name in SUSPICIOUS_PROCESS_NAMES:
                finding = Finding(
                    title="Suspicious Process",
                    severity="HIGH",
                    message=f"Suspicious process: {name} (PID {pid}) — matches known malware name",
                    check="running_processes"
                )
                findings.append(finding.to_dict())

            elif cpu > CPU_THRESHOLD_PCT:
                finding = Finding(
                    title="High CPU Usage",
                    severity="MEDIUM",
                    message=f"High CPU: {name} (PID {pid}) using {cpu:.1f}% CPU",
                    check="running_processes"
                )
                findings.append(finding.to_dict())

            elif mem_mb > MEM_THRESHOLD_MB:
                finding = Finding(
                    title="High Memory Usage",
                    severity="MEDIUM",
                    message=f"High memory: {name} (PID {pid}) using {mem_mb:.0f} MB RAM",
                    check="running_processes"
                )
                findings.append(finding.to_dict())

            elif not exe and name not in ("system", "registry", "smss.exe", "csrss.exe", "wininit.exe"):
                finding = Finding(
                    title="Process with No Executable Path",
                    severity="LOW",
                    message=f"Process with no exe path: {name} (PID {pid})",
                    check="running_processes"
                )
                findings.append(finding.to_dict())

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return findings