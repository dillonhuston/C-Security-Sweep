import sys
import re
import datetime
from utils.helpers import run_cmd

def outdated_packages():
    findings = []

    # pip check - shorter timeout
    try:
        pip_out = run_cmd([sys.executable, "-m", "pip", "list", "--outdated", "--format=columns"], timeout=30)
        if pip_out:
            lines = [l for l in pip_out.splitlines() if l and not l.startswith(("Package", "---"))]
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    pkg, current, latest = parts[0], parts[1], parts[2]
                    findings.append({
                        "severity": "LOW",
                        "message": f"pip: {pkg} {current} → {latest} available",
                        "check": "outdated_packages",
                        "timestamp": datetime.datetime.now().isoformat()
                    })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "message": f"pip check failed: {str(e)}",
            "check": "outdated_packages",
            "timestamp": datetime.datetime.now().isoformat()
        })

    # winget check - skip if it hangs
    try:
        winget_out = run_cmd(["winget", "upgrade", "--include-unknown"], timeout=15)
        if winget_out:
            in_packages = False
            for line in winget_out.splitlines():
                if re.match(r"^-+", line):
                    in_packages = True
                    continue
                if in_packages and line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        findings.append({
                            "severity": "LOW",
                            "message": f"winget: {parts[0]} — update available ({parts[3]})",
                            "check": "outdated_packages",
                            "timestamp": datetime.datetime.now().isoformat()
                        })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "message": f"winget check failed: {str(e)}",
            "check": "outdated_packages",
            "timestamp": datetime.datetime.now().isoformat()
        })

    return findings