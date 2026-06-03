import os
import re
import datetime
from config.constants import WRITABLE_SCAN_DIRS
from utils.helpers import run_cmd
from models.finding import Finding

def world_writable():
    findings = []
    MAX_DEPTH = 3
    MAX_FILES = 500

    scanned = 0
    flagged_paths = set()

    for base_dir in WRITABLE_SCAN_DIRS:
        if not os.path.isdir(base_dir):
            continue

        for root, dirs, files in os.walk(base_dir):
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

                out = run_cmd(["icacls", target], timeout=5)
                if re.search(r"(Everyone|BUILTIN\\Users).*(\\(W\\)|\\(F\\)|\\(M\\))", out, re.IGNORECASE):
                    flagged_paths.add(target)
                    is_dir = os.path.isdir(target)
                    sev = "HIGH" if is_dir else "MEDIUM"
                    finding = Finding(
                        title="World-Writable Path",
                        severity=sev,
                        message=f"World-writable {'directory' if is_dir else 'file'}: {target}",
                        check="world_writable"
                    )
                    findings.append(finding.to_dict())

            if scanned >= MAX_FILES:
                break

    return findings