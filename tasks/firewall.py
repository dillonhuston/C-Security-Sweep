import re
import datetime
from utils.helpers import run_cmd
from models.finding import Finding

def firewall():
    findings = []

    raw = run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
    if not raw:
        finding = Finding(
            title="Firewall Unavailable",
            severity="HIGH",
            message="Could not query firewall — run as Administrator",
            check="firewall"
        )
        findings.append(finding.to_dict())
        return findings

    profile = None
    for line in raw.splitlines():
        m = re.match(r"^(Domain|Private|Public)\s+Profile.*", line, re.IGNORECASE)
        if m:
            profile = m.group(1)
        if "state" in line.lower() and "off" in line.lower():
            finding = Finding(
                title="Firewall Disabled",
                severity="HIGH",
                message=f"Firewall {profile} profile is DISABLED",
                check="firewall"
            )
            findings.append(finding.to_dict())

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
            if (current_rule.get("remote_ip", "").lower() in ("any", "") and
                    current_rule.get("port", "").lower() in ("any", "")):
                broad_rules.append(current_rule.get("name", "unknown"))

    for rule_name in broad_rules[:10]:
        finding = Finding(
            title="Broad Firewall Rule",
            severity="MEDIUM",
            message=f"Broad inbound allow rule: '{rule_name}' (Any IP, Any Port)",
            check="firewall"
        )
        findings.append(finding.to_dict())

    return findings