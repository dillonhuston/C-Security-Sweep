import psutil
from config.constants import SUSPICIOUS_PORTS
from models.finding import Finding

def open_ports() -> list[dict]:
    """
    Enumerate all listening TCP/UDP ports using psutil.
    Flag any port in the SUSPICIOUS_PORTS dictionary as HIGH or MEDIUM.
    """
    findings = []

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        finding = Finding(
            title="Access Denied",
            severity="MEDIUM",
            message="Access denied reading network connections — run as Administrator",
            check="open_ports"
        )
        findings.append(finding.to_dict())
        return findings

    listening_ports = {}
    for conn in connections:
        if conn.status in ("LISTEN", "NONE", "") and conn.laddr:
            port = conn.laddr.port
            pid = conn.pid
            try:
                proc_name = psutil.Process(pid).name() if pid else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "unknown"
            listening_ports[port] = proc_name

    if not listening_ports:
        return findings

    for port, proc in sorted(listening_ports.items()):
        label = SUSPICIOUS_PORTS.get(port)
        if label:
            sev = "HIGH" if port in (3389, 445, 4444, 6666, 6667) else "MEDIUM"
            finding = Finding(
                title=f"Port {port} open",
                severity=sev,
                message=f"{label} (process: {proc})",
                check="open_ports"
            )
            findings.append(finding.to_dict())

    return findings