import os
from pathlib import Path

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
