import json
from collections import defaultdict

LOG_FILE = "logs/windows_events.json"

findings = []

with open(LOG_FILE, "r") as f:
    events = json.load(f)

failed_logins = defaultdict(int)

for event in events:

    event_id = event.get("event_id")

    # Hunt 1: Failed Logins
    if event_id == 4625:
        ip = event.get("source_ip", "unknown")
        failed_logins[ip] += 1

    # Hunt 2: Encoded PowerShell
    if event_id == 4688:
        command = event.get("command", "").lower()

        if "-enc" in command or "-encodedcommand" in command:
            findings.append({
                "severity": "HIGH",
                "technique": "T1059.001",
                "title": "Encoded PowerShell Execution",
                "details": command
            })

    # Hunt 3: Privilege Escalation
    if event_id == 4732:
        findings.append({
            "severity": "HIGH",
            "technique": "T1136",
            "title": "User Added To Administrators Group",
            "details": event.get("message", "")
        })

# Brute Force Detection
for ip, count in failed_logins.items():

    if count >= 2:
        findings.append({
            "severity": "MEDIUM",
            "technique": "T1110",
            "title": "Potential Brute Force Activity",
            "details": f"{count} failed logins from {ip}"
        })

print("\n=== Threat Hunt Results ===\n")

for finding in findings:

    print(f"[{finding['severity']}]")
    print(f"Technique : {finding['technique']}")
    print(f"Finding   : {finding['title']}")
    print(f"Details   : {finding['details']}")
    print()