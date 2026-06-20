import json
from collections import defaultdict

LOG_FILE = "logs/windows_events.json"
REPORT_FILE = "reports/threat_hunt_report.md"

findings = []

with open(LOG_FILE, "r") as f:
    events = json.load(f)

failed_logins = defaultdict(int)

for event in events:

    event_id = event.get("event_id")

    if event_id == 4625:
        failed_logins[event.get("source_ip", "unknown")] += 1

    if event_id == 4688:

        command = event.get("command", "").lower()

        if "-enc" in command:

            findings.append(
                (
                    "HIGH",
                    "Encoded PowerShell Execution",
                    "T1059.001"
                )
            )

    if event_id == 4732:

        findings.append(
            (
                "HIGH",
                "Privilege Escalation",
                "T1136"
            )
        )

for ip, count in failed_logins.items():

    if count >= 2:

        findings.append(
            (
                "MEDIUM",
                f"Brute Force From {ip}",
                "T1110"
            )
        )

with open(REPORT_FILE, "w") as report:

    report.write("# Threat Hunt Report\n\n")

    for severity, title, technique in findings:

        report.write(f"## {title}\n")
        report.write(f"- Severity: {severity}\n")
        report.write(f"- MITRE: {technique}\n\n")

print("Report generated successfully.")