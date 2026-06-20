# Threat Hunting Framework

A Python-based threat hunting framework that analyzes Windows event logs, identifies suspicious activity, matches indicators of compromise (IOCs), and generates investigation reports mapped to the MITRE ATT&CK framework.

## Features

- Automated threat hunting
- Rule-based detection engine
- IOC matching
- MITRE ATT&CK mapping
- Risk scoring
- Automated report generation
- Interactive dashboard

## Project Structure

```text
threat-hunting-framework/

├── detections/
├── iocs/
├── logs/
├── reports/
├── hunter.py
├── report_generator.py
├── ioc_matcher.py
├── dashboard.py
├── requirements.txt
└── README.md
```

## Detection Capabilities

| Detection | MITRE ATT&CK |
|------------|-------------|
| Encoded PowerShell Execution | T1059.001 |
| Brute Force Authentication | T1110 |
| Privilege Escalation | T1136 |
| Credential Dumping | T1003 |
| Suspicious Service Creation | T1543 |

## Sample Findings

- Encoded PowerShell execution detected
- Repeated failed login attempts
- Administrative privilege escalation
- IOC matches against known malicious IPs

## Technologies

- Python
- JSON
- Streamlit
- MITRE ATT&CK

## Skills Demonstrated

- Threat Hunting
- Security Automation
- Detection Engineering
- IOC Analysis
- Log Analysis
- Incident Investigation
- SOC Operations

## Future Enhancements

- Sigma rule support
- Sysmon integration
- EVTX log parsing
- Threat intelligence feeds
- ATT&CK coverage visualization

## Resume Summary

Developed a Python-based Threat Hunting Framework capable of analyzing Windows security logs, applying detection rules, matching indicators of compromise, generating investigation reports, and mapping findings to MITRE ATT&CK techniques.