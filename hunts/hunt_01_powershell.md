# Hunt 01 - PowerShell Abuse

## Objective

Identify suspicious PowerShell execution.

## Indicators

- powershell.exe
- -enc
- -encodedcommand

## Findings

Detected:

powershell.exe -enc SQBFAFgA

## MITRE ATT&CK

T1059.001
