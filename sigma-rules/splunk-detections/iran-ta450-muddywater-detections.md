# Splunk Detection Pack: TA450 / MuddyWater Activity

## Overview
This detection pack identifies tradecraft associated with Iranian state-sponsored actors, specifically TA450 (MuddyWater / Mango Sandstorm).

---

## Detection 1: Suspicious PowerShell Execution (ClickFix Pattern)

### MITRE ATT&CK
- T1059 – Command and Scripting Interpreter
- T1105 – Ingress Tool Transfer

### Description
Detects PowerShell execution with encoded or download-based commands launched from user-driven processes such as browsers. This aligns with ClickFix-style social engineering campaigns observed in TA450 activity.

### SPL
```spl
index=edr OR index=sysmon
(process_name="powershell.exe")
(
  CommandLine="*-enc *" OR CommandLine="*FromBase64String*" OR CommandLine="*DownloadString*" 
  OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*iwr *" OR CommandLine="*iex *"
  OR CommandLine="* -w hidden *"
)
(parent_process_name="chrome.exe" OR parent_process_name="msedge.exe" OR parent_process_name="explorer.exe")
| stats values(host) as host values(user) as user values(parent_process_name) as parent_process values(CommandLine) as command_line by process_guid
