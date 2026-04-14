# Splunk Correlation Detection: TA450 Attack Chain (Curl → PowerShell → RMM → Persistence)

## Overview
Detects a multi-stage attack chain associated with Iranian state-sponsored actors (TA450 / MuddyWater), including payload download via `curl.exe`, execution via PowerShell, deployment of remote management tools (RMM), and persistence via scheduled tasks.

This detection focuses on behavioral correlation across process execution events to identify high-confidence malicious activity.

---

## MITRE ATT&CK
- T1105 – Ingress Tool Transfer  
- T1059 – Command and Scripting Interpreter  
- T1219 – Remote Access Software  
- T1053 – Scheduled Task/Job  

---

## Detection Logic

This analytic correlates the following sequence on a single host:

1. `curl.exe` downloading a file  
2. PowerShell execution with encoded or download-based commands  
3. Execution of RMM tools (Atera, ScreenConnect, SimpleHelp, etc.)  
4. Scheduled task creation for persistence  

---

## Splunk SPL (Correlation Detection)

```spl
index=edr OR index=sysmon
(
  process_name IN ("curl.exe","powershell.exe","cmd.exe","wscript.exe","mshta.exe","schtasks.exe",
                   "ateraagent.exe","screenconnect.clientservice.exe","simplehelp.exe")
)
| eval stage=case(
    process_name="curl.exe","Stage 1 - Payload Download",
    process_name="powershell.exe","Stage 2 - Execution",
    process_name IN ("ateraagent.exe","screenconnect.clientservice.exe","simplehelp.exe"),"Stage 3 - RMM Deployment",
    process_name="schtasks.exe","Stage 4 - Persistence"
)
| stats values(stage) as stages values(process_name) as process_name values(CommandLine) as command_line values(parent_process_name) as parent_process by host
| where mvcount(stages) >= 3
```

---

## Detection Description
This detection identifies hosts exhibiting multiple stages of an attack chain consistent with TA450 activity, significantly increasing detection fidelity compared to single-event alerts.

---

## Indicators of Suspicion
- `curl.exe` downloading files to user-writable directories  
- PowerShell execution with encoded or obfuscated commands  
- Installation or execution of RMM tools  
- Scheduled task creation shortly after execution  

---

## Investigation Steps
1. Review process lineage across all stages  
2. Identify downloaded payload and source domain  
3. Validate execution chain and file artifacts  
4. Confirm persistence mechanisms  
5. Scope activity across additional hosts  

---

## Response Actions
- Isolate affected endpoint  
- Terminate malicious processes  
- Remove persistence mechanisms  
- Block associated domains/IPs  
- Initiate incident response procedures  

---

## Severity
Critical

---

## References
- [MITRE ATT&CK T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK T1053 – Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)

- [Proofpoint: TA450 ClickFix Campaign – PowerShell execution and RMM delivery](https://www.proofpoint.com/us/blog/threat-insight/around-world-90-days-state-sponsored-actors-try-clickfix)

- [SentinelOne: Iranian Cyber Activity Outlook – persistence and tunneling techniques](https://www.sentinelone.com/blog/sentinelone-intelligence-brief-iranian-cyber-activity-outlook/)
