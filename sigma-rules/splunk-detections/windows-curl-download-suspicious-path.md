# Windows Curl Download to Suspicious Path

## Overview
Detects the use of `curl.exe` to download content from an external source into suspicious local directories commonly used for malware staging or payload delivery.

## Detection Logic
This analytic looks for:
- process executions involving `curl.exe`
- command lines containing common download flags such as `-o`, `-O`, or `--output`
- destination paths associated with suspicious staging activity such as:
  - `AppData`
  - `ProgramData`
  - `Public`
  - `Temp`

## MITRE ATT&CK
- T1105 - Ingress Tool Transfer

## Splunk SPL
```spl
index=* sourcetype=* 
(
  Image="*\\curl.exe" OR process_name="curl.exe" OR Processes.process_name="curl.exe"
)
(
  CommandLine="*-o *" OR CommandLine="* -O *" OR CommandLine="*--output*"
  OR process="*-o *" OR process="* -O *" OR process="*--output*"
  OR Processes.process="*-o *" OR Processes.process="* -O *" OR Processes.process="*--output*"
)
(
  CommandLine="*AppData*" OR CommandLine="*ProgramData*" OR CommandLine="*\\Users\\Public\\*" OR CommandLine="*Temp*"
  OR process="*AppData*" OR process="*ProgramData*" OR process="*\\Users\\Public\\*" OR process="*Temp*"
  OR Processes.process="*AppData*" OR Processes.process="*ProgramData*" OR Processes.process="*\\Users\\Public\\*" OR Processes.process="*Temp*"
)
| eval process_cmd=coalesce(CommandLine, process, Processes.process)
| eval process_image=coalesce(Image, process_name, Processes.process_name)
| stats count min(_time) as firstTime max(_time) as lastTime values(dest) as dest values(user) as user values(parent_process_name) as parent_process values(process_image) as process_image values(process_cmd) as process_cmd by host
| convert ctime(firstTime) ctime(lastTime)
```

## Why This Matters
Threat actors linked to Black Basta have been observed using scripted `curl` commands to download payloads, and similar tradecraft has been documented in campaigns involving malicious batch files, ZIP files, and follow-on malware deployment.

## Tuning Guidance
Reduce noise by:
- excluding known software deployment tools
- excluding known internal package repositories or artifact servers
- filtering expected admin activity
- correlating with child processes such as:
  - `wscript.exe`
  - `cscript.exe`
  - `powershell.exe`
  - `cmd.exe`
  - `rundll32.exe`

## Investigation Tips
When this fires, review:
- the full command line
- parent process
- destination file path
- URL or domain contacted
- whether the downloaded file was later executed
- any child process spawned after `curl.exe`

## False Positives
- legitimate software installation or update activity
- administrator downloads
- internal automation or scripting

## Severity
High

## References
- https://attack.mitre.org/techniques/T1105/
- https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/
- https://www.trendmicro.com/en_us/research/24/a/a-look-into-pikabot-spam-wave-campaign.html
- https://research.splunk.com/endpoint/c32f091e-30db-11ec-8738-acde48001122/
