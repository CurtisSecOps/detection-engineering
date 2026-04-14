# Threat Hunt: Suspicious Curl Payload Delivery

## Hunt Objective
Identify potential malicious payload delivery using `curl.exe`, commonly associated with initial access or post-exploitation activity.

## Hypothesis
Adversaries may leverage `curl.exe` to download payloads from external infrastructure into user-writable directories such as AppData or Temp, followed by execution via scripting engines or LOLBins.

## MITRE ATT&CK
- T1105 – Ingress Tool Transfer
- T1059 – Command and Scripting Interpreter

## Hunt Logic (Splunk)
```spl
index=* sourcetype=* 
(
  Image="*\\curl.exe" OR process_name="curl.exe"
)
(
  CommandLine="*-o *" OR CommandLine="* -O *" OR CommandLine="*--output*"
)
| eval process_cmd=coalesce(CommandLine, process)
| stats count values(host) as host values(user) as user values(process_cmd) as process_cmd by _time
| sort -_time
