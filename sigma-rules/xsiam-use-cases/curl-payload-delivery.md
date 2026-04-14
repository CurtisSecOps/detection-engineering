# XSIAM Use Case: Curl-Based Payload Delivery

## Overview
Detects the use of `curl.exe` to download payloads from external sources into suspicious directories, potentially indicating malware staging or ransomware delivery activity. This behavior aligns with common ingress tool transfer techniques observed in modern ransomware campaigns, including those associated with Black Basta.

## MITRE ATT&CK
- T1105 – Ingress Tool Transfer

## Detection Logic

### Data Sources
- Endpoint process execution logs
- Command-line telemetry
- File write activity
- Network connection logs

### Behavioral Indicators
- Execution of `curl.exe`
- Use of download flags:
  - `-o`
  - `-O`
  - `--output`
- File download into user-writable or staging directories:
  - `AppData`
  - `ProgramData`
  - `Temp`
  - `Users\Public`

### Sample XQL Query
```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter process_name = "curl.exe"
| filter (
    command_line contains "-o" or 
    command_line contains "-O" or 
    command_line contains "--output"
)
| filter (
    command_line contains "AppData" or
    command_line contains "ProgramData" or
    command_line contains "Temp" or
    command_line contains "Users\\Public"
)
| fields _time, agent_hostname, actor_process_image_name, command_line, actor_process_parent_image_name
