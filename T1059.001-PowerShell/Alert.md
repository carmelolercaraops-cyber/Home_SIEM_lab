# Splunk Alert - T1059.001 PowerShell

## Alert Overview

A real-time Splunk alert was configured to detect PowerShell process execution involving encoded command-line parameters.

The alert is associated with MITRE ATT&CK technique **T1059.001 - PowerShell**.

The purpose of the alert is to identify PowerShell executions using parameters commonly associated with encoded commands, while excluding Splunk's own PowerShell process.

## Detection Query

    index=siem_lab sourcetype="WinEventLog:Sysmon"
    | search Message="*Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe*"
    | search NOT Message="*splunk-powershell.exe*"
    | rex field=Message "(?i)CommandLine:\s*(?<CommandLine>[^\r\n]+)"
    | rex field=Message "(?i)ParentImage:\s*(?<ParentImage>[^\r\n]+)"
    | search CommandLine="*-e *" OR CommandLine="*-enc *" OR CommandLine="*-encodedcommand*"

## Alert Configuration

- **Alert type:** Real-time
- **Trigger condition:** Search returns matching results
- **Severity:** Medium
- **Action:** Add to Triggered Alerts
- **Expiration:** 30 days
- **Index:** `siem_lab`
- **Sourcetype:** `WinEventLog:Sysmon`

## Detection Logic

The alert:

1. Searches Sysmon telemetry stored in the `siem_lab` index.
2. Limits the search to `WinEventLog:Sysmon` events.
3. Identifies Windows PowerShell process creation events.
4. Excludes Splunk's own PowerShell process.
5. Extracts the command line and parent process from the Sysmon message.
6. Searches for encoded PowerShell command-line parameters:
   - `-e`
   - `-enc`
   - `-encodedcommand`

## Validation

The alert was validated using the same controlled Atomic Red Team activity used for the corresponding analysis.

The laboratory activity generated a PowerShell process containing an encoded command.

The telemetry was successfully ingested by Splunk, matched the detection query, and triggered the configured real-time alert.

This confirms the complete detection workflow:

    Controlled Activity
            ↓
    Sysmon Event
            ↓
    Splunk Universal Forwarder
            ↓
    Splunk Enterprise
            ↓
    SPL Detection
            ↓
    Real-Time Alert
            ↓
    Triggered Alert

## Classification

The alert represents a **confirmed laboratory test-positive event**.

The activity was intentionally generated as part of the Home SIEM Lab and does not represent evidence of a real-world compromise.

## Notes

The detection is intentionally focused on observable command-line characteristics rather than attempting to determine malicious intent from the encoded command alone.

In a production environment, additional contextual analysis would be required before determining whether a matching event represents malicious activity.
