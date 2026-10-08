# Splunk Alert - T1083 File and Directory Discovery

## Alert Overview

A real-time Splunk alert was configured to detect File and Directory Discovery through Sysmon Process Create telemetry.

The alert is associated with MITRE ATT&CK technique **T1083 - File and Directory Discovery**.

The purpose of the alert is to identify recursive directory enumeration using `dir /s` executed through `cmd.exe` during the controlled Atomic Red Team test.

## Detection Query

    index=siem_lab sourcetype="WinEventLog:Sysmon" EventCode=1 Image="C:\\Windows\\System32\\cmd.exe" Message="*dir /s*"

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
3. Limits the search to Sysmon Process Create events.
4. Searches for the execution of `cmd.exe`.
5. Matches command lines containing `dir /s`.
6. Identifies recursive directory enumeration associated with File and Directory Discovery activity.
7. Generates an alert when matching telemetry is observed.

## Validation

The alert was validated using the controlled Atomic Red Team T1083-1 activity used for the corresponding analysis.

The laboratory activity generated a `cmd.exe` process creation event containing recursive directory enumeration commands.

The Atomic execution subsequently timed out, but the expected Sysmon telemetry was successfully generated and ingested by Splunk.

The telemetry matched the detection query and triggered the configured real-time alert.

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

The detection is intentionally focused on the execution of `cmd.exe` containing `dir /s`, which directly represents the recursive directory enumeration observed during the controlled T1083 activity.

The observed command line contained:

    "cmd.exe" /c dir /s c:\ ... & dir /s "c:\Documents and Settings" ... & dir /s "c:\Program Files\" ... & dir "%%systemdrive%%\Users\*.*" ... & dir "%%userprofile%%\AppData\Roaming\Microsoft\Windows\Recent\*.*" ... & dir "%%userprofile%%\Desktop\*.*" ... & tree /F ...

The parent process was:

    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

The parent process and associated process lineage are documented as contextual investigation data and are not used as the primary detection criteria.

In a production environment, a broader detection strategy would be required to identify suspicious File and Directory Discovery activity without relying exclusively on a single command pattern.
