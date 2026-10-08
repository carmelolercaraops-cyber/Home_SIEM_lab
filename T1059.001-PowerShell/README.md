# T1059.001 - PowerShell

## Overview

This analysis documents a controlled laboratory exercise focused on MITRE ATT&CK technique **T1059.001 - PowerShell**.

The objective is to observe PowerShell execution through Windows endpoint telemetry, forward the generated events to Splunk, develop detection logic, validate the detection, and investigate the resulting activity from a SOC perspective.

The activity was intentionally generated using Atomic Red Team inside the Windows laboratory environment.

## Laboratory Activity

The Atomic Red Team test used for this analysis was:

- **Technique:** T1059.001 - PowerShell
- **Test:** T1059.001-17 - PowerShell Command Execution
- **Execution result:** Successful
- **Observed output:** `Hello, from PowerShell!`
- **Exit code:** `0`

The test generated PowerShell activity that was observable through multiple Windows telemetry sources.

## Telemetry

The analysis uses telemetry collected from:

- Sysmon
- PowerShell Script Block Logging
- Splunk Universal Forwarder
- Splunk Enterprise

Relevant telemetry included:

- Sysmon Event ID 1 - Process Create
- PowerShell Event ID 4104 - Script Block Logging

Sysmon provided process-level information such as the executable, command line, process ID, parent process, and hash.

PowerShell Script Block Logging provided additional visibility into the PowerShell script content.

The combination of these telemetry sources allowed the execution to be investigated with greater context than relying on a single event source.

## Detection

The detection was developed and tested in Splunk using SPL.

The detection focuses on PowerShell process creation involving encoded command execution, including:

- `powershell.exe`
- Encoded PowerShell command-line parameters such as `-e`, `-enc`, and `-EncodedCommand`
- Parent process information
- Exclusion of Splunk's own PowerShell process where necessary

The final detection logic used during the laboratory validation is stored in:

`detection.spl`

## Alert Validation

A real-time Splunk alert was configured using the validated detection.

The alert workflow was tested end-to-end:

    Atomic Red Team
          ↓
    Windows / Sysmon telemetry
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

The alert was successfully triggered after the laboratory activity was executed.

## Investigation

The observed process chain provided additional context for the investigation.

The laboratory execution included PowerShell activity involving `cmd.exe` and an encoded PowerShell command.

The encoded command was decoded during the analysis to understand the observed execution and correlate it with the intended Atomic Red Team activity.

PowerShell Event ID 4104 independently provided the script content:

`Write-Host 'Hello, from PowerShell!'`

This additional telemetry supported the classification of the observed activity as a confirmed laboratory test-positive event.

## Evidence

The `evidence/` directory contains sanitized copies of the relevant telemetry collected during the analysis.

Current evidence includes:

- `sysmon_1.csv`
- `powershell_4104.csv`

The published evidence is sanitized before being committed to the repository.

Personal or environment-specific information such as the original hostname and username is replaced with laboratory-safe values where appropriate.

Raw logs are not published.

## Report

The SOC-style investigation report is available in:

`report.md`

The report documents:

- Time of activity
- Affected entities
- Reason for classifying the activity as a true positive
- Reason for escalating the alert
- Recommended remediation actions
- Attack indicators

## Reproducibility

The analysis is based on an activity actually executed in the laboratory environment.

The repository contains the relevant detection logic, sanitized evidence, alert documentation, and investigation report so that the analysis can be reviewed as a complete detection workflow.

Results documented here represent controlled laboratory activity and should not be interpreted as evidence of a real-world compromise.

## Status

**Analysis completed and detection validated.**

The analysis may be extended in the future with additional telemetry, correlation logic, investigation steps, or related detection improvements.
