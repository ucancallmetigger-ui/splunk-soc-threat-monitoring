# Detection and Investigation Notes

This document records the intent and limitations of the searches used in the SOC Threat Monitoring dashboard.

## 1. PowerShell Script Block Activity

**Purpose:** Find PowerShell Script Block Logging events that contain potentially notable execution patterns.

**Patterns reviewed:** `DownloadString`, `FromBase64String`, `EncodedCommand`, `Invoke-Expression`, `IEX`, `Hidden`, and script-block logging configuration changes.

**Why it matters:** Remote content retrieval, encoded content, dynamic execution, and attempts to alter logging can appear in malicious scripts.

**Triage guidance:**
1. Review the complete script block rather than only the matching keyword.
2. Correlate host and timestamp with process creation, network connections, and user logon events.
3. Check whether the activity matches approved administration or software behavior.
4. Record the evidence supporting the assessment and any unresolved gaps.

**Caution:** These strings are not unique to malware. The presence of one is an indicator for review, not a verdict.

## 2. DNS NXDOMAIN Activity

**Purpose:** Summarize DNS query events with an `NXDOMAIN` response.

**Why it matters:** Repeated failed lookups can be associated with misconfiguration, typo-heavy application behavior, domain generation, or other suspicious activity.

**Triage guidance:**
- Identify the querying host and queried domain.
- Check whether the domain is expected for the application or environment.
- Review the frequency and timing of queries.
- Correlate with endpoint and network events before escalating.

**Caution:** NXDOMAIN alone does not establish DNS tunneling or command-and-control activity.

## 3. AWS VPC Flow Logs

**Purpose:** Summarize flow volume and review rejected connections to selected destination ports.

**Fields used where available:** source address, destination address, source port, destination port, protocol, packets, bytes, action, and log status.

**Why it matters:** Flow summaries can help prioritize traffic for review, while rejected connections may provide context about blocked access attempts.

**Triage guidance:**
- Confirm the source and destination asset roles.
- Review protocol, destination port, action, byte count, packet count, and time window.
- Compare with expected network architecture and approved services.
- Correlate with endpoint and identity telemetry.

**Caution:** `ACCEPT` does not mean benign, and `REJECT` does not prove an attack. A byte threshold is a prioritization filter, not proof of exfiltration.

## 4. Windows Failed Logons (Event ID 4625)

**Purpose:** Summarize failed logon events by host.

**Triage guidance:** Review account, source address where available, logon type, timing, and nearby successful logons. Consider expected service-account failures and user mistakes.

**Caution:** A small count may still be important in context; a high count may reflect benign misconfiguration.

## 5. Windows Process Creation (Event ID 4688)

**Purpose:** Review process-creation activity in Windows Security logs.

**Triage guidance:** Inspect the event message for the process path, creator/subject details, and command line if recorded. Correlate with PowerShell and network events.

**Caution:** Process names alone are weak evidence. Validate paths, signatures where possible, parent-child relationships, and user context.

## 6. Windows Process Termination (Event ID 4689)

**Purpose:** Summarize process termination events by host.

**Caution:** Event volume alone is operational context, not a standalone detection. Use process details and neighboring events for investigation.

## 7. Windows Special Privileges (Event ID 4672)

**Purpose:** Review events indicating special privileges assigned to a new logon.

**Caution:** These events can be expected for administrators and system accounts. Assess the account, logon session, host role, and timing.

## 8. Windows Object Access (Event ID 4663)

**Purpose:** Review object-access events and extract available object and access details from the event message.

**Caution:** The event may refer to an object other than a file. Interpret `Object Type`, `Object Name`, and `Accesses` together; do not assume every event is file access.

## 9. Windows Object Permission Changes (Event ID 4670)

**Purpose:** Summarize changes to permissions on Windows objects and inspect object type and process context.

**Observation from this lab:** A sample of the dataset contained `Token` as the object type, with processes including Chrome and Windows system components. This demonstrates why the event ID should not be described as file-permission changes without checking `Object Type`.

**Caution:** High event counts can reflect normal operating-system or application behavior. Review the security descriptor change and surrounding context before escalation.

## 10. Windows Firewall Rule Application Failures (Event ID 4957)

**Purpose:** Group events where Windows Firewall did not apply a rule.

**Observed reasons in this dataset:** remote addresses, interfaces, or local ports resolved to an empty set.

**Caution:** These messages can indicate configuration or interface-resolution issues. They are not, by themselves, evidence of malicious firewall tampering.

## Severity and confidence

This repository does not assign a high severity solely from a keyword match or event count. Severity should be assigned only after considering asset criticality, user context, event frequency, corroborating evidence, and operational expectations.

Suggested investigation labels:
- **Informational:** expected or low-context activity requiring no immediate action.
- **Needs review:** pattern warrants contextual validation.
- **Escalate:** multiple corroborating indicators support further incident response.

These labels are workflow guidance, not automatic conclusions generated by the SPL.
