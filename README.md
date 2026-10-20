# SOC Threat Monitoring with Splunk

A hands-on SOC monitoring project built in Splunk using the BOTS v3 dataset. The dashboard brings together Windows security events, PowerShell activity, DNS telemetry, and AWS VPC Flow Logs to support investigation and triage.

The goal is practical: make useful event patterns easier to review, document the SPL behind each view, and distinguish an investigation lead from a confirmed security incident.

## Project overview

This project uses Splunk Search Processing Language (SPL) to explore historical security telemetry and build a dashboard named **SOC Threat Monitoring**.

The dashboard and supporting searches cover:

- DNS query activity and NXDOMAIN responses
- AWS VPC Flow Log traffic, including accepted flows, rejected connections, and high-volume flow summaries
- Windows security events, including failed logons, process creation and termination, special privileges, object access, and permission changes
- PowerShell Script Block Logging events and suspicious script patterns such as remote content retrieval, Base64 decoding, and dynamic execution

These searches are intended to support analyst triage. A match is not, by itself, proof of compromise.

## Data source and scope

The lab uses the publicly available **Boss of the SOC (BOTS) v3** dataset from Splunk. The events are historical training data, not live telemetry from the analyst's own machine or network.

- Dataset: [Splunk BOTS v3](https://github.com/splunk/botsv3)
- Data source used in this lab: BOTS v3 dataset files indexed locally in Splunk
- Splunk index: `botsv3`
- Dashboard: `SOC Threat Monitoring`

The dataset is not included in this repository. Follow the dataset provider's instructions and license/terms when obtaining and using it.

## Repository layout

```text
.
├── README.md
├── dashboard.xml
├── docs/
│   ├── Detection-Notes.md
│   └── Lab-Setup.md
├── SPL/
│   ├── dns/
│   ├── network/
│   ├── powershell/
│   └── windows/
└── screenshots/
```

`dashboard.xml` is the exported dashboard definition. The `SPL/` directory contains standalone searches used for analysis. `docs/` explains the lab assumptions, interpretation, and limitations. Add screenshots of the dashboard to `screenshots/` after removing any sensitive or environment-specific information.

## Example investigations

### PowerShell script block review

The PowerShell searches look for patterns including `DownloadString`, `FromBase64String`, `EncodedCommand`, and dynamic execution. These are investigation leads because legitimate administration and software can use similar techniques. Review the full script block, host, timestamp, parent process where available, and surrounding events before drawing a conclusion.

### DNS response review

NXDOMAIN results can help identify failed lookups or unusual domain activity. High NXDOMAIN volume can also be caused by typos, application behavior, misconfiguration, or normal background activity. Domain reputation and host context are needed before assigning severity.

### Network flow review

VPC Flow Log searches summarize accepted or rejected flows and traffic volume. A high byte count or a connection to a sensitive port is not sufficient evidence of data exfiltration or malicious access. Validate source and destination roles, time window, protocol, action, and related events.

### Windows security events

Event IDs are interpreted in context. For example, 4625 is associated with failed logons, 4688 with process creation, 4672 with special privileges assigned, and 4670 with changes to object permissions. The exact fields available depend on event formatting and Splunk field extraction.

## Reproducing the analysis

1. Install and configure a Splunk instance suitable for a local lab.
2. Obtain the BOTS v3 dataset from the official project and follow its instructions.
3. Ensure the events are searchable in the `botsv3` index.
4. Import `dashboard.xml` using Splunk's dashboard interface or the supported dashboard import method for your Splunk version.
5. Run the searches in `SPL/` and adjust the time range to cover the dataset's historical timestamps.
6. Compare results with the notes in `docs/Detection-Notes.md`.

The searches use `earliest=0` in several examples to include historical events. For a real environment, use a bounded time range and adapt the index, sourcetypes, field names, and thresholds to local logging standards.

## Limitations

- This is a portfolio lab based on historical sample data, not a production detection pack.
- Some event fields may be embedded in `Message` rather than extracted as standalone fields; searches use `rex` where needed.
- Thresholds are starting points for investigation, not validated alerting thresholds.
- Event counts reflect the dataset and the search scope, not current threat prevalence.
- A dashboard visualization does not replace investigation, corroborating evidence, or incident response procedures.

## Responsible use

Use these searches only on systems and data you are authorized to analyze. Treat findings as leads, preserve relevant context, and avoid labeling activity as malicious without sufficient evidence.

## Author

Built as a practical Splunk and SOC analysis portfolio project. The repository is intended to show the investigation workflow, SPL logic, and reasoning behind the dashboard—not just screenshots of charts.
