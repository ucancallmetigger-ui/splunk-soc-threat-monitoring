# Lab Setup and Reproduction

## Requirements

- A supported Splunk Enterprise instance or equivalent lab environment
- The Splunk BOTS v3 sample dataset
- Sufficient local storage for the dataset and indexed events
- Permission to access the Splunk Search and dashboard interfaces

## Data preparation

1. Obtain BOTS v3 from the official [Splunk BOTS v3 repository](https://github.com/splunk/botsv3) and follow its current documentation for the dataset.
2. Load the data using the method documented for the dataset and your Splunk version.
3. Confirm that the `botsv3` index contains events.
4. Confirm the relevant sourcetypes are present before running the saved searches.

Example validation searches:

```spl
index=botsv3
| stats count by sourcetype
| sort - count
```

```spl
index=botsv3 sourcetype=wineventlog:security
| stats count by EventCode
| sort - count
```

The dataset contains historical events. Set the time picker to include the data's historical timestamps or use an explicit range appropriate for the dataset.

## Dashboard import

The repository includes `dashboard.xml` as the exported dashboard source captured from the lab. Dashboard import and source formats vary between Splunk versions and dashboard types. If the UI does not offer a direct import action, use the supported dashboard source/editor or deploy the XML as a view in a Splunk app, following the documentation for your installed version.

After importing, verify:
- The dashboard title is `SOC Threat Monitoring`.
- Searches reference the intended index and sourcetypes.
- Panels return data for the historical time range.
- No credentials, private addresses, or unrelated local environment details were accidentally included.

## SPL compatibility

The SPL files are provided as standalone examples. Depending on the Splunk version, field extraction settings, and the exact event payload, you may need to adapt sourcetype names or `rex` expressions.

Do not run a search against a production index without confirming the scope and time range first.
