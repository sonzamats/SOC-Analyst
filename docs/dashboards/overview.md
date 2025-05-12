# Security Overview Dashboard

The Security Overview dashboard provides a high-level summary of your security posture, showing key metrics and recent security events across your environment.

![Security Overview Dashboard](../images/dashboard-preview.png)

## Features

This dashboard includes:

- Security event counts and trends
- Critical alerts requiring attention
- Active security incidents
- MITRE ATT&CK coverage visualization
- Security event timeline
- Recent critical alerts
- Top threat categories

## Setup Instructions

1. **Import the Dashboard**

   Navigate to Kibana and import the dashboard:
   
   ```
   Management > Stack Management > Saved Objects > Import
   ```
   
   Select the `security_overview_dashboard.ndjson` file from the `dashboards` directory.

2. **Configure Data Sources**

   The dashboard expects data from the following sources:
   
   - Filebeat logs (system, authentication)
   - Wazuh alerts
   - Packetbeat network data
   - Custom SIEM indices for incidents and alerts

3. **Customize Time Range**

   By default, the dashboard shows data from the last 24 hours. You can adjust this:
   
   - Click the time picker in the top right
   - Select a predefined range or set a custom range
   - Click "Apply"

## Dashboard Panels

### Security Events Summary

This panel shows the total number of security events detected in the selected time period, with a trend line showing the event volume over time.

**Data source**: `filebeat-*` and `wazuh-alerts-*` indices
**Refresh rate**: 5 minutes

### Critical Alerts

Displays the number of high-severity alerts that require attention.

**Data source**: `siem-alerts-*` index
**Refresh rate**: 1 minute

### Active Incidents

Shows the number of security incidents that are currently open and being investigated.

**Data source**: `siem-incidents-*` index
**Refresh rate**: 5 minutes

### MITRE ATT&CK Coverage

Visualizes your coverage of MITRE ATT&CK techniques with detection rules.

**Data source**: `siem-mitre-coverage` index
**Refresh rate**: 1 hour

### Security Event Timeline

Displays security events over time, allowing you to identify patterns or spikes in activity.

**Data source**: Combined from all security indices
**Refresh rate**: 5 minutes

### MITRE Heat Map

Shows which MITRE ATT&CK tactics and techniques are seeing the most activity in your environment.

**Data source**: `siem-alerts-*` with MITRE mapping
**Refresh rate**: 15 minutes

### Recent Critical Alerts

A table showing the most recent critical security alerts with key details.

**Data source**: `siem-alerts-*` and `wazuh-alerts-*` indices
**Refresh rate**: 1 minute

### Top Threat Categories

Bar chart showing the most common types of threats detected in your environment.

**Data source**: `siem-alerts-*` with threat categorization
**Refresh rate**: 15 minutes

## Using the Dashboard

### Filtering Data

You can filter the entire dashboard by:

1. Clicking on any element in a visualization
2. Using the Kibana query language (KQL) in the search bar
3. Using the time picker to adjust the time range

Common filters:
- `host.name: "servername"` - Show only events from a specific host
- `event.severity: "high"` - Show only high severity events
- `threat.technique.id: "T1078"` - Show only events related to a specific MITRE technique

### Drilling Down

From the dashboard, you can drill down into specific events:

1. Click on any event in the "Recent Critical Alerts" table
2. Select "View surrounding documents" to see events that occurred around the same time
3. Select "View document details" to see the full event data

### Saving and Sharing

You can save modifications to the dashboard or share it with others:

1. Click the "Save" button in the top right
2. Choose "Save as new" to create a personal copy
3. Click "Share" to generate a link or download the dashboard as a PDF

## Advanced Customization

To modify the dashboard:

1. Click "Edit" in the top right
2. Add new visualizations by clicking the "Add" button
3. Resize or rearrange panels by dragging them
4. Click on any visualization's title and select "Edit visualization" to customize it
5. Save your changes when done

## Troubleshooting

If data is not appearing in the dashboard:

1. Verify that indices exist and contain data:
   ```
   Management > Stack Management > Index Management
   ```

2. Check that index patterns are correctly defined:
   ```
   Management > Stack Management > Index Patterns
   ```

3. Ensure Elasticsearch is receiving data from log collectors

4. Verify the time range is appropriate for your data