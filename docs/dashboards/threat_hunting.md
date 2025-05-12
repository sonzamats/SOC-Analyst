# Threat Hunting Dashboard Guide

This document provides information about the threat hunting dashboards implemented in the Enterprise SOC SIEM, designed to help security analysts proactively search for threats that may have evaded automated detections.

## Overview

The threat hunting dashboards provide a set of visualizations and tools optimized for security analysts to conduct hypothesis-driven searches through security telemetry. Unlike regular monitoring dashboards that focus on known threats and alerts, these hunting dashboards emphasize flexible exploration, pattern discovery, and anomaly identification.

## Available Hunting Dashboards

### 1. User Behavior Analytics Dashboard

**Purpose:** Identify unusual user activities that may indicate account compromise.

**Key Visualizations:**
- **Authentication Timeline:** Shows authentication events over time with color coding for success/failure
- **Unusual Hours Activity:** Highlights user activity outside normal working hours
- **Authentication Source Map:** Geographic visualization of login locations
- **First-Time Seen Activity:** Tables showing first occurrence of:
  - User logging in from new IP address
  - User logging in from new location
  - User accessing new resources
  - User executing unusual commands
- **Privilege Usage Heatmap:** Shows privileged account usage patterns

**Data Sources:**
- Authentication logs
- VPN logs
- Remote access logs
- Command execution logs

### 2. Network Traffic Analysis Dashboard

**Purpose:** Identify unusual network communications that may indicate C2, exfiltration, or lateral movement.

**Key Visualizations:**
- **Unusual Connections Tracker:** Shows connections to rare or first-time-seen destinations
- **Long-lived Connection Monitor:** Identifies unusually persistent connections
- **Data Volume Outliers:** Highlights unusual data transfer volumes by host
- **Beaconing Detection:** Visualizes potential beaconing patterns in network traffic
- **Domain Entropy Analysis:** Displays high-entropy domains that may indicate DGAs
- **Protocol Mismatch Detection:** Identifies services running on non-standard ports

**Data Sources:**
- NetFlow/IPFIX data
- DNS logs
- Proxy logs
- Firewall logs

### 3. Endpoint Activity Dashboard

**Purpose:** Identify suspicious process execution and file operations on endpoints.

**Key Visualizations:**
- **Rare Process Execution:** Lists processes rarely seen in your environment
- **Process Tree Visualization:** Shows parent-child relationships for processes
- **Command Line Argument Analysis:** Highlights unusual command line parameters
- **Sensitive File Access:** Tracks access to critical system files and directories
- **Memory/Execution Anomalies:** Identifies processes with unusual memory patterns
- **Script Execution Tracker:** Monitors PowerShell, WMI, batch, and other scripting activity

**Data Sources:**
- EDR logs
- Sysmon events
- PowerShell logs
- Windows Event Logs

### 4. MITRE ATT&CK Coverage Explorer

**Purpose:** Assess your defensive coverage and hunt through technique-based queries.

**Key Visualizations:**
- **Technique Coverage Heatmap:** Visual representation of detection coverage
- **Tactic Explorer:** Drilldown by tactic to see related techniques
- **Data Source Mapping:** Shows which data sources are available for each technique
- **Technique Search Interface:** Allows searching for specific techniques
- **Pre-built Hunting Queries:** Library of queries mapped to ATT&CK techniques

**Data Sources:**
- All SIEM data sources
- Coverage mapping configuration

## Setting Up the Hunting Environment

### 1. Dashboard Import

To import these dashboards into your Kibana instance:

1. Navigate to **Management > Stack Management > Saved Objects**
2. Click **Import** and select the appropriate JSON file from `dashboards/hunting/`
3. Resolve any conflicts if prompted
4. Refresh your Kibana page

### 2. Custom Index Patterns

For optimal performance, some hunting dashboards use specialized index patterns:

- **auth-hunting-\*:** Optimized index for authentication data
- **network-hunting-\*:** Optimized index for network traffic analysis
- **endpoint-hunting-\*:** Optimized index for endpoint telemetry

These can be configured in **Management > Stack Management > Index Patterns**.

### 3. Time Range Configuration

Threat hunting often requires looking at longer time periods than regular monitoring:

1. Most hunting dashboards default to a 7-day lookback period
2. Adjust time range based on your hunting hypothesis
3. For first-time-seen analysis, ensure sufficient historical data (30+ days recommended)

## Hunting Methodologies

### TTP-based Hunting

1. Start with the MITRE ATT&CK Coverage Explorer dashboard
2. Select a technique of interest based on recent threat intelligence
3. Use the pre-built queries to search for specific patterns
4. Refine and customize queries based on your environment

### Anomaly-based Hunting

1. Start with User Behavior, Network Traffic, or Endpoint Activity dashboards
2. Focus on outliers, rare events, and statistical anomalies
3. Investigate notable deviations by drilling down to raw events
4. Establish baseline behavior before concluding an anomaly is malicious

### IOC-based Hunting

1. Import indicators from threat intelligence sources
2. Use the search functionality to look for matches in your environment
3. Pivot from matches to discover related activity
4. Look for patterns that extend beyond the known indicators

## Adding Custom Visualizations

Analysts can extend the hunting dashboards with custom visualizations:

1. Navigate to **Visualize** in Kibana
2. Create a new visualization using the appropriate data source
3. Save the visualization with a "hunt-" prefix
4. Add the visualization to one of the existing dashboards or create a new one

## Saving and Sharing Hunt Results

To document and share findings from a threat hunt:

1. Use the **Canvas** feature to create a visual summary of findings
2. Save queries that yielded interesting results to the **Saved Queries** library
3. Use the **Timeline** feature to create a sequence of notable events
4. Export findings to your case management system

## Integrating with Detection Engineering

Successful threat hunts should feed back into detection engineering:

1. Convert effective hunting queries into automated detection rules
2. Refine existing rules based on hunting insights
3. Update MITRE ATT&CK coverage mapping
4. Document hunting methodologies for future reference

## Scheduled Hunts

Certain hunt activities can be scheduled to run regularly:

1. **Weekly Rare Process Summary:** Automatically runs every Monday
2. **New Domain Connections Report:** Generated daily
3. **Authentication Anomaly Scan:** Runs every 12 hours
4. **Privileged Account Usage Review:** Generated every Friday

Access these reports in the **Reports** section of Kibana.

## Performance Considerations

Hunting queries can be resource-intensive. Consider these best practices:

1. Limit time ranges appropriately for exploratory searches
2. Use data sampling for initial hypothesis testing
3. Schedule intensive hunts during off-peak hours
4. Leverage aggregations and visualizations to identify areas for deeper investigation
5. Use the query profiler to optimize resource-intensive searches

## Example Hunt Scenarios

### 1. Hunt for Lateral Movement

1. Navigate to the Network Traffic Analysis dashboard
2. Focus on the "Internal Connection Patterns" visualization
3. Look for systems connecting to an unusual number of other internal systems
4. Filter for connections to administrative ports (RDP, SSH, WMI)
5. Investigate systems with sudden changes in connection patterns

### 2. Hunt for Data Staging

1. Navigate to the Endpoint Activity dashboard
2. Review the "Unusual File Operations" panel
3. Look for large numbers of file copies, compressions, or encryptions
4. Correlate with user activity and time of day
5. Investigate file paths and destinations for suspicious patterns

### 3. Hunt for Persistence Mechanisms

1. Navigate to the MITRE ATT&CK Coverage Explorer
2. Select the "Persistence" tactic
3. Review techniques with limited detection coverage
4. Run pre-built queries for registry modifications, scheduled tasks, and startup items
5. Look for recently created persistence mechanisms on critical systems