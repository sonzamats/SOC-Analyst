# Data Exfiltration Detection & Response Playbook

This document provides detailed information about the automated data exfiltration detection and response playbook implemented in the Enterprise SOC SIEM.

## Overview

The data exfiltration playbook is designed to detect and respond to suspicious outbound data transfers that may indicate data theft or exfiltration. It uses multiple detection methods to identify different types of exfiltration techniques.

## Detection Methods

The playbook implements three primary detection methods:

### 1. Volume-Based Detection

Identifies high-volume data transfers from internal systems to external destinations.

**Detection Logic:**
- Aggregates outbound network traffic by source and destination IP
- Calculates total data volume transferred during the monitoring window
- Flags transfers exceeding the configured volume threshold

**Use Cases:**
- Detecting large file uploads to external servers
- Identifying bulk data transfers to unauthorized destinations
- Discovering backup exfiltration attempts

### 2. Frequency-Based Detection

Identifies high-frequency connections that may indicate command & control activity or slow data leakage.

**Detection Logic:**
- Counts the number of outbound connections between each source-destination pair
- Flags connections exceeding the configured frequency threshold
- Focuses on persistent, frequent communications

**Use Cases:**
- Detecting command & control beaconing
- Identifying slow/low exfiltration attempts
- Discovering network scanning or enumeration

### 3. DNS Tunneling Detection

Identifies potential DNS tunneling used to exfiltrate data or maintain covert command & control channels.

**Detection Logic:**
- Analyzes DNS query patterns for each host
- Measures DNS query frequency and average query length
- Flags hosts making numerous, long DNS queries to unusual domains

**Use Cases:**
- Detecting data exfiltration via DNS
- Identifying malware using DNS for command & control
- Discovering attempts to bypass security controls via DNS tunneling

## Response Actions

When potential data exfiltration is detected, the playbook automatically initiates several response actions:

### 1. Communication Blocking

Blocks the suspicious communication path to prevent further data loss.

- **Implementation:** Communicates with a firewall or network security device API
- **Duration:** Configurable (default: 120 minutes)
- **Coverage:** Specific source-destination pair involved in the exfiltration

### 2. Case Creation

Creates a case in the incident management system for investigation.

- **Information Included:**
  - Detection type and method
  - Source and destination details
  - Volume/frequency metrics
  - Timestamp and duration
  - Recommended investigation steps

### 3. Alerting & Notification

Sends alerts to security personnel via configured notification channels.

- **Channels:** Webhook integration (supports Slack, Teams, email, etc.)
- **Details:** Includes incident summary, metrics, timestamps, and case reference

### 4. Dashboard Updates

Updates SIEM dashboards with data exfiltration incidents for visibility.

- **Index:** `siem-data-exfil-incidents`
- **Metrics:** Tracks volume, frequency, and type of exfiltration attempts
- **Visualization:** Available in security overview and dedicated exfiltration dashboards

## Implementation

The playbook is implemented as a Python script (`scripts/detect_data_exfil.py`) that can be run on a schedule or triggered by events.

### Prerequisites

- Elasticsearch with network traffic data (Packetbeat or similar)
- Python 3.6+ with required libraries (elasticsearch, requests)
- Network flow data with proper field mapping (ECS format recommended)
- Optional: Webhook endpoint for notifications
- Optional: Firewall/network API for blocking actions
- Optional: Case management system API

### Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--es-host` | Elasticsearch host | localhost |
| `--es-port` | Elasticsearch port | 9200 |
| `--es-user` | Elasticsearch username | elastic |
| `--es-password` | Elasticsearch password | secureSIEMpassword123 |
| `--volume-threshold` | Volume threshold in MB | 100 |
| `--time-window` | Analysis time window in minutes | 60 |
| `--frequency-threshold` | Connection frequency threshold | 1000 |
| `--dns-threshold` | DNS query threshold | 50 |
| `--webhook-url` | Notification webhook URL | None |
| `--firewall-api` | Firewall API URL | None |
| `--case-system-url` | Case management system URL | None |

### Whitelisting

The playbook supports whitelisting to reduce false positives:

- **IP Whitelist:** File with one IP per line (`ip_whitelist.txt`)
- **Domain Whitelist:** File with one domain per line (`domain_whitelist.txt`)
- **Built-in Rules:** Automatically excludes private IP ranges and common services

## Usage Examples

### Basic Usage

```bash
python3 scripts/detect_data_exfil.py
```

### Custom Thresholds

```bash
python3 scripts/detect_data_exfil.py --volume-threshold 200 --time-window 30
```

### Integration with Security Tools

```bash
python3 scripts/detect_data_exfil.py \
  --webhook-url "https://hooks.slack.com/services/YOUR/WEBHOOK/URL" \
  --firewall-api "https://firewall.example.com/api/block" \
  --case-system-url "https://thehive.example.com/api/case"
```

## Integration in SOAR Platform

The playbook can be integrated with Shuffle SOAR for enhanced automation:

1. Create a Shuffle workflow that triggers on a schedule or event
2. Add a "Run Command" node to execute the script
3. Add conditional nodes for additional actions based on results
4. Connect to other workflows for containment and remediation

## Dashboard

The data exfiltration dashboard in Kibana includes:

1. **Overview Panel:** Summary metrics of exfiltration attempts
2. **Volume Chart:** Visualization of data transfer volumes over time
3. **Top Sources/Destinations:** Ranking of most active endpoints
4. **Exfiltration Map:** Geographic visualization of destinations
5. **Detection Method Breakdown:** Distribution of detection methods
6. **Recent Incidents:** Table of the latest exfiltration attempts

## Investigation Guidance

When investigating data exfiltration alerts:

1. **Verify the Alert:**
   - Check if the communication is expected business activity
   - Validate the volume/frequency against normal baselines
   - Look for legitimate business purposes for the transfer

2. **Assess the Impact:**
   - Identify what systems and data are involved
   - Determine what information may have been exposed
   - Estimate the duration and volume of the exfiltration

3. **Gather Evidence:**
   - Collect full packet captures if available
   - Preserve logs from relevant endpoints
   - Document the timeline of events

4. **Contain the Threat:**
   - Verify blocking actions were successful
   - Isolate affected systems if necessary
   - Revoke compromised credentials

5. **Remediate and Recover:**
   - Remove malware or unauthorized tools
   - Patch exploited vulnerabilities
   - Restore systems to known good state

## Maintenance and Tuning

To maintain effective detection:

1. **Regular Threshold Review:**
   - Analyze false positive/negative rates
   - Adjust thresholds based on your environment
   - Consider time-based thresholds (e.g., different for business vs. non-business hours)

2. **Whitelist Management:**
   - Regularly update whitelist files with legitimate services
   - Document reasons for whitelist additions
   - Periodically review whitelist for unnecessary entries

3. **Index Management:**
   - Ensure proper retention of `siem-data-exfil-incidents` index
   - Apply appropriate ILM policies
   - Consider archiving historical incidents for trend analysis

## Troubleshooting

| Issue | Possible Cause | Solution |
|-------|----------------|----------|
| No detections despite known exfiltration | Thresholds too high | Lower the detection thresholds |
| Too many false positives | Thresholds too low | Increase thresholds or expand whitelist |
| Script errors when searching DNS data | Missing DNS fields | Verify Packetbeat DNS module is enabled |
| Blocking actions not working | API configuration issue | Check firewall API credentials and connectivity |
| Missing network direction field | Field mapping issue | Ensure network.direction field is populated 