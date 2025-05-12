# Lateral Movement Detection & Response Playbook

This document provides detailed information about the automated lateral movement detection and response playbook implemented in the Enterprise SOC SIEM.

## Overview

The lateral movement playbook is designed to detect and respond to potential attacker movement between systems in your network. It uses multiple detection methods to identify different lateral movement techniques employed by adversaries.

## Detection Methods

The playbook implements three primary detection mechanisms to identify lateral movement:

### 1. Authentication Anomaly Detection

Identifies unusual authentication patterns that may indicate an attacker moving laterally.

**Detection Logic:**
- Tracks successful authentications by username across multiple hosts
- Identifies users who authenticate to more systems than normally expected
- Alerts when a user authenticates to a threshold number of systems within a time window

**Use Cases:**
- Detecting compromised user credentials being used across multiple systems
- Identifying administrative account misuse
- Discovering account harvesting followed by lateral movement

### 2. Administrative Tool Usage Detection

Identifies the use of administrative/remote access tools commonly leveraged for lateral movement.

**Detection Logic:**
- Monitors for execution of known lateral movement tools (PsExec, WMIC, PowerShell remoting, etc.)
- Analyzes command lines for remote execution patterns
- Correlates tool usage with user accounts and target systems

**Use Cases:**
- Detecting use of PsExec and similar tools for remote command execution
- Identifying PowerShell remoting being used for lateral movement
- Discovering credential dumping tools like Mimikatz being utilized

### 3. Connection Pattern Detection

Identifies suspicious network connection patterns indicative of lateral movement.

**Detection Logic:**
- Monitors connections to administrative/remote access ports (RDP, SSH, WinRM, SMB)
- Detects when a single host connects to multiple other hosts on these ports
- Flags unusual connection volumes or patterns

**Use Cases:**
- Detecting scanning followed by targeted connections
- Identifying RDP/SSH pivoting across network segments
- Discovering unusual remote management connections

## Response Actions

When potential lateral movement is detected, the playbook automatically initiates several response actions:

### 1. Source Blocking (for Connection-based Detection)

Blocks the source IP to prevent further lateral movement.

- **Implementation:** Integrates with firewall or network security controls
- **Duration:** Configurable (default: 60 minutes)
- **Scope:** Only blocks IPs detected by connection-based method

### 2. Case Creation

Creates a case in the incident management system for investigation.

- **Information Included:**
  - Detection type and details
  - User accounts involved (if applicable)
  - Host systems affected
  - Command lines (for admin tool detection)
  - Timestamps and severity assessment
  - Recommended investigation tasks

### 3. Alerting & Notification

Sends alerts to security personnel via configured notification channels.

- **Channels:** Webhook integration (supports Slack, Teams, email)
- **Details:** Includes incident summary, technique used, affected systems

### 4. Dashboard Updates

Updates SIEM dashboards with lateral movement incidents for visibility.

- **Index:** `siem-lateral-movement-incidents`
- **Metrics:** Tracks detection method, users, systems, and severity
- **Visualization:** Available in security overview and dedicated dashboards

## Implementation

The playbook is implemented as a Python script (`scripts/detect_lateral_movement.py`) that can be run on a schedule or triggered by events.

### Prerequisites

- Elasticsearch with properly formatted authentication, process, and network events
- Python 3.6+ with required libraries (elasticsearch, requests)
- Windows Event Logs configured to capture account logon events, process creation, and command lines
- (Optional) Network flow logs from firewalls, routers, or packet capture systems
- (Optional) Webhook endpoint for notifications
- (Optional) Firewall/network API for blocking actions
- (Optional) Case management system API

### Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--es-host` | Elasticsearch host | localhost |
| `--es-port` | Elasticsearch port | 9200 |
| `--es-user` | Elasticsearch username | elastic |
| `--es-password` | Elasticsearch password | secureSIEMpassword123 |
| `--time-window` | Analysis time window in minutes | 60 |
| `--auth-threshold` | Authentication threshold (hosts) | 3 |
| `--webhook-url` | Notification webhook URL | None |
| `--firewall-api` | Firewall API URL | None |
| `--case-system-url` | Case management system URL | None |

### Whitelisting

The playbook supports whitelisting to reduce false positives:

- **IP Whitelist:** File with one IP per line (`ip_whitelist.txt`)
- **Built-in Rules:** Automatically excludes localhost IPs

## Usage Examples

### Basic Usage

```bash
python3 scripts/detect_lateral_movement.py
```

### Custom Configuration

```bash
python3 scripts/detect_lateral_movement.py --time-window 30 --auth-threshold 5
```

### Integration with Security Tools

```bash
python3 scripts/detect_lateral_movement.py \
  --webhook-url "https://hooks.slack.com/services/YOUR/WEBHOOK/URL" \
  --firewall-api "https://firewall.example.com/api/block" \
  --case-system-url "https://thehive.example.com/api/case"
```

## Integration in SOAR Platform

The playbook can be integrated with Shuffle SOAR for enhanced automation:

1. Create a Shuffle workflow with a schedule trigger (hourly recommended)
2. Execute the lateral movement detection script
3. Process the results for multiple incidents
4. Trigger additional workflows for specific detection types
5. Implement approval workflows for blocking actions

## Dashboard

The lateral movement dashboard in Kibana includes:

1. **Overview Panel:** Summary metrics of detected lateral movement
2. **User Activity Map:** Visualization of user authentications across systems
3. **Admin Tool Usage:** Breakdown of administrative tools detected
4. **Connection Patterns:** Network graph showing suspicious connections
5. **Affected Systems:** Top systems targeted in lateral movement
6. **Recent Incidents:** Table of the latest lateral movement detections

## Investigation Guidance

When investigating lateral movement alerts:

1. **Verify the Alert:**
   - Check if the activity is expected (system administrator work, automation)
   - Review the user account's normal behavior and privileges
   - Examine the timing and context of the activity

2. **Scope the Incident:**
   - Identify all systems involved in the potential lateral movement
   - Determine which credentials or access methods were used
   - Establish a timeline of events

3. **Determine the Entry Point:**
   - Identify the initial access vector if possible
   - Check for recent phishing incidents or external compromises
   - Look for signs of initial compromise on the source system

4. **Containment and Eradication:**
   - Isolate affected systems if active compromise is confirmed
   - Reset compromised credentials
   - Block malicious IP addresses and domains
   - Remove malware or unauthorized access tools

5. **Recovery and Improvement:**
   - Restore systems to known good state if necessary
   - Update detection thresholds based on findings
   - Consider architecture improvements to limit lateral movement

## Known False Positives

Common sources of false positives in lateral movement detection:

1. **IT Administrators:** System administrators often legitimately move between multiple systems
2. **Automation/Orchestration:** Scripts and automation tools may connect to many systems
3. **Backup Solutions:** Backup software can trigger connection-based detections
4. **Vulnerability Scanners:** Security scanning tools may be detected as connection-based lateral movement

## Maintenance and Tuning

To maintain effective detection:

1. **Threshold Adjustment:**
   - Adjust the authentication threshold based on your environment
   - Consider different thresholds for different user groups
   - Tune time windows to align with typical work patterns

2. **Whitelist Management:**
   - Add legitimate administrative IPs to the whitelist
   - Document all whitelist additions with justification
   - Regularly review the whitelist for unnecessary entries

3. **Tool Detection Updates:**
   - Periodically update the list of monitored administrative tools
   - Add new lateral movement tools as they emerge
   - Consider custom detection for organization-specific tools

## Recommended Integration with Other Detections

This lateral movement detection works best when combined with:

1. **Initial Access Monitoring:** To identify the start of an attack chain
2. **Credential Theft Detection:** To catch credential harvesting before lateral movement
3. **Privilege Escalation Monitoring:** To detect elevation of privileges during movement
4. **Data Exfiltration Detection:** To identify the ultimate goal of many lateral movements

## MITRE ATT&CK Mapping

This playbook addresses the following MITRE ATT&CK techniques:

- **T1021 - Remote Services:** Detection of various remote access methods
- **T1078 - Valid Accounts:** Identification of compromised credential usage
- **T1550 - Use Alternate Authentication Material:** Some forms of credential abuse
- **T1563 - Remote Service Session Hijacking:** Certain lateral movement patterns
- **T1570 - Lateral Tool Transfer:** Detection of tool usage across systems