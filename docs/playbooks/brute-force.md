# Brute Force Attack Response Playbook

This playbook outlines the automated and manual processes for responding to brute force attacks detected by the SIEM system.

## Overview

This playbook is triggered when multiple failed authentication attempts are detected from the same source IP address to the same destination within a defined time window. It helps security teams quickly respond to and mitigate potential unauthorized access attempts.

## Playbook Workflow

![Brute Force Response Workflow](../../assets/images/brute-force-workflow.png)

## Detection Criteria

| Parameter | Default Setting | Description |
|-----------|----------------|-------------|
| Threshold | 5 failed attempts | Number of failed authentication attempts that triggers an alert |
| Time Window | 5 minutes | Time period within which failed attempts are counted |
| Target Types | SSH, RDP, Web Applications | Authentication mechanisms monitored |
| Exclusions | Whitelisted IPs | IPs excluded from detection (e.g., security scanners) |

## Automated Response Actions

1. **Alert Creation & Enrichment**
   - Create alert in TheHive with all relevant details
   - Enrich source IP with geolocation data
   - Check IP reputation against threat intelligence sources
   - Determine if source IP is internal or external

2. **Initial Triage**
   - Check if targeted account is high-privileged (admin, service account)
   - Verify if the account was eventually compromised (successful login after failures)
   - Check if the IP address has been involved in other security events

3. **Containment Actions**
   - For external IPs: Add IP to blocklist on firewall/WAF
   - For internal IPs: Isolate host on network for investigation
   - Temporarily lock targeted account(s) if attack is ongoing

4. **Notification**
   - Send email alert to SOC team with attack details
   - If target is a critical system, send SMS/page to on-call personnel
   - Create ticket in IT service management system

## Manual Response Steps

### Level 1 SOC Analyst Actions

1. **Verification & Assessment**
   - Review alert details and authentication logs
   - Determine attack vector (SSH, RDP, web application)
   - Assess potential impact based on targeted account(s)

2. **Context Gathering**
   - Check if targeted account shows other suspicious activities
   - Review recent activities from the attacking IP address
   - Determine if other systems are being targeted by the same source

3. **Response Actions**
   - Verify automated blocking was successful
   - For high-severity cases, initiate password reset for targeted account(s)
   - Document findings in the incident case

### Level 2 SOC Analyst Actions

1. **Deeper Investigation**
   - Perform timeline analysis of all activities from attacking IP
   - Analyze any payloads or command patterns used in the attack
   - Check for persistence mechanisms if compromise is suspected

2. **Expanded Response**
   - Update security controls to prevent similar attacks
   - If compromise occurred, initiate Incident Response procedure
   - Review and adjust brute force detection thresholds if needed

3. **Communication & Coordination**
   - Brief management on attack and response status
   - Coordinate with IT team on any required changes
   - Document lessons learned and update playbook if needed

## Playbook Integration

This playbook is implemented through:

1. **Detection Rules**
   - Elasticsearch detection rules for authentication events
   - Wazuh rules for SSH/RDP brute force detection

2. **SOAR Workflow**
   - Shuffle workflow: `brute_force_response.yaml`
   - TheHive case template: `brute_force_case.json`

3. **Automation Scripts**
   - IP blocking script: `scripts/block_brute_force.py`
   - Account protection: `scripts/account_protection.py`

## Metrics & KPIs

| Metric | Target | Description |
|--------|--------|-------------|
| Time to Detection | < 5 minutes | Time from attack initiation to alert creation |
| Time to Containment | < 15 minutes | Time from alert to blocking attacking IP |
| False Positive Rate | < 10% | Percentage of alerts that are not actual attacks |
| Successful Blocks | > 95% | Percentage of attacks successfully blocked |

## Continuous Improvement

This playbook should be reviewed and updated:
- After each high-severity brute force incident
- When new authentication systems are added to the environment
- At least quarterly as part of regular security procedure reviews

## References

- [NIST SP800-61: Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [MITRE ATT&CK: Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [CIS Controls: Control 16](https://www.cisecurity.org/controls/account-monitoring-and-control)