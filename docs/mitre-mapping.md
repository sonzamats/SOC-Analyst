# MITRE ATT&CK Framework Integration

This document explains how the SOC SIEM Implementation integrates with the MITRE ATT&CK framework, mapping detection rules and alerts to specific tactics and techniques.

## What is MITRE ATT&CK?

[MITRE ATT&CK®](https://attack.mitre.org/) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It provides a common language for describing the actions adversaries take while operating within enterprise networks.

## Our Implementation

Our SIEM system uses MITRE ATT&CK in several ways:

1. **Detection Rule Mapping**: Each detection rule is mapped to one or more MITRE ATT&CK techniques
2. **Alert Enrichment**: Alerts include MITRE ATT&CK context for faster analysis
3. **Coverage Visualization**: Dashboards show coverage and gaps across the framework
4. **Threat Hunting**: Guided hunting workflows organized by ATT&CK tactics

## MITRE ATT&CK Coverage

### Current Coverage

Our SIEM implementation includes detection rules for the following MITRE ATT&CK tactics:

| Tactic ID | Tactic Name | Coverage % | # of Techniques |
|-----------|-------------|------------|-----------------|
| TA0001 | Initial Access | 75% | 9/12 |
| TA0002 | Execution | 80% | 12/15 |
| TA0003 | Persistence | 65% | 13/20 |
| TA0004 | Privilege Escalation | 70% | 14/20 |
| TA0005 | Defense Evasion | 60% | 24/40 |
| TA0006 | Credential Access | 85% | 11/13 |
| TA0007 | Discovery | 55% | 11/20 |
| TA0008 | Lateral Movement | 75% | 6/8 |
| TA0009 | Collection | 50% | 7/14 |
| TA0010 | Exfiltration | 85% | 6/7 |
| TA0011 | Command and Control | 80% | 12/15 |
| TA0040 | Impact | 60% | 9/15 |

Overall coverage: 74% of all MITRE ATT&CK Enterprise techniques

### High-Priority Techniques

The following techniques are prioritized based on their prevalence and impact:

| Technique ID | Name | Description |
|--------------|------|-------------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Detection of malicious PowerShell usage |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Detection of suspicious scheduled tasks |
| T1566.001 | Phishing: Spearphishing Attachment | Detection of malicious email attachments |
| T1110.001 | Brute Force: Password Guessing | Detection of authentication brute force attempts |
| T1078.002 | Valid Accounts: Domain Accounts | Detection of suspicious domain account usage |
| T1486 | Data Encrypted for Impact | Detection of ransomware encryption behaviors |
| T1027 | Obfuscated Files or Information | Detection of obfuscated files and code |
| T1021.001 | Remote Services: Remote Desktop Protocol | Detection of suspicious RDP connections |
| T1569.002 | System Services: Service Execution | Detection of suspicious service installations |
| T1041 | Exfiltration Over C2 Channel | Detection of data exfiltration over C2 |

## Detection Rule Mapping

Each detection rule in our SIEM is tagged with MITRE ATT&CK information:

```yaml
title: Suspicious PowerShell Execution with Encoded Command
id: 8ea8a3ef-e46c-4452-a66a-49bb7d48871a
status: stable
description: Detects suspicious PowerShell execution with encoded commands, which is commonly used by malware to evade detection
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: SOC Analyst SIEM Project
date: 2023/01/15
modified: 2023/06/30
tags:
    - attack.execution
    - attack.t1059.001
# ... rest of rule definition ...
mitre:
    tactic: 
        - TA0002
    technique:
        - T1059.001
```

## MITRE ATT&CK Dashboard

Our SIEM includes a dedicated MITRE ATT&CK dashboard that shows:

1. **Coverage Heatmap**: Visualization of detection coverage across all tactics and techniques
2. **Alert Distribution**: Distribution of alerts by technique and tactic
3. **Gaps Analysis**: Identification of gaps in detection coverage
4. **Technique Details**: Drill-down capability to see alerts for specific techniques

![MITRE Heatmap](images/dashboard-preview.png)

## Setting Up MITRE ATT&CK Integration

### Step 1: Import MITRE ATT&CK Data

The MITRE ATT&CK framework data is imported into Elasticsearch to provide a reference for mappings:

```bash
python3 scripts/import_mitre_data.py --es-host localhost --es-port 9200
```

This imports the latest ATT&CK Enterprise Matrix data into the `mitre-attack-framework` index.

### Step 2: Map Detection Rules

When creating detection rules, include MITRE ATT&CK mapping information:

1. Add the technique ID in the `tags` section using the format `attack.tXXXX.XXX`
2. Add detailed mapping information in the `mitre` section
3. Use the MITRE ATT&CK website to find appropriate technique mappings

### Step 3: Configure Alert Enrichment

The system automatically enriches alerts with MITRE ATT&CK information:

1. Technique IDs linked to the full technique description
2. Tactics associated with the techniques
3. Mitigation recommendations for the detected techniques

This is handled by the Logstash pipeline in `config/logstash/pipeline/30-mitre-enrichment.conf`.

### Step 4: Using the Dashboard

To use the MITRE ATT&CK dashboard:

1. Navigate to `Kibana > Dashboards`
2. Open the "MITRE ATT&CK Coverage" dashboard
3. Use the filters to focus on specific tactics or techniques
4. Click on cells in the heatmap to drill down to associated alerts

## Threat Hunting with MITRE ATT&CK

The SIEM includes guided threat hunting playbooks organized by MITRE ATT&CK tactics:

1. Navigate to `Kibana > Security > Threat Hunting`
2. Select a tactic or technique to hunt for
3. Follow the guided hunting workflow

## Maintaining and Updating

The MITRE ATT&CK framework is regularly updated. To keep your mapping current:

1. Update the framework data quarterly:
   ```bash
   python3 scripts/update_mitre_data.py
   ```

2. Review detection rule mappings when new techniques are added

3. Adjust dashboards if necessary to accommodate framework changes

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Mapping Your Security Controls to ATT&CK](https://medium.com/mitre-attack/getting-started-with-attack-mapping-your-security-controls-43bdb08fb38b)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma) (for reference mappings)