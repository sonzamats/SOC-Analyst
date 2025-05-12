# SOC-Analyst
# 🛡️ Custom SIEM Project – SOC Analyst Portfolio

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-mapped-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Welcome to my advanced Security Information and Event Management (SIEM) project built to simulate a real-world SOC Analyst environment. This project demonstrates my hands-on experience in log collection, threat detection, MITRE mapping, and automated incident response using open-source tools.

## 📌 Project Objectives
- Design a lightweight, scalable SIEM using the ELK Stack, Wazuh, and additional telemetry sources.
- Simulate real-world attacks and detect them using custom rules.
- Map all detection use cases to the [MITRE ATT&CK Framework](https://attack.mitre.org/).
- Showcase threat hunting dashboards and alerting workflows.
- Automate incident response using SOAR principles and open-source tools.
- Host and document the project for demonstration at [https://github.com/sonzamats/SOC-Analyst](https://github.com/sonzamats/SOC-Analyst).

---

## 🧱 Architecture

![Architecture Diagram](docs/images/soc_architecture.png)

### 🧩 Tools Used
| Tool             | Purpose                              |
|------------------|--------------------------------------|
| **Elasticsearch** | Log indexing and search              |
| **Logstash**      | Parsing and enrichment               |
| **Kibana**        | Dashboards and visualizations        |
| **Wazuh**         | Security detection and alerting      |
| **Sysmon**        | Windows endpoint telemetry           |
| **Zeek**          | Network analysis and logging         |
| **Sigma Rules**   | Threat detection patterns            |
| **Python**        | Anomaly detection, ML jobs           |
| **MITRE ATT&CK**  | Threat mapping and coverage analysis |
| **Shuffle SOAR**  | Automated incident response          |

---

## 🔍 Detection Use Cases

| Threat Scenario            | Data Source | Detection Method        | MITRE ID        |
|----------------------------|-------------|--------------------------|------------------|
| Brute-force login          | Win Event Log | Failed login count over time | `T1110` |
| Suspicious PowerShell Use  | Sysmon      | Regex match on cmdline       | `T1059.001` |
| Lateral Movement via SMB   | Zeek        | Internal IP → Internal IP w/ SMB flags | `T1021.002` |
| C2 Beaconing Behavior      | Zeek/DNS    | Periodic outbound traffic, domain entropy | `T1071.001` |
| Credential Dumping         | Sysmon      | LSASS access detection         | `T1003.001` |

---

## 📈 Dashboards & Visuals

- 📊 **Kibana Dashboards:** Alert heatmaps, anomaly timelines, endpoint activity graphs
- 🧠 **MITRE Coverage Map:** Visualized matrix of covered TTPs
- 🧪 **Threat Simulation Walkthroughs:** Each detection use case includes a step-by-step simulated attack

![MITRE Mapping](docs/images/mitre_matrix.png)
![Kibana Dashboard](docs/images/kibana_dashboard.png)

---

## 🔄 Automated Incident Response

- **SOAR Tool Used:** [Shuffle](https://shuffler.io/)
- **Playbooks Implemented:**
  - Alert-Based Host Isolation
  - Auto-email with IOC data to security team
  - Disable suspicious AD accounts
  - Send Slack notifications to SOC channel

---

## 🧪 Simulated Attacks & Testing Scripts

> Use included attack simulation scripts and test logs to validate detection rules:

- `/simulations/brute_force.ps1`
- `/simulations/beaconing_test.py`
- `/simulations/lateral_movement_sim.bat`
- `/data/sample_logs/`

---

## 🧰 Setup Instructions

### 🖥️ Prerequisites:
- Docker + Docker Compose
- Python 3.9+
- 16GB RAM minimum

### 🔧 Install
```bash
git clone https://github.com/sonzamats/SOC-Analyst.git
cd SOC-Analyst
docker-compose up -d
