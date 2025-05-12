# 🛡️ SOC SIEM Implementation - SOC Analyst Portfolio

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-mapped-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

This repository contains a complete Security Operations Center (SOC) and Security Information and Event Management (SIEM) solution using the Elastic Stack.

## 📌 Project Objectives
- Design a lightweight, scalable SIEM using the ELK Stack for security monitoring
- Create a real-world SOC analyst environment for threat detection
- Process security logs and detect anomalies
- Visualize security data through custom dashboards
- Demonstrate security monitoring capabilities

## 🧩 Components

- **Elasticsearch**: For storing and searching security logs and events
- **Kibana**: For visualization and dashboard creation
- **Logstash**: For log processing and normalization
- **Filebeat**: For log collection

## 🚀 Quick Start

1. Ensure Docker and Docker Compose are installed on your system
2. Clone this repository
3. Run `docker-compose up -d` to start the stack
4. Access Kibana at http://localhost:5601 (credentials: elastic/changeme)

## 🔧 Setup Instructions

1. Create an index pattern in Kibana:
   - Go to Stack Management → Index Patterns
   - Create new pattern `logstash-*`
   - Select `@timestamp` as the time field

2. Explore the data:
   - Go to Discover tab to search logs
   - Create visualizations for security metrics
   - Build dashboards for monitoring

## 📊 Sample Logs

The repository includes sample security logs for testing. Add your own logs to the `logs/` directory to have them processed by the system.

## 🔍 Security Features

- Preconfigured log parsing for common security events
- Alert capability for suspicious activities
- Dashboards for security monitoring
- Integration with threat intelligence feeds

## 🛠️ Customizing

- Modify Logstash pipelines in `logstash/pipeline/` to adapt to your log formats
- Adjust Filebeat configuration to collect logs from different sources
- Create custom dashboards based on your security requirements

## 📋 Detection Use Cases

| Threat Scenario          | Data Source    | Detection Method                        |
|--------------------------|----------------|----------------------------------------|
| Brute-force login        | Auth logs      | Failed login count over time           |
| Suspicious Access        | System logs    | Unusual access patterns                |
| Data Exfiltration        | Network logs   | Large outbound data transfers          |
| Privilege Escalation     | System logs    | Unexpected permission changes          |

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
