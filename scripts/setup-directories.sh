#!/bin/bash

# Enterprise SOC SIEM Implementation Directory Setup
# This script creates the necessary directory structure for the project

# Exit on any error
set -e

echo "Creating Enterprise SOC SIEM directory structure..."

# Create main directories
mkdir -p config/{elasticsearch,kibana,logstash,wazuh,thehive,cortex,shuffle}
mkdir -p scripts/{setup,backup,maintenance,quickstart}
mkdir -p docs/{dashboards,playbooks}
mkdir -p simulations
mkdir -p assets/images
mkdir -p playbooks/{account-compromise,malware-detection,data-exfiltration,brute-force}
mkdir -p detection/{sigma,yara,ml}
mkdir -p docker/{elasticsearch,kibana,logstash,wazuh,thehive,cortex,shuffle}

# Create placeholder files for important components
touch config/elasticsearch/elasticsearch.yml
touch config/kibana/kibana.yml
touch config/logstash/logstash.yml
touch config/logstash/pipelines.yml
touch config/wazuh/ossec.conf
touch config/thehive/application.conf
touch config/cortex/application.conf
touch config/shuffle/docker-compose.yml

# Create Docker Compose files
touch docker-compose.yml
touch docker-compose.quickstart.yml
touch docker-compose.production.yml

# Create basic README files in directories
echo "# Configuration Files" > config/README.md
echo "# Scripts for setup, maintenance, and operations" > scripts/README.md
echo "# Documentation" > docs/README.md
echo "# Attack Simulations" > simulations/README.md
echo "# Detection Rules" > detection/README.md
echo "# Response Playbooks" > playbooks/README.md
echo "# Docker files" > docker/README.md

# Create placeholder for dashboard configs
touch docs/dashboards/overview.md
touch docs/dashboards/mitre-coverage.md
touch docs/dashboards/threat-hunting.md
touch docs/dashboards/network.md

# Create placeholder for playbook documentation
touch docs/playbooks/index.md
touch docs/playbooks/account-compromise.md
touch docs/playbooks/malware-containment.md
touch docs/playbooks/data-exfil.md
touch docs/playbooks/brute-force.md

# Create main documentation files
touch docs/installation.md
touch docs/architecture.md
touch docs/log-collection.md
touch docs/detection-rules.md
touch docs/alerting.md
touch docs/troubleshooting.md

# Create sample rules and scripts
touch detection/sigma/windows_auth_failure.yml
touch detection/sigma/suspicious_process.yml
touch detection/yara/malware_detection.yar
touch scripts/block_brute_force.py
touch simulations/brute_force.py
touch simulations/data_exfil.py

# Create sample dashboard export
touch config/kibana/dashboards/quickstart-dashboards.ndjson

# Create assets directory for images
mkdir -p assets/images

echo "Directory structure created successfully!"
echo ""
echo "Next steps:"
echo "1. Clone the necessary components"
echo "2. Configure your environment settings"
echo "3. Run docker-compose to start the stack" 