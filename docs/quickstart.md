# Quick Start Guide

This guide will help you get the Enterprise SOC SIEM Implementation up and running quickly with default settings for evaluation or testing purposes.

## Prerequisites

- Docker and Docker Compose installed (Docker Desktop for Windows/Mac)
- 16GB RAM minimum (32GB recommended)
- 100GB free disk space
- Internet connection for pulling Docker images

## Step 1: Clone the Repository

```bash
git clone https://github.com/your-organization/enterprise-soc-siem.git
cd enterprise-soc-siem
```

## Step 2: Start the SIEM Stack

The quick start configuration uses Docker Compose to deploy all components with default settings:

```bash
# Start all services
docker-compose -f docker-compose.quickstart.yml up -d
```

This will start:
- Elasticsearch (single node)
- Kibana
- Logstash
- Filebeat
- Wazuh Manager & API
- TheHive
- Cortex
- Shuffle SOAR

## Step 3: Wait for Services to Initialize

Initial startup may take several minutes as data structures are created and components initialize. You can monitor the startup process with:

```bash
# Check container status
docker-compose -f docker-compose.quickstart.yml ps

# View logs for all containers
docker-compose -f docker-compose.quickstart.yml logs -f
```

## Step 4: Access Web Interfaces

Once services have started, you can access the web interfaces:

| Component | URL | Default Credentials |
|-----------|-----|---------------------|
| Kibana | http://localhost:5601 | elastic / changeme |
| Wazuh | http://localhost:443 | admin / admin |
| TheHive | http://localhost:9000 | admin@thehive.local / secret |
| Cortex | http://localhost:9001 | admin@cortex.local / changeme |
| Shuffle | http://localhost:3001 | admin@shuffle.io / password |

## Step 5: Import Sample Dashboards

The quick start environment comes with pre-configured dashboards for immediate use:

1. In Kibana, navigate to **Management** > **Stack Management** > **Saved Objects**
2. Click **Import**
3. Select `config/kibana/dashboards/quickstart-dashboards.ndjson`
4. Click **Import**

## Step 6: Generate Sample Data

To test the system with sample data:

```bash
# Run basic attack simulation script
./scripts/quickstart/generate-sample-data.sh
```

This will:
- Generate authentication events (successful and failed logins)
- Simulate network traffic (including suspicious connections)
- Create sample security alerts

## Step 7: View Security Dashboards

1. In Kibana, navigate to the dashboard section
2. Open the "Security Overview" dashboard
3. You should see data populated from the sample data generation script

## Step 8: Configure Log Collection

### For Local Logs:

```bash
# Deploy Filebeat to collect local logs
./scripts/quickstart/deploy-local-collector.sh
```

### For Windows Endpoints:

1. Download the Wazuh agent installer for Windows from http://localhost:55000/agents-setup
2. Install on your Windows system using the provided key
3. Verify agent connection in the Wazuh dashboard

## Step 9: Test Response Playbooks

The quickstart environment includes basic response playbooks:

1. Go to Shuffle UI (http://localhost:3001)
2. Navigate to **Workflows**
3. Find "Brute Force Response" workflow
4. Click **Execute** to test the workflow manually

## Step 10: Explore Detection Rules

1. In Kibana, navigate to **Security** > **Detections** > **Rules**
2. Review the pre-configured detection rules
3. Enable or disable rules based on your testing requirements

## Common Issues and Solutions

### Services Failing to Start

If any containers fail to start:

```bash
# Restart all services
docker-compose -f docker-compose.quickstart.yml restart

# Increase memory for Elasticsearch
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Elasticsearch Showing Yellow Status

This is normal in a single-node deployment and doesn't affect functionality for testing.

### Dashboard Data Not Appearing

If dashboards don't show data:

1. Check the timeframe in the upper-right corner of Kibana
2. Adjust to "Last 24 hours" or a timeframe that includes when you generated sample data
3. Verify indices were created: `curl localhost:9200/_cat/indices`

## Next Steps

After becoming familiar with the basic functionality:

1. Review the full [Installation Guide](installation.md) for production deployment
2. Configure [Log Collection](log-collection.md) from your production systems
3. Customize [Detection Rules](detection-rules.md) for your environment
4. Set up [Alerting](alerting.md) notifications
5. Explore advanced [SOAR Playbooks](playbooks/index.md)

## Stopping the Environment

When you're done testing:

```bash
# Stop all containers
docker-compose -f docker-compose.quickstart.yml stop

# Remove containers and their data
docker-compose -f docker-compose.quickstart.yml down -v
```