# Installation Guide

This guide walks you through the steps to install and configure the Enterprise SOC SIEM Implementation.

## Prerequisites

Before you begin, ensure your system meets the following requirements:

- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **Docker**: Docker Engine 19.03.0+ and Docker Compose 1.27.0+
- **Hardware**:
  - Minimum: 8GB RAM, 4 CPU cores, 100GB storage
  - Recommended: 16GB RAM, 8 CPU cores, 500GB SSD storage
- **Network**: Outbound internet connectivity for pulling container images

## Step 1: Clone the Repository

```bash
git clone https://github.com/sonzamats/SOC-Analyst.git
cd SOC-Analyst
```

## Step 2: Configure Environment

### Basic Configuration

For a standard setup with default settings, simply run the setup script:

```bash
./setup.sh
```

This will create the necessary directories, configuration files, and start the SIEM components using Docker Compose.

### Advanced Configuration

For a more customized setup, you can modify the following configuration files before running the setup script:

1. **Elasticsearch**: `config/elasticsearch/elasticsearch.yml`
2. **Logstash**: `config/logstash/config/logstash.yml` and pipeline files in `config/logstash/pipeline/`
3. **Kibana**: `config/kibana/kibana.yml`
4. **Filebeat**: `config/filebeat/filebeat.yml`
5. **Wazuh**: Configuration will be automatically generated on first run

You can also modify the Docker Compose file directly to adjust resource allocations, ports, or other container settings:

```bash
nano docker-compose.yml
```

## Step 3: Start the Services

If you didn't use the setup script, or want to restart the services after configuration, run:

```bash
docker-compose up -d
```

For a more controlled startup of individual components:

```bash
# Start Elasticsearch first
docker-compose up -d elasticsearch

# Wait for Elasticsearch to become available (about 1-2 minutes)
sleep 90

# Start the remaining components
docker-compose up -d
```

## Step 4: Access the Web Interfaces

After all services have started, you can access the following web interfaces:

- **Kibana**: `http://localhost:5601` - The main dashboard for visualizing and analyzing logs
- **Wazuh**: `https://localhost:443` - Security monitoring and incident response
- **Shuffle SOAR**: `http://localhost:3001` - Automation workflows for incident response
- **TheHive**: `http://localhost:9000` - Case management for security incidents
- **Jupyter Notebook**: `http://localhost:8888` - ML analytics (token: siemsecuretoken)
- **Zeek Web UI**: `http://localhost:8080` - Network traffic analysis

Default credentials:

- Elasticsearch/Kibana:
  - Username: `elastic`
  - Password: `secureSIEMpassword123`

- Wazuh:
  - Username: `admin`
  - Password: `admin`

- Shuffle:
  - Register a new account on first access

- TheHive:
  - Username: `admin@thehive.local`
  - Password: `secret`

**Note**: For production environments, you should immediately change these default passwords!

## Step 5: Configure Log Collection

### Local Logs

The default configuration will collect logs from the Docker host system. To collect logs from other systems, you need to configure and deploy log collectors:

1. **Windows Logs**: Deploy Winlogbeat to Windows systems
2. **Linux/Unix Logs**: Deploy Filebeat to Linux/Unix systems
3. **Network Traffic**: Configure Packetbeat or deploy Zeek sensors

For detailed instructions on configuring log sources, see the [Log Collection Guide](log-collection.md).

### Cloud Logs

To collect logs from cloud platforms:

1. **AWS**: Configure CloudWatch to forward logs to Logstash or use the AWS module in Filebeat
2. **Azure**: Set up Azure Event Hubs or Azure Monitor to forward logs
3. **Google Cloud**: Use Cloud Logging to export logs to Pub/Sub, then use Filebeat to collect them

## Step 6: Configure Detection Rules

Import detection rules into your environment:

```bash
# Import Sigma rules
./scripts/import_sigma_rules.sh

# Import YARA rules
./scripts/import_yara_rules.sh
```

Configure automated detection playbooks:

```bash
# Configure the brute force response playbook
python3 scripts/block_brute_force.py --es-host localhost --es-port 9200 --webhook-url "https://your-webhook-url"
```

## Troubleshooting

If you encounter issues during installation:

1. **Elasticsearch fails to start**: Check the logs with `docker-compose logs elasticsearch`. The most common issue is insufficient memory or incorrect permissions on data volumes.

2. **Connection problems between components**: Ensure all containers are running with `docker-compose ps`. Check network connectivity with `docker network inspect soc-siem-network`.

3. **Log collection issues**: Verify Filebeat and other collectors are properly configured and can reach their destinations.

For more detailed troubleshooting, refer to the [Troubleshooting Guide](troubleshooting.md).

## Next Steps

After installation, proceed to:

1. [Configuration Guide](configuration.md) - Fine-tune your deployment
2. [MITRE ATT&CK Mapping](mitre-mapping.md) - Configure threat detections aligned with MITRE framework
3. [Building Custom Dashboards](dashboards/custom.md) - Create visualizations for your specific needs
4. [Running Attack Simulations](../simulations/README.md) - Test your SIEM with simulated attacks