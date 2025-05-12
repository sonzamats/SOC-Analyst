# Log Collection Configuration

This document provides detailed guidance on configuring log collection from various sources for the Enterprise SOC SIEM Implementation.

## Supported Log Sources

The SIEM platform can collect and analyze logs from a wide range of sources:

### Endpoint Sources
- Windows Event Logs
- Linux System Logs (syslog, journal)
- Mac OS Logs
- Application Logs
- EDR/Antivirus Logs

### Network Sources
- Firewall Logs
- Router/Switch Logs
- IDS/IPS Alerts
- VPN Logs
- Network Flow Data
- DNS Logs
- DHCP Logs
- Web Proxy Logs
- Load Balancer Logs

### Cloud & SaaS Sources
- AWS CloudTrail
- AWS GuardDuty
- AWS VPC Flow Logs
- Azure Activity Logs
- Azure Security Center
- GCP Cloud Audit Logs
- Office 365 Audit Logs
- Microsoft 365 Defender
- G Suite Admin Logs
- Salesforce Event Logs

### Security Tools
- Wazuh Alerts
- Suricata IDS/IPS
- Zeek Network Monitor
- Vulnerability Scanner Results
- Web Application Firewall Logs
- Authentication Systems
- DLP Solutions
- CASB Platforms

## Collection Methods

### Beats Agents (Elastic)

Beats are lightweight data shippers that can be installed as agents on servers to collect different types of data.

#### Filebeat
For collecting log files:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/apache2/*.log
  fields:
    source_type: apache
  fields_under_root: true
  
output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"
```

#### Winlogbeat
For collecting Windows event logs:

```yaml
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h
  - name: System
  - name: Security
    processors:
      - drop_event.when.not.or:
          - equals.winlog.event_id: 4624
          - equals.winlog.event_id: 4625
          - equals.winlog.event_id: 4673
          
output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "winlogbeat-%{[agent.version]}-%{+yyyy.MM.dd}"
```

#### Packetbeat
For capturing network traffic:

```yaml
packetbeat.interfaces.device: any
packetbeat.flows:
  timeout: 30s
  period: 10s
  
packetbeat.protocols:
- type: http
  ports: [80, 8080, 443, 8443]
- type: dns
  ports: [53]
- type: tls
  ports: [443, 8443]
  
output.elasticsearch:
  hosts: ["elasticsearch:9200"]
```

### Wazuh Agents

Wazuh provides comprehensive endpoint monitoring and security:

```xml
<ossec_config>
  <client>
    <server-ip>WAZUH_MANAGER_IP</server-ip>
  </client>
  
  <syscheck>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin</directories>
  </syscheck>
  
  <rootcheck>
    <system_audit>/var/ossec/etc/shared/system_audit_ssh.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
  </rootcheck>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</ossec_config>
```

### Logstash Direct Ingestion

For direct ingestion of logs:

```ruby
input {
  tcp {
    port => 5044
    codec => json
  }
  udp {
    port => 5044
    codec => json
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
    }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
  }
}
```

### Cloud Integration

#### AWS CloudWatch Logs

```yaml
filebeat.inputs:
- type: aws-cloudwatch
  regions: ["us-east-1", "us-west-2"]
  log_groups:
    - /aws/lambda/my-function
    - /aws/rds/instance/database/error

processors:
  - add_cloud_metadata: ~
  - add_host_metadata: ~

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "cloudwatch-%{+yyyy.MM.dd}"
```

#### Azure Logs

```yaml
filebeat.inputs:
- type: azure-eventhub
  connection_string: "${AZURE_EVENTHUB_CONNECTION_STRING}"
  eventhub: "insights-operational-logs"
  consumer_group: "$Default"
  storage_account: "${AZURE_STORAGE_ACCOUNT_NAME}"
  storage_account_key: "${AZURE_STORAGE_ACCOUNT_KEY}"
  resource_manager_endpoint: "https://management.azure.com"

processors:
  - add_cloud_metadata: ~

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "azure-%{+yyyy.MM.dd}"
```

## Log Parsing and Normalization

### Common Event Format (CEF)

Example Logstash configuration for CEF parsing:

```ruby
filter {
  if [type] == "cef" {
    grok {
      match => { "message" => "%{SYSLOG5424PRI}%{NONNEGINT:cef_version}\|%{DATA:device_vendor}\|%{DATA:device_product}\|%{DATA:device_version}\|%{DATA:signature_id}\|%{DATA:name}\|%{DATA:severity}\|%{GREEDYDATA:cef_extension}" }
    }
    
    kv {
      source => "cef_extension"
      field_split => " "
      value_split => "="
    }
  }
}
```

### Elastic Common Schema (ECS)

Example for mapping to ECS format:

```ruby
filter {
  mutate {
    rename => {
      "source_ip" => "[source][ip]"
      "dest_ip" => "[destination][ip]"
      "src_port" => "[source][port]"
      "dst_port" => "[destination][port]"
      "username" => "[user][name]"
    }
  }
}
```

## Log Enrichment

### Geo-IP Enrichment

```ruby
filter {
  geoip {
    source => "[source][ip]"
    target => "[source][geo]"
    fields => ["city_name", "country_name", "region_name", "location"]
  }
}
```

### Threat Intelligence Enrichment

```ruby
filter {
  translate {
    field => "[source][ip]"
    destination => "[threat][is_known_malicious]"
    dictionary_path => "/etc/logstash/threat_intel/malicious_ips.yml"
    fallback => "false"
  }
}
```

## Deployment and Configuration

### Agent Deployment

#### Windows Deployment (PowerShell)

```powershell
# Download Winlogbeat
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-7.16.2-windows-x86_64.zip" -OutFile "C:\Temp\winlogbeat.zip"

# Extract
Expand-Archive -Path "C:\Temp\winlogbeat.zip" -DestinationPath "C:\Program Files"
Rename-Item -Path "C:\Program Files\winlogbeat-7.16.2-windows-x86_64" -NewName "Winlogbeat"

# Setup and install
cd "C:\Program Files\Winlogbeat"
Copy-Item -Path "winlogbeat.yml" -Destination "winlogbeat.yml.bak"
# Copy your custom config to winlogbeat.yml
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

#### Linux Deployment (Bash)

```bash
# Download and install Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.16.2-amd64.deb
sudo dpkg -i filebeat-7.16.2-amd64.deb

# Configure
sudo cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak
# Copy your custom config to /etc/filebeat/filebeat.yml

# Start service
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### Containerized Environment

```yaml
# docker-compose.yml excerpt
filebeat:
  image: docker.elastic.co/beats/filebeat:7.16.2
  volumes:
    - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
    - /var/lib/docker/containers:/var/lib/docker/containers:ro
    - /var/log:/var/log:ro
  environment:
    - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
  user: root
  networks:
    - elastic
```

## Performance Considerations

- **Hardware Recommendations**: For high-volume environments, dedicated collection servers with 8+ CPU cores and 16+ GB RAM
- **Network Impact**: Implement rate limiting for bandwidth-constrained environments
- **Storage Requirements**: Plan for log volume growth; typically 1-5 GB per day per 100 devices

## Monitoring Collection Status

### Filebeat Status API

```bash
curl -XGET 'http://localhost:5066/stats' -H 'Content-Type: application/json'
```

### Wazuh Agent Status

```bash
/var/ossec/bin/agent_control -l
```

## Troubleshooting

### Common Issues and Resolutions

1. **Logs Not Appearing in Elasticsearch**
   - Check agent status: `sudo systemctl status filebeat`
   - Verify connectivity: `ping elasticsearch_host`
   - Check permissions on log files

2. **High CPU Usage on Collection Server**
   - Reduce logging verbosity level
   - Implement proper filtering to reduce log volume
   - Adjust batch size and workers in configuration

3. **TLS Connection Issues**
   - Verify certificate paths are correct
   - Check certificate expiration dates
   - Ensure proper CA trust is established

4. **Parsing Errors**
   - Use Logstash debug mode: `logstash -e 'input { stdin { } } filter { your_filter_here } output { stdout { codec => rubydebug } }'`
   - Check for malformed logs in the source
   - Update Grok patterns to handle variations

## Appendix: Sample Agent Configurations

### Critical Windows Events to Collect

```yaml
winlogbeat.event_logs:
  - name: Security
    processors:
      - drop_event.when.not.or:
        # Authentication events
        - equals.winlog.event_id: 4624  # Successful logon
        - equals.winlog.event_id: 4625  # Failed logon
        - equals.winlog.event_id: 4634  # Logoff
        # Privilege usage
        - equals.winlog.event_id: 4672  # Admin logon
        - equals.winlog.event_id: 4673  # Privileged service called
        - equals.winlog.event_id: 4674  # Operation on privileged object
        # Account management
        - equals.winlog.event_id: 4720  # Account created
        - equals.winlog.event_id: 4722  # Account enabled
        - equals.winlog.event_id: 4723  # Password change attempt
        - equals.winlog.event_id: 4724  # Password reset
        - equals.winlog.event_id: 4725  # Account disabled
        - equals.winlog.event_id: 4726  # Account deleted
        - equals.winlog.event_id: 4728  # Member added to security-enabled global group
        - equals.winlog.event_id: 4732  # Member added to security-enabled local group
        # System events
        - equals.winlog.event_id: 4697  # Service installed
        - equals.winlog.event_id: 7045  # Service installed
        # Other security events
        - equals.winlog.event_id: 5156  # Windows Filtering Platform allowed connection
        - equals.winlog.event_id: 5157  # Windows Filtering Platform blocked connection
```

### Critical Linux Logs to Collect

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log    # Authentication logs
    - /var/log/secure      # Authentication logs (RHEL/CentOS)
    - /var/log/audit/audit.log  # Audit logs
    - /var/log/syslog      # System logs
    - /var/log/messages    # System logs (RHEL/CentOS)
    - /var/log/cron        # Scheduled tasks
    - /var/log/kern.log    # Kernel logs
    - /var/log/apache2/*   # Web server logs
    - /var/log/nginx/*     # Web server logs
    - /var/log/mysql/*     # Database logs
```

### Cloud Service Configuration Example (AWS)

```yaml
- type: s3
  queue_url: https://sqs.us-east-1.amazonaws.com/123456789/my-queue
  access_key_id: "${AWS_ACCESS_KEY_ID}"
  secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
  scan_frequency: 10s
  include_s3_info: true
  processors:
    - add_fields:
        target: cloud
        fields:
          provider: aws
          region: us-east-1
          account:
            name: production
            id: "123456789"