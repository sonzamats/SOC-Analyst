#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to create necessary directories
create_directories() {
    print_message "Creating necessary directories..."
    
    mkdir -p config/logstash/pipeline
    mkdir -p config/logstash/config
    mkdir -p config/kibana
    mkdir -p config/filebeat
    mkdir -p config/packetbeat
    mkdir -p config/zeek
    mkdir -p config/zeek-web
    mkdir -p config/thehive
    mkdir -p config/cortex
    mkdir -p logs/zeek
    
    print_success "Directories created."
}

# Function to create basic config files
create_config_files() {
    print_message "Creating basic configuration files..."
    
    # Logstash configuration
    cat > config/logstash/config/logstash.yml << EOF
http.host: "0.0.0.0"
xpack.monitoring.elasticsearch.hosts: ["http://elasticsearch:9200"]
xpack.monitoring.enabled: true
EOF

    # Sample Logstash pipeline
    cat > config/logstash/pipeline/logstash.conf << EOF
input {
  beats {
    port => 5044
  }
  tcp {
    port => 5000
  }
  udp {
    port => 5514
    codec => "json"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
    }
    
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
  
  if [type] == "windows" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{WORD:log_level} %{WORD:component} %{GREEDYDATA:message}" }
    }
  }

  if [message] =~ "failed password" {
    mutate {
      add_tag => ["authentication_failure"]
    }
  }

  # Enrichment with threat intelligence
  if [src_ip] {
    translate {
      field => "src_ip"
      destination => "threat_intel"
      dictionary_path => "/etc/logstash/threat_intel.yml"
      fallback => "No Intel"
    }
  }

  # Add MITRE ATT&CK tagging
  if [process] =~ "powershell.exe" and [command_line] =~ "-encodedcommand" {
    mutate {
      add_field => {
        "mitre_tactic" => "Execution"
        "mitre_technique" => "T1059.001"
        "mitre_description" => "PowerShell"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    user => "elastic"
    password => "secureSIEMpassword123"
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
    manage_template => false
  }
}
EOF

    # Kibana configuration
    cat > config/kibana/kibana.yml << EOF
server.name: kibana
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://elasticsearch:9200"]
elasticsearch.username: elastic
elasticsearch.password: secureSIEMpassword123
xpack.monitoring.ui.container.elasticsearch.enabled: true
EOF

    # Filebeat configuration
    cat > config/filebeat/filebeat.yml << EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/syslog
    - /var/log/auth.log
  fields:
    type: syslog

- type: log
  enabled: true
  paths:
    - /var/log/windows/*.log
  fields:
    type: windows

filebeat.config.modules:
  path: \${path.config}/modules.d/*.yml
  reload.enabled: false

setup.dashboards.enabled: true
setup.template.name: "filebeat"
setup.template.pattern: "filebeat-*"

output.logstash:
  hosts: ["logstash:5044"]
EOF

    # Packetbeat configuration
    cat > config/packetbeat/packetbeat.yml << EOF
packetbeat.interfaces.device: any

packetbeat.flows:
  timeout: 30s
  period: 10s

packetbeat.protocols:
- type: icmp
  enabled: true
- type: dns
  enabled: true
  ports: [53]
- type: http
  enabled: true
  ports: [80, 8080, 8000, 5000, 8002]
- type: tls
  enabled: true
  ports: [443, 8443]

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  username: "elastic"
  password: "secureSIEMpassword123"
EOF

    # Zeek configuration
    cat > config/zeek/local.zeek << EOF
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ftp
@load base/protocols/ssh
@load base/protocols/ssl
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/protocols/http/detect-sqli
EOF

    # Create a simple web interface for Zeek logs
    cat > config/zeek-web/default.conf << EOF
server {
    listen       80;
    server_name  localhost;

    location / {
        root   /usr/share/nginx/html;
        index  index.html;
        autoindex on;
    }
}
EOF

    cat > config/zeek-web/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Zeek Logs Viewer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .log-list { margin-top: 20px; }
        .log-list a { display: block; padding: 10px; border-bottom: 1px solid #eee; color: #0275d8; text-decoration: none; }
        .log-list a:hover { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Zeek Network Logs</h1>
        <p>This page provides access to the Zeek network monitoring logs generated by the SIEM system.</p>
        <div class="log-list">
            <h2>Available Logs:</h2>
            <a href="/logs/">Browse All Logs</a>
        </div>
    </div>
</body>
</html>
EOF

    print_success "Configuration files created."
}

# Main setup function
main() {
    echo "=========================================================="
    echo "        Enterprise SOC SIEM Implementation Setup          "
    echo "=========================================================="
    
    # Check for required dependencies
    print_message "Checking dependencies..."
    
    if ! command_exists docker; then
        print_error "Docker is not installed. Please install Docker and try again."
        exit 1
    fi
    
    if ! command_exists docker-compose; then
        print_warning "Docker Compose is not installed. Attempting to install..."
        sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        if command_exists docker-compose; then
            print_success "Docker Compose installed successfully."
        else
            print_error "Failed to install Docker Compose. Please install it manually."
            exit 1
        fi
    fi
    
    # Create necessary directories and config files
    create_directories
    create_config_files
    
    # Start the SIEM stack
    if [[ "$1" == "--dev" ]]; then
        print_message "Starting SIEM stack in development mode..."
        docker-compose up -d elasticsearch kibana logstash filebeat
    else
        print_message "Starting SIEM stack..."
        docker-compose up -d
    fi
    
    # Wait for services to be ready
    print_message "Waiting for services to start (this may take a few minutes)..."
    sleep 30
    
    print_success "Setup completed!"
    echo ""
    echo "Access your SIEM stack:"
    echo "- Kibana: http://localhost:5601"
    echo "- Wazuh: https://localhost:443"
    echo "- Shuffle SOAR: http://localhost:3001"
    echo "- TheHive: http://localhost:9000"
    echo "- Jupyter Notebook: http://localhost:8888 (token: siemsecuretoken)"
    echo "- Zeek Web UI: http://localhost:8080"
    echo ""
    echo "For more information, refer to the documentation in the docs/ directory."
    echo "To stop the SIEM stack, run: docker-compose down"
}

# Run the setup with any provided arguments
main "$@"