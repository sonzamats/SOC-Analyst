#!/bin/bash

# Script to set up proper permissions and configuration for all scripts
# in the Enterprise SOC SIEM Implementation

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

# Function to set up script permissions
setup_permissions() {
    print_message "Setting up script permissions..."
    
    # Make Python scripts executable
    find scripts -name "*.py" -exec chmod +x {} \;
    find simulations -name "*.py" -exec chmod +x {} \;
    
    # Make utility scripts executable
    chmod +x scripts/*.sh
    
    print_success "Script permissions set up successfully."
}

# Function to check script dependencies
check_dependencies() {
    print_message "Checking for dependencies..."
    
    # Check for Python3
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 is required but not found."
        exit 1
    fi
    
    # Check for pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is required but not found."
        exit 1
    fi
    
    print_success "All dependencies found."
}

# Function to install required packages
install_packages() {
    print_message "Installing required Python packages..."
    
    # Create a temporary requirements file
    cat > /tmp/requirements.txt << EOF
pyyaml>=6.0
requests>=2.27.1
scapy>=2.4.5
elasticsearch>=7.14.0
dnspython>=2.2.1
python-dateutil>=2.8.2
argparse>=1.4.0
ipaddress>=1.0.23
psutil>=5.9.0
EOF
    
    # Install the required packages
    pip3 install -r /tmp/requirements.txt
    
    # Clean up
    rm /tmp/requirements.txt
    
    print_success "Python packages installed successfully."
}

# Function to create whitelists if they don't exist
create_whitelists() {
    print_message "Setting up whitelist files..."
    
    # Create directories if they don't exist
    mkdir -p config/whitelists
    mkdir -p logs
    mkdir -p dashboards/threat-intel
    mkdir -p logstash/pipelines
    mkdir -p docs/dashboards
    
    # Create IP whitelist file
    if [ ! -f config/whitelists/ip_whitelist.txt ]; then
        echo "# List of whitelisted IP addresses (one per line)" > config/whitelists/ip_whitelist.txt
        echo "# Add your trusted IPs below" >> config/whitelists/ip_whitelist.txt
        echo "127.0.0.1" >> config/whitelists/ip_whitelist.txt
        echo "192.168.1.1" >> config/whitelists/ip_whitelist.txt
    fi
    
    # Create domain whitelist file
    if [ ! -f config/whitelists/domain_whitelist.txt ]; then
        echo "# List of whitelisted domains (one per line)" > config/whitelists/domain_whitelist.txt
        echo "# Add your trusted domains below" >> config/whitelists/domain_whitelist.txt
        echo "google.com" >> config/whitelists/domain_whitelist.txt
        echo "microsoft.com" >> config/whitelists/domain_whitelist.txt
    fi

    # Create hash whitelist file
    if [ ! -f config/whitelists/hash_whitelist.txt ]; then
        echo "# List of whitelisted file hashes (one per line)" > config/whitelists/hash_whitelist.txt
        echo "# Add your trusted file hashes below" >> config/whitelists/hash_whitelist.txt
    fi
    
    print_success "Whitelist files set up successfully."
}

# Function to verify scripts
verify_scripts() {
    print_message "Verifying scripts..."
    
    # Define an array of scripts to verify
    declare -a scripts_to_verify=(
        "scripts/detect_data_exfil.py"
        "scripts/detect_lateral_movement.py"
        "scripts/threat_intel_collector.py"
        "scripts/ti_rule_tagger.py"
        "simulations/data_exfil.py"
        "simulations/lateral_movement.py"
    )
    
    # Check each script for syntax errors
    for script in "${scripts_to_verify[@]}"; do
        if [ -f "$script" ]; then
            echo -e "Verifying ${YELLOW}$script${NC}..."
            if ! python3 -m py_compile "$script"; then
                echo -e "${RED}Syntax errors found in $script${NC}"
            fi
        else
            echo -e "${YELLOW}Warning: $script not found, skipping verification.${NC}"
        fi
    done
    
    print_success "Script verification completed."
}

# Function to setup threat intelligence components
setup_threat_intel() {
    print_message "Setting up threat intelligence components..."
    
    # Create threat intel config if it doesn't exist
    if [ ! -f config/threat_intel_config.yml ] && [ -f config/threat_intel_config.example.yml ]; then
        cp config/threat_intel_config.example.yml config/threat_intel_config.yml
        print_success "Created threat intelligence configuration file."
    fi
    
    # Create threat intel directories
    mkdir -p config/rules
    mkdir -p config/dashboards
    
    # Ensure the elasticsearch container is running if using Docker
    if command -v docker &> /dev/null && docker ps | grep -q elasticsearch; then
        print_warning "Elasticsearch appears to be running in a Docker container."
        print_warning "Please ensure ELASTIC_PASSWORD environment variable is set for the collector to connect."
    fi
    
    print_success "Threat intelligence components set up successfully."
}

# Main function
main() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}  Enterprise SOC SIEM Implementation Setup  ${NC}"
    echo -e "${BLUE}============================================${NC}"
    
    # Run setup functions
    check_dependencies
    setup_permissions
    install_packages
    create_whitelists
    setup_threat_intel
    verify_scripts
    
    echo -e "${GREEN}Setup completed successfully!${NC}"
    echo -e "${YELLOW}You can now run the detection and simulation scripts.${NC}"
    echo -e "${YELLOW}For threat intelligence, run: ./scripts/threat_intel_collector.py --config config/threat_intel_config.yml${NC}"
}

# Run the main function
main