# Attack Simulations

This directory contains scripts and tools for simulating various attack scenarios to test your SIEM implementation and detection capabilities.

## Purpose

Security simulations serve several important purposes:

1. **Testing Detection Rules**: Verify that your SIEM correctly detects and alerts on malicious behavior
2. **Tuning Alert Thresholds**: Determine appropriate thresholds to minimize false positives/negatives
3. **Validating Response Playbooks**: Ensure that your automated response workflows function as expected
4. **Training Security Analysts**: Provide realistic scenarios for training and exercises

## Included Simulations

### Brute Force Attacks

The `brute_force.py` script simulates SSH brute force login attempts against a target server.

```bash
# Example: Simulate a medium-intensity brute force attack against 10.0.0.10 for 5 minutes
python3 brute_force.py --target 10.0.0.10 --duration 5 --intensity medium

# Example: Simulate and send logs directly to Logstash
python3 brute_force.py --target 10.0.0.10 --logstash "http://localhost:5000"
```

### Data Exfiltration

The `data_exfil.py` script simulates suspicious data transfers that might indicate exfiltration.

```bash
# Example: Simulate data exfiltration from an internal host to an external IP
python3 data_exfil.py --source 192.168.1.100 --destination 45.67.89.12 --volume large

# Example: Simulate DNS tunneling exfiltration
python3 data_exfil.py --technique dns --domain suspicious-domain.com
```

### Lateral Movement

The `lateral_movement.py` script simulates an attacker moving between systems after initial compromise.

```bash
# Example: Simulate lateral movement across 5 internal systems
python3 lateral_movement.py --initial-host 192.168.1.100 --hosts 5

# Example: Simulate specific technique (e.g., WMI lateral movement)
python3 lateral_movement.py --technique wmi --domain example.local
```

### Command & Control

The `c2_beacon.py` script simulates command and control beaconing activity.

```bash
# Example: Simulate beaconing to a C2 server every 5 minutes
python3 c2_beacon.py --c2-server evil-domain.com --interval 300 --duration 60

# Example: Simulate a specific C2 protocol (e.g., HTTPS with specific URI patterns)
python3 c2_beacon.py --c2-server 185.192.69.24 --protocol https --profile covenant
```

## Usage Guidelines

### Prerequisites

Before running these simulations, make sure:

1. You have the necessary permissions to run security testing in your environment
2. You've documented the testing in advance and informed relevant stakeholders
3. You're running the simulations in a controlled environment
4. Your SIEM stack (especially Elasticsearch and Logstash) is running and configured

### Configuring Simulations

Each simulation script has its own configuration options. Common parameters include:

- `--target`: The target IP or host for the simulation
- `--duration`: How long the simulation should run (in minutes)
- `--intensity`: How aggressive the simulation should be (low, medium, high)
- `--logstash`: URL for sending generated logs directly to Logstash

### Sending Logs

Simulation logs can be sent to your SIEM in several ways:

1. **Direct to Logstash**: Use the `--logstash` parameter to send logs directly to a Logstash HTTP input
2. **File Output**: Save logs to a file that can be picked up by a log collector (Filebeat, etc.)
3. **Syslog**: Some simulations can send logs via syslog to a collector

### Customizing Simulations

To customize simulations for your specific environment:

1. Copy an existing simulation script as a starting point
2. Modify the script to match your network architecture and naming conventions
3. Adjust the log formats to match your expected log structure
4. Test with a limited scope before expanding

## Creating New Simulations

To create a new simulation:

1. Create a new Python script in the `simulations/` directory
2. Follow the structure of existing simulations, with a class-based approach
3. Implement required methods:
   - `__init__`: Initialize parameters
   - `run_simulation`: Execute the simulation
   - `generate_log`: Generate appropriate log entries
   - `send_to_logstash`: Send logs to the SIEM

## Simulation Safety

These simulations are designed to be safe and non-destructive. However, always follow these guidelines:

1. **Never run simulations in production environments** without proper authorization and safeguards
2. Start with low-intensity simulations to validate behavior
3. Monitor system performance during simulations
4. Have a plan to terminate simulations if they cause unexpected issues
5. Exclude critical systems from test targets

## Troubleshooting

If your simulations aren't being detected by your SIEM:

1. Check that logs are being generated and sent correctly
2. Verify Logstash is receiving and processing the logs
3. Examine Elasticsearch to ensure logs are being indexed
4. Confirm that your detection rules are properly configured
5. Check time synchronization between systems