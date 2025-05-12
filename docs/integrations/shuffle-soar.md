# Shuffle SOAR Integration Guide

This guide explains how to integrate the Enterprise SOC SIEM Implementation with Shuffle SOAR (Security Orchestration, Automation, and Response) to automate security workflows.

## Overview

[Shuffle](https://shuffler.io/) is an open-source SOAR platform that helps security teams automate their operations. By integrating our SIEM with Shuffle, we can:

1. Automate detection and response workflows
2. Reduce response time for security incidents
3. Ensure consistent handling of security events
4. Track metrics and effectiveness of security playbooks

## Prerequisites

- Shuffle SOAR instance running (included in the default deployment)
- API access to required systems (firewalls, email, ticketing, etc.)
- Python scripts from the SOC SIEM implementation

## Setting Up Shuffle

### Initial Configuration

1. Access Shuffle at http://localhost:3001
2. Create a new account or use the default credentials
3. Navigate to **Settings** > **Authentication** and set up API keys

### Adding Apps

To integrate with our SOC SIEM, you'll need the following apps in Shuffle:

1. **Elasticsearch** - For querying log data
2. **TheHive** - For case management
3. **Email** - For notifications
4. **Firewall/NGFW** - For blocking actions (specific to your environment)
5. **Python** - For running custom scripts

To add each app:

1. Go to **Apps** in the sidebar
2. Click **Discover apps**
3. Search for the app you want to add
4. Click **Add** to include it in your Shuffle environment

## Creating Data Exfiltration Detection Workflow

### Workflow Overview

We'll create a workflow to:
1. Run the data exfiltration detection script periodically
2. Process detection results
3. Create cases and send notifications for detected incidents
4. Implement blocking actions

### Step 1: Create New Workflow

1. Go to **Workflows** in the sidebar
2. Click **New workflow**
3. Name it "Data Exfiltration Detection and Response"
4. Add a description and set the appropriate sharing settings

### Step 2: Add Trigger

1. Add a **Schedule** trigger to run the workflow at regular intervals
2. Set the schedule to run every hour (or your preferred interval)
3. Configure the trigger with:
   ```
   Name: Hourly Detection
   Interval: 3600 seconds
   ```

### Step 3: Add Python Script Execution

1. Add a **Python** node to run the data exfiltration detection script
2. Connect it to the Schedule trigger
3. Configure the Python node with:
   ```
   Name: Run Data Exfil Detection
   Script: 
   import subprocess
   import json

   # Run the detection script
   result = subprocess.run([
       "python3", 
       "/path/to/scripts/detect_data_exfil.py", 
       "--es-host", "elasticsearch", 
       "--es-port", "9200",
       "--volume-threshold", "100",
       "--time-window", "60"
   ], capture_output=True, text=True)

   # Parse the output
   if result.returncode == 0:
       try:
           detection_results = json.loads(result.stdout)
           execution_argument["detection_results"] = detection_results
       except json.JSONDecodeError:
           execution_argument["error"] = "Failed to parse script output"
   else:
       execution_argument["error"] = result.stderr

   return execution_argument
   ```

### Step 4: Add Condition Check

1. Add a **Condition** node to check if incidents were detected
2. Connect it to the Python script node
3. Configure the condition with:
   ```
   Name: Incidents Detected?
   Condition: $detection_results.length > 0
   ```

### Step 5: Add TheHive Case Creation

1. Add a **TheHive** node for the "True" branch of the condition
2. Configure it to create a case:
   ```
   Name: Create TheHive Case
   Action: Create Case
   Title: Data Exfiltration Detected - $detection_results[0].incident.source_ip
   Description: $detection_results[0].incident.detection_type exfiltration detected from $detection_results[0].incident.source_ip
   Severity: 3
   Tags: ["data-exfiltration", "automated-detection"]
   ```

### Step 6: Add Notification Node

1. Add an **Email** node connected to the TheHive node
2. Configure it to send an alert email:
   ```
   Name: Send Email Alert
   To: soc@yourcompany.com
   Subject: [ALERT] Data Exfiltration Detected
   Body: 
   Data exfiltration detected:
   - Source IP: $detection_results[0].incident.source_ip
   - Destination: $detection_results[0].incident.destination_ip
   - Type: $detection_results[0].incident.detection_type
   - Volume: $detection_results[0].incident.total_mb MB
   
   Case created in TheHive: $thehive_case_url
   ```

### Step 7: Add Blocking Action (Optional)

1. Add your firewall app node connected to the notification node
2. Configure it to implement blocking:
   ```
   Name: Block Exfiltration Source
   Action: Block IP
   IP: $detection_results[0].incident.source_ip
   Duration: 24h
   Reason: Automated block due to detected data exfiltration
   ```

### Step 8: Test and Save

1. Click **Save** to save your workflow
2. Use the **Execute** button to test the workflow with live data
3. Check the execution results in the workflow debugger
4. Adjust the workflow as needed

## Enhanced Data Exfiltration Workflow

For a more advanced implementation, you can:

1. **Add Looping**: Process multiple incidents when detected
2. **Add Enrichment**: Include threat intelligence lookup for detected IPs
3. **Implement Approval Steps**: Add manual approval for blocking actions
4. **Create Dashboard Widgets**: Add Shuffle widgets to track exfiltration incidents

## Example Loop Implementation

To process multiple incidents:

```python
# In the Python node
for incident in detection_results:
    # Create a case for each incident
    case_id = create_case(incident)
    
    # Send notification for each incident
    send_notification(incident, case_id)
    
    # Implement blocking if configured
    if incident.actions.should_block:
        block_communication(incident.source_ip, incident.destination)
```

## Troubleshooting

Common issues and solutions:

1. **Workflow not triggering**: Check the schedule configuration and Shuffle service status
2. **Script execution failing**: Verify the script path and permissions
3. **TheHive integration issues**: Check API keys and connectivity to TheHive
4. **Email notifications not sending**: Verify SMTP settings in Shuffle

## Additional Resources

- [Shuffle Documentation](https://shuffler.io/docs)
- [TheHive Integration Guide](https://docs.thehive-project.org/thehive/user-guides/api/)
- [Enterprise SOC SIEM Playbooks](../playbooks/index.md)