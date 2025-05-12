#!/usr/bin/env python3
"""
Lateral Movement Detection Script

This script analyzes authentication, process execution, and network connection logs
to identify potential lateral movement activities in the network.

Author: SOC Analyst SIEM Project
Date: 2023-07-25
Version: 1.0
"""

import os
import sys
import json
import time
import logging
import argparse
import ipaddress
import requests
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("lateral_movement_detection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("LateralMovementDetection")

class LateralMovementDetector:
    """Class for detecting lateral movement attempts across hosts"""
    
    def __init__(self, es_host="elasticsearch", es_port=9200, 
                 es_user="elastic", es_password="secureSIEMpassword123",
                 time_window=60, auth_threshold=3, webhook_url=None, 
                 firewall_api=None, case_system_url=None):
        """Initialize the detector with configuration parameters"""
        # Elasticsearch connection
        self.es = Elasticsearch(
            [f"http://{es_host}:{es_port}"],
            http_auth=(es_user, es_password)
        )
        
        # Detection parameters
        self.time_window = time_window  # Time window in minutes
        self.auth_threshold = auth_threshold  # Number of auth events before alert
        
        # Response endpoints
        self.webhook_url = webhook_url  # For notifications
        self.firewall_api = firewall_api  # For blocking
        self.case_system_url = case_system_url  # For case creation
        
        # Known admin tools that might be used for lateral movement
        self.admin_tools = [
            "psexec", "wmic", "powershell", "wmiexec", "mimikatz", "paexec",
            "atexec", "smbexec", "dcomexec", "winrm", "ssh", "rsh", "rexec"
        ]
        
        # Suspicious process creation patterns
        self.suspicious_processes = [
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", 
            "rundll32.exe", "regsvr32.exe", "mshta.exe", "msiexec.exe"
        ]
        
        # Whitelist of IPs that should never trigger alerts
        self.ip_whitelist = self.load_whitelist()
        
        logger.info(f"Initialized lateral movement detector with time window of {time_window} minutes")
    
    def load_whitelist(self, whitelist_file="ip_whitelist.txt"):
        """Load IP whitelist from a file"""
        whitelist = set()
        try:
            if os.path.exists(whitelist_file):
                with open(whitelist_file, "r") as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith("#"):
                            whitelist.add(ip)
                logger.info(f"Loaded {len(whitelist)} IPs in whitelist from {whitelist_file}")
            else:
                logger.warning(f"Whitelist file {whitelist_file} not found. Using empty whitelist.")
        except Exception as e:
            logger.error(f"Error loading whitelist: {str(e)}")
        
        # Always include localhost
        whitelist.add("127.0.0.1")
        whitelist.add("::1")
        
        return whitelist
    
    def is_private_ip(self, ip):
        """Check if IP is private/internal"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def detect_authentication_anomalies(self, index="winlogbeat-*"):
        """Detect unusual authentication patterns across multiple hosts"""
        logger.info("Searching for authentication anomalies...")
        
        # Calculate time range
        now = datetime.utcnow()
        time_from = (now - timedelta(minutes=self.time_window)).isoformat()
        
        # Elasticsearch query for authentication events
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"terms": {"event.category": ["authentication", "session"]}},
                        {"term": {"event.outcome": "success"}}
                    ],
                    "must_not": [
                        {"terms": {"source.ip": list(self.ip_whitelist)}}
                    ]
                }
            },
            "aggs": {
                "by_source_user": {
                    "terms": {
                        "field": "user.name",
                        "size": 100
                    },
                    "aggs": {
                        "distinct_targets": {
                            "cardinality": {
                                "field": "host.name"
                            }
                        },
                        "by_target": {
                            "terms": {
                                "field": "host.name",
                                "size": 100
                            }
                        }
                    }
                }
            }
        }
        
        try:
            # Execute the query
            response = self.es.search(index=index, body=query)
            
            # Process results
            lateral_candidates = []
            
            # Check each user
            for user_bucket in response.get("aggregations", {}).get("by_source_user", {}).get("buckets", []):
                username = user_bucket.get("key", "")
                distinct_hosts = user_bucket.get("distinct_targets", {}).get("value", 0)
                
                # Alert if user authenticated to multiple hosts
                if distinct_hosts >= self.auth_threshold:
                    # Get the host targets
                    hosts = [host.get("key", "") for host in user_bucket.get("by_target", {}).get("buckets", [])]
                    
                    lateral_candidates.append({
                        "username": username,
                        "auth_count": distinct_hosts,
                        "hosts": hosts,
                        "detection_type": "auth_anomaly",
                        "time_window_minutes": self.time_window,
                        "detected_at": now.isoformat(),
                        "severity": "medium" if distinct_hosts < 5 else "high"
                    })
            
            logger.info(f"Detected {len(lateral_candidates)} potential authentication-based lateral movement patterns")
            return lateral_candidates
            
        except Exception as e:
            logger.error(f"Error searching Elasticsearch for authentication anomalies: {str(e)}")
            return []

    def detect_admin_tool_usage(self, index="winlogbeat-*"):
        """Detect usage of administrative tools for lateral movement"""
        logger.info("Searching for suspicious admin tool usage...")
        
        # Calculate time range
        now = datetime.utcnow()
        time_from = (now - timedelta(minutes=self.time_window)).isoformat()
        
        # Build query for admin tool usage
        should_clauses = []
        for tool in self.admin_tools:
            should_clauses.append({"wildcard": {"process.name": f"*{tool}*"}})
            should_clauses.append({"wildcard": {"process.command_line": f"*{tool}*"}})
        
        query = {
            "size": 1000,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"term": {"event.category": "process"}},
                        {"term": {"event.type": "start"}}
                    ],
                    "should": should_clauses,
                    "minimum_should_match": 1,
                    "must_not": [
                        {"terms": {"source.ip": list(self.ip_whitelist)}}
                    ]
                }
            }
        }
        
        try:
            # Execute the query
            response = self.es.search(index=index, body=query)
            
            # Process results
            lateral_candidates = []
            host_user_tools = {}
            
            # Analyze each hit
            for hit in response.get("hits", {}).get("hits", []):
                source = hit.get("_source", {})
                
                host = source.get("host", {}).get("name", "unknown")
                user = source.get("user", {}).get("name", "unknown")
                process = source.get("process", {}).get("name", "unknown")
                cmdline = source.get("process", {}).get("command_line", "")
                timestamp = source.get("@timestamp", "")
                
                # Create a key for the host-user combination
                host_user_key = f"{host}:{user}"
                
                # Initialize if not exists
                if host_user_key not in host_user_tools:
                    host_user_tools[host_user_key] = {"tools": set(), "details": []}
                
                # Add detected admin tool
                detected_tool = None
                for tool in self.admin_tools:
                    if (tool.lower() in process.lower() or 
                        tool.lower() in cmdline.lower()):
                        detected_tool = tool
                        break
                
                if detected_tool:
                    host_user_tools[host_user_key]["tools"].add(detected_tool)
                    host_user_tools[host_user_key]["details"].append({
                        "timestamp": timestamp,
                        "process": process,
                        "command_line": cmdline,
                        "tool": detected_tool
                    })
            
            # Convert to candidates list
            for host_user_key, data in host_user_tools.items():
                if len(data["tools"]) >= 1:  # Alert if using at least one admin tool
                    host, user = host_user_key.split(":", 1)
                    
                    lateral_candidates.append({
                        "username": user,
                        "host": host,
                        "tools_used": list(data["tools"]),
                        "event_count": len(data["details"]),
                        "events": data["details"][:10],  # First 10 events for context
                        "detection_type": "admin_tool_usage",
                        "time_window_minutes": self.time_window,
                        "detected_at": now.isoformat(),
                        "severity": "high" if len(data["tools"]) > 1 else "medium"
                    })
            
            logger.info(f"Detected {len(lateral_candidates)} potential admin tool-based lateral movement patterns")
            return lateral_candidates
            
        except Exception as e:
            logger.error(f"Error searching Elasticsearch for admin tool usage: {str(e)}")
            return []

    def detect_connection_patterns(self, index="packetbeat-*"):
        """Detect suspicious connection patterns between hosts"""
        logger.info("Searching for suspicious connection patterns...")
        
        # Calculate time range
        now = datetime.utcnow()
        time_from = (now - timedelta(minutes=self.time_window)).isoformat()
        
        # Elasticsearch query for connection patterns
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"terms": {"destination.port": [22, 23, 135, 139, 445, 3389, 5985, 5986]}}
                    ],
                    "must_not": [
                        {"terms": {"source.ip": list(self.ip_whitelist)}}
                    ]
                }
            },
            "aggs": {
                "by_source": {
                    "terms": {
                        "field": "source.ip",
                        "size": 100
                    },
                    "aggs": {
                        "distinct_targets": {
                            "cardinality": {
                                "field": "destination.ip"
                            }
                        },
                        "by_port": {
                            "terms": {
                                "field": "destination.port",
                                "size": 10
                            }
                        },
                        "by_target": {
                            "terms": {
                                "field": "destination.ip",
                                "size": 100
                            }
                        }
                    }
                }
            }
        }
        
        try:
            # Execute the query
            response = self.es.search(index=index, body=query)
            
            # Process results
            lateral_candidates = []
            
            # Check each source IP
            for source_bucket in response.get("aggregations", {}).get("by_source", {}).get("buckets", []):
                source_ip = source_bucket.get("key", "")
                distinct_targets = source_bucket.get("distinct_targets", {}).get("value", 0)
                
                # Alert if connecting to multiple targets
                if distinct_targets >= self.auth_threshold:
                    # Get the target IPs
                    target_ips = [target.get("key", "") for target in source_bucket.get("by_target", {}).get("buckets", [])]
                    
                    # Get the ports used
                    ports_used = [port.get("key", 0) for port in source_bucket.get("by_port", {}).get("buckets", [])]
                    
                    lateral_candidates.append({
                        "source_ip": source_ip,
                        "target_count": distinct_targets,
                        "target_ips": target_ips,
                        "ports_used": ports_used,
                        "detection_type": "connection_pattern",
                        "time_window_minutes": self.time_window,
                        "detected_at": now.isoformat(),
                        "severity": "medium" if distinct_targets < 5 else "high"
                    })
            
            logger.info(f"Detected {len(lateral_candidates)} potential connection-based lateral movement patterns")
            return lateral_candidates
            
        except Exception as e:
            logger.error(f"Error searching Elasticsearch for connection patterns: {str(e)}")
            return []

    def block_source(self, source_ip, duration=60, reason="Lateral Movement"):
        """Block a source IP involved in lateral movement"""
        if not self.firewall_api:
            logger.warning(f"No firewall API configured. Cannot block source IP {source_ip}")
            return False
        
        logger.info(f"Attempting to block source IP {source_ip} for {duration} minutes")
        
        try:
            # Prepare request data
            payload = {
                "source_ip": source_ip,
                "duration_minutes": duration,
                "reason": reason
            }
            
            # Send to firewall API
            response = requests.post(
                self.firewall_api,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully blocked source IP {source_ip}")
                return True
            else:
                logger.error(f"Failed to block source IP: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking source IP: {str(e)}")
            return False

    def create_case(self, incident_data):
        """Create a case in the incident management system"""
        if not self.case_system_url:
            logger.warning("No case management system configured. Cannot create case.")
            return None
        
        detection_type = incident_data.get('detection_type', 'unknown')
        
        # Prepare case data based on detection type
        if detection_type == "auth_anomaly":
            username = incident_data.get('username', 'unknown')
            hosts = incident_data.get('hosts', [])
            
            title = f"Authentication-based Lateral Movement: {username} on {len(hosts)} hosts"
            description = f"Detected user {username} authenticating to {len(hosts)} hosts within {incident_data.get('time_window_minutes', 60)} minutes."
            
            # Add details for hosts
            description += f"\n\nAffected hosts: {', '.join(hosts[:10])}"
            if len(hosts) > 10:
                description += f" and {len(hosts) - 10} more"
                
        elif detection_type == "admin_tool_usage":
            username = incident_data.get('username', 'unknown')
            host = incident_data.get('host', 'unknown')
            tools = incident_data.get('tools_used', [])
            
            title = f"Admin Tool-based Lateral Movement: {username} using {len(tools)} tools on {host}"
            description = f"Detected user {username} using suspicious administrative tools on {host}."
            
            # Add details for tools used
            description += f"\n\nTools used: {', '.join(tools)}"
            
            # Add command line examples
            events = incident_data.get('events', [])
            if events:
                description += "\n\nCommand examples:"
                for event in events[:3]:
                    description += f"\n- {event.get('command_line', 'N/A')}"
                    
        elif detection_type == "connection_pattern":
            source_ip = incident_data.get('source_ip', 'unknown')
            target_count = incident_data.get('target_count', 0)
            ports = incident_data.get('ports_used', [])
            
            title = f"Connection-based Lateral Movement: {source_ip} to {target_count} hosts"
            description = f"Detected {source_ip} connecting to {target_count} different hosts on suspicious ports."
            
            # Add details for ports
            description += f"\n\nPorts used: {', '.join(map(str, ports))}"
            
            # Add target IPs
            target_ips = incident_data.get('target_ips', [])
            description += f"\n\nTarget IPs: {', '.join(target_ips[:10])}"
            if len(target_ips) > 10:
                description += f" and {len(target_ips) - 10} more"
                
        else:
            title = f"Potential Lateral Movement: {detection_type}"
            description = f"Detected suspicious lateral movement activity."
                
        logger.info(f"Creating case for {detection_type} lateral movement")
        
        try:
            # Common case data
            case_data = {
                "title": title,
                "description": description,
                "severity": incident_data.get('severity', 'medium'),
                "type": "Lateral Movement",
                "source": "SIEM",
                "tlp": "AMBER",
                "tags": ["lateral-movement", "automated-detection"],
                "tasks": [
                    {
                        "title": "Validate lateral movement activity",
                        "status": "Pending",
                        "description": "Investigate if this is a genuine lateral movement attempt or legitimate activity"
                    },
                    {
                        "title": "Check account security",
                        "status": "Pending",
                        "description": "Verify if account credentials have been compromised"
                    },
                    {
                        "title": "Investigate endpoints",
                        "status": "Pending",
                        "description": "Check for compromise or unauthorized access on affected endpoints"
                    },
                    {
                        "title": "Implement containment",
                        "status": "Pending",
                        "description": "Contain the threat by isolating affected systems and blocking malicious IPs"
                    }
                ]
            }
            
            # Add appropriate artifacts based on detection type
            artifacts = []
            
            if detection_type == "auth_anomaly":
                artifacts.append({
                    "type": "user-account",
                    "value": incident_data.get('username', 'unknown'),
                    "tags": ["account"]
                })
                
                for host in incident_data.get('hosts', [])[:5]:
                    artifacts.append({
                        "type": "hostname",
                        "value": host,
                        "tags": ["affected-host"]
                    })
                    
            elif detection_type == "admin_tool_usage":
                artifacts.append({
                    "type": "user-account",
                    "value": incident_data.get('username', 'unknown'),
                    "tags": ["account"]
                })
                
                artifacts.append({
                    "type": "hostname",
                    "value": incident_data.get('host', 'unknown'),
                    "tags": ["affected-host"]
                })
                
                for tool in incident_data.get('tools_used', []):
                    artifacts.append({
                        "type": "process-name",
                        "value": tool,
                        "tags": ["tool"]
                    })
                    
            elif detection_type == "connection_pattern":
                artifacts.append({
                    "type": "ip",
                    "value": incident_data.get('source_ip', 'unknown'),
                    "tags": ["source"]
                })
                
                for ip in incident_data.get('target_ips', [])[:5]:
                    artifacts.append({
                        "type": "ip",
                        "value": ip,
                        "tags": ["target"]
                    })
            
            case_data["artifacts"] = artifacts
            
            # Send to case management system
            response = requests.post(
                self.case_system_url,
                json=case_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in (200, 201):
                case_id = response.json().get("id", "Unknown")
                logger.info(f"Successfully created case {case_id} for lateral movement")
                return case_id
            else:
                logger.error(f"Failed to create case: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating case: {str(e)}")
            return None

    def send_notification(self, incident_data, case_id=None, block_successful=None):
        """Send notification about lateral movement incident"""
        if not self.webhook_url:
            logger.warning("No webhook URL configured. Cannot send notification.")
            return False
        
        detection_type = incident_data.get('detection_type', 'unknown')
        
        logger.info(f"Sending notification for {detection_type} lateral movement")
        
        try:
            # Prepare notification message based on detection type
            if detection_type == "auth_anomaly":
                username = incident_data.get('username', 'unknown')
                hosts = incident_data.get('hosts', [])
                
                title = f"Authentication-based Lateral Movement Detected"
                details = f"User {username} authenticated to {len(hosts)} hosts"
                
            elif detection_type == "admin_tool_usage":
                username = incident_data.get('username', 'unknown')
                host = incident_data.get('host', 'unknown')
                tools = incident_data.get('tools_used', [])
                
                title = f"Admin Tool-based Lateral Movement Detected"
                details = f"User {username} used {', '.join(tools)} on {host}"
                
            elif detection_type == "connection_pattern":
                source_ip = incident_data.get('source_ip', 'unknown')
                target_count = incident_data.get('target_count', 0)
                
                title = f"Connection-based Lateral Movement Detected"
                details = f"{source_ip} connected to {target_count} hosts on suspicious ports"
                
            else:
                title = f"Potential Lateral Movement Detected"
                details = f"Suspicious lateral movement activity detected"
            
            # Common notification data
            msg = {
                "summary": title,
                "text": f"ALERT: {details} within {incident_data.get('time_window_minutes', 60)} minutes.",
                "severity": incident_data.get('severity', 'medium'),
                "timestamp": datetime.now().isoformat(),
                "detection_type": detection_type,
                "incident_details": incident_data
            }
            
            # Add case ID if available
            if case_id:
                msg["case_id"] = case_id
            
            # Add blocking status if available
            if block_successful is not None:
                msg["blocked"] = block_successful
                
            # Send notification
            response = requests.post(
                self.webhook_url,
                json=msg,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully sent notification for lateral movement")
                return True
            else:
                logger.error(f"Failed to send notification: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
            return False
    
    def update_dashboards(self, incidents):
        """Update SIEM dashboards with incident data"""
        if not incidents:
            return
            
        logger.info(f"Updating dashboards with {len(incidents)} incidents")
        
        # Prepare bulk index for Elasticsearch
        bulk_data = []
        for incident in incidents:
            # Add metadata for indexing
            index_op = {
                "index": {
                    "_index": "siem-lateral-movement-incidents"
                }
            }
            
            # Add to bulk data
            bulk_data.append(index_op)
            bulk_data.append(incident)
        
        try:
            # Send to Elasticsearch
            if bulk_data:
                self.es.bulk(body=bulk_data)
                logger.info("Successfully updated dashboards with incident data")
        except Exception as e:
            logger.error(f"Error updating dashboards: {str(e)}")

    def run_playbook(self):
        """Run the lateral movement detection and response playbook"""
        logger.info("Starting lateral movement detection playbook")
        
        # Step 1: Detect potential lateral movement using different methods
        auth_incidents = self.detect_authentication_anomalies()
        tool_incidents = self.detect_admin_tool_usage()
        connection_incidents = self.detect_connection_patterns()
        
        # Combine all incidents
        all_incidents = auth_incidents + tool_incidents + connection_incidents
        
        if not all_incidents:
            logger.info("No lateral movement incidents detected. Playbook complete.")
            return []
        
        response_actions = []
        
        # Process each incident
        for incident in all_incidents:
            detection_type = incident.get('detection_type', 'unknown')
            
            logger.info(f"Processing {detection_type} incident")
            
            # Step 2: Block the source (if it's an IP-based detection)
            blocked = False
            if detection_type == "connection_pattern":
                source_ip = incident.get('source_ip', 'unknown')
                if source_ip != 'unknown':
                    blocked = self.block_source(
                        source_ip, 
                        duration=60, 
                        reason=f"Lateral Movement: {detection_type}"
                    )
            
            # Step 3: Create a case
            case_id = self.create_case(incident)
            
            # Step 4: Send notification
            notified = self.send_notification(incident, case_id, blocked)
            
            # Record the response actions
            response_actions.append({
                "incident": incident,
                "actions": {
                    "blocked": blocked,
                    "case_id": case_id,
                    "notified": notified
                }
            })
        
        # Step 5: Update dashboards
        self.update_dashboards(all_incidents)
        
        logger.info(f"Lateral movement response playbook completed for {len(all_incidents)} incidents")
        return response_actions

def main():
    """Main function to run the lateral movement detection playbook"""
    parser = argparse.ArgumentParser(description="Lateral Movement Detection and Response Playbook")
    
    parser.add_argument("--es-host", 
                        default="localhost",
                        help="Elasticsearch host (default: localhost)")
    
    parser.add_argument("--es-port",
                        type=int,
                        default=9200,
                        help="Elasticsearch port (default: 9200)")
    
    parser.add_argument("--es-user",
                        default="elastic",
                        help="Elasticsearch username (default: elastic)")
    
    parser.add_argument("--es-password",
                        default="secureSIEMpassword123",
                        help="Elasticsearch password")
    
    parser.add_argument("--time-window",
                        type=int,
                        default=60,
                        help="Time window in minutes (default: 60)")
    
    parser.add_argument("--auth-threshold",
                        type=int,
                        default=3,
                        help="Authentication threshold for alerts (default: 3)")
    
    parser.add_argument("--webhook-url",
                        help="Webhook URL for notifications")
    
    parser.add_argument("--firewall-api",
                        help="Firewall API URL for blocking IPs")
    
    parser.add_argument("--case-system-url",
                        help="Case management system URL")
    
    args = parser.parse_args()
    
    # Create and run the detector
    detector = LateralMovementDetector(
        es_host=args.es_host,
        es_port=args.es_port,
        es_user=args.es_user,
        es_password=args.es_password,
        time_window=args.time_window,
        auth_threshold=args.auth_threshold,
        webhook_url=args.webhook_url,
        firewall_api=args.firewall_api,
        case_system_url=args.case_system_url
    )
    
    # Run the playbook
    results = detector.run_playbook()
    
    # Print results as JSON
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()