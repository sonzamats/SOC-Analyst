#!/usr/bin/env python3
"""
Automated Brute Force Response Playbook

This script implements an automated incident response playbook for brute force attacks.
It queries Elasticsearch for authentication failures, identifies potential brute force
attacks, and takes response actions such as blocking IPs and notifying stakeholders.

Author: SOC Analyst SIEM Project
Date: 2023-07-15
Version: 1.0
"""

import os
import sys
import json
import time
import logging
import argparse
import requests
import ipaddress
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("brute_force_response.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("BruteForceResponse")

class BruteForceResponse:
    """Class for automated brute force attack response"""
    
    def __init__(self, es_host="elasticsearch", es_port=9200, 
                 es_user="elastic", es_password="secureSIEMpassword123",
                 threshold=5, time_window=5, webhook_url=None, 
                 firewall_api=None, case_system_url=None):
        """Initialize the response playbook"""
        # Elasticsearch connection
        self.es = Elasticsearch(
            [f"http://{es_host}:{es_port}"],
            http_auth=(es_user, es_password)
        )
        
        # Detection thresholds
        self.threshold = threshold  # Number of failed attempts to trigger alert
        self.time_window = time_window  # Time window in minutes
        
        # Response endpoints
        self.webhook_url = webhook_url  # For notifications
        self.firewall_api = firewall_api  # For blocking
        self.case_system_url = case_system_url  # For case creation
        
        # Whitelist of IPs that should never be blocked
        self.ip_whitelist = self.load_whitelist()
        
        logger.info(f"Initialized brute force response playbook with threshold of {threshold} failures in {time_window} minutes")
    
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
        
        # Always include localhost and private IP ranges
        whitelist.add("127.0.0.1")
        whitelist.add("::1")
        
        return whitelist
    
    def is_private_ip(self, ip):
        """Check if IP is private/internal"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    def detect_brute_force(self, index="filebeat-*"):
        """Detect potential brute force attacks"""
        logger.info("Searching for potential brute force attacks")
        
        # Calculate time range
        now = datetime.utcnow()
        time_from = (now - timedelta(minutes=self.time_window)).isoformat()
        
        # Elasticsearch query to find authentication failures
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"match_phrase": {"event.outcome": "failure"}},
                        {"match_phrase": {"event.type": "authentication"}}
                    ]
                }
            },
            "aggs": {
                "source_ips": {
                    "terms": {
                        "field": "source.ip",
                        "size": 100,
                        "min_doc_count": self.threshold
                    },
                    "aggs": {
                        "targets": {
                            "terms": {
                                "field": "destination.ip",
                                "size": 10
                            }
                        },
                        "usernames": {
                            "terms": {
                                "field": "user.name",
                                "size": 10
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
            brute_force_candidates = []
            buckets = response.get("aggregations", {}).get("source_ips", {}).get("buckets", [])
            
            for bucket in buckets:
                source_ip = bucket.get("key", "")
                failure_count = bucket.get("doc_count", 0)
                
                # Skip if IP is in whitelist
                if source_ip in self.ip_whitelist or self.is_private_ip(source_ip):
                    logger.info(f"Skipping whitelisted/private IP: {source_ip} with {failure_count} failures")
                    continue
                
                # Get targeted systems
                targets = []
                for target_bucket in bucket.get("targets", {}).get("buckets", []):
                    targets.append({
                        "ip": target_bucket.get("key", ""),
                        "count": target_bucket.get("doc_count", 0)
                    })
                
                # Get targeted usernames
                usernames = []
                for user_bucket in bucket.get("usernames", {}).get("buckets", []):
                    usernames.append({
                        "name": user_bucket.get("key", ""),
                        "count": user_bucket.get("doc_count", 0)
                    })
                
                # Add to candidates list
                brute_force_candidates.append({
                    "source_ip": source_ip,
                    "failure_count": failure_count,
                    "targets": targets,
                    "usernames": usernames,
                    "time_window_minutes": self.time_window,
                    "detected_at": now.isoformat()
                })
            
            logger.info(f"Detected {len(brute_force_candidates)} potential brute force attacks")
            return brute_force_candidates
            
        except Exception as e:
            logger.error(f"Error searching Elasticsearch: {str(e)}")
            return []
    
    def block_ip(self, ip_address, duration=60, reason="Brute Force Attack"):
        """Block an IP address (through firewall API or other mechanism)"""
        if not self.firewall_api:
            logger.warning(f"No firewall API configured. Cannot block IP: {ip_address}")
            return False
        
        logger.info(f"Attempting to block IP {ip_address} for {duration} minutes")
        
        try:
            # Dummy implementation - replace with actual firewall API
            payload = {
                "ip": ip_address,
                "duration_minutes": duration,
                "reason": reason
            }
            
            response = requests.post(
                self.firewall_api,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully blocked IP {ip_address}")
                return True
            else:
                logger.error(f"Failed to block IP {ip_address}: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {str(e)}")
            return False
    
    def create_case(self, incident_data):
        """Create a case in the incident management system"""
        if not self.case_system_url:
            logger.warning("No case management system configured. Cannot create case.")
            return None
        
        logger.info(f"Creating case for brute force attack from {incident_data['source_ip']}")
        
        try:
            # Prepare case data
            case_data = {
                "title": f"Brute Force Attack from {incident_data['source_ip']}",
                "description": f"Detected brute force attack with {incident_data['failure_count']} failed login attempts within {incident_data['time_window_minutes']} minutes.",
                "severity": "Medium",
                "type": "Brute Force",
                "source": "SIEM",
                "tlp": "AMBER",
                "tags": ["brute-force", "authentication", "automated-response"],
                "artifacts": [
                    {
                        "type": "ip",
                        "value": incident_data['source_ip'],
                        "tags": ["attacker"]
                    }
                ],
                "tasks": [
                    {
                        "title": "Investigate source IP",
                        "status": "Pending",
                        "description": "Check reputation and historical activity of the source IP"
                    },
                    {
                        "title": "Review logs for successful compromise",
                        "status": "Pending",
                        "description": "Check if any successful logins occurred from this IP"
                    },
                    {
                        "title": "Update blocklist",
                        "status": "Pending",
                        "description": "Add IP to permanent blocklist if malicious"
                    }
                ]
            }
            
            # Add target systems to artifacts
            for target in incident_data.get("targets", []):
                case_data["artifacts"].append({
                    "type": "ip",
                    "value": target["ip"],
                    "tags": ["target"]
                })
            
            # Add target usernames to artifacts
            for user in incident_data.get("usernames", []):
                case_data["artifacts"].append({
                    "type": "username",
                    "value": user["name"],
                    "tags": ["target-account"]
                })
            
            # Send to case management system
            response = requests.post(
                self.case_system_url,
                json=case_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in (200, 201):
                case_id = response.json().get("id", "Unknown")
                logger.info(f"Successfully created case {case_id} for IP {incident_data['source_ip']}")
                return case_id
            else:
                logger.error(f"Failed to create case: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating case: {str(e)}")
            return None
    
    def send_notification(self, incident_data, case_id=None, block_successful=None):
        """Send notification to webhook (e.g., Slack, Teams, etc.)"""
        if not self.webhook_url:
            logger.warning("No webhook URL configured. Cannot send notification.")
            return False
        
        logger.info(f"Sending notification for brute force attack from {incident_data['source_ip']}")
        
        try:
            # Prepare notification message
            msg = {
                "summary": f"Brute Force Attack Detected from {incident_data['source_ip']}",
                "text": f"Detected {incident_data['failure_count']} failed login attempts from {incident_data['source_ip']} within {incident_data['time_window_minutes']} minutes.",
                "severity": "Medium",
                "source_ip": incident_data['source_ip'],
                "timestamp": datetime.now().isoformat(),
                "targets": incident_data.get("targets", []),
                "usernames": incident_data.get("usernames", []),
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
                logger.info(f"Successfully sent notification for IP {incident_data['source_ip']}")
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
                    "_index": "siem-brute-force-incidents"
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
        """Run the brute force response playbook end-to-end"""
        logger.info("Starting brute force response playbook")
        
        # Step 1: Detect brute force attempts
        incidents = self.detect_brute_force()
        
        if not incidents:
            logger.info("No brute force incidents detected. Playbook complete.")
            return []
        
        response_actions = []
        
        # Process each incident
        for incident in incidents:
            logger.info(f"Processing incident for source IP: {incident['source_ip']}")
            
            # Step 2: Block the IP
            blocked = self.block_ip(
                incident['source_ip'], 
                duration=60, 
                reason=f"Brute Force Attack: {incident['failure_count']} failures in {incident['time_window_minutes']} minutes"
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
        self.update_dashboards(incidents)
        
        logger.info(f"Brute force response playbook completed for {len(incidents)} incidents")
        return response_actions

def main():
    """Main function to run the brute force response playbook"""
    parser = argparse.ArgumentParser(description="Automated Brute Force Response Playbook")
    
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
    
    parser.add_argument("--threshold",
                        type=int,
                        default=5,
                        help="Failed login threshold (default: 5)")
    
    parser.add_argument("--time-window",
                        type=int,
                        default=5,
                        help="Time window in minutes (default: 5)")
    
    parser.add_argument("--webhook-url",
                        help="Webhook URL for notifications")
    
    parser.add_argument("--firewall-api",
                        help="Firewall API URL for blocking IPs")
    
    parser.add_argument("--case-system-url",
                        help="Case management system URL")
    
    args = parser.parse_args()
    
    # Create and run the response playbook
    response = BruteForceResponse(
        es_host=args.es_host,
        es_port=args.es_port,
        es_user=args.es_user,
        es_password=args.es_password,
        threshold=args.threshold,
        time_window=args.time_window,
        webhook_url=args.webhook_url,
        firewall_api=args.firewall_api,
        case_system_url=args.case_system_url
    )
    
    # Run the playbook
    results = response.run_playbook()
    
    # Print results as JSON
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()