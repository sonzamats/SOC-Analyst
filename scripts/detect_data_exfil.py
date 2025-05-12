#!/usr/bin/env python3
"""
Data Exfiltration Detection and Response Playbook

This script implements an automated detection and response system for potential
data exfiltration activities. It analyzes network traffic patterns to identify 
suspicious outbound data transfers and initiates response actions.

Author: SOC Analyst SIEM Project
Date: 2023-07-20
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
        logging.FileHandler("data_exfil_response.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DataExfilDetection")

class DataExfiltrationDetector:
    """Class for detecting and responding to data exfiltration"""
    
    def __init__(self, es_host="elasticsearch", es_port=9200, 
                 es_user="elastic", es_password="secureSIEMpassword123",
                 volume_threshold=100, time_window=60, 
                 frequency_threshold=1000, dns_query_threshold=50,
                 webhook_url=None, firewall_api=None, case_system_url=None):
        """Initialize the detector with configuration parameters"""
        # Elasticsearch connection
        self.es = Elasticsearch(
            [f"http://{es_host}:{es_port}"],
            http_auth=(es_user, es_password)
        )
        
        # Detection thresholds
        self.volume_threshold = volume_threshold  # MB per time window
        self.time_window = time_window  # Time window in minutes
        self.frequency_threshold = frequency_threshold  # Number of connections
        self.dns_query_threshold = dns_query_threshold  # DNS queries per time window
        
        # Response endpoints
        self.webhook_url = webhook_url  # For notifications
        self.firewall_api = firewall_api  # For blocking
        self.case_system_url = case_system_url  # For case creation
        
        # Whitelist of IPs and domains that should never be blocked
        self.ip_whitelist = self.load_whitelist()
        self.domain_whitelist = self.load_domain_whitelist()
        
        logger.info(f"Initialized data exfiltration detector with volume threshold of {volume_threshold}MB in {time_window} minutes")
    
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
        
        # Always include localhost and common services
        whitelist.add("127.0.0.1")
        whitelist.add("::1")
        
        return whitelist
    
    def load_domain_whitelist(self, whitelist_file="domain_whitelist.txt"):
        """Load domain whitelist from a file"""
        whitelist = set()
        try:
            if os.path.exists(whitelist_file):
                with open(whitelist_file, "r") as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith("#"):
                            whitelist.add(domain)
                logger.info(f"Loaded {len(whitelist)} domains in whitelist from {whitelist_file}")
            else:
                logger.warning(f"Domain whitelist file {whitelist_file} not found. Using default whitelist.")
                # Add default trusted domains
                default_domains = [
                    "google.com", "microsoft.com", "amazon.com", "amazonaws.com", 
                    "github.com", "office365.com", "live.com", "apple.com"
                ]
                whitelist.update(default_domains)
        except Exception as e:
            logger.error(f"Error loading domain whitelist: {str(e)}")
        
        return whitelist
    
    def is_private_ip(self, ip):
        """Check if IP is private/internal"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    def detect_volume_exfiltration(self, index="packetbeat-*"):
        """Detect potential data exfiltration based on volume"""
        logger.info("Searching for high volume data transfers")
        
        # Calculate time range
        now = datetime.utcnow()
        time_from = (now - timedelta(minutes=self.time_window)).isoformat()
        
        # Elasticsearch query for high volume outbound traffic
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"term": {"network.direction": "outbound"}}
                    ],
                    "must_not": [
                        {"terms": {"destination.ip": list(self.ip_whitelist)}}
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
                        "by_destination": {
                            "terms": {
                                "field": "destination.ip",
                                "size": 100
                            },
                            "aggs": {
                                "total_bytes": {
                                    "sum": {
                                        "field": "network.bytes"
                                    }
                                }
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
            exfil_candidates = []
            
            # Check each source IP
            for source_bucket in response.get("aggregations", {}).get("by_source", {}).get("buckets", []):
                source_ip = source_bucket.get("key", "")
                
                # Check destinations for this source
                for dest_bucket in source_bucket.get("by_destination", {}).get("buckets", []):
                    dest_ip = dest_bucket.get("key", "")
                    total_bytes = dest_bucket.get("total_bytes", {}).get("value", 0)
                    
                    # Convert bytes to MB
                    total_mb = total_bytes / (1024 * 1024)
                    
                    # If exceeds threshold, add to candidates
                    if total_mb > self.volume_threshold and not self.is_private_ip(dest_ip):
                        exfil_candidates.append({
                            "source_ip": source_ip,
                            "destination_ip": dest_ip,
                            "total_mb": total_mb,
                            "time_window_minutes": self.time_window,
                            "detection_type": "high_volume",
                            "detected_at": now.isoformat()
                        })
            
            logger.info(f"Detected {len(exfil_candidates)} potential volume-based exfiltration attempts")
            return exfil_candidates
            
        except Exception as e:
            logger.error(f"Error searching Elasticsearch for volume exfil: {str(e)}")
            return []
    
    def detect_frequency_exfiltration(self, index="packetbeat-*"):
        """Detect potential data exfiltration based on connection frequency"""
        logger.info("Searching for high frequency connections")
        
        # Calculate time range
        now = datetime.utcnow()
        time_from = (now - timedelta(minutes=self.time_window)).isoformat()
        
        # Elasticsearch query for high frequency outbound connections
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"term": {"network.direction": "outbound"}}
                    ],
                    "must_not": [
                        {"terms": {"destination.ip": list(self.ip_whitelist)}}
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
                        "by_destination": {
                            "terms": {
                                "field": "destination.ip",
                                "size": 100
                            },
                            "aggs": {
                                "connection_count": {
                                    "value_count": {
                                        "field": "_id"
                                    }
                                }
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
            exfil_candidates = []
            
            # Check each source IP
            for source_bucket in response.get("aggregations", {}).get("by_source", {}).get("buckets", []):
                source_ip = source_bucket.get("key", "")
                
                # Check destinations for this source
                for dest_bucket in source_bucket.get("by_destination", {}).get("buckets", []):
                    dest_ip = dest_bucket.get("key", "")
                    connection_count = dest_bucket.get("connection_count", {}).get("value", 0)
                    
                    # If exceeds threshold, add to candidates
                    if connection_count > self.frequency_threshold and not self.is_private_ip(dest_ip):
                        exfil_candidates.append({
                            "source_ip": source_ip,
                            "destination_ip": dest_ip,
                            "connection_count": connection_count,
                            "time_window_minutes": self.time_window,
                            "detection_type": "high_frequency",
                            "detected_at": now.isoformat()
                        })
            
            logger.info(f"Detected {len(exfil_candidates)} potential frequency-based exfiltration attempts")
            return exfil_candidates
            
        except Exception as e:
            logger.error(f"Error searching Elasticsearch for frequency exfil: {str(e)}")
            return []
    
    def detect_dns_exfiltration(self, index="packetbeat-*"):
        """Detect potential DNS tunneling/exfiltration"""
        logger.info("Searching for potential DNS tunneling")
        
        # Calculate time range
        now = datetime.utcnow()
        time_from = (now - timedelta(minutes=self.time_window)).isoformat()
        
        # Elasticsearch query for suspicious DNS activity
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"term": {"network.protocol": "dns"}}
                    ],
                    "must_not": [
                        {"terms": {"dns.question.name": list(self.domain_whitelist)}}
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
                        "by_domain": {
                            "terms": {
                                "field": "dns.question.name",
                                "size": 100
                            },
                            "aggs": {
                                "query_count": {
                                    "value_count": {
                                        "field": "_id"
                                    }
                                },
                                "avg_query_length": {
                                    "avg": {
                                        "script": {
                                            "source": "doc['dns.question.name'].value.length()"
                                        }
                                    }
                                }
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
            exfil_candidates = []
            
            # Check each source IP
            for source_bucket in response.get("aggregations", {}).get("by_source", {}).get("buckets", []):
                source_ip = source_bucket.get("key", "")
                
                # Check domains for this source
                for domain_bucket in source_bucket.get("by_domain", {}).get("buckets", []):
                    domain = domain_bucket.get("key", "")
                    query_count = domain_bucket.get("query_count", {}).get("value", 0)
                    avg_length = domain_bucket.get("avg_query_length", {}).get("value", 0)
                    
                    # If exceeds threshold and has long average query length, add to candidates
                    if query_count > self.dns_query_threshold and avg_length > 30:
                        exfil_candidates.append({
                            "source_ip": source_ip,
                            "domain": domain,
                            "query_count": query_count,
                            "avg_query_length": avg_length,
                            "time_window_minutes": self.time_window,
                            "detection_type": "dns_tunneling",
                            "detected_at": now.isoformat()
                        })
            
            logger.info(f"Detected {len(exfil_candidates)} potential DNS exfiltration attempts")
            return exfil_candidates
            
        except Exception as e:
            logger.error(f"Error searching Elasticsearch for DNS exfil: {str(e)}")
            return []
    
    def block_communication(self, source_ip, destination, duration=60, reason="Data Exfiltration"):
        """Block communication between source and destination"""
        if not self.firewall_api:
            logger.warning(f"No firewall API configured. Cannot block communication from {source_ip} to {destination}")
            return False
        
        logger.info(f"Attempting to block communication from {source_ip} to {destination} for {duration} minutes")
        
        try:
            # Payload depends on whether destination is IP or domain
            payload = {
                "source_ip": source_ip,
                "duration_minutes": duration,
                "reason": reason
            }
            
            # Add destination - could be IP or domain
            if "." in destination and any(c.isalpha() for c in destination):
                payload["destination_domain"] = destination
            else:
                payload["destination_ip"] = destination
            
            # Send to firewall API
            response = requests.post(
                self.firewall_api,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully blocked communication from {source_ip} to {destination}")
                return True
            else:
                logger.error(f"Failed to block communication: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking communication: {str(e)}")
            return False
    
    def create_case(self, incident_data):
        """Create a case in the incident management system"""
        if not self.case_system_url:
            logger.warning("No case management system configured. Cannot create case.")
            return None
        
        detection_type = incident_data.get('detection_type', 'unknown')
        source_ip = incident_data.get('source_ip', 'unknown')
        
        if detection_type == "dns_tunneling":
            destination = incident_data.get('domain', 'unknown_domain')
        else:
            destination = incident_data.get('destination_ip', 'unknown_destination')
        
        logger.info(f"Creating case for {detection_type} exfiltration from {source_ip} to {destination}")
        
        try:
            # Prepare case data based on detection type
            if detection_type == "high_volume":
                title = f"High Volume Data Transfer: {source_ip} to {destination}"
                description = f"Detected {incident_data.get('total_mb', 0):.2f} MB of data transferred from {source_ip} to {destination} within {incident_data.get('time_window_minutes', 60)} minutes."
            elif detection_type == "high_frequency":
                title = f"High Frequency Connections: {source_ip} to {destination}"
                description = f"Detected {incident_data.get('connection_count', 0)} connections from {source_ip} to {destination} within {incident_data.get('time_window_minutes', 60)} minutes."
            elif detection_type == "dns_tunneling":
                title = f"Potential DNS Tunneling: {source_ip} to {destination}"
                description = f"Detected {incident_data.get('query_count', 0)} DNS queries from {source_ip} to {destination} with average query length of {incident_data.get('avg_query_length', 0):.2f} characters."
            else:
                title = f"Potential Data Exfiltration: {source_ip}"
                description = f"Detected suspicious data transfer activity from {source_ip}."
            
            # Common case data
            case_data = {
                "title": title,
                "description": description,
                "severity": "High",
                "type": "Data Exfiltration",
                "source": "SIEM",
                "tlp": "AMBER",
                "tags": ["data-exfiltration", "automated-response"],
                "artifacts": [
                    {
                        "type": "ip",
                        "value": source_ip,
                        "tags": ["source"]
                    }
                ],
                "tasks": [
                    {
                        "title": "Validate exfiltration attempt",
                        "status": "Pending",
                        "description": "Investigate if this is a genuine data exfiltration attempt or false positive"
                    },
                    {
                        "title": "Identify compromised data",
                        "status": "Pending",
                        "description": "Determine what data may have been exfiltrated"
                    },
                    {
                        "title": "Investigate source system",
                        "status": "Pending",
                        "description": "Check for compromise, malware, or insider threat on the source system"
                    },
                    {
                        "title": "Verify blocking effectiveness",
                        "status": "Pending",
                        "description": "Confirm that blocking measures have been effective in stopping the exfiltration"
                    }
                ]
            }
            
            # Add appropriate destination to artifacts
            if detection_type == "dns_tunneling":
                case_data["artifacts"].append({
                    "type": "domain",
                    "value": destination,
                    "tags": ["destination"]
                })
            else:
                case_data["artifacts"].append({
                    "type": "ip",
                    "value": destination,
                    "tags": ["destination"]
                })
            
            # Send to case management system
            response = requests.post(
                self.case_system_url,
                json=case_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in (200, 201):
                case_id = response.json().get("id", "Unknown")
                logger.info(f"Successfully created case {case_id} for exfiltration from {source_ip}")
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
        
        detection_type = incident_data.get('detection_type', 'unknown')
        source_ip = incident_data.get('source_ip', 'unknown')
        
        if detection_type == "dns_tunneling":
            destination = incident_data.get('domain', 'unknown_domain')
        else:
            destination = incident_data.get('destination_ip', 'unknown_destination')
        
        logger.info(f"Sending notification for {detection_type} exfiltration from {source_ip} to {destination}")
        
        try:
            # Prepare notification message
            if detection_type == "high_volume":
                title = f"High Volume Data Transfer Detected"
                details = f"{incident_data.get('total_mb', 0):.2f} MB transferred from {source_ip} to {destination}"
            elif detection_type == "high_frequency":
                title = f"High Frequency Connections Detected"
                details = f"{incident_data.get('connection_count', 0)} connections from {source_ip} to {destination}"
            elif detection_type == "dns_tunneling":
                title = f"Potential DNS Tunneling Detected"
                details = f"{incident_data.get('query_count', 0)} DNS queries with avg length {incident_data.get('avg_query_length', 0):.2f}"
            else:
                title = f"Potential Data Exfiltration Detected"
                details = f"Suspicious activity from {source_ip} to {destination}"
            
            # Common notification data
            msg = {
                "summary": title,
                "text": f"ALERT: {details} within {incident_data.get('time_window_minutes', 60)} minutes.",
                "severity": "High",
                "source_ip": source_ip,
                "destination": destination,
                "timestamp": datetime.now().isoformat(),
                "detection_type": detection_type
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
                logger.info(f"Successfully sent notification for exfiltration from {source_ip}")
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
                    "_index": "siem-data-exfil-incidents"
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
        """Run the data exfiltration detection and response playbook"""
        logger.info("Starting data exfiltration detection playbook")
        
        # Step 1: Detect potential exfiltration using different methods
        volume_incidents = self.detect_volume_exfiltration()
        frequency_incidents = self.detect_frequency_exfiltration()
        dns_incidents = self.detect_dns_exfiltration()
        
        # Combine all incidents
        all_incidents = volume_incidents + frequency_incidents + dns_incidents
        
        if not all_incidents:
            logger.info("No data exfiltration incidents detected. Playbook complete.")
            return []
        
        response_actions = []
        
        # Process each incident
        for incident in all_incidents:
            detection_type = incident.get('detection_type', 'unknown')
            source_ip = incident.get('source_ip', 'unknown')
            
            if detection_type == "dns_tunneling":
                destination = incident.get('domain', 'unknown_domain')
            else:
                destination = incident.get('destination_ip', 'unknown_destination')
            
            logger.info(f"Processing {detection_type} incident from {source_ip} to {destination}")
            
            # Step 2: Block the communication
            blocked = self.block_communication(
                source_ip, 
                destination, 
                duration=120, 
                reason=f"Data Exfiltration: {detection_type}"
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
        
        logger.info(f"Data exfiltration response playbook completed for {len(all_incidents)} incidents")
        return response_actions

def main():
    """Main function to run the data exfiltration detection playbook"""
    parser = argparse.ArgumentParser(description="Data Exfiltration Detection and Response Playbook")
    
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
    
    parser.add_argument("--volume-threshold",
                        type=int,
                        default=100,
                        help="Volume threshold in MB (default: 100)")
    
    parser.add_argument("--time-window",
                        type=int,
                        default=60,
                        help="Time window in minutes (default: 60)")
    
    parser.add_argument("--frequency-threshold",
                        type=int,
                        default=1000,
                        help="Connection frequency threshold (default: 1000)")
    
    parser.add_argument("--dns-threshold",
                        type=int,
                        default=50,
                        help="DNS query threshold (default: 50)")
    
    parser.add_argument("--webhook-url",
                        help="Webhook URL for notifications")
    
    parser.add_argument("--firewall-api",
                        help="Firewall API URL for blocking communications")
    
    parser.add_argument("--case-system-url",
                        help="Case management system URL")
    
    args = parser.parse_args()
    
    # Create and run the detector
    detector = DataExfiltrationDetector(
        es_host=args.es_host,
        es_port=args.es_port,
        es_user=args.es_user,
        es_password=args.es_password,
        volume_threshold=args.volume_threshold,
        time_window=args.time_window,
        frequency_threshold=args.frequency_threshold,
        dns_query_threshold=args.dns_threshold,
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