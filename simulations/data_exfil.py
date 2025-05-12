#!/usr/bin/env python3
"""
Data Exfiltration Simulation Script

This script simulates various data exfiltration scenarios to test detection
capabilities of the SOC SIEM Implementation.

Author: SOC Analyst SIEM Project
Date: 2023-07-22
Version: 1.0
"""

import os
import sys
import json
import time
import random
import socket
import logging
import argparse
import ipaddress
import requests
import dns.resolver
from datetime import datetime
from scapy.all import IP, TCP, UDP, DNS, DNSQR, send, sr1, Raw, Ether

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DataExfilSimulator")

class DataExfiltrationSimulator:
    """Class for simulating different data exfiltration techniques"""
    
    def __init__(self, source_ip=None, destination=None, duration=10, 
                 technique="http", volume="medium", logstash_url=None):
        """Initialize the simulator with configuration parameters"""
        
        # If no source IP provided, use the primary interface IP
        if source_ip is None:
            self.source_ip = self.get_local_ip()
        else:
            self.source_ip = source_ip
            
        # If no destination provided, generate or use default based on technique
        if destination is None:
            if "dns" in technique:
                self.destination = "exfil.example.com"
            else:
                self.destination = self.generate_random_ip(private=False)
        else:
            self.destination = destination
            
        # Attack duration in minutes
        self.duration = duration
        
        # Exfiltration technique
        self.technique = technique
        
        # Volume/intensity of exfiltration
        volume_map = {
            "low": {"size_mb": (1, 5), "frequency": (10, 30)},
            "medium": {"size_mb": (10, 50), "frequency": (50, 100)},
            "high": {"size_mb": (100, 500), "frequency": (200, 500)}
        }
        self.volume = volume_map.get(volume.lower(), volume_map["medium"])
        
        # Logstash URL for sending logs
        self.logstash_url = logstash_url
        
        logger.info(f"Initialized data exfiltration simulation from {self.source_ip} to {self.destination}")
        logger.info(f"Technique: {technique}, Duration: {duration} minutes, Volume: {volume}")
    
    def get_local_ip(self):
        """Get the primary interface IP of this host"""
        try:
            # Create a socket to determine primary interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # This doesn't actually establish a connection
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.error(f"Error determining local IP: {str(e)}")
            return "127.0.0.1"
    
    def generate_random_ip(self, private=False):
        """Generate a random IP address"""
        if private:
            # Generate a private IP from common ranges
            private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            chosen_range = random.choice(private_ranges)
            chosen_network = ipaddress.IPv4Network(chosen_range)
            random_int = random.randint(0, chosen_network.num_addresses - 1)
            ip = chosen_network[random_int]
        else:
            # Generate a public IP (avoiding reserved ranges)
            while True:
                octets = [random.randint(1, 254) for _ in range(4)]
                ip = ".".join(str(o) for o in octets)
                addr = ipaddress.IPv4Address(ip)
                if not addr.is_private and not addr.is_reserved:
                    break
        return str(ip)
    
    def generate_data(self, size_kb):
        """Generate random data of specified size in KB"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return ''.join(random.choice(chars) for _ in range(size_kb * 1024))
    
    def generate_http_log(self, timestamp, size_kb, status_code=200):
        """Generate an HTTP exfiltration log entry"""
        hostname = socket.gethostname()
        url_paths = [
            "/api/data", "/upload", "/files/transfer", 
            "/backup", "/sync", "/data_export"
        ]
        url_path = random.choice(url_paths)
        log_message = f"{timestamp.isoformat()} {hostname} HTTP POST {url_path} to {self.destination} - {size_kb}KB transferred - Status: {status_code}"
        
        # Create structured log for Logstash
        structured_log = {
            "@timestamp": timestamp.isoformat(),
            "host": {
                "name": hostname
            },
            "source": {
                "ip": self.source_ip,
                "port": random.randint(30000, 65000)
            },
            "destination": {
                "ip": self.destination,
                "port": 443 if self.technique == "https" else 80
            },
            "network": {
                "protocol": "http",
                "bytes": size_kb * 1024,
                "direction": "outbound"
            },
            "http": {
                "request": {
                    "method": "POST",
                    "body": {
                        "bytes": size_kb * 1024
                    }
                },
                "response": {
                    "status_code": status_code
                }
            },
            "url": {
                "full": f"http{'s' if self.technique == 'https' else ''}://{self.destination}{url_path}"
            },
            "message": log_message
        }
        
        return log_message, structured_log
    
    def generate_dns_log(self, timestamp, query_length):
        """Generate a DNS tunneling log entry"""
        hostname = socket.gethostname()
        random_prefix = ''.join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(query_length))
        query = f"{random_prefix}.{self.destination}"
        
        log_message = f"{timestamp.isoformat()} {hostname} DNS query {query} from {self.source_ip}"
        
        # Create structured log for Logstash
        structured_log = {
            "@timestamp": timestamp.isoformat(),
            "host": {
                "name": hostname
            },
            "source": {
                "ip": self.source_ip,
                "port": random.randint(30000, 65000)
            },
            "destination": {
                "ip": "8.8.8.8",  # Typical DNS server
                "port": 53
            },
            "network": {
                "protocol": "dns",
                "bytes": len(query) + 20,  # Approximate DNS packet size
                "direction": "outbound"
            },
            "dns": {
                "question": {
                    "name": query,
                    "type": "A"
                },
                "response_code": "NOERROR"
            },
            "message": log_message
        }
        
        return log_message, structured_log
    
    def generate_ftp_log(self, timestamp, size_kb):
        """Generate an FTP exfiltration log entry"""
        hostname = socket.gethostname()
        files = ["customer_data.csv", "financial_records.xls", "passwords.txt", "source_code.zip", "database_backup.sql"]
        filename = random.choice(files)
        
        log_message = f"{timestamp.isoformat()} {hostname} FTP PUT {filename} to {self.destination} - {size_kb}KB transferred"
        
        # Create structured log for Logstash
        structured_log = {
            "@timestamp": timestamp.isoformat(),
            "host": {
                "name": hostname
            },
            "source": {
                "ip": self.source_ip,
                "port": random.randint(30000, 65000)
            },
            "destination": {
                "ip": self.destination,
                "port": 21
            },
            "network": {
                "protocol": "ftp",
                "bytes": size_kb * 1024,
                "direction": "outbound"
            },
            "ftp": {
                "command": "PUT",
                "file": {
                    "name": filename,
                    "size": size_kb * 1024
                }
            },
            "message": log_message
        }
        
        return log_message, structured_log
    
    def send_to_logstash(self, log_data):
        """Send log data to Logstash"""
        if not self.logstash_url:
            return False
        
        try:
            response = requests.post(
                self.logstash_url,
                data=json.dumps(log_data),
                headers={"Content-Type": "application/json"}
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error sending log to Logstash: {str(e)}")
            return False
    
    def write_to_file(self, log_message, filename="data_exfil_logs.txt"):
        """Write log message to a file"""
        try:
            with open(filename, "a") as f:
                f.write(log_message + "\n")
            return True
        except Exception as e:
            logger.error(f"Error writing to file: {str(e)}")
            return False
    
    def simulate_http_exfiltration(self):
        """Simulate HTTP-based data exfiltration"""
        logger.info(f"Starting HTTP{'S' if self.technique == 'https' else ''} exfiltration simulation")
        
        # Calculate end time
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=self.duration)
        
        # Total data volume to exfiltrate (in MB)
        size_mb_range = self.volume["size_mb"]
        total_mb = random.uniform(size_mb_range[0], size_mb_range[1])
        total_kb = int(total_mb * 1024)
        
        # Frequency range (transfers per minute)
        frequency_range = self.volume["frequency"]
        frequency = random.randint(frequency_range[0], frequency_range[1])
        
        # Size of each transfer
        transfer_size_kb = max(1, int(total_kb / (frequency * self.duration)))
        
        logger.info(f"Simulating exfiltration of {total_mb:.2f}MB in chunks of {transfer_size_kb}KB")
        logger.info(f"Frequency: ~{frequency} transfers per minute")
        
        # Track statistics
        successful_transfers = 0
        total_size_kb = 0
        
        # Simulate the exfiltration until the duration is over
        current_time = start_time
        while current_time < end_time:
            # Time between transfers in seconds
            time_between = 60 / frequency
            
            # Generate and log the transfer
            log_message, structured_log = self.generate_http_log(current_time, transfer_size_kb)
            
            # Write to file
            self.write_to_file(log_message)
            
            # Send to Logstash if URL provided
            if self.logstash_url:
                self.send_to_logstash(structured_log)
            
            # Update statistics
            successful_transfers += 1
            total_size_kb += transfer_size_kb
            
            # Display progress
            if successful_transfers % 10 == 0:
                logger.info(f"Generated {successful_transfers} transfers, {total_size_kb/1024:.2f}MB total")
            
            # Increment the current time
            current_time += timedelta(seconds=time_between)
            
            # Sleep briefly to simulate real-time behavior
            time.sleep(min(time_between, 0.1))
        
        logger.info(f"HTTP exfiltration simulation completed. Generated {successful_transfers} transfers, {total_size_kb/1024:.2f}MB total")
        
        # Return a summary of the simulation
        return {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_minutes": self.duration,
            "source_ip": self.source_ip,
            "destination": self.destination,
            "technique": self.technique,
            "transfers": successful_transfers,
            "total_size_mb": total_size_kb / 1024
        }
    
    def simulate_dns_tunneling(self):
        """Simulate DNS tunneling exfiltration"""
        logger.info(f"Starting DNS tunneling simulation")
        
        # Calculate end time
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=self.duration)
        
        # Number of queries per minute
        frequency_range = self.volume["frequency"]
        frequency = random.randint(frequency_range[0], frequency_range[1])
        
        # Query length for data exfiltration
        query_length = random.randint(30, 60)  # Bytes per query
        
        logger.info(f"Simulating DNS tunneling with {frequency} queries per minute")
        logger.info(f"Query length: {query_length} bytes")
        
        # Track statistics
        total_queries = 0
        total_bytes = 0
        
        # Simulate the DNS tunneling until the duration is over
        current_time = start_time
        while current_time < end_time:
            # Time between queries in seconds
            time_between = 60 / frequency
            
            # Generate and log the DNS query
            log_message, structured_log = self.generate_dns_log(current_time, query_length)
            
            # Write to file
            self.write_to_file(log_message)
            
            # Send to Logstash if URL provided
            if self.logstash_url:
                self.send_to_logstash(structured_log)
            
            # Update statistics
            total_queries += 1
            total_bytes += query_length
            
            # Display progress
            if total_queries % 50 == 0:
                logger.info(f"Generated {total_queries} DNS queries, {total_bytes/1024:.2f}KB total")
            
            # Increment the current time
            current_time += timedelta(seconds=time_between)
            
            # Sleep briefly to simulate real-time behavior
            time.sleep(min(time_between, 0.05))
        
        logger.info(f"DNS tunneling simulation completed. Generated {total_queries} queries, {total_bytes/1024:.2f}KB total")
        
        # Return a summary of the simulation
        return {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_minutes": self.duration,
            "source_ip": self.source_ip,
            "destination": self.destination,
            "technique": self.technique,
            "total_queries": total_queries,
            "total_size_kb": total_bytes / 1024
        }
    
    def simulate_ftp_exfiltration(self):
        """Simulate FTP-based data exfiltration"""
        logger.info(f"Starting FTP exfiltration simulation")
        
        # Calculate end time
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=self.duration)
        
        # Total data volume to exfiltrate (in MB)
        size_mb_range = self.volume["size_mb"]
        total_mb = random.uniform(size_mb_range[0], size_mb_range[1])
        total_kb = int(total_mb * 1024)
        
        # Frequency range (transfers per minute)
        frequency_range = self.volume["frequency"]
        frequency = random.randint(frequency_range[0], frequency_range[1])
        
        # Size of each transfer
        transfer_size_kb = max(1, int(total_kb / (frequency * self.duration)))
        
        logger.info(f"Simulating FTP exfiltration of {total_mb:.2f}MB in chunks of {transfer_size_kb}KB")
        logger.info(f"Frequency: ~{frequency} transfers per minute")
        
        # Track statistics
        successful_transfers = 0
        total_size_kb = 0
        
        # Simulate the exfiltration until the duration is over
        current_time = start_time
        while current_time < end_time:
            # Time between transfers in seconds
            time_between = 60 / frequency
            
            # Generate and log the transfer
            log_message, structured_log = self.generate_ftp_log(current_time, transfer_size_kb)
            
            # Write to file
            self.write_to_file(log_message)
            
            # Send to Logstash if URL provided
            if self.logstash_url:
                self.send_to_logstash(structured_log)
            
            # Update statistics
            successful_transfers += 1
            total_size_kb += transfer_size_kb
            
            # Display progress
            if successful_transfers % 10 == 0:
                logger.info(f"Generated {successful_transfers} transfers, {total_size_kb/1024:.2f}MB total")
            
            # Increment the current time
            current_time += timedelta(seconds=time_between)
            
            # Sleep briefly to simulate real-time behavior
            time.sleep(min(time_between, 0.1))
        
        logger.info(f"FTP exfiltration simulation completed. Generated {successful_transfers} transfers, {total_size_kb/1024:.2f}MB total")
        
        # Return a summary of the simulation
        return {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_minutes": self.duration,
            "source_ip": self.source_ip,
            "destination": self.destination,
            "technique": self.technique,
            "transfers": successful_transfers,
            "total_size_mb": total_size_kb / 1024
        }
    
    def run_simulation(self):
        """Run the data exfiltration simulation"""
        logger.info("Starting data exfiltration simulation")
        
        # Run the appropriate simulation based on technique
        if self.technique == "http" or self.technique == "https":
            results = self.simulate_http_exfiltration()
        elif self.technique == "dns" or self.technique == "dns-tunneling":
            results = self.simulate_dns_tunneling()
        elif self.technique == "ftp":
            results = self.simulate_ftp_exfiltration()
        else:
            logger.error(f"Unsupported exfiltration technique: {self.technique}")
            results = {"error": f"Unsupported exfiltration technique: {self.technique}"}
        
        return results

def main():
    """Main function to run the data exfiltration simulator"""
    parser = argparse.ArgumentParser(description="Simulate data exfiltration attacks")
    
    parser.add_argument("--source", "-s", 
                        help="Source IP address (default: auto-detect)")
    
    parser.add_argument("--destination", "-d",
                        help="Destination IP or domain (default: random based on technique)")
    
    parser.add_argument("--technique", "-t",
                        choices=["http", "https", "dns", "dns-tunneling", "ftp"],
                        default="http",
                        help="Exfiltration technique (default: http)")
    
    parser.add_argument("--duration",
                        type=int,
                        default=10,
                        help="Simulation duration in minutes (default: 10)")
    
    parser.add_argument("--volume", "-v",
                        choices=["low", "medium", "high"],
                        default="medium",
                        help="Volume of data to exfiltrate (default: medium)")
    
    parser.add_argument("--logstash", "-l",
                        help="Logstash URL to send logs (e.g., http://localhost:5000)")
    
    args = parser.parse_args()
    
    # Create and run the simulator
    simulator = DataExfiltrationSimulator(
        source_ip=args.source,
        destination=args.destination,
        duration=args.duration,
        technique=args.technique,
        volume=args.volume,
        logstash_url=args.logstash
    )
    
    # Run the simulation
    summary = simulator.run_simulation()
    
    # Print the summary as JSON
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    from datetime import timedelta
    main()