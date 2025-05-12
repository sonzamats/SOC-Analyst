#!/usr/bin/env python3
"""
Lateral Movement Simulation Script

This script simulates different lateral movement techniques across a network to
test detection capabilities of the SOC SIEM Implementation.

Author: SOC Analyst SIEM Project
Date: 2023-07-26
Version: 1.0
"""

import os
import sys
import json
import time
import random
import socket
import ipaddress
import argparse
import logging
import requests
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("LateralMovementSimulator")

class LateralMovementSimulator:
    """Class for simulating lateral movement across network hosts"""
    
    def __init__(self, source_ip=None, target_count=3, technique="all", 
                 duration=10, intensity="medium", logstash_url=None):
        """Initialize the simulator with configuration parameters"""
        
        # If no source IP provided, use the primary interface IP
        if source_ip is None:
            self.source_ip = self.get_local_ip()
        else:
            self.source_ip = source_ip
            
        # Number of target hosts to include in the simulation
        self.target_count = target_count
        
        # Generate target hosts
        self.target_hosts = self.generate_target_hosts(target_count)
        
        # Simulation duration in minutes
        self.duration = duration
        
        # Lateral movement technique to simulate
        self.technique = technique.lower()
        
        # Intensity of simulation (affects frequency of events)
        intensity_map = {
            "low": {"auth_freq": (1, 3), "tool_freq": (1, 2), "conn_freq": (3, 8)},
            "medium": {"auth_freq": (3, 8), "tool_freq": (2, 5), "conn_freq": (8, 15)},
            "high": {"auth_freq": (8, 20), "tool_freq": (5, 15), "conn_freq": (15, 30)}
        }
        self.intensity = intensity_map.get(intensity.lower(), intensity_map["medium"])
        
        # Logstash URL for sending logs
        self.logstash_url = logstash_url
        
        # Admin users that might be used for lateral movement
        self.admin_users = [
            "administrator", "admin", "system", "root", "superuser", "sysadmin", 
            "netadmin", "secadmin", "backup", "domain-admin"
        ]
        
        # Admin tools often used in lateral movement
        self.admin_tools = [
            "psexec.exe", "wmic.exe", "powershell.exe", "wmiexec.py", "mimikatz.exe", 
            "paexec.exe", "atexec.py", "smbexec.py", "ssh.exe", "pth-winexe"
        ]
        
        # Remote access ports
        self.remote_ports = [22, 23, 135, 139, 445, 3389, 5985, 5986]
        
        logger.info(f"Initialized lateral movement simulation from {self.source_ip}")
        logger.info(f"Targeting {len(self.target_hosts)} hosts with {self.technique} technique")
        logger.info(f"Duration: {duration} minutes, Intensity: {intensity}")
    
    def get_local_ip(self):
        """Get the primary interface IP of this host"""
        try:
            # Create a socket to determine primary interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.error(f"Error determining local IP: {str(e)}")
            return "127.0.0.1"
    
    def generate_target_hosts(self, count):
        """Generate a list of target hosts"""
        hosts = []
        
        # Generate random hostnames
        host_prefixes = ["srv", "ws", "pc", "dc", "app", "db", "web", "mail", "file", "print"]
        host_suffixes = ["", "-01", "-02", "-prod", "-dev", "-test", "-corp", "-dmz"]
        domains = [".local", ".corp", ".internal", ".example.com", ".test"]
        
        # Generate random IP addresses (in the same subnet as source if possible)
        try:
            source_network = ".".join(self.source_ip.split(".")[:3]) + "."
        except:
            source_network = "192.168.1."
            
        # Create hosts with names and IPs
        for i in range(count):
            prefix = random.choice(host_prefixes)
            suffix = random.choice(host_suffixes)
            domain = random.choice(domains)
            hostname = f"{prefix}{suffix}{domain}"
            
            # Generate IP - try to keep in same subnet as source
            if random.random() < 0.8:  # 80% chance to stay in same subnet
                last_octet = random.randint(1, 254)
                ip = f"{source_network}{last_octet}"
            else:
                # Generate a completely random internal IP
                ip = self.generate_random_internal_ip()
            
            # Operating system selection
            os_types = ["Windows Server 2019", "Windows 10", "Windows Server 2016",
                        "Linux Ubuntu 20.04", "Linux CentOS 7", "Windows Server 2012 R2"]
            os_type = random.choice(os_types)
            
            hosts.append({
                "hostname": hostname,
                "ip": ip,
                "os": os_type,
                "criticality": random.choice(["low", "medium", "high"])
            })
        
        return hosts
    
    def generate_random_internal_ip(self):
        """Generate a random internal IP address"""
        private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        chosen_range = random.choice(private_ranges)
        network = ipaddress.IPv4Network(chosen_range)
        random_int = random.randint(0, min(network.num_addresses - 1, 10000))  # Limit to avoid huge calculations
        return str(network[random_int])

    def generate_auth_log(self, timestamp, username, target_host, status="success"):
        """Generate an authentication log entry"""
        hostname = socket.gethostname()
        auth_method = random.choice(["password", "kerberos", "ntlm", "ssh-key", "oauth"])
        
        log_message = f"{timestamp.isoformat()} {hostname} Authentication: User {username} authenticated to {target_host['hostname']} ({target_host['ip']}) via {auth_method} - Status: {status}"
        
        # Create structured log for Logstash
        structured_log = {
            "@timestamp": timestamp.isoformat(),
            "host": {
                "name": hostname,
                "ip": self.source_ip
            },
            "user": {
                "name": username
            },
            "source": {
                "ip": self.source_ip
            },
            "destination": {
                "ip": target_host['ip'],
                "host": target_host['hostname']
            },
            "event": {
                "category": "authentication",
                "type": "start",
                "outcome": status,
                "action": "logon"
            },
            "authentication": {
                "method": auth_method,
                "protocol": "ssh" if auth_method == "ssh-key" else "kerberos" if auth_method == "kerberos" else "ntlm"
            },
            "message": log_message
        }
        
        return log_message, structured_log
    
    def generate_admin_tool_log(self, timestamp, username, target_host, tool=None):
        """Generate a log entry for administrative tool usage"""
        hostname = socket.gethostname()
        
        if not tool:
            tool = random.choice(self.admin_tools)
        
        # Generate command line based on the tool
        if "psexec" in tool.lower():
            cmdline = f"{tool} \\\\{target_host['ip']} -u {username} -p Password123! cmd.exe /c whoami"
        elif "wmic" in tool.lower():
            cmdline = f"{tool} /node:{target_host['ip']} process call create \"cmd.exe /c dir c:\\users\""
        elif "powershell" in tool.lower():
            cmdline = f"{tool} -Command \"Invoke-Command -ComputerName {target_host['hostname']} -ScriptBlock {{Get-Process}}\""
        elif "mimikatz" in tool.lower():
            cmdline = f"{tool} \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\""
        elif "ssh" in tool.lower():
            cmdline = f"{tool} {username}@{target_host['ip']} \"whoami\""
        else:
            cmdline = f"{tool} {target_host['ip']} -u {username} -p Password123!"
        
        log_message = f"{timestamp.isoformat()} {hostname} Process: User {username} executed {tool} - Command: {cmdline}"
        
        # Create structured log for Logstash
        structured_log = {
            "@timestamp": timestamp.isoformat(),
            "host": {
                "name": hostname,
                "ip": self.source_ip
            },
            "user": {
                "name": username
            },
            "process": {
                "name": tool,
                "command_line": cmdline,
                "executable": f"c:\\tools\\{tool}" if "\\" not in tool else tool
            },
            "target": {
                "ip": target_host['ip'],
                "hostname": target_host['hostname']
            },
            "event": {
                "category": "process",
                "type": "start",
                "provider": "Microsoft-Windows-Security-Auditing"
            },
            "message": log_message
        }
        
        return log_message, structured_log
    
    def generate_connection_log(self, timestamp, target_host, port=None):
        """Generate a network connection log entry"""
        hostname = socket.gethostname()
        
        if not port:
            port = random.choice(self.remote_ports)
        
        # Determine protocol based on port
        if port == 22:
            protocol = "ssh"
        elif port == 23:
            protocol = "telnet"
        elif port in [135, 139, 445]:
            protocol = "smb"
        elif port == 3389:
            protocol = "rdp"
        elif port in [5985, 5986]:
            protocol = "winrm"
        else:
            protocol = "tcp"
            
        # Connection details
        source_port = random.randint(49152, 65535)
        bytes_sent = random.randint(1024, 10240)
        bytes_recv = random.randint(1024, 10240)
        duration = random.uniform(0.5, 5.0)
            
        log_message = f"{timestamp.isoformat()} {hostname} Connection: {self.source_ip}:{source_port} -> {target_host['ip']}:{port} ({protocol}) - Sent: {bytes_sent} bytes, Recv: {bytes_recv} bytes, Duration: {duration:.2f}s"
        
        # Create structured log for Logstash
        structured_log = {
            "@timestamp": timestamp.isoformat(),
            "host": {
                "name": hostname,
                "ip": self.source_ip
            },
            "source": {
                "ip": self.source_ip,
                "port": source_port
            },
            "destination": {
                "ip": target_host['ip'],
                "port": port
            },
            "network": {
                "protocol": protocol,
                "bytes": bytes_sent + bytes_recv,
                "direction": "outbound",
                "transport": "tcp"
            },
            "event": {
                "category": "network",
                "type": "connection",
                "duration": duration * 1000000000  # nanoseconds
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
    
    def write_to_file(self, log_message, filename="lateral_movement_logs.txt"):
        """Write log message to a file"""
        try:
            with open(filename, "a") as f:
                f.write(log_message + "\n")
            return True
        except Exception as e:
            logger.error(f"Error writing to file: {str(e)}")
            return False
    
    def simulate_authentication_based(self):
        """Simulate authentication-based lateral movement"""
        logger.info(f"Starting authentication-based lateral movement simulation")
        
        # Calculate end time
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=self.duration)
        
        # Authentication frequency (events per minute)
        auth_freq_range = self.intensity["auth_freq"]
        auth_freq = random.randint(auth_freq_range[0], auth_freq_range[1])
        
        # Select a user account for the simulation
        username = random.choice(self.admin_users)
        
        logger.info(f"Simulating user {username} authenticating to {len(self.target_hosts)} hosts")
        logger.info(f"Frequency: ~{auth_freq} authentications per minute")
        
        # Track statistics
        successful_auths = 0
        failed_auths = 0
        
        # Simulate the authentication events until the duration is over
        current_time = start_time
        while current_time < end_time:
            # Time between authentications in seconds
            time_between = 60 / auth_freq
            
            # Select a random target host
            target_host = random.choice(self.target_hosts)
            
            # 90% success rate for authentications
            status = "success" if random.random() < 0.9 else "failure"
            
            # Generate and log the authentication
            log_message, structured_log = self.generate_auth_log(current_time, username, target_host, status)
            
            # Write to file
            self.write_to_file(log_message)
            
            # Send to Logstash if URL provided
            if self.logstash_url:
                self.send_to_logstash(structured_log)
            
            # Update statistics
            if status == "success":
                successful_auths += 1
            else:
                failed_auths += 1
            
            # Display progress
            if (successful_auths + failed_auths) % 10 == 0:
                logger.info(f"Generated {successful_auths} successful and {failed_auths} failed authentications")
            
            # Increment the current time
            current_time += timedelta(seconds=time_between)
            
            # Sleep briefly to simulate real-time behavior
            time.sleep(min(time_between, 0.1))
        
        logger.info(f"Authentication-based simulation completed. Generated {successful_auths} successful and {failed_auths} failed authentications")
        
        # Return a summary of the simulation
        return {
            "technique": "authentication_based",
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_minutes": self.duration,
            "source_ip": self.source_ip,
            "username": username,
            "target_hosts": len(self.target_hosts),
            "successful_auths": successful_auths,
            "failed_auths": failed_auths
        }

    def simulate_tool_based(self):
        """Simulate lateral movement using administrative tools"""
        logger.info(f"Starting admin tool-based lateral movement simulation")
        
        # Calculate end time
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=self.duration)
        
        # Tool execution frequency (events per minute)
        tool_freq_range = self.intensity["tool_freq"]
        tool_freq = random.randint(tool_freq_range[0], tool_freq_range[1])
        
        # Select a user account and tools for the simulation
        username = random.choice(self.admin_users)
        tools = random.sample(self.admin_tools, min(3, len(self.admin_tools)))
        
        logger.info(f"Simulating user {username} using {tools} against {len(self.target_hosts)} hosts")
        logger.info(f"Frequency: ~{tool_freq} tool executions per minute")
        
        # Track statistics
        tool_executions = 0
        
        # Simulate the tool executions until the duration is over
        current_time = start_time
        while current_time < end_time:
            # Time between tool executions in seconds
            time_between = 60 / tool_freq
            
            # Select a random target host and tool
            target_host = random.choice(self.target_hosts)
            tool = random.choice(tools)
            
            # Generate and log the tool execution
            log_message, structured_log = self.generate_admin_tool_log(current_time, username, target_host, tool)
            
            # Write to file
            self.write_to_file(log_message)
            
            # Send to Logstash if URL provided
            if self.logstash_url:
                self.send_to_logstash(structured_log)
            
            # Update statistics
            tool_executions += 1
            
            # Display progress
            if tool_executions % 10 == 0:
                logger.info(f"Generated {tool_executions} tool executions")
            
            # Increment the current time
            current_time += timedelta(seconds=time_between)
            
            # Sleep briefly to simulate real-time behavior
            time.sleep(min(time_between, 0.1))
        
        logger.info(f"Tool-based simulation completed. Generated {tool_executions} tool executions")
        
        # Return a summary of the simulation
        return {
            "technique": "tool_based",
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_minutes": self.duration,
            "source_ip": self.source_ip,
            "username": username,
            "tools_used": tools,
            "target_hosts": len(self.target_hosts),
            "tool_executions": tool_executions
        }

    def simulate_connection_based(self):
        """Simulate connection-based lateral movement"""
        logger.info(f"Starting connection-based lateral movement simulation")
        
        # Calculate end time
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=self.duration)
        
        # Connection frequency (events per minute)
        conn_freq_range = self.intensity["conn_freq"]
        conn_freq = random.randint(conn_freq_range[0], conn_freq_range[1])
        
        # Select ports for the simulation
        ports = random.sample(self.remote_ports, min(4, len(self.remote_ports)))
        
        logger.info(f"Simulating connections from {self.source_ip} to {len(self.target_hosts)} hosts on ports {ports}")
        logger.info(f"Frequency: ~{conn_freq} connections per minute")
        
        # Track statistics
        connections = 0
        
        # Simulate the connections until the duration is over
        current_time = start_time
        while current_time < end_time:
            # Time between connections in seconds
            time_between = 60 / conn_freq
            
            # Select a random target host and port
            target_host = random.choice(self.target_hosts)
            port = random.choice(ports)
            
            # Generate and log the connection
            log_message, structured_log = self.generate_connection_log(current_time, target_host, port)
            
            # Write to file
            self.write_to_file(log_message)
            
            # Send to Logstash if URL provided
            if self.logstash_url:
                self.send_to_logstash(structured_log)
            
            # Update statistics
            connections += 1
            
            # Display progress
            if connections % 20 == 0:
                logger.info(f"Generated {connections} connections")
            
            # Increment the current time
            current_time += timedelta(seconds=time_between)
            
            # Sleep briefly to simulate real-time behavior
            time.sleep(min(time_between, 0.05))
        
        logger.info(f"Connection-based simulation completed. Generated {connections} connections")
        
        # Return a summary of the simulation
        return {
            "technique": "connection_based",
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_minutes": self.duration,
            "source_ip": self.source_ip,
            "ports_used": ports,
            "target_hosts": len(self.target_hosts),
            "connections": connections
        }
    
    def run_simulation(self):
        """Run the lateral movement simulation"""
        logger.info("Starting lateral movement simulation")
        
        results = []
        
        # Run the appropriate simulations based on technique
        if self.technique == "auth" or self.technique == "all":
            auth_results = self.simulate_authentication_based()
            results.append(auth_results)
            
        if self.technique == "tool" or self.technique == "all":
            tool_results = self.simulate_tool_based()
            results.append(tool_results)
            
        if self.technique == "connection" or self.technique == "all":
            conn_results = self.simulate_connection_based()
            results.append(conn_results)
        
        return results

def main():
    """Main function to run the lateral movement simulator"""
    parser = argparse.ArgumentParser(description="Simulate lateral movement attacks")
    
    parser.add_argument("--source", "-s", 
                        help="Source IP address (default: auto-detect)")
    
    parser.add_argument("--targets", "-t",
                        type=int,
                        default=5,
                        help="Number of target hosts to generate (default: 5)")
    
    parser.add_argument("--technique", "-m",
                        choices=["auth", "tool", "connection", "all"],
                        default="all",
                        help="Lateral movement technique to simulate (default: all)")
    
    parser.add_argument("--duration", "-d",
                        type=int,
                        default=10,
                        help="Simulation duration in minutes (default: 10)")
    
    parser.add_argument("--intensity", "-i",
                        choices=["low", "medium", "high"],
                        default="medium",
                        help="Intensity of simulation (default: medium)")
    
    parser.add_argument("--logstash", "-l",
                        help="Logstash URL to send logs (e.g., http://localhost:5000)")
    
    args = parser.parse_args()
    
    # Create and run the simulator
    simulator = LateralMovementSimulator(
        source_ip=args.source,
        target_count=args.targets,
        technique=args.technique,
        duration=args.duration,
        intensity=args.intensity,
        logstash_url=args.logstash
    )
    
    # Run the simulation
    summary = simulator.run_simulation()
    
    # Print the summary as JSON
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()