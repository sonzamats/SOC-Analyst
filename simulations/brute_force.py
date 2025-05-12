#!/usr/bin/env python3
"""
Brute Force Attack Simulator

This script simulates a brute force SSH attack against a target server by 
generating log entries that would typically appear during such an attack.

Author: SOC Analyst SIEM Project
Date: 2023-07-15
Version: 1.0
"""

import random
import time
import socket
import argparse
import logging
import json
from datetime import datetime, timedelta
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("BruteForceSimulator")

# Common usernames for brute force attempts
COMMON_USERNAMES = [
    "admin", "root", "administrator", "oracle", "user", 
    "test", "guest", "postgres", "ubuntu", "centos", 
    "azureuser", "ec2-user", "mysql", "ftpuser", "www-data"
]

class BruteForceSimulator:
    """Class for simulating brute force attacks"""
    
    def __init__(self, target_ip, target_port=22, attacker_ip=None, 
                 duration=10, intensity="medium", logstash_url=None):
        """Initialize the brute force simulator"""
        self.target_ip = target_ip
        self.target_port = target_port
        
        # If no attacker IP is provided, generate a random one
        if attacker_ip is None:
            self.attacker_ip = self.generate_random_ip()
        else:
            self.attacker_ip = attacker_ip
            
        # Attack duration in minutes
        self.duration = duration
        
        # Attack intensity (attempts per minute)
        intensity_map = {
            "low": (5, 10),     # 5-10 attempts per minute
            "medium": (20, 40), # 20-40 attempts per minute
            "high": (50, 100)   # 50-100 attempts per minute
        }
        self.intensity = intensity_map.get(intensity.lower(), intensity_map["medium"])
        
        # Logstash URL for sending logs
        self.logstash_url = logstash_url
        
        logger.info(f"Initialized brute force simulation from {self.attacker_ip} to {self.target_ip}:{self.target_port}")
        logger.info(f"Duration: {self.duration} minutes, Intensity: {intensity} ({self.intensity[0]}-{self.intensity[1]} attempts/min)")
    
    def generate_random_ip(self):
        """Generate a random IP address"""
        octets = [str(random.randint(1, 254)) for _ in range(4)]
        return ".".join(octets)
    
    def generate_password(self, length=8):
        """Generate a random password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
        return ''.join(random.choice(chars) for _ in range(length))
    
    def generate_auth_log(self, timestamp, username, success=False):
        """Generate an authentication log entry"""
        hostname = socket.gethostname()
        pid = random.randint(1000, 9999)
        
        if success:
            log_message = f"{timestamp} {hostname} sshd[{pid}]: Accepted password for {username} from {self.attacker_ip} port {random.randint(30000, 65000)} ssh2"
        else:
            log_message = f"{timestamp} {hostname} sshd[{pid}]: Failed password for {username} from {self.attacker_ip} port {random.randint(30000, 65000)} ssh2"
        
        # Create structured log for Logstash
        structured_log = {
            "@timestamp": timestamp.isoformat(),
            "host": hostname,
            "program": "sshd",
            "pid": pid,
            "message": log_message,
            "event": {
                "type": "authentication",
                "outcome": "success" if success else "failure"
            },
            "source": {
                "ip": self.attacker_ip,
                "port": random.randint(30000, 65000)
            },
            "destination": {
                "ip": self.target_ip,
                "port": self.target_port
            },
            "user": {
                "name": username
            },
            "service": {
                "type": "ssh"
            }
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
    
    def write_to_file(self, log_message, filename="brute_force_logs.txt"):
        """Write log message to a file"""
        try:
            with open(filename, "a") as f:
                f.write(log_message + "\n")
            return True
        except Exception as e:
            logger.error(f"Error writing to file: {str(e)}")
            return False
    
    def run_simulation(self):
        """Run the brute force attack simulation"""
        logger.info("Starting brute force attack simulation")
        
        # Calculate end time
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=self.duration)
        
        # Track successful login attempts (should be rare in a brute force)
        successful_attempts = 0
        total_attempts = 0
        
        # Select users to try
        usernames = random.sample(COMMON_USERNAMES, min(5, len(COMMON_USERNAMES)))
        current_user_index = 0
        
        # Simulate the attack until the duration is over
        current_time = start_time
        while current_time < end_time:
            # Determine number of attempts for this minute
            attempts_this_minute = random.randint(self.intensity[0], self.intensity[1])
            
            # Time between attempts in seconds
            time_between = 60 / attempts_this_minute
            
            # Generate attempts for this minute
            for _ in range(attempts_this_minute):
                # Rotate through usernames
                username = usernames[current_user_index]
                current_user_index = (current_user_index + 1) % len(usernames)
                
                # Determine if this attempt is successful (rare in brute force)
                # Only allow success after many failures and near the end
                success = False
                if (total_attempts > 20 and
                    successful_attempts == 0 and
                    random.random() < 0.02 and
                    current_time > (end_time - timedelta(minutes=2))):
                    success = True
                    successful_attempts += 1
                
                # Generate the log
                log_message, structured_log = self.generate_auth_log(current_time, username, success)
                
                # Write to file
                self.write_to_file(log_message)
                
                # Send to Logstash if URL provided
                if self.logstash_url:
                    self.send_to_logstash(structured_log)
                
                # Display progress
                if total_attempts % 10 == 0:
                    logger.info(f"Generated {total_attempts} authentication attempts, {successful_attempts} successful")
                
                # Increment counters
                total_attempts += 1
                
                # Increment the current time
                current_time += timedelta(seconds=time_between)
                
                # Sleep briefly to simulate real-time behavior when debugging
                if not self.logstash_url:  # If we're not sending to logstash, slow down for visibility
                    time.sleep(0.1)
        
        logger.info(f"Brute force simulation completed. Generated {total_attempts} authentication attempts, {successful_attempts} successful")
        
        # Return a summary of the simulation
        return {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration": self.duration,
            "attacker_ip": self.attacker_ip,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "total_attempts": total_attempts,
            "successful_attempts": successful_attempts,
            "intensity": f"{self.intensity[0]}-{self.intensity[1]} attempts/min"
        }

def main():
    """Main function to run the brute force simulator"""
    parser = argparse.ArgumentParser(description="Simulate a brute force SSH attack")
    
    parser.add_argument("--target", "-t", 
                        required=True,
                        help="Target IP address")
    
    parser.add_argument("--port", "-p",
                        type=int,
                        default=22,
                        help="Target port (default: 22)")
    
    parser.add_argument("--attacker", "-a",
                        help="Attacker IP address (default: random)")
    
    parser.add_argument("--duration", "-d",
                        type=int,
                        default=10,
                        help="Attack duration in minutes (default: 10)")
    
    parser.add_argument("--intensity", "-i",
                        choices=["low", "medium", "high"],
                        default="medium",
                        help="Attack intensity (default: medium)")
    
    parser.add_argument("--logstash", "-l",
                        help="Logstash URL to send logs (e.g., http://localhost:5000)")
    
    args = parser.parse_args()
    
    # Create and run the simulator
    simulator = BruteForceSimulator(
        target_ip=args.target,
        target_port=args.port,
        attacker_ip=args.attacker,
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