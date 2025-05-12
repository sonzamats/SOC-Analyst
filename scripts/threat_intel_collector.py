#!/usr/bin/env python3
"""
Threat Intelligence Collector

This script collects threat intelligence from various sources and imports it into Elasticsearch.
It supports multiple feed types including STIX/TAXII, REST APIs, CSV files, and MISP instances.

Author: SOC Team
Version: 1.0
"""

import os
import sys
import yaml
import json
import time
import logging
import argparse
import hashlib
import datetime
import requests
import csv
import ipaddress
from urllib.parse import urlparse
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/threat_intel_collector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatIntelCollector:
    """Class to collect and process threat intelligence from various sources."""
    
    def __init__(self, config_file, force_refresh=False):
        """Initialize the collector with the configuration file."""
        self.config_file = config_file
        self.force_refresh = force_refresh
        self.config = self._load_config()
        self.es_client = self._init_elasticsearch()
        self.processed_indicators = 0
        self.failed_indicators = 0
        self.feed_stats = {}
        
    def _load_config(self):
        """Load the configuration file."""
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from {self.config_file}")
                return config
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            sys.exit(1)
            
    def _init_elasticsearch(self):
        """Initialize Elasticsearch client."""
        try:
            es_host = self.config.get('elasticsearch', {}).get('host', 'localhost')
            es_port = self.config.get('elasticsearch', {}).get('port', 9200)
            es_user = self.config.get('elasticsearch', {}).get('username', '')
            es_pass = self.config.get('elasticsearch', {}).get('password', '')
            
            # Use environment variables if available
            if 'ELASTIC_PASSWORD' in os.environ and not es_pass:
                es_pass = os.environ['ELASTIC_PASSWORD']
            
            es_url = f"http://{es_host}:{es_port}"
            
            # Create client with or without authentication
            if es_user and es_pass:
                client = Elasticsearch([es_url], http_auth=(es_user, es_pass))
            else:
                client = Elasticsearch([es_url])
                
            logger.info(f"Connected to Elasticsearch at {es_url}")
            return client
        except Exception as e:
            logger.error(f"Error connecting to Elasticsearch: {str(e)}")
            sys.exit(1)
            
    def _create_indicator_id(self, indicator_value, indicator_type, feed_name):
        """Create a unique ID for an indicator."""
        id_string = f"{indicator_value}|{indicator_type}|{feed_name}"
        return hashlib.md5(id_string.encode()).hexdigest()
    
    def _validate_indicator(self, indicator_type, indicator_value):
        """Validate indicator format based on type."""
        try:
            if indicator_type == 'ipv4':
                ipaddress.IPv4Address(indicator_value)
                return True
            elif indicator_type == 'ipv6':
                ipaddress.IPv6Address(indicator_value)
                return True
            elif indicator_type == 'domain':
                if len(indicator_value) > 0 and '.' in indicator_value:
                    return True
            elif indicator_type == 'url':
                result = urlparse(indicator_value)
                return all([result.scheme, result.netloc])
            elif indicator_type in ['md5', 'sha1', 'sha256', 'file_hash']:
                if indicator_type == 'md5' and len(indicator_value) == 32:
                    return True
                elif indicator_type == 'sha1' and len(indicator_value) == 40:
                    return True
                elif indicator_type == 'sha256' and len(indicator_value) == 64:
                    return True
                elif indicator_type == 'file_hash':
                    return len(indicator_value) in [32, 40, 64]
            return False
        except:
            return False
    
    def process_api_source(self, source_config):
        """Process a REST API-based threat intelligence source."""
        try:
            source_name = source_config.get('name', 'Unknown API Source')
            url = source_config.get('url')
            api_key = source_config.get('api_key')
            indicator_types = source_config.get('indicator_types', [])
            confidence = source_config.get('confidence_level', 
                                         self.config.get('global', {}).get('default_confidence', 50))
            
            logger.info(f"Processing API source: {source_name}")
            
            headers = {}
            if api_key:
                if 'alienvault' in url.lower():
                    headers = {'X-OTX-API-KEY': api_key}
                elif 'api_key_header' in source_config:
                    headers = {source_config['api_key_header']: api_key}
                else:
                    headers = {'Authorization': f'Bearer {api_key}'}
            
            response = requests.get(url, headers=headers, 
                                   timeout=source_config.get('timeout', 60),
                                   verify=source_config.get('verify_ssl', True))
            
            if response.status_code != 200:
                logger.error(f"Error fetching from {source_name}: HTTP {response.status_code}")
                self.feed_stats[source_name] = {'status': 'error', 'indicators_processed': 0}
                return
                
            # Try to parse as JSON
            try:
                data = response.json()
                
                # Handle different API response formats
                indicators = []
                
                # AlienVault OTX format
                if 'results' in data and isinstance(data['results'], list):
                    indicators = data['results']
                # Generic list format
                elif isinstance(data, list):
                    indicators = data
                # Custom format specified in config
                elif 'json_path' in source_config:
                    path = source_config['json_path'].split('.')
                    temp_data = data
                    for p in path:
                        if p in temp_data:
                            temp_data = temp_data[p]
                        else:
                            logger.error(f"JSON path {source_config['json_path']} not found in response")
                            break
                    if isinstance(temp_data, list):
                        indicators = temp_data
                
                processed_count = 0
                indicator_docs = []
                
                for indicator in indicators:
                    ind_type = None
                    ind_value = None
                    
                    # Extract type and value based on format
                    if 'type' in indicator and 'indicator' in indicator:
                        # AlienVault OTX format
                        ind_type = indicator['type']
                        ind_value = indicator['indicator']
                    elif 'type_field' in source_config and 'value_field' in source_config:
                        # Custom field mapping
                        type_field = source_config['type_field']
                        value_field = source_config['value_field']
                        if type_field in indicator and value_field in indicator:
                            ind_type = indicator[type_field]
                            ind_value = indicator[value_field]
                    elif isinstance(indicator, str):
                        # Simple string list, use default type
                        ind_type = source_config.get('default_type', 'unknown')
                        ind_value = indicator
                    
                    # Skip if we couldn't extract type/value
                    if not ind_type or not ind_value:
                        continue
                        
                    # Map indicator types to standard format
                    if ind_type in ['IPv4', 'ip', 'ipv4', 'IP']:
                        ind_type = 'ipv4'
                    elif ind_type in ['IPv6', 'ipv6']:
                        ind_type = 'ipv6'
                    elif ind_type in ['domain', 'hostname', 'DOMAIN']:
                        ind_type = 'domain'
                    elif ind_type in ['URL', 'uri', 'link']:
                        ind_type = 'url'
                    elif ind_type in ['MD5', 'md5', 'hash-md5']:
                        ind_type = 'md5'
                    elif ind_type in ['SHA1', 'sha1', 'hash-sha1']:
                        ind_type = 'sha1'
                    elif ind_type in ['SHA256', 'sha256', 'hash-sha256']:
                        ind_type = 'sha256'
                    
                    # Skip if not in our requested types
                    if indicator_types and ind_type not in indicator_types:
                        continue
                        
                    # Validate indicator format
                    if not self._validate_indicator(ind_type, ind_value):
                        logger.debug(f"Invalid indicator format: {ind_type} - {ind_value}")
                        continue
                    
                    # Create the document
                    now = datetime.datetime.utcnow().isoformat()
                    doc = {
                        "_index": f"threat-intel-indicators-{datetime.datetime.utcnow().strftime('%Y.%m')}",
                        "_id": self._create_indicator_id(ind_value, ind_type, source_name),
                        "@timestamp": now,
                        "indicator": {
                            "type": ind_type,
                            "value": ind_value
                        },
                        "threat": {
                            "feed": {
                                "name": source_name
                            },
                            "indicator": {
                                "confidence": confidence,
                                "first_seen": now,
                                "last_seen": now,
                                "type": "unknown"  # Default, can be overridden
                            }
                        },
                        "tags": ["threat_intel"]
                    }
                    
                    # Add additional fields if available
                    if isinstance(indicator, dict):
                        # Description/name
                        if 'description' in indicator:
                            doc['threat']['indicator']['description'] = indicator['description']
                        elif 'name' in indicator:
                            doc['threat']['indicator']['description'] = indicator['name']
                            
                        # Indicator type (malware, c2, etc.)
                        if 'threat_type' in indicator:
                            doc['threat']['indicator']['type'] = indicator['threat_type']
                            
                        # Timestamps
                        if 'created' in indicator:
                            doc['threat']['indicator']['first_seen'] = indicator['created']
                        if 'modified' in indicator:
                            doc['threat']['indicator']['last_seen'] = indicator['modified']
                    
                    indicator_docs.append(doc)
                    processed_count += 1
                    
                    # Bulk index in batches of 1000
                    if len(indicator_docs) >= 1000:
                        success, failed = bulk(self.es_client, indicator_docs, raise_on_error=False)
                        self.processed_indicators += success
                        self.failed_indicators += failed
                        indicator_docs = []
                
                # Index any remaining documents
                if indicator_docs:
                    success, failed = bulk(self.es_client, indicator_docs, raise_on_error=False)
                    self.processed_indicators += success
                    self.failed_indicators += failed
                
                logger.info(f"Processed {processed_count} indicators from {source_name}")
                self.feed_stats[source_name] = {
                    'status': 'success',
                    'indicators_processed': processed_count
                }
                
            except json.JSONDecodeError:
                # Handle non-JSON responses (might be CSV, etc.)
                logger.warning(f"Non-JSON response from {source_name}, trying alternative formats")
                if source_config.get('type') == 'txt' or url.endswith('.txt'):
                    self.process_txt_source(source_config, response.text)
                else:
                    logger.error(f"Unsupported response format from {source_name}")
                    self.feed_stats[source_name] = {'status': 'error', 'indicators_processed': 0}
                
        except Exception as e:
            logger.error(f"Error processing API source {source_config.get('name')}: {str(e)}")
            self.feed_stats[source_config.get('name', 'Unknown API Source')] = {
                'status': 'error',
                'indicators_processed': 0,
                'error': str(e)
            }
    
    def process_csv_source(self, source_config):
        """Process a CSV-based threat intelligence source."""
        try:
            source_name = source_config.get('name', 'Unknown CSV Source')
            url = source_config.get('url')
            delimiter = source_config.get('delimiter', ',')
            indicator_column = source_config.get('indicator_column', 0)
            indicator_type_column = source_config.get('indicator_type_column')
            default_type = source_config.get('default_type', 'unknown')
            skip_header = source_config.get('skip_header', True)
            confidence = source_config.get('confidence_level', 
                                         self.config.get('global', {}).get('default_confidence', 50))
            
            logger.info(f"Processing CSV source: {source_name}")
            
            # Download the CSV file
            response = requests.get(url, timeout=source_config.get('timeout', 60),
                                   verify=source_config.get('verify_ssl', True))
            
            if response.status_code != 200:
                logger.error(f"Error fetching from {source_name}: HTTP {response.status_code}")
                self.feed_stats[source_name] = {'status': 'error', 'indicators_processed': 0}
                return
                
            # Process the CSV data
            lines = response.text.splitlines()
            csv_reader = csv.reader(lines, delimiter=delimiter)
            
            if skip_header:
                next(csv_reader, None)
                
            processed_count = 0
            indicator_docs = []
            
            for row in csv_reader:
                try:
                    # Skip empty rows
                    if not row or len(row) <= indicator_column:
                        continue
                        
                    # Get indicator value
                    ind_value = row[indicator_column].strip()
                    if not ind_value:
                        continue
                    
                    # Get indicator type if column specified
                    if indicator_type_column is not None and len(row) > indicator_type_column:
                        ind_type = row[indicator_type_column].strip().lower()
                    else:
                        ind_type = default_type
                        
                    # Map indicator types to standard format
                    if ind_type in ['IPv4', 'ip', 'ipv4', 'IP']:
                        ind_type = 'ipv4'
                    elif ind_type in ['IPv6', 'ipv6']:
                        ind_type = 'ipv6'
                    elif ind_type in ['domain', 'hostname', 'DOMAIN']:
                        ind_type = 'domain'
                    elif ind_type in ['URL', 'uri', 'link']:
                        ind_type = 'url'
                    elif ind_type in ['MD5', 'md5', 'hash-md5']:
                        ind_type = 'md5'
                    elif ind_type in ['SHA1', 'sha1', 'hash-sha1']:
                        ind_type = 'sha1'
                    elif ind_type in ['SHA256', 'sha256', 'hash-sha256']:
                        ind_type = 'sha256'
                    
                    # Try to auto-detect type if not specified
                    if ind_type == 'unknown':
                        if self._validate_indicator('ipv4', ind_value):
                            ind_type = 'ipv4'
                        elif self._validate_indicator('domain', ind_value):
                            ind_type = 'domain'
                        elif self._validate_indicator('url', ind_value):
                            ind_type = 'url'
                        elif self._validate_indicator('md5', ind_value):
                            ind_type = 'md5'
                        elif self._validate_indicator('sha1', ind_value):
                            ind_type = 'sha1'
                        elif self._validate_indicator('sha256', ind_value):
                            ind_type = 'sha256'
                    
                    # Validate indicator format
                    if not self._validate_indicator(ind_type, ind_value):
                        continue
                    
                    # Create the document
                    now = datetime.datetime.utcnow().isoformat()
                    doc = {
                        "_index": f"threat-intel-indicators-{datetime.datetime.utcnow().strftime('%Y.%m')}",
                        "_id": self._create_indicator_id(ind_value, ind_type, source_name),
                        "@timestamp": now,
                        "indicator": {
                            "type": ind_type,
                            "value": ind_value
                        },
                        "threat": {
                            "feed": {
                                "name": source_name
                            },
                            "indicator": {
                                "confidence": confidence,
                                "first_seen": now,
                                "last_seen": now,
                                "type": "unknown"
                            }
                        },
                        "tags": ["threat_intel"]
                    }
                    
                    # Add description column if specified
                    description_column = source_config.get('description_column')
                    if description_column is not None and len(row) > description_column:
                        description = row[description_column].strip()
                        if description:
                            doc['threat']['indicator']['description'] = description
                    
                    indicator_docs.append(doc)
                    processed_count += 1
                    
                    # Bulk index in batches of 1000
                    if len(indicator_docs) >= 1000:
                        success, failed = bulk(self.es_client, indicator_docs, raise_on_error=False)
                        self.processed_indicators += success
                        self.failed_indicators += failed
                        indicator_docs = []
                
                except Exception as e:
                    logger.debug(f"Error processing CSV row: {str(e)}")
                    continue
            
            # Index any remaining documents
            if indicator_docs:
                success, failed = bulk(self.es_client, indicator_docs, raise_on_error=False)
                self.processed_indicators += success
                self.failed_indicators += failed
            
            logger.info(f"Processed {processed_count} indicators from {source_name}")
            self.feed_stats[source_name] = {
                'status': 'success',
                'indicators_processed': processed_count
            }
                
        except Exception as e:
            logger.error(f"Error processing CSV source {source_config.get('name')}: {str(e)}")
            self.feed_stats[source_config.get('name', 'Unknown CSV Source')] = {
                'status': 'error',
                'indicators_processed': 0,
                'error': str(e)
            }
    
    def process_txt_source(self, source_config, text=None):
        """Process a plain text-based threat intelligence source (one indicator per line)."""
        try:
            source_name = source_config.get('name', 'Unknown Text Source')
            url = source_config.get('url')
            default_type = source_config.get('default_type', 'unknown')
            comment_char = source_config.get('comment_char', '#')
            confidence = source_config.get('confidence_level', 
                                         self.config.get('global', {}).get('default_confidence', 50))
            
            logger.info(f"Processing text source: {source_name}")
            
            # Download the text file if not provided
            if text is None:
                response = requests.get(url, timeout=source_config.get('timeout', 60),
                                       verify=source_config.get('verify_ssl', True))
                
                if response.status_code != 200:
                    logger.error(f"Error fetching from {source_name}: HTTP {response.status_code}")
                    self.feed_stats[source_name] = {'status': 'error', 'indicators_processed': 0}
                    return
                    
                text = response.text
                
            # Process the text data
            lines = text.splitlines()
            processed_count = 0
            indicator_docs = []
            
            for line in lines:
                # Skip empty lines and comments
                line = line.strip()
                if not line or line.startswith(comment_char):
                    continue
                
                # Extract the indicator (first non-whitespace token)
                ind_value = line.split()[0].strip()
                if not ind_value:
                    continue
                
                # Try to auto-detect type
                ind_type = default_type
                if self._validate_indicator('ipv4', ind_value):
                    ind_type = 'ipv4'
                elif self._validate_indicator('domain', ind_value):
                    ind_type = 'domain'
                elif self._validate_indicator('url', ind_value):
                    ind_type = 'url'
                elif self._validate_indicator('md5', ind_value):
                    ind_type = 'md5'
                elif self._validate_indicator('sha1', ind_value):
                    ind_type = 'sha1'
                elif self._validate_indicator('sha256', ind_value):
                    ind_type = 'sha256'
                
                # Skip if we couldn't determine the type
                if ind_type == 'unknown' and not source_config.get('allow_unknown_types', False):
                    continue
                
                # Create the document
                now = datetime.datetime.utcnow().isoformat()
                doc = {
                    "_index": f"threat-intel-indicators-{datetime.datetime.utcnow().strftime('%Y.%m')}",
                    "_id": self._create_indicator_id(ind_value, ind_type, source_name),
                    "@timestamp": now,
                    "indicator": {
                        "type": ind_type,
                        "value": ind_value
                    },
                    "threat": {
                        "feed": {
                            "name": source_name
                        },
                        "indicator": {
                            "confidence": confidence,
                            "first_seen": now,
                            "last_seen": now,
                            "type": "unknown"
                        }
                    },
                    "tags": ["threat_intel"]
                }
                
                # Extract description from rest of line if available
                description = line[len(ind_value):].strip()
                if description and not description.startswith(comment_char):
                    doc['threat']['indicator']['description'] = description
                
                indicator_docs.append(doc)
                processed_count += 1
                
                # Bulk index in batches of 1000
                if len(indicator_docs) >= 1000:
                    success, failed = bulk(self.es_client, indicator_docs, raise_on_error=False)
                    self.processed_indicators += success
                    self.failed_indicators += failed
                    indicator_docs = []
            
            # Index any remaining documents
            if indicator_docs:
                success, failed = bulk(self.es_client, indicator_docs, raise_on_error=False)
                self.processed_indicators += success
                self.failed_indicators += failed
            
            logger.info(f"Processed {processed_count} indicators from {source_name}")
            self.feed_stats[source_name] = {
                'status': 'success',
                'indicators_processed': processed_count
            }
                
        except Exception as e:
            logger.error(f"Error processing text source {source_config.get('name')}: {str(e)}")
            self.feed_stats[source_config.get('name', 'Unknown Text Source')] = {
                'status': 'error',
                'indicators_processed': 0,
                'error': str(e)
            }
            
    def record_feed_health(self):
        """Record feed health metrics in Elasticsearch."""
        try:
            now = datetime.datetime.utcnow().isoformat()
            index_name = f"threat-intel-health-{datetime.datetime.utcnow().strftime('%Y.%m')}"
            
            docs = []
            for feed_name, stats in self.feed_stats.items():
                doc = {
                    "_index": index_name,
                    "@timestamp": now,
                    "threat_intel": {
                        "feed": {
                            "name": feed_name,
                            "status": stats.get('status', 'unknown'),
                            "indicators_processed": stats.get('indicators_processed', 0)
                        }
                    }
                }
                
                if 'error' in stats:
                    doc['threat_intel']['feed']['error'] = stats['error']
                    
                docs.append(doc)
            
            if docs:
                bulk(self.es_client, docs)
                logger.info(f"Recorded health metrics for {len(docs)} feeds")
        except Exception as e:
            logger.error(f"Error recording feed health: {str(e)}")
            
    def run(self):
        """Run the threat intelligence collection process."""
        start_time = time.time()
        logger.info("Starting threat intelligence collection")
        
        # Process each source
        for source in self.config.get('sources', []):
            # Skip disabled sources
            if not source.get('enabled', True):
                logger.info(f"Skipping disabled source: {source.get('name')}")
                continue
                
            # Check if we should process this source based on polling interval
            if not self.force_refresh and 'last_update' in source:
                try:
                    last_update = datetime.datetime.fromisoformat(source['last_update'])
                    polling_interval = source.get('polling_interval', 
                                               self.config.get('global', {}).get('update_interval', 3600))
                    next_update = last_update + datetime.timedelta(seconds=polling_interval)
                    
                    if datetime.datetime.utcnow() < next_update:
                        logger.info(f"Skipping {source.get('name')} - not due for update until {next_update}")
                        continue
                except Exception as e:
                    logger.debug(f"Error checking polling interval: {str(e)}")
            
            # Process based on source type
            source_type = source.get('type', '').lower()
            if source_type == 'api':
                self.process_api_source(source)
            elif source_type == 'csv':
                self.process_csv_source(source)
            elif source_type == 'txt':
                self.process_txt_source(source)
            else:
                logger.warning(f"Unsupported source type: {source_type} for {source.get('name')}")
        
        # Record feed health metrics
        self.record_feed_health()
        
        # Log summary
        elapsed_time = time.time() - start_time
        logger.info(f"Threat intelligence collection completed in {elapsed_time:.2f} seconds")
        logger.info(f"Processed {self.processed_indicators} indicators successfully")
        if self.failed_indicators > 0:
            logger.warning(f"Failed to process {self.failed_indicators} indicators")
            
        return {
            'processed': self.processed_indicators,
            'failed': self.failed_indicators,
            'elapsed_time': elapsed_time
        }

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='Collect threat intelligence from various sources')
    parser.add_argument('--config', default='config/threat_intel_config.yml', 
                        help='Path to configuration file')
    parser.add_argument('--force-refresh', action='store_true', 
                        help='Force refresh all sources regardless of polling interval')
    args = parser.parse_args()
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Run the collector
    collector = ThreatIntelCollector(args.config, args.force_refresh)
    collector.run()

if __name__ == "__main__":
    main() 