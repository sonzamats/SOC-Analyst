#!/usr/bin/env python3
"""
Threat Intelligence Rule Tagger

This script analyzes detection rules and automatically tags them with appropriate
MITRE ATT&CK techniques and threat intelligence metadata.

Author: SOC Team
Version: 1.0
"""

import os
import sys
import yaml
import json
import argparse
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Union, Optional, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ti_rule_tagger.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RuleTagger:
    """Class for tagging detection rules with threat intelligence information."""

    def __init__(self, mitre_file: str, rules_dir: str, output_dir: Optional[str] = None):
        """
        Initialize the rule tagger.
        
        Args:
            mitre_file: Path to the MITRE ATT&CK mapping file (JSON).
            rules_dir: Directory containing detection rules to process.
            output_dir: Directory to write updated rules (if None, overwrites original files).
        """
        self.mitre_file = mitre_file
        self.rules_dir = rules_dir
        self.output_dir = output_dir or rules_dir
        self.mitre_data = self._load_mitre_data()
        self.rule_count = 0
        self.tagged_count = 0
        self.errors = 0
        
        # Create the output directory if it doesn't exist
        if self.output_dir != self.rules_dir:
            os.makedirs(self.output_dir, exist_ok=True)
    
    def _load_mitre_data(self) -> Dict[str, Dict[str, Any]]:
        """
        Load MITRE ATT&CK data from file.
        
        Returns:
            Dictionary mapping technique names/keywords to technique data.
        """
        try:
            with open(self.mitre_file, 'r') as f:
                data = json.load(f)
                
            # Create a lookup map for faster matching
            technique_map = {}
            
            # Process each technique
            for technique in data.get('techniques', []):
                # Map by ID for exact matching
                tid = technique.get('technique_id', '')
                if tid:
                    technique_map[tid.lower()] = technique
                
                # Map by name for exact matching
                name = technique.get('name', '')
                if name:
                    technique_map[name.lower()] = technique
                
                # Map by keywords for fuzzy matching
                keywords = technique.get('keywords', [])
                for keyword in keywords:
                    if keyword:
                        technique_map[keyword.lower()] = technique
            
            logger.info(f"Loaded {len(data.get('techniques', []))} MITRE ATT&CK techniques")
            return technique_map
            
        except Exception as e:
            logger.error(f"Error loading MITRE data: {str(e)}")
            sys.exit(1)
    
    def _find_matching_techniques(self, rule_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Find matching MITRE ATT&CK techniques for a rule.
        
        Args:
            rule_content: The detection rule content.
            
        Returns:
            List of matching technique dictionaries.
        """
        matches = set()
        techniques = []
        
        # Extract searchable fields from the rule
        name = rule_content.get('name', '')
        description = rule_content.get('description', '')
        query = str(rule_content.get('query', ''))
        
        # Combine all text fields for searching
        search_text = f"{name} {description} {query}".lower()
        
        # Look for existing tags - they may already have MITRE tags
        tags = rule_content.get('tags', [])
        for tag in tags:
            if tag.lower().startswith('attack.t'):
                # Extract technique ID from tag
                tid = tag.split('.')[-1].upper()
                if tid in self.mitre_data:
                    matches.add(tid)
        
        # Search in rule content for technique names and keywords
        for key, technique in self.mitre_data.items():
            # Skip if we already matched this technique
            tid = technique.get('technique_id', '').upper()
            if tid in matches:
                continue
                
            # Check for exact matches on technique ID
            if tid.lower() in search_text:
                matches.add(tid)
                continue
                
            # Check for technique name match (full words only)
            name = technique.get('name', '')
            if name and re.search(r'\b' + re.escape(name.lower()) + r'\b', search_text):
                matches.add(tid)
                continue
                
            # Check for keyword matches (full words only)
            keywords = technique.get('keywords', [])
            for keyword in keywords:
                if keyword and re.search(r'\b' + re.escape(keyword.lower()) + r'\b', search_text):
                    matches.add(tid)
                    break
        
        # Convert matches to technique dictionaries
        for tid in matches:
            for key, technique in self.mitre_data.items():
                if technique.get('technique_id', '').upper() == tid:
                    techniques.append(technique)
                    break
        
        return techniques
    
    def _update_rule_with_techniques(self, rule_content: Dict[str, Any], 
                                    techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Update a rule with MITRE ATT&CK technique information.
        
        Args:
            rule_content: The detection rule content.
            techniques: List of matching technique dictionaries.
            
        Returns:
            Updated rule content.
        """
        # Create a copy of the rule to modify
        updated_rule = rule_content.copy()
        
        # Initialize tags list if it doesn't exist
        if 'tags' not in updated_rule:
            updated_rule['tags'] = []
        
        # Add MITRE tags if they don't already exist
        for technique in techniques:
            tid = technique.get('technique_id', '').upper()
            tactic = technique.get('tactic', '').lower().replace(' ', '_')
            
            # Add technique tag
            tag = f"attack.t{tid}"
            if tag not in updated_rule['tags']:
                updated_rule['tags'].append(tag)
            
            # Add tactic tag if available
            if tactic:
                tag = f"attack.{tactic}"
                if tag not in updated_rule['tags']:
                    updated_rule['tags'].append(tag)
        
        # Add threat metadata if it doesn't exist
        if 'threat' not in updated_rule:
            updated_rule['threat'] = []
        
        # Add technique metadata to threat field
        for technique in techniques:
            # Avoid duplicating existing techniques
            exists = False
            for threat in updated_rule['threat']:
                if 'technique' in threat:
                    if threat['technique'].get('id', '') == technique.get('technique_id', ''):
                        exists = True
                        break
            
            if not exists:
                threat_entry = {
                    "framework": "MITRE ATT&CK",
                    "technique": {
                        "id": technique.get('technique_id', ''),
                        "name": technique.get('name', '')
                    }
                }
                
                # Add tactic if available
                if technique.get('tactic', ''):
                    threat_entry['tactic'] = {
                        "name": technique.get('tactic', ''),
                        "id": technique.get('tactic_id', '')
                    }
                
                updated_rule['threat'].append(threat_entry)
        
        return updated_rule
    
    def process_rule_file(self, file_path: str) -> bool:
        """
        Process a single rule file and tag it with MITRE ATT&CK information.
        
        Args:
            file_path: Path to the rule file.
            
        Returns:
            Boolean indicating if the rule was updated.
        """
        try:
            # Skip non-YAML files
            if not file_path.endswith(('.yml', '.yaml')):
                return False
                
            logger.info(f"Processing rule file: {file_path}")
            
            # Read the rule file
            with open(file_path, 'r') as f:
                rule_content = yaml.safe_load(f)
                
            if not rule_content:
                logger.warning(f"Empty rule file: {file_path}")
                return False
                
            # Find matching techniques
            techniques = self._find_matching_techniques(rule_content)
            
            if not techniques:
                logger.info(f"No matching techniques found for {file_path}")
                return False
                
            # Update the rule with technique information
            updated_rule = self._update_rule_with_techniques(rule_content, techniques)
            
            # Determine output path
            base_name = os.path.basename(file_path)
            output_path = os.path.join(self.output_dir, base_name)
            
            # Write the updated rule
            with open(output_path, 'w') as f:
                yaml.dump(updated_rule, f, default_flow_style=False, sort_keys=False)
                
            technique_ids = [t.get('technique_id', '') for t in techniques]
            logger.info(f"Tagged rule {base_name} with techniques: {', '.join(technique_ids)}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error processing rule file {file_path}: {str(e)}")
            self.errors += 1
            return False
    
    def process_rules(self) -> Dict[str, int]:
        """
        Process all rule files in the specified directory.
        
        Returns:
            Dictionary with stats about processed rules.
        """
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    self.rule_count += 1
                    
                    if self.process_rule_file(file_path):
                        self.tagged_count += 1
        
        logger.info(f"Processed {self.rule_count} rules, tagged {self.tagged_count} rules")
        logger.info(f"Encountered {self.errors} errors")
        
        return {
            'total': self.rule_count,
            'tagged': self.tagged_count,
            'errors': self.errors
        }

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='Tag detection rules with MITRE ATT&CK information')
    parser.add_argument('--mitre-file', default='config/mitre_techniques.json',
                      help='Path to MITRE ATT&CK mapping file')
    parser.add_argument('--rules-dir', required=True,
                      help='Directory containing detection rules to process')
    parser.add_argument('--output-dir',
                      help='Directory to write updated rules (default: overwrite original files)')
    args = parser.parse_args()
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Process rules
    tagger = RuleTagger(args.mitre_file, args.rules_dir, args.output_dir)
    tagger.process_rules()

if __name__ == "__main__":
    main() 