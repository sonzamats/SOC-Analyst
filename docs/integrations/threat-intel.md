# Threat Intelligence Integration Guide

This document provides information about integrating threat intelligence feeds into the Enterprise SOC SIEM Implementation to enrich security monitoring and detection capabilities.

## Overview

Threat intelligence integration enables the SIEM to correlate observed activities with known indicators of compromise (IOCs), threat actor TTPs, and emerging threats. This integration helps security teams prioritize alerts, reduce false positives, and provide context for investigation.

## Supported Threat Intelligence Sources

The SOC SIEM Implementation supports the following threat intelligence sources:

### 1. STIX/TAXII Feeds

**Description:** Structured Threat Information eXpression (STIX) is a standardized language for cyber threat intelligence. TAXII (Trusted Automated eXchange of Indicator Information) is the transport mechanism.

**Supported Versions:**
- STIX 1.x via TAXII 1.x
- STIX 2.x via TAXII 2.1

**Examples:**
- MITRE ATT&CK (STIX 2.x)
- US-CERT Automated Indicator Sharing (AIS)
- CIRCL.LU OpenTAXII
- EclecticIQ Intelligence Center

### 2. Open Source Feeds

**Description:** Free, publicly available threat intelligence feeds.

**Examples:**
- AlienVault OTX (API-based)
- Abuse.ch (Various feeds: URLhaus, SSL Blacklist, etc.)
- PhishTank
- Emerging Threats Open Rules
- Tor Exit Node List
- Feodo Tracker

### 3. Commercial Threat Intelligence Platforms

**Description:** Paid threat intelligence services with API access.

**Examples:**
- Recorded Future
- ThreatConnect
- Mandiant Threat Intelligence
- Crowdstrike Falcon Intelligence
- IBM X-Force Exchange

### 4. ISAC/ISAO Feeds

**Description:** Industry-specific threat intelligence sharing organizations.

**Examples:**
- FS-ISAC (Financial Services)
- H-ISAC (Healthcare)
- E-ISAC (Energy)
- Multiple ISAOs

### 5. Custom/Internal Sources

**Description:** Organization-specific intelligence sources.

**Examples:**
- Internally generated IOCs
- Threat hunting discoveries
- Incident response findings
- Partner-shared intelligence

## Integration Components

The threat intelligence integration framework consists of several components:

### 1. Threat Intel Collector

A Python script (`scripts/threat_intel_collector.py`) that connects to various threat intelligence sources, normalizes the data, and imports it into the SIEM.

**Features:**
- Supports multiple feed types (STIX/TAXII, API, CSV, MISP)
- Deduplication of indicators
- Format conversion and normalization
- Confidence scoring and filtering
- Scheduled updates via cron

### 2. Elasticsearch Threat Intel Index

A dedicated Elasticsearch index (`threat-intel-*`) that stores all threat intelligence data.

**Index Structure:**
- `indicator.type`: Type of indicator (IP, domain, hash, URL, etc.)
- `indicator.value`: The actual indicator value
- `threat.feed.name`: Source feed name
- `threat.indicator.confidence`: Confidence score (0-100)
- `threat.indicator.description`: Description of the threat
- `threat.indicator.first_seen`: First observation timestamp
- `threat.indicator.last_seen`: Last observation timestamp
- `threat.indicator.type`: Type of threat (malware, C2, phishing, etc.)
- `threat.indicator.ip_rep_score`: Reputation score for IPs
- `threat.indicator.domain_rep_score`: Reputation score for domains
- Additional contextual fields depending on indicator type

### 3. Logstash Enrichment Pipeline

A Logstash pipeline configuration (`logstash/pipelines/30-threat-intel-enrichment.conf`) that enriches incoming logs with threat intelligence data.

**Enrichment Types:**
- IP address matching
- Domain/hostname matching
- File hash matching
- URL matching
- Email address matching

### 4. Kibana Dashboards

A set of Kibana dashboards for visualizing threat intelligence data and matches.

**Dashboards:**
- Threat Intelligence Overview
- IOC Matches Dashboard
- Threat Feed Health Monitor
- MITRE ATT&CK Integration Dashboard

## Implementation Guide

### 1. Prerequisites

Before implementing threat intelligence integration, ensure:

- Elasticsearch cluster has sufficient resources
- Logstash is properly configured
- Network access to external threat intelligence sources is available
- API keys/credentials for commercial sources are obtained

### 2. Collector Configuration

1. Copy the example configuration file:
   ```
   cp config/threat_intel_config.example.yml config/threat_intel_config.yml
   ```

2. Edit the configuration file to include your sources:
   ```yaml
   sources:
     - name: "AlienVault OTX"
       type: "api"
       url: "https://otx.alienvault.com/api/v1/indicators/export"
       api_key: "YOUR_API_KEY"
       polling_interval: 3600
       enabled: true
       indicator_types:
         - ipv4
         - domain
         - url
         - file_hash
       confidence_level: 70
       
     - name: "MISP Instance"
       type: "misp"
       url: "https://misp.example.org"
       api_key: "YOUR_MISP_API_KEY"
       polling_interval: 3600
       enabled: true
       verify_ssl: true
       
     - name: "Custom CSV Feed"
       type: "csv"
       url: "https://internal.example.org/iocs.csv"
       polling_interval: 86400
       enabled: true
       indicator_column: 2
       indicator_type_column: 3
       delimiter: ","
       
     - name: "TAXII Feed"
       type: "taxii"
       url: "https://taxii.example.org/taxii/"
       collection_name: "collection1"
       username: "user"
       password: "pass"
       polling_interval: 86400
       enabled: true
       version: "2.1"
   
   global:
     enrichment_index: "threat-intel-indicators"
     historical_index: "threat-intel-historical"
     update_interval: 3600
     default_confidence: 50
     minimum_confidence: 30
   ```

3. Run the collector manually to test:
   ```
   python3 scripts/threat_intel_collector.py --config config/threat_intel_config.yml
   ```

4. Set up a cron job to run periodically:
   ```
   0 */6 * * * cd /path/to/soc-siem && python3 scripts/threat_intel_collector.py --config config/threat_intel_config.yml >> /var/log/threat-intel-collector.log 2>&1
   ```

### 3. Logstash Enrichment Configuration

1. Edit the Logstash enrichment pipeline:
   ```
   vi logstash/pipelines/30-threat-intel-enrichment.conf
   ```

2. Configure the enrichment filter:
   ```
   filter {
     # IP enrichment
     if [source][ip] or [destination][ip] {
       elasticsearch {
         hosts => ["elasticsearch:9200"]
         user => "elastic"
         password => "${ELASTIC_PASSWORD}"
         index => "threat-intel-indicators-*"
         query => "indicator.type:ip AND indicator.value:%{[source][ip]}"
         fields => { 
           "threat" => "[source][threat]"
         }
         tag_on_failure => ["_elasticsearch_lookup_failure_source_ip"]
       }
       
       elasticsearch {
         hosts => ["elasticsearch:9200"]
         user => "elastic"
         password => "${ELASTIC_PASSWORD}"
         index => "threat-intel-indicators-*"
         query => "indicator.type:ip AND indicator.value:%{[destination][ip]}"
         fields => { 
           "threat" => "[destination][threat]"
         }
         tag_on_failure => ["_elasticsearch_lookup_failure_destination_ip"]
       }
     }
     
     # Domain enrichment
     if [dns][question][name] {
       elasticsearch {
         hosts => ["elasticsearch:9200"]
         user => "elastic"
         password => "${ELASTIC_PASSWORD}"
         index => "threat-intel-indicators-*"
         query => "indicator.type:domain AND indicator.value:%{[dns][question][name]}"
         fields => { 
           "threat" => "[dns][threat]"
         }
         tag_on_failure => ["_elasticsearch_lookup_failure_dns"]
       }
     }
     
     # File hash enrichment
     if [file][hash][md5] or [file][hash][sha1] or [file][hash][sha256] {
       if [file][hash][sha256] {
         elasticsearch {
           hosts => ["elasticsearch:9200"]
           user => "elastic"
           password => "${ELASTIC_PASSWORD}"
           index => "threat-intel-indicators-*"
           query => "indicator.type:file AND indicator.value:%{[file][hash][sha256]}"
           fields => { 
             "threat" => "[file][threat]"
           }
           tag_on_failure => ["_elasticsearch_lookup_failure_file_hash_sha256"]
         }
       } else if [file][hash][sha1] {
         elasticsearch {
           hosts => ["elasticsearch:9200"]
           user => "elastic"
           password => "${ELASTIC_PASSWORD}"
           index => "threat-intel-indicators-*"
           query => "indicator.type:file AND indicator.value:%{[file][hash][sha1]}"
           fields => { 
             "threat" => "[file][threat]"
           }
           tag_on_failure => ["_elasticsearch_lookup_failure_file_hash_sha1"]
         }
       } else if [file][hash][md5] {
         elasticsearch {
           hosts => ["elasticsearch:9200"]
           user => "elastic"
           password => "${ELASTIC_PASSWORD}"
           index => "threat-intel-indicators-*"
           query => "indicator.type:file AND indicator.value:%{[file][hash][md5]}"
           fields => { 
             "threat" => "[file][threat]"
           }
           tag_on_failure => ["_elasticsearch_lookup_failure_file_hash_md5"]
         }
       }
     }
     
     # Add enrichment flag if threat data was found
     if [source][threat] or [destination][threat] or [dns][threat] or [file][threat] {
       mutate {
         add_field => { "threat_match" => "true" }
         add_tag => [ "threat_intelligence_match" ]
       }
     }
   }
   ```

3. Restart Logstash to apply changes:
   ```
   docker-compose restart logstash
   ```

### 4. Alert and Dashboard Setup

1. Import the Threat Intelligence dashboards:
   ```
   ./scripts/setup-directories.sh --import-dashboards dashboards/threat-intel
   ```

2. Create alerting rules that leverage threat intelligence:
   - Navigate to Kibana > Security > Rules
   - Create a new rule with the condition: `threat_match: true`
   - Customize severity based on threat confidence scores

## Use Cases

### 1. Network Traffic Enrichment

**Scenario:** Correlate network connections with known malicious IP addresses.

**Implementation:**
1. Configure the threat intel collector to import IP watchlists
2. Ensure the Logstash pipeline enriches network flow logs
3. Create alerts for any traffic to/from known malicious IPs
4. Add severity escalation for connections to high-confidence IOCs

### 2. Domain Reputation Checking

**Scenario:** Identify DNS lookups and web traffic to malicious domains.

**Implementation:**
1. Configure domain/URL intelligence feeds
2. Enrich DNS query logs and web proxy logs
3. Alert on access attempts to known malicious domains
4. Create dashboards showing top malicious domain access attempts

### 3. Malware Detection via Hashes

**Scenario:** Identify known malicious files by their hash values.

**Implementation:**
1. Import file hash IOCs from threat intel sources
2. Configure endpoint logs to include file hash information
3. Enrich file events with threat intelligence
4. Alert on detection of files with known malicious hashes

### 4. Threat Actor Attribution

**Scenario:** Correlate observed activity with known threat actor TTPs.

**Implementation:**
1. Import STIX 2.0 data with threat actor information
2. Create a custom dashboard showing potential threat actor matches
3. Develop MITRE ATT&CK-based correlation rules
4. Include attribution information in alerts when confidence is high

## Maintenance and Optimization

### Indicator Lifecycle Management

Configure expiration for indicators to prevent database bloat:

```yaml
global:
  indicator_expiration:
    default: 90  # days
    ip: 30       # days for IP indicators
    url: 14      # days for URL indicators
```

### Performance Considerations

For large-scale deployments:

1. **Index Optimization:**
   - Use ILM policies to manage threat intel indices
   - Consider time-based indices for historical tracking

2. **Caching Strategy:**
   - Enable in-memory caching for frequently matched indicators
   - Configure the `scripts/threat_intel_cache_warmer.py` script

3. **Selective Enrichment:**
   - Only enrich high-value log sources rather than all data
   - Create dedicated Logstash pipelines for specific use cases

### Feed Quality Management

Periodically review feed quality and usefulness:

1. Run the feed quality report:
   ```
   python3 scripts/threat_intel_quality_report.py
   ```

2. The report provides metrics on:
   - False positive rates by feed
   - Alert volumes generated by each feed
   - Indicator uniqueness and overlap between feeds
   - Age distribution of indicators

3. Based on the report, adjust feed configuration:
   - Disable low-quality feeds
   - Adjust confidence thresholds
   - Modify polling intervals

## Troubleshooting

### Common Issues

1. **No Indicators in Index:**
   - Check collector logs for API errors
   - Verify network connectivity to sources
   - Validate API credentials

2. **No Enrichment in Logs:**
   - Ensure field mappings match in collector and Logstash config
   - Verify Logstash has access to Elasticsearch
   - Check for Elasticsearch query errors in Logstash logs

3. **High False Positive Rate:**
   - Increase minimum confidence threshold
   - Add more context to indicator matching rules
   - Implement whitelisting for known-good indicators

### Diagnostic Commands

1. Check indicator count by type:
   ```
   curl -X GET "localhost:9200/threat-intel-indicators-*/_search?pretty" -H 'Content-Type: application/json' -d'
   {
     "size": 0,
     "aggs": {
       "indicator_types": {
         "terms": {
           "field": "indicator.type",
           "size": 10
         }
       }
     }
   }'
   ```

2. Check feed health:
   ```
   curl -X GET "localhost:9200/threat-intel-health-*/_search?pretty" -H 'Content-Type: application/json' -d'
   {
     "size": 10,
     "sort": [
       {
         "@timestamp": {
           "order": "desc"
         }
       }
     ]
   }'
   ```

3. Force refresh of threat intelligence:
   ```
   python3 scripts/threat_intel_collector.py --config config/threat_intel_config.yml --force-refresh
   ```

## References

- [Elastic Common Schema (ECS) Threat Fields](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html) 