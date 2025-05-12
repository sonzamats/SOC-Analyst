# SOC SIEM Troubleshooting Guide

This guide provides solutions for common issues encountered when deploying, configuring, and operating the Enterprise SOC SIEM Implementation.

## Table of Contents
- [Elasticsearch Issues](#elasticsearch-issues)
- [Logstash Issues](#logstash-issues)
- [Kibana Issues](#kibana-issues)
- [Beats Collector Issues](#beats-collector-issues)
- [Wazuh Issues](#wazuh-issues)
- [TheHive & Cortex Issues](#thehive--cortex-issues)
- [Shuffle SOAR Issues](#shuffle-soar-issues)
- [Integration Issues](#integration-issues)
- [Performance Issues](#performance-issues)
- [Data Issues](#data-issues)
- [Alerting Issues](#alerting-issues)
- [Common Error Messages](#common-error-messages)

## Elasticsearch Issues

### Elasticsearch Won't Start

**Symptoms:**
- Elasticsearch service fails to start
- Error messages in logs about bootstrap checks failing

**Possible Causes & Solutions:**

1. **Insufficient System Resources**
   ```bash
   # Check system memory
   free -h
   
   # Check disk space
   df -h
   
   # Check open file limits
   ulimit -a
   ```
   
   **Solution:** Increase memory, disk space, or file descriptors as needed:
   ```bash
   # Edit /etc/elasticsearch/jvm.options to adjust memory
   # Set appropriate values (don't exceed 50% of system RAM)
   -Xms2g
   -Xmx2g
   
   # Increase file descriptors in /etc/security/limits.conf
   elasticsearch soft nofile 65536
   elasticsearch hard nofile 65536
   ```

2. **Incorrect Permissions**
   ```bash
   # Fix data directory permissions
   chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
   chmod -R 750 /var/lib/elasticsearch
   ```

3. **Invalid Configuration**
   ```bash
   # Check configuration for errors
   /usr/share/elasticsearch/bin/elasticsearch --verify-config
   ```

### Cluster Status Red

**Symptoms:**
- Kibana reports cluster health as red
- Some indices may be unavailable
- Search operations may fail

**Solutions:**

1. **Identify Problem Indices**
   ```bash
   # Get list of red indices
   curl -X GET "localhost:9200/_cat/indices?v&health=red"
   ```

2. **Check Unassigned Shards**
   ```bash
   # Get information about unassigned shards
   curl -X GET "localhost:9200/_cluster/allocation/explain?pretty"
   ```

3. **Fix Common Shard Allocation Issues**
   ```bash
   # For disk space issues, increase threshold
   curl -X PUT "localhost:9200/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
   {
     "persistent": {
       "cluster.routing.allocation.disk.threshold_enabled": false
     }
   }
   '
   
   # Re-enable after fixing disk space
   curl -X PUT "localhost:9200/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
   {
     "persistent": {
       "cluster.routing.allocation.disk.threshold_enabled": true
     }
   }
   '
   ```

### High Disk Usage in Elasticsearch

**Symptoms:**
- Rapidly filling disk space
- Warnings about high disk watermark reached

**Solutions:**

1. **Check Index Sizes**
   ```bash
   curl -X GET "localhost:9200/_cat/indices?v&s=store.size:desc"
   ```

2. **Implement/Review Index Lifecycle Management**
   ```bash
   # Create ILM policy
   curl -X PUT "localhost:9200/_ilm/policy/siem_logs_policy?pretty" -H 'Content-Type: application/json' -d'
   {
     "policy": {
       "phases": {
         "hot": {
           "min_age": "0ms",
           "actions": {
             "rollover": {
               "max_age": "7d",
               "max_size": "50gb"
             }
           }
         },
         "warm": {
           "min_age": "30d",
           "actions": {
             "shrink": {
               "number_of_shards": 1
             },
             "forcemerge": {
               "max_num_segments": 1
             }
           }
         },
         "cold": {
           "min_age": "60d",
           "actions": {}
         },
         "delete": {
           "min_age": "90d",
           "actions": {
             "delete": {}
           }
         }
       }
     }
   }
   '
   ```

## Logstash Issues

### Logstash Not Starting

**Symptoms:**
- Service fails to start
- Error messages in logs

**Solutions:**

1. **JVM Memory Issues**
   ```bash
   # Edit /etc/logstash/jvm.options
   -Xms1g
   -Xmx1g
   ```

2. **Configuration Syntax Errors**
   ```bash
   # Test configuration files
   /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/*.conf
   ```

3. **Pipeline Validation**
   ```bash
   # Check for configuration errors in specific pipeline
   /usr/share/logstash/bin/logstash -tf /etc/logstash/conf.d/problematic-pipeline.conf
   ```

### Logstash Processing Delays

**Symptoms:**
- High processing times
- Growing input queue
- Delayed log ingestion

**Solutions:**

1. **Optimize Filter Configuration**
   - Reduce complex regex patterns
   - Move frequently used patterns to the top of conditionals
   - Use if/else statements efficiently

2. **Increase Worker Capacity**
   ```ruby
   # In logstash.yml
   pipeline.workers: 4  # Adjust based on available CPU cores
   pipeline.batch.size: 250
   ```

3. **Monitor Performance**
   ```bash
   # Enable API monitoring in logstash.yml
   http.host: "0.0.0.0"
   http.port: 9600
   
   # Check pipeline stats
   curl -X GET 'http://localhost:9600/_node/stats/pipelines?pretty'
   ```

### Logstash Parse Failures

**Symptoms:**
- `_grokparsefailure` tags in documents
- Missing fields in processed documents

**Solutions:**

1. **Debug Grok Patterns**
   ```ruby
   filter {
     grok {
       match => { "message" => "%{PATTERN}" }
       tag_on_failure => ["_grokparsefailure", "specific_pattern_failed"]
       named_captures_only => true
     }
   }
   ```

2. **Test Pattern on Sample Data**
   - Use [Grok Debugger](https://grokdebug.herokuapp.com/) or Kibana Dev Tools
   - Adjust patterns to accommodate variations in log formats

3. **Add Multiple Match Patterns**
   ```ruby
   filter {
     grok {
       match => [
         "message", "pattern1",
         "message", "pattern2",
         "message", "pattern3"
       ]
     }
   }
   ```

## Kibana Issues

### Kibana Not Connecting to Elasticsearch

**Symptoms:**
- "Kibana server is not ready yet" message
- Unable to load Kibana interface
- Connection errors in logs

**Solutions:**

1. **Check Elasticsearch Connectivity**
   ```bash
   # Verify Elasticsearch is running
   curl -X GET "localhost:9200/"
   
   # Check Kibana configuration
   cat /etc/kibana/kibana.yml
   ```

2. **Verify Settings in kibana.yml**
   ```yaml
   elasticsearch.hosts: ["http://localhost:9200"]
   elasticsearch.username: "kibana_system"
   elasticsearch.password: "password"
   ```

3. **Check Network Issues**
   ```bash
   # Test network connection
   telnet elasticsearch 9200
   
   # Check firewall status
   sudo ufw status
   ```

### Visualizations Not Loading Data

**Symptoms:**
- Blank visualizations
- "No results found" message
- Error loading data

**Solutions:**

1. **Verify Index Patterns**
   - Go to Stack Management > Index Patterns
   - Ensure pattern matches existing indices
   - Recreate index pattern if needed

2. **Check Time Range**
   - Adjust time filter to match when data was ingested
   - Use "Last 30 days" initially to ensure data is in view

3. **Inspect Queries**
   - Click "Inspect" on visualization
   - Review request and response for errors
   - Modify query to match existing data

### Kibana Performance Issues

**Symptoms:**
- Slow dashboard loading
- Browser high memory usage
- Timeouts when loading visualizations

**Solutions:**

1. **Optimize Dashboards**
   - Reduce number of visualizations per dashboard
   - Use time-based indices for faster queries
   - Implement dashboard filters to narrow search scope

2. **Adjust Browser Settings**
   ```yaml
   # In kibana.yml
   server.maxPayloadBytes: 10485760
   ```

3. **Tune Elasticsearch for Kibana**
   ```yaml
   # In elasticsearch.yml
   search.max_buckets: 10000
   search.max_keep_alive: 24h
   ```

## Beats Collector Issues

### Filebeat Not Shipping Logs

**Symptoms:**
- No data in Elasticsearch
- No errors in Filebeat logs
- Increasing CPU/memory usage

**Solutions:**

1. **Check Configuration**
   ```bash
   filebeat test config -c /etc/filebeat/filebeat.yml
   ```

2. **Verify Output Connectivity**
   ```bash
   filebeat test output -c /etc/filebeat/filebeat.yml
   ```

3. **Inspect Harvester Status**
   ```bash
   # Check if files are being monitored
   filebeat -c /etc/filebeat/filebeat.yml -e -d "publish"
   ```

4. **File Permissions**
   ```bash
   # Ensure Filebeat can read log files
   sudo chmod 644 /path/to/log/files/*.log
   ```

### Winlogbeat Missing Events

**Symptoms:**
- Specific Windows events not appearing in Elasticsearch
- Incomplete event data

**Solutions:**

1. **Check Event Log Permissions**
   - Ensure Winlogbeat service runs with appropriate permissions
   - Grant "Read" permissions on Windows Event Logs

2. **Verify Event Channel Configuration**
   ```yaml
   winlogbeat.event_logs:
     - name: Security
       ignore_older: 72h
       include_xml: true  # Add for full event data
   ```

3. **Enable Debug Logging**
   ```yaml
   logging.level: debug
   logging.to_files: true
   logging.files:
     path: C:/ProgramData/winlogbeat/logs
   ```

## Wazuh Issues

### Wazuh Manager Not Starting

**Symptoms:**
- Service fails to start
- Error messages in `/var/ossec/logs/ossec.log`

**Solutions:**

1. **Check Configuration**
   ```bash
   /var/ossec/bin/ossec-logtest
   ```

2. **Fix Database Issues**
   ```bash
   # Stop Wazuh
   systemctl stop wazuh-manager
   
   # Fix database
   rm -f /var/ossec/queue/db/*.db*
   /var/ossec/bin/ossec-analysisd -t
   
   # Start Wazuh
   systemctl start wazuh-manager
   ```

3. **Verify File Permissions**
   ```bash
   # Reset permissions
   chmod 750 /var/ossec/etc
   chown root:wazuh /var/ossec/etc
   ```

### Wazuh Agents Not Connecting

**Symptoms:**
- Agents show as disconnected in Wazuh dashboard
- Authentication errors in agent logs

**Solutions:**

1. **Check Agent Status**
   ```bash
   # On agent
   /var/ossec/bin/agent_control -l
   
   # On manager
   /var/ossec/bin/agent_control -i <agent_id>
   ```

2. **Verify Network Connectivity**
   ```bash
   # Test connectivity to manager
   telnet <manager_ip> 1514
   telnet <manager_ip> 1515
   ```

3. **Regenerate Authentication Keys**
   ```bash
   # On manager
   /var/ossec/bin/manage_agents -r <agent_id>
   
   # Generate new key
   /var/ossec/bin/manage_agents -a -n <agent_name> -i <agent_ip>
   
   # Extract key
   /var/ossec/bin/manage_agents -e <agent_id>
   
   # On agent, import key
   /var/ossec/bin/manage_agents -i <key>
   ```

## TheHive & Cortex Issues

### TheHive Database Connection Issues

**Symptoms:**
- Service fails to start
- Database connection errors in logs

**Solutions:**

1. **Check Database Connection**
   ```bash
   # For Elasticsearch backend
   curl -X GET "http://localhost:9200/_cluster/health?pretty"
   
   # For Cassandra backend
   nodetool status
   ```

2. **Verify Database Configuration**
   ```bash
   # Check TheHive configuration
   cat /etc/thehive/application.conf
   ```

3. **Reset TheHive Database (Last Resort)**
   ```bash
   # For Elasticsearch backend
   curl -X DELETE "http://localhost:9200/the_hive_*"
   
   # Restart service
   systemctl restart thehive
   ```

### Cortex Analyzer Failures

**Symptoms:**
- Analyzers failing to run
- "Invalid API key" errors
- Missing results in TheHive

**Solutions:**

1. **Check Analyzer Configuration**
   - Verify API keys in analyzer configuration files
   - Ensure external services are accessible

2. **Test Individual Analyzers**
   ```bash
   # Check analyzer status
   curl -H "Authorization: Bearer <api_key>" http://localhost:9001/api/analyzer
   ```

3. **Verify Cortex-TheHive Integration**
   - Check Cortex API key in TheHive configuration
   - Ensure correct Cortex URL in TheHive settings

## Shuffle SOAR Issues

### Workflows Not Executing

**Symptoms:**
- Workflows triggered but not completing
- Actions failing within workflows
- Execution errors in logs

**Solutions:**

1. **Check App Connectivity**
   - Verify API endpoints are accessible from Shuffle
   - Test individual app actions in isolation

2. **Review Workflow Variables**
   - Ensure environment variables are correctly set
   - Verify variable values are passed between nodes

3. **Debug Mode**
   - Enable debug mode in workflow execution settings
   - Check execution logs for specific errors at each step

### App Authentication Issues

**Symptoms:**
- "Authentication failed" errors
- Apps show as disconnected
- API calls failing

**Solutions:**

1. **Verify Credentials**
   - Update API keys, tokens, or passwords
   - Check for expired credentials

2. **Test API Connection**
   ```bash
   # Example using curl for a REST API
   curl -H "Authorization: Bearer <token>" https://api-endpoint.example.com
   ```

3. **Check Network Connectivity**
   - Ensure Shuffle can reach external services
   - Verify proxy settings if applicable

## Integration Issues

### SIEM-Ticketing System Integration

**Symptoms:**
- Alerts not creating tickets
- Missing information in tickets
- Webhook failures

**Solutions:**

1. **Check Webhook Configuration**
   - Verify endpoint URLs are correct
   - Ensure authentication tokens are valid
   - Test webhook manually:
   ```bash
   curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"title":"Test Alert","description":"Testing webhook"}' https://ticketing-system/api/webhooks
   ```

2. **Review Mapping Configuration**
   - Ensure field mappings match expected formats
   - Check for required fields in the integration template

3. **Enable Detailed Logging**
   - Increase logging level for the integration service
   - Monitor webhook responses for error codes

### Email Notification Issues

**Symptoms:**
- Alerts not triggering emails
- Emails delivered to spam folder
- Formatting issues in email content

**Solutions:**

1. **Verify SMTP Configuration**
   ```bash
   # Test SMTP connection
   openssl s_client -connect smtp.example.com:587 -starttls smtp
   ```

2. **Check Email Templates**
   - Ensure templates have proper HTML formatting
   - Verify variable substitution is working

3. **Authenticate Sender Domain**
   - Configure SPF, DKIM, and DMARC records
   - Use authorized sending domains

## Performance Issues

### High CPU Usage

**Symptoms:**
- Sustained high CPU on Elasticsearch nodes
- System becoming unresponsive
- Slow query response times

**Solutions:**

1. **Identify Resource-Intensive Operations**
   ```bash
   # Find hot threads in Elasticsearch
   curl -X GET "localhost:9200/_nodes/hot_threads?pretty"
   
   # Check top processes
   top -c
   ```

2. **Optimize Query Performance**
   - Use query profiling in Kibana Dev Tools
   - Implement more specific filters
   - Avoid wildcard queries when possible

3. **Adjust JVM Settings**
   ```bash
   # Edit jvm.options for appropriate heap size
   -Xms4g
   -Xmx4g
   ```

### Memory Issues

**Symptoms:**
- Services crashing with OOM errors
- Swapping affecting performance
- High memory usage warnings

**Solutions:**

1. **Check Memory Usage**
   ```bash
   # View memory statistics
   free -h
   
   # Check if swapping is occurring
   vmstat 1 10
   ```

2. **Adjust Memory Settings**
   - Limit Elasticsearch heap size to 50% of system RAM
   - Tune Logstash batch sizes and worker counts

3. **Enable Memory Circuit Breakers**
   ```bash
   # Configure Elasticsearch circuit breakers
   curl -X PUT "localhost:9200/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
   {
     "persistent": {
       "indices.breaker.total.limit": "70%",
       "indices.breaker.request.limit": "60%",
       "indices.breaker.fielddata.limit": "40%"
     }
   }
   '
   ```

### Slow Search Performance

**Symptoms:**
- Dashboard loading takes excessive time
- Search queries timing out
- High query latency

**Solutions:**

1. **Optimize Index Settings**
   ```bash
   # Increase refresh interval for write-heavy indices
   curl -X PUT "localhost:9200/my-index/_settings?pretty" -H 'Content-Type: application/json' -d'
   {
     "index": {
       "refresh_interval": "30s"
     }
   }
   '
   ```

2. **Implement Index Lifecycle Management**
   - Move older indices to warm/cold storage
   - Use force-merge on read-only indices

3. **Use Index Templates with Optimized Mappings**
   - Limit fields that are indexed
   - Use appropriate data types (keyword vs text)
   - Disable index-time scoring for logs

## Data Issues

### Missing or Incomplete Data

**Symptoms:**
- Gaps in timelines
- Expected logs not appearing
- Partial records

**Solutions:**

1. **Verify Log Collection**
   ```bash
   # Check agent status
   filebeat status
   
   # Examine log files for collection gaps
   tail -f /var/log/filebeat/filebeat
   ```

2. **Review Pipeline Errors**
   ```bash
   # Check Logstash pipeline errors
   curl -X GET 'http://localhost:9600/_node/stats/pipelines?pretty'
   ```

3. **Test Input Sources**
   - Ensure logs are being generated
   - Check file permissions and rotation settings
   - Verify agent access to log sources

### Data Parsing Errors

**Symptoms:**
- Fields missing from documents
- Incorrect field types
- `_grokparsefailure` tags

**Solutions:**

1. **Review Grok Patterns**
   - Update patterns to match current log formats
   - Create multiple patterns for variations

2. **Enable Debug Logging**
   ```bash
   # In logstash.yml
   log.level: debug
   ```

3. **Use Dissect Instead of Grok for Simple Logs**
   ```ruby
   filter {
     dissect {
       mapping => {
         "message" => "%{timestamp} %{+timestamp} %{level} %{message}"
       }
     }
   }
   ```

### Index Lifecycle Issues

**Symptoms:**
- Indices not rolling over
- Old indices not moving to warm/cold phases
- Index lifecycle errors in logs

**Solutions:**

1. **Check ILM Status**
   ```bash
   # View ILM status
   curl -X GET "localhost:9200/_ilm/status?pretty"
   
   # Check policy execution
   curl -X GET "localhost:9200/_ilm/policy/my_policy?pretty"
   ```

2. **Debug Index Status**
   ```bash
   # Check index with ILM issues
   curl -X GET "localhost:9200/problematic-index/_ilm/explain?pretty"
   ```

3. **Manually Move Index to Correct Phase**
   ```bash
   # Force index to move to next phase
   curl -X POST "localhost:9200/_ilm/move/problematic-index?pretty"
   ```

## Alerting Issues

### Alerts Not Triggering

**Symptoms:**
- Expected alerts not firing
- Rules showing 0 matches when they should match
- Missing notifications

**Solutions:**

1. **Verify Rule Syntax**
   - Check query syntax in alert definition
   - Test query directly in Kibana Dev Tools

2. **Check Indices and Mappings**
   - Ensure alert is watching the correct indices
   - Verify field names match current index mappings

3. **Review Time Windows**
   - Adjust alert time window to match data ingestion timing
   - Check timezone settings in alert configuration

### False Positive Alerts

**Symptoms:**
- Too many irrelevant alerts
- Alerts triggered by normal activity

**Solutions:**

1. **Refine Rule Conditions**
   - Add exclusions for known good patterns
   - Increase thresholds for noise reduction

2. **Implement Aggregation**
   - Group related events before alerting
   - Use cardinality aggregations for unusual behavior

3. **Whitelist Known Good**
   ```json
   {
     "query": {
       "bool": {
         "must": [
           {"match": {"event.type": "authentication_failure"}}
         ],
         "must_not": [
           {"terms": {"source.ip": ["192.168.1.100", "10.0.0.25"]}}
         ]
       }
     }
   }
   ```

## Common Error Messages

| Error Message | Possible Cause | Solution |
|---------------|----------------|----------|
| `Cluster health status changed from [YELLOW] to [RED]` | Unassigned primary shards | Check disk space, restart node, or restore from snapshot |
| `circuit_breaking_exception: [parent] Data too large` | Query or aggregation using too much memory | Simplify query, add filters, or increase circuit breaker limits |
| `cannot allocate because allocation is not permitted` | Disk threshold reached | Free up disk space or adjust disk threshold settings |
| `Connection refused to Elasticsearch` | Elasticsearch not running or network issue | Verify ES is running, check firewall settings |
| `Unable to authenticate user` | Invalid credentials or expired token | Update credentials, check user permissions |
| `Timeout connecting to Elasticsearch` | Network latency or ES overloaded | Check network, increase timeout settings |
| `FORBIDDEN/12/index read-only` | Index marked read-only due to disk space | Free up disk space, then clear read-only flag |
| `Failed to parse mapping [_doc]` | Invalid mapping definition | Fix field mapping syntax |
| `Cannot create index [...] because it matches with template pattern` | Conflicting index templates | Update template priorities or patterns |
| `No Living connections` | All Elasticsearch nodes unreachable | Check cluster health, network connectivity |
| `Logstash Could not find codec` | Missing plugin or typo in config | Install required plugins, check codec name |
| `Pipeline worker error` | Error in Logstash pipeline | Check filter configuration, increase worker timeout |
| `max file descriptors [4096] for elasticsearch process is too low` | System limits too restrictive | Increase ulimit settings for Elasticsearch user |
| `max virtual memory areas vm.max_map_count [65530] is too low` | VM settings too restrictive | Increase vm.max_map_count to 262144 |
| `filebeat harvester error` | File permission issues | Check file permissions, ensure Filebeat has read access |
| `Field is not valid` | Field referenced in visualization doesn't exist | Update field reference or recreate index pattern |
| `Deprecated field [...]` | Using outdated field or syntax | Update to newer syntax or field names |

## Diagnostic Commands

### Elasticsearch Health Check
```bash
# Check cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# View node stats
curl -X GET "localhost:9200/_nodes/stats?pretty"

# List indices with health
curl -X GET "localhost:9200/_cat/indices?v&h=index,health,status,docs.count,store.size"
```

### Logstash Diagnostics
```bash
# Test specific pipeline
/usr/share/logstash/bin/logstash -tf /etc/logstash/conf.d/pipeline.conf

# View pipeline stats
curl -X GET 'http://localhost:9600/_node/stats/pipelines?pretty'

# List plugins
/usr/share/logstash/bin/logstash-plugin list
```

### Log Collection Diagnostics
```bash
# Test Filebeat config
filebeat test config -c /etc/filebeat/filebeat.yml

# Test Filebeat output
filebeat test output -c /etc/filebeat/filebeat.yml

# Check Filebeat status
filebeat status -c /etc/filebeat/filebeat.yml
```

### System Resource Checks
```bash
# Check disk space
df -h

# View memory usage
free -h

# Monitor system in real time
top -c
```

## Support Resources

If you're unable to resolve an issue using this guide:

1. **Search Documentation**
   - [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
   - [Wazuh Documentation](https://documentation.wazuh.com/)
   - [TheHive Documentation](https://docs.thehive-project.org/)

2. **Community Support**
   - [Elastic Community Forums](https://discuss.elastic.co/)
   - [Wazuh Google Group](https://groups.google.com/g/wazuh)
   - [TheHive Project on Gitter](https://gitter.im/TheHive-Project/TheHive)

3. **Commercial Support**
   - Contact your support provider 
   - Submit a support ticket via your vendor portal