![Tests](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/actions/workflows/test.yml/badge.svg)
![Coverage
Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/3c445ef26310e9f2d2ca09c697db1c71/raw/SigmaHQ-pySigma-backend-elasticsearch.json)
![Status](https://img.shields.io/badge/Status-release-green)

# pySigma Elasticsearch Backend

This is the Elasticsearch backend for pySigma. It provides the package `sigma.backends.elasticsearch` with the `LuceneBackend` class.

It supports the following output formats:

* default: Lucene queries.
* dsl_lucene: DSL with embedded Lucene queries.
* eql: Elastic Event Query Language queries.
* kibana_ndjson: Kibana NDJSON with Lucene queries.

Further, it contains the following processing pipelines in `sigma.pipelines.elasticsearch`:

* ecs_windows in windows submodule: ECS mapping for Windows event logs ingested with Winlogbeat.
* ecs_windows_old in windows submodule: ECS mapping for Windows event logs ingested with Winlogbeat <= 6.x.
* ecs_zeek_beats in zeek submodule: Zeek ECS mapping from Elastic.
* ecs_zeek_corelight in zeek submodule: Zeek ECS mapping from Corelight.
* zeek_raw in zeek submodule: Zeek raw JSON log field naming.
* ecs_kubernetes in kubernetes submodule: ECS mapping for Kubernetes audit logs ingested with Kubernetes integration.
* ecs_macos_esf in macos submodule: ECS mapping for macOS Endpoint Security Framework (ESF) events.

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/SigmaHQ/)
* [Hendrik Bäcker](https://github.com/andurin)

Further maintainers required! Send a message to [Thomas](mailto:thomas@patzke.org) if you want to co-maintain this
backend.

## Processing Pipelines: Purpose and Differences

All processing pipelines in this backend serve a unified purpose: **transform Sigma detection rules (which use generic Sigma taxonomy field names like `Image`, `CommandLine`, `ProcessId`) into Elasticsearch queries using Elastic Common Schema (ECS) field naming conventions** that match how logs are stored after being ingested by different log collection agents.

The pipelines act as adapters between:
- **Input**: Sigma rules using standardized field taxonomy
- **Output**: Elasticsearch queries using platform-specific and ingestion-method-specific ECS field names

This allows security analysts to write detection rules once and apply them across multiple data sources, platforms, and log collection methods.

### Pipeline Categories and Data Flow

#### **Windows Pipelines** (Windows Event Logs)

Three pipelines handle Windows event log ingestion via different Winlogbeat versions and Elastic Defend:

1. **`ecs_windows`** - For Winlogbeat ≥ 7.x
   - Maps 100+ Windows event fields to modern ECS format (e.g., `EventID` → `event.code`, `Image` → `process.executable`)
   - Conditionally maps fields that differ based on event category/service (e.g., `CommandLine` maps to `process.command_line` for process creation but `powershell.command.value` for PowerShell logs)
   - Adds `winlog.event_data.` prefix to unmapped fields
   - Supported by: Elasticsearch, EQL, ES|QL, Lucene, OpenSearch

2. **`ecs_windows_old`** - For Winlogbeat ≤ 6.x
   - Handles legacy field naming: `event_id` instead of `event.code`, `event_data.*` instead of `winlog.event_data.*`
   - Minimal field mapping for backward compatibility
   - Supported by: Elasticsearch, EQL, ES|QL, Lucene, OpenSearch

3. **`ecs_windows_elastic_defend`** (Add-on) - For Elastic Defend EDR Agent
   - Remaps executable and process name fields to `.caseless` subfields for case-insensitive Lucene matching
   - Works in conjunction with `ecs_windows` for Elastic Defend-collected data
   - Addresses case-sensitivity in Windows filesystem paths

#### **Network/IDS Pipelines** (Zeek Network Detection)

Three pipelines handle Zeek IDS/NSM log ingestion via different methods:

1. **`ecs_zeek_beats`** - For Zeek logs ingested via Filebeat
   - Remaps Zeek log categories to services (e.g., `firewall` → `conn`, `dns` → `dns`, `proxy` → `http`)
   - Maps 100+ Zeek-specific network fields to ECS (e.g., `src_ip` → `source.ip`, `ssl_cipher` → `zeek.ssl.cipher`)
   - Preserves protocol-specific metadata under the `zeek.*` namespace
   - Adds `event.dataset: zeek.$service` condition for index targeting
   - Supported by: Elasticsearch, EQL, ES|QL, Lucene, OpenSearch

2. **`ecs_zeek_corelight`** - For Zeek logs from Corelight Sensors
   - Adapts to Corelight-specific log format variations
   - Use when ingesting Zeek data via Corelight security sensors rather than vanilla Filebeat

3. **`zeek_raw`** - For Direct Zeek JSON Logs
   - Minimal transformation; preserves native Zeek field names (`src_ip`, `dst_ip`, `uid`, etc.)
   - For advanced users requiring direct access to Zeek field naming
   - No index conditions added

#### **Container/Orchestration Pipeline** (Kubernetes Audit Logs)

1. **`ecs_kubernetes`** - For Kubernetes Audit Logs via Kubernetes Integration
   - Maps Kubernetes audit event fields to ECS (e.g., `verb` → `kubernetes.audit.verb`, `username` → `kubernetes.audit.user.username`)
   - Adds index condition filtering: `kubernetes.audit.kind: "Event"`
   - Drops empty `apiGroup` and `subresource` fields to reduce noise
   - Supported by: Elasticsearch, EQL, ES|QL, Lucene

#### **Endpoint Security Framework Pipeline** (macOS Endpoint Detection)

1. **`ecs_macos_esf`** - For macOS ESF Events from Elastic Defend
   - Comprehensive field mapping (100+ fields) for macOS-specific event types
   - Maps Sigma taxonomy to ECS + ESF-specific fields:
     - Process: `Image` → `process.executable`, `ProcessId` → `process.pid`
     - Users: `User` → `process.user.name`, `RealUserId` → `process.real_user.id`
     - Files: `TargetFilename` → `file.path`
     - Code Signing: `SigningID` → `process.code_signature.signing_id`
   - Adds category-specific ESF event type conditions (e.g., `process_creation` → `esf.event_type: 9`)
   - Supports macOS-specific event types: ptrace (process injection), signals, kernel extensions, XPC, code signing
   - Supported by: Elasticsearch, EQL, ES|QL, Lucene, OpenSearch

### Data Collection and Logging Software

Each pipeline transforms logs collected by specific agents:

| Pipeline | Collection Agent | Purpose |
|----------|------------------|---------|
| `ecs_windows` | Winlogbeat ≥7.x | Collect Windows event logs in ECS format |
| `ecs_windows_old` | Winlogbeat ≤6.x | Collect Windows event logs in legacy format |
| `ecs_windows_elastic_defend` | Elastic Defend EDR | Endpoint detection & response with case-insensitive field variants |
| `ecs_zeek_beats` | Filebeat + Zeek | Collect Zeek IDS logs with Filebeat shipper |
| `ecs_zeek_corelight` | Filebeat + Corelight | Collect Zeek logs from Corelight sensors |
| `zeek_raw` | Direct Zeek Output | Query native Zeek JSON format directly |
| `ecs_kubernetes` | Kubernetes Integration | Collect Kubernetes audit logs |
| `ecs_macos_esf` | Elastic Defend + eslogger | Collect macOS Endpoint Security Framework events |

## Formats vs. Query Post Processing

While trying to support the minimum compatible output the built-in formats can't fits everyones needs. This gap is filled by a feature called "query post processing" available since pysigma v0.10.

For further information please read ["Introducing Query Post-Processing and Output Finalization to Processing Pipelines"](https://medium.com/sigma-hq/introducing-query-post-processing-and-output-finalization-to-processing-pipelines-4bfe74087ac1).

### Lucene Kibana NDJSON

Instead of using the format `-t lucene -f kibana_ndjson` you can also use the following query postprocessing pipeline
to get the same output or use this as a starting point for your own customizations.

```yaml
# lucene-kibana-ndjson.yml
postprocessing:
- type: template
  template: |+
    {"id": "{{ rule.id }}", "type": "search", "attributes": {"title": "SIGMA - {{ rule.title }}", "description": "{{ rule.description }}", "hits": 0, "columns": [], "sort": ["@timestamp", "desc"], "version": 1, "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"index\": \"beats-*\", \"filter\": [], \"highlight\": {\"pre_tags\": [\"@kibana-highlighted-field@\"], \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fields\": {\"*\": {}}, \"require_field_match\": false, \"fragment_size\": 2147483647}, \"query\": {\"query_string\": {\"query\": \"{{ query }}\", \"analyze_wildcard\": true}}}"}}, "references": [{"id": "beats-*", "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]}
```

Use this pipeline with: `-t lucene -p lucene-kibana-ndjson.yml` but now without `-f kibana_ndjson`.

### Lucene Kibana SIEM Rule

Instead of using the format `-t lucene -f siem_rule` you can also use the following query postprocessing pipeline
to get the same output or use this as a starting point for your own customizations.

```yaml
# lucene-kibana-siemrule.yml
vars:
  index_names: 
    - "apm-*-transaction*"
    - "auditbeat-*"
    - "endgame-*"
    - "filebeat-*"
    - "logs-*"
    - "packetbeat-*"
    - "traces-apm*"
    - "winlogbeat-*"
    - "-*elastic-cloud-logs-*"
  schedule_interval: 5
  schedule_interval_unit: m
  loopback_time: 1
  loopback_unit: m
postprocessing:
- type: template
  template: |+
    {
      "name": "SIGMA - {{ rule.title }}",
      "consumer": "siem",
      "enabled": true,
      "throttle": null,
      "schedule": {
        "interval": "{{ pipeline.vars.schedule_interval }}{{ pipeline.vars.schedule_interval_unit }}"
      },
      "params": {
        "author": [
        {% if rule.author is string -%}
          "{{rule.author}}"
        {% else %}
        {% for a in rule.author -%}
          "{{ a }}"{% if not loop.last %},{%endif%}
        {% endfor -%}
        {% endif -%} 
        ],
        "description": "{{ rule.description }}",
        "ruleId": "{{ rule.id }}",
        "falsePositives": {{ rule.falsepositives }},
        "from": "now-{{ pipeline.vars.schedule_interval }}{{ pipeline.vars.schedule_interval_unit }}-{{ pipeline.vars.loopback_time }}{{ pipeline.vars.loopback_unit }}",
        "immutable": false,
        "license": "DRL",
        "outputIndex": "",
        "maxSignals": 100,
        "riskScore": (
            self.severity_risk_mapping[rule.level.name]
            if rule.level is not None
            else 21
        ),
        "riskScoreMapping": [],
        "severity": (
            str(rule.level.name).lower() if rule.level is not None else "low"
        ),
        "severityMapping": [],
        "threat": list(self.finalize_output_threat_model(rule.tags)),
        "to": "now",
        "references": {{ rule.references |tojson(indent=6)}},
        "version": 1,
        "exceptionsList": [],
        "relatedIntegrations": [],
        "requiredFields": [],
        "setup": "",
        "type": "query",
        "language": "lucene",
        "index": {{ pipeline.vars.index_names | tojson(indent=6)}},
        "query": "{{ query }}",
        "filters": []
      },
      "rule_type_id": "siem.queryRule",
      "tags": [
        {% for n in rule.tags -%}
        "{{ n.namespace }}-{{ n.name }}"{% if not loop.last %},{%endif%}
      {% endfor -%}
      ],
      "notify_when": "onActiveAlert",
      "actions": []
    }
```

Use this pipeline with: `-t lucene -p lucene-kibana-siemrule.yml` but now without `-f kibana_ndjson`.

### EQL siem_rule_ndjson
```yaml
vars:
  schedule_interval: 5
  schedule_interval_unit: m
  loopback_time: 1
  loopback_unit: m
postprocessing:
  - type: template
    template: |+
      {%- set tags = [] -%}
      {% for n in rule.tags %}
        {%- set tag_string = n.namespace ~ '-' ~ n.name -%}
        {%- set tags=tags.append(tag_string) -%}
      {% endfor %}

      {%- set rule_data = {
        "name": rule.title,
        "id": rule.id | lower,
        "author": [rule.author] if rule.author is string else rule.author or "",
        "description": rule.description if rule.description else "empty description",
        "references": rule.references,
        "enabled": true,
        "interval": pipeline.vars.schedule_interval|string ~ pipeline.vars.schedule_interval_unit,
        "from": "now-" ~ pipeline.vars.schedule_interval|string ~ pipeline.vars.schedule_interval_unit ~ "-" ~ pipeline.vars.loopback_time|string ~ pipeline.vars.loopback_unit,
        "rule_id": rule.id | lower,
        "false_positives": rule.falsepositives,
        "immutable": false,
        "output_index": "",
        "risk_score": rule.custom_attributes.risk_score | default(21),
        "severity": rule.level.name | string | lower if rule.level is not none else 'low',
        "threat": rule.custom_attributes.threat | default([]),
        "severity_mapping": [],
        "to": "now",
        "version": 1,
        "max_signals": 100,
        "exceptions_list": [],
        "setup": "",
        "type": "eql",
        "note": "",
        "license": "DRL",
        "language": "eql",
        "query": query,
        "tags": tags,
        "index": pipeline.state.index,
        "actions": [],
        "related_integrations": [],
        "required_fields": [],
        "risk_score_mapping": []
      }
      -%}
      
      {{ rule_data | tojson }}
```
Use this pipeline with: `-t eql -p eql-siemrule-ndjson.yml` but now without `-f siem_rule_ndjson`.
The output can be imported directly into Kibana as a Detection Rule.


### ESQL siem_rule_ndjson
```yaml
vars:
  schedule_interval: 5
  schedule_interval_unit: m
  loopback_time: 1
  loopback_unit: m
postprocessing:
  - type: template
    template: |+
      {%- set tags = [] -%}
      {% for n in rule.tags %}
        {%- set tag_string = n.namespace ~ '-' ~ n.name -%}
        {%- set tags=tags.append(tag_string) -%}
      {% endfor %}
      {%- set rule_data = {
        "name": rule.title,
        "id": rule.id | lower,
        "author": [rule.author] if rule.author is string else rule.author,
        "description": rule.description,
        "references": rule.references,
        "enabled": true,
        "interval": pipeline.vars.schedule_interval|string ~ pipeline.vars.schedule_interval_unit,
        "from": "now-" ~ pipeline.vars.schedule_interval|string ~ pipeline.vars.schedule_interval_unit ~ "-" ~ pipeline.vars.loopback_time|string ~ pipeline.vars.loopback_unit,
        "rule_id": rule.id | lower,
        "false_positives": rule.falsepositives,
        "immutable": false,
        "output_index": "",
        "risk_score": backend.severity_risk_mapping[rule.level.name] if rule.level is not none else 21, 
        "severity": rule.level.name | string | lower if rule.level is not none else "low",
        "severity_mapping": [],
        "threat": backend.finalize_output_threat_model(rule.tags) | list,
        "to": "now",
        "version": 1,
        "max_signals": 100,
        "exceptions_list": [],
        "setup": "",
        "type": "esql",
        "note": "",
        "license": "DRL",
        "language": "esql",
        "index": pipeline.vars.index_names | list,
      "query": query,
      "tags": tags,
      "actions": [],
      "related_integrations": [],
      "required_fields": [],
      "risk_score_mapping": []
      }
      -%}
      
      {{ rule_data | tojson }}
```
Use this pipeline with: `-t esql -p esql-siemrule-ndjson.yml` but now without `-f siem_rule_ndjson`.
The output can be imported directly into Kibana as a Detection Rule.

### Lucene siem_rule_ndjson

> To be continued...

## Known Limitations

### ES|QL Correlation Rules: Static Time Boundaries

ES|QL correlation rules (event count, value count, and temporal correlation types) use `DATE_TRUNC()` to assign events to fixed, epoch-aligned time buckets. This means that the `timespan` window in a correlation rule is aligned to clock boundaries rather than being a true sliding window.

**Consequence:** A correlation rule with a `timespan` of `5m` only matches if all relevant events appear within the same clock-aligned 5-minute interval (e.g. 17:15:00–17:20:00 or 17:20:00–17:25:00, where the end is exclusive). If events straddle a boundary — some falling in one bucket and some in the next — neither bucket may independently meet the detection threshold, resulting in a false negative.

**Example:** Five SSH authentication failures spanning the 17:19–17:20 boundary would be split into two buckets (4 events + 1 event). A rule requiring 5 distinct usernames would not fire, even though all 5 events occurred within a 5-minute window.

This behavior is [described in the Sigma correlation rules specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md#compatibility) and is an intentional trade-off, as ES|QL does not natively support true sliding-window aggregations. Users authoring correlation rules should be aware that detections may be missed when attack activity straddles a clock-aligned bucket boundary.
