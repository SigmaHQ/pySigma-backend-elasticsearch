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
* ecs_kubernetes in kubernetes submodule: ECS mapping for Kubernetes audit logs ingested with Kubernetes integration

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/SigmaHQ/)
* [Hendrik Bäcker](https://github.com/andurin)

Further maintainers required! Send a message to [Thomas](mailto:thomas@patzke.org) if you want to co-maintain this
backend.

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
        "from": "now-{{ pipeline.vars.schedule_interval }}{{ pipeline.vars.schedule_interval_unit }}",
        "immutable": false,
        "license": "DRL",
        "outputIndex": "",
        "meta": {
          "from": "1m"
        },
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

### Lucene siem_rule_ndjson

> To be continued...
