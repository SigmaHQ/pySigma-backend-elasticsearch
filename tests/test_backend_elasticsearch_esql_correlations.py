import pytest
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from tests.test_backend_elasticsearch_esql import esql_backend


def test_event_count_correlation_rule_stats_query(esql_backend: ESQLBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1" and fieldB=="value2"
| eval timebucket=date_trunc(15minutes, @timestamp) | stats event_count=count() by timebucket, fieldC, fieldD
| where event_count >= 10"""
    ]


def test_event_count_correlation_rule_stats_query_no_group_field(
    esql_backend: ESQLBackend,
):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1" and fieldB=="value2"
| eval timebucket=date_trunc(15minutes, @timestamp) | stats event_count=count() by timebucket
| where event_count >= 10"""
    ]


def test_value_count_correlation_rule_stats_query(esql_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        lt: 10
        field: fieldD
            """
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * metadata _id, _index, _version | where fieldA=="value1" and fieldB=="value2"
| eval timebucket=date_trunc(15minutes, @timestamp) | stats value_count=count_distinct(fieldD) by timebucket, fieldC
| where value_count < 10"""
    ]


def test_temporal_correlation_rule_stats_query(esql_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    assert esql_backend.convert(correlation_rule) == [
        """from * | where (fieldA=="value1" and fieldB=="value2") or (fieldA=="value3" and fieldB=="value4")
| eval event_type=case(fieldA=="value1" and fieldB=="value2", "base_rule_1", fieldA=="value3" and fieldB=="value4", "base_rule_2")
| eval timebucket=date_trunc(15minutes, @timestamp) | stats event_type_count=count_distinct(event_type) by timebucket, fieldC
| where event_type_count >= 2"""
    ]
