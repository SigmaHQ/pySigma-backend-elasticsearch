import pytest
from sigma.backends.elasticsearch.elasticsearch_elastalert import ElastalertBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.fixture(name="elastalert_backend")
def fixture_elastalert_backend():
    return ElastalertBackend()


def test_event_count_correlation_rule_query(elastalert_backend: ElastalertBackend):
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
        gt: 10
            """
    )
    assert elastalert_backend.convert(correlation_rule)[0] == (
        """description: 
index: *
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
priority: 1
timeframe:
  minutes: 15
query_key:
- fieldC
- fieldD
num_events: 10
type: frequency"""
    )


def test_value_count_correlation_rule_query(elastalert_backend: ElastalertBackend):
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
        field: fieldD
        gt: 10
            """
    )
    assert elastalert_backend.convert(correlation_rule)[0] == (
        """description: 
index: *
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
priority: 1
buffer_time:
  minutes: 15
query_key:
- fieldC
metric_agg_type: cardinality
metric_agg_key: fieldD
max_threshold: 10
type: metric_aggregation"""
    )

def test_elastalert_change_severity(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value1
                    fieldB: value2
                condition: sel
            level: critical
        """
    )

    assert elastalert_backend.convert(rule)[0] == (
        """description: 
index: *
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
priority: 4"""
    )


def test_elastalert_aggregation_change_severity(elastalert_backend: ElastalertBackend):
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
level: critical
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
        field: fieldD
        gt: 10
            """
    )
    assert elastalert_backend.convert(correlation_rule)[0] == (
        """description: 
index: *
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
priority: 4
buffer_time:
  minutes: 15
query_key:
- fieldC
metric_agg_type: cardinality
metric_agg_key: fieldD
max_threshold: 10
type: metric_aggregation"""
    )

def test_elastalert_and_expression(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value1
                    fieldB: value2
                condition: sel
        """
    )

    assert elastalert_backend.convert(rule)[0] == (
        """description: 
index: *
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
priority: 1"""
    )


def test_elastalert_and_expression_empty_string(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value1
                    fieldB: ''
                condition: sel
        """
    )

    assert elastalert_backend.convert(rule)[0] == (
        """description: 
index: *
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:""
priority: 1"""
    )


def test_elastalert_or_expression(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel2:
                    fieldB: value2
                condition: 1 of sel*
        """
    )
    assert elastalert_backend.convert(rule)[0] == (
        """description: 
index: *
filter:
- query:
    query_string:
      query: fieldA:value1 OR fieldB:value2
priority: 1"""
    )


def test_elastalert_temporal_correlation_rule(elastalert_backend: ElastalertBackend):
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
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    with pytest.raises(NotImplementedError):
        elastalert_backend.convert(correlation_rule)

def test_elastalert_multi_rule_query(elastalert_backend: ElastalertBackend):
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
        fieldC: value2
        fieldD: value3
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldA
        - fieldC
    timespan: 15m
    condition:
        gt: 10
"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        elastalert_backend.convert(correlation_rule)