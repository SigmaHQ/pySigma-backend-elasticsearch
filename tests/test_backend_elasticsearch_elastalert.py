import pytest
from sigma.backends.elasticsearch.elasticsearch_elastalert import ElastalertBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.pipeline import ProcessingPipeline

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
name: Multiple occurrences of base event
index: "*"
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
timeframe:
  minutes: 15
query_key:
- fieldC
- fieldD
num_events: 10
type: frequency
priority: 1"""
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
name: Multiple occurrences of base event
index: "*"
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
buffer_time:
  minutes: 15
query_key:
- fieldC
metric_agg_type: cardinality
metric_agg_key: fieldD
max_threshold: 10
type: metric_aggregation
priority: 1"""
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
name: Test
index: "*"
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
type: any
priority: 4"""
    )


def test_elastalert_single_index():
    assert(
        ElastalertBackend(processing_pipeline=ProcessingPipeline.from_yaml(
                """
                name: test
                priority: 30
                transformations:
                  - id: set_state_index
                    type: set_state
                    key: index
                    val: 
                      - logs-test
                    rule_conditions:
                      - type: logsource
                        category: test_category
                        product: test_product
        """)).convert(
            SigmaCollection.from_yaml(
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
            level: critical"""
            )
        )
        == [
            """description: 
name: Test
index: "logs-test"
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
type: any
priority: 4"""])


def test_elastalert_multiple_indexes():
    assert(
        ElastalertBackend(processing_pipeline=ProcessingPipeline.from_yaml(
                """
                name: test
                priority: 30
                transformations:
                  - id: set_state_index
                    type: set_state
                    key: index
                    val: 
                      - logs-test1-*
                      - logs-test2-*
                    rule_conditions:
                      - type: logsource
                        category: test_category
                        product: test_product
        """)).convert(
            SigmaCollection.from_yaml(
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
            level: critical"""
            )
        )
        == [
            """description: 
name: Test
index: "logs-test1-*,logs-test2-*"
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
type: any
priority: 4"""])


def test_elastalert_empty_list_of_indexes():
    assert(
        ElastalertBackend(processing_pipeline=ProcessingPipeline.from_yaml(
                """
                name: test
                priority: 30
                transformations:
                  - id: set_state_index
                    type: set_state
                    key: index
                    val:
                    rule_conditions:
                      - type: logsource
                        category: test_category
                        product: test_product
        """)).convert(
            SigmaCollection.from_yaml(
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
            level: critical"""
            )
        )
        == [
            """description: 
name: Test
index: "*"
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
type: any
priority: 4"""])


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
level: critical
            """
    )
    assert elastalert_backend.convert(correlation_rule)[0] == (
        """description: 
name: Multiple occurrences of base event
index: "*"
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
buffer_time:
  minutes: 15
query_key:
- fieldC
metric_agg_type: cardinality
metric_agg_key: fieldD
max_threshold: 10
type: metric_aggregation
priority: 4"""
    )


def test_elastalert_temporal_correlation_rule(elastalert_backend: ElastalertBackend):
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
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    with pytest.raises(NotImplementedError):
        elastalert_backend.convert(correlation_rule)


def test_elastalert_temporal_ordered_correlation_rule(
    elastalert_backend: ElastalertBackend,
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
title: Temporal correlation rule
status: test
correlation:
    type: temporal_ordered
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    with pytest.raises(NotImplementedError):
        elastalert_backend.convert(correlation_rule)


def test_elastalert_multi_correlation_rules(elastalert_backend: ElastalertBackend):
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
