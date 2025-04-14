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
        """description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: '*'
name: Multiple occurrences of base event
num_events: 11
priority: 1
query_key:
- fieldC
- fieldD
timeframe:
  minutes: 15
type: frequency
"""
    )


def test_event_count_greater_and_equal_correlation_rule_query(elastalert_backend: ElastalertBackend):
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
    assert elastalert_backend.convert(correlation_rule)[0] == (
        """description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: '*'
name: Multiple occurrences of base event
num_events: 10
priority: 1
query_key:
- fieldC
- fieldD
timeframe:
  minutes: 15
type: frequency
"""
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
        """buffer_time:
  minutes: 15
description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: '*'
max_threshold: 10
metric_agg_key: fieldD
metric_agg_type: cardinality
name: Multiple occurrences of base event
priority: 1
query_key:
- fieldC
type: metric_aggregation
"""
    )


def test_value_count_greater_and_equal_correlation_rule_query(elastalert_backend: ElastalertBackend):
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
        gte: 10
            """
    )
    assert elastalert_backend.convert(correlation_rule)[0] == (
        """buffer_time:
  minutes: 15
description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: '*'
max_threshold: 9
metric_agg_key: fieldD
metric_agg_type: cardinality
name: Multiple occurrences of base event
priority: 1
query_key:
- fieldC
type: metric_aggregation
"""
    )


def test_value_count_lesser_and_equal_correlation_rule_query(elastalert_backend: ElastalertBackend):
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
        lte: 10
            """
    )
    assert elastalert_backend.convert(correlation_rule)[0] == (
        """buffer_time:
  minutes: 15
description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: '*'
metric_agg_key: fieldD
metric_agg_type: cardinality
min_threshold: 9
name: Multiple occurrences of base event
priority: 1
query_key:
- fieldC
type: metric_aggregation
"""
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
        """description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: '*'
name: Test
priority: 4
type: any
"""
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
            """description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: logs-test
name: Test
priority: 4
type: any
"""])


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
            """description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: logs-test1-*,logs-test2-*
name: Test
priority: 4
type: any
"""])


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
            """description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: '*'
name: Test
priority: 4
type: any
"""])


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
        """buffer_time:
  minutes: 15
description: ''
filter:
- query:
    query_string:
      query: fieldA:value1 AND fieldB:value2
index: '*'
max_threshold: 10
metric_agg_key: fieldD
metric_agg_type: cardinality
name: Multiple occurrences of base event
priority: 4
query_key:
- fieldC
type: metric_aggregation
"""
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
