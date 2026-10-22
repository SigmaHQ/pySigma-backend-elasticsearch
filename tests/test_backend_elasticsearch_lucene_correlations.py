import pytest
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.fixture(name="lucene_backend")
def fixture_lucene_backend():
    return LuceneBackend()


def test_event_count_single_groupby(lucene_backend: LuceneBackend):
    """event_count with one group-by field produces a terms + bucket_selector."""
    rule = SigmaCollection.from_yaml(
        r"""
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
title: Event count correlation
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 10
        """
    )
    result = lucene_backend.convert(rule, output_format="dsl_lucene")
    assert len(result) == 1
    body = result[0]

    # Top-level structure
    assert "query" in body
    assert "aggs" in body
    assert body["size"] == 0

    # Query includes Lucene query_string + time range
    must = body["query"]["bool"]["must"]
    assert len(must) == 2
    assert "query_string" in must[0]
    assert "fieldA:value1 AND fieldB:value2" in must[0]["query_string"]["query"]
    assert "range" in must[1]
    assert must[1]["range"]["@timestamp"]["gte"] == "now-900s"

    # Aggregation: terms on fieldC with bucket_selector
    assert "by_fieldC" in body["aggs"]
    terms_agg = body["aggs"]["by_fieldC"]
    assert terms_agg["terms"]["field"] == "fieldC"
    assert "count_check" in terms_agg["aggs"]
    selector = terms_agg["aggs"]["count_check"]["bucket_selector"]
    assert selector["buckets_path"]["count"] == "_count"
    assert selector["script"] == "params.count >= 10"


def test_event_count_multiple_groupby(lucene_backend: LuceneBackend):
    """event_count with two group-by fields produces nested terms aggregations."""
    rule = SigmaCollection.from_yaml(
        r"""
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Event count correlation
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
        - fieldD
    timespan: 10m
    condition:
        gt: 5
        """
    )
    result = lucene_backend.convert(rule, output_format="dsl_lucene")
    body = result[0]

    # Outer agg: by_fieldC
    assert "by_fieldC" in body["aggs"]
    outer = body["aggs"]["by_fieldC"]
    assert outer["terms"]["field"] == "fieldC"

    # Inner agg: by_fieldD
    assert "by_fieldD" in outer["aggs"]
    inner = outer["aggs"]["by_fieldD"]
    assert inner["terms"]["field"] == "fieldD"

    # Leaf: bucket_selector
    assert "count_check" in inner["aggs"]
    assert inner["aggs"]["count_check"]["bucket_selector"]["script"] == "params.count > 5"


def test_event_count_lt_operator(lucene_backend: LuceneBackend):
    """event_count with lt operator."""
    rule = SigmaCollection.from_yaml(
        r"""
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Event count lt
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        lt: 3
        """
    )
    result = lucene_backend.convert(rule, output_format="dsl_lucene")
    body = result[0]
    selector = body["aggs"]["by_fieldC"]["aggs"]["count_check"]["bucket_selector"]
    assert selector["script"] == "params.count < 3"


def test_value_count_single_groupby(lucene_backend: LuceneBackend):
    """value_count produces cardinality + bucket_selector."""
    rule = SigmaCollection.from_yaml(
        r"""
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Value count correlation
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
    result = lucene_backend.convert(rule, output_format="dsl_lucene")
    body = result[0]

    assert body["size"] == 0
    assert "by_fieldC" in body["aggs"]

    inner_aggs = body["aggs"]["by_fieldC"]["aggs"]

    # Cardinality aggregation on the distinct field
    assert "distinct_values" in inner_aggs
    assert inner_aggs["distinct_values"]["cardinality"]["field"] == "fieldD"

    # Bucket selector references the cardinality agg
    assert "count_check" in inner_aggs
    selector = inner_aggs["count_check"]["bucket_selector"]
    assert selector["buckets_path"]["count"] == "distinct_values"
    assert selector["script"] == "params.count >= 10"


def test_value_count_gt_operator(lucene_backend: LuceneBackend):
    """value_count with gt operator."""
    rule = SigmaCollection.from_yaml(
        r"""
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 8004
    condition: selection
---
title: Password spraying detection
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - SChannelName
    timespan: 15m
    condition:
        field: UserName
        gt: 35
        """
    )
    result = lucene_backend.convert(rule, output_format="dsl_lucene")
    body = result[0]

    inner_aggs = body["aggs"]["by_SChannelName"]["aggs"]
    assert inner_aggs["distinct_values"]["cardinality"]["field"] == "UserName"
    assert inner_aggs["count_check"]["bucket_selector"]["script"] == "params.count > 35"


def test_event_count_no_groupby(lucene_backend: LuceneBackend):
    """event_count without group-by produces bucket_selector directly."""
    rule = SigmaCollection.from_yaml(
        r"""
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Event count no group
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    timespan: 5m
    condition:
        gte: 100
        """
    )
    result = lucene_backend.convert(rule, output_format="dsl_lucene")
    body = result[0]

    # No terms aggregation, just the bucket_selector at root
    assert "count_check" in body["aggs"]


def test_event_count_default_output(lucene_backend: LuceneBackend):
    """event_count with default (Lucene string) output format still works."""
    rule = SigmaCollection.from_yaml(
        r"""
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Event count default
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 10m
    condition:
        gte: 5
        """
    )
    # Default output should return the aggregation dict too
    result = lucene_backend.convert(rule)
    assert len(result) == 1
    assert isinstance(result[0], dict)


def test_temporal_not_supported(lucene_backend: LuceneBackend):
    """temporal correlation should raise an error."""
    rule = SigmaCollection.from_yaml(
        r"""
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value2
    condition: selection
---
title: Temporal correlation
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
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        lucene_backend.convert(rule)
