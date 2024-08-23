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
relalert:
  minutes: 15
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
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
    )

    assert elastalert_backend.convert(rule) == ["fieldA:valueA AND fieldB:valueB"]


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
                    fieldA: valueA
                    fieldB: ''
                condition: sel
        """
    )

    assert elastalert_backend.convert(rule) == ['fieldA:valueA AND fieldB:""']


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
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
    )
    assert elastalert_backend.convert(rule) == ["fieldA:valueA OR fieldB:valueB"]


def test_elastalert_and_or_expression(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
    )
    assert elastalert_backend.convert(rule) == [
        "(fieldA:(valueA1 OR valueA2)) AND (fieldB:(valueB1 OR valueB2))"
    ]


def test_elastalert_or_and_expression(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
    )
    assert elastalert_backend.convert(rule) == [
        "(fieldA:valueA1 AND fieldB:valueB1) OR (fieldA:valueA2 AND fieldB:valueB2)"
    ]


def test_elastalert_in_expression(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
    )
    assert elastalert_backend.convert(rule) == ["fieldA:(valueA OR valueB OR valueC*)"]


def test_elastalert_in_expression_empty_string(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - ''
                condition: sel
        """
    )
    assert elastalert_backend.convert(rule) == ['fieldA:(valueA OR "")']


def test_elastalert_regex_query(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """
    )
    assert elastalert_backend.convert(rule) == ["fieldA:/foo.*bar/ AND fieldB:foo"]


def test_elastalert_regex_query_escaped_input(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: 127\.0\.0\.1:[1-9]\d{3}
                    fieldB: foo
                    fieldC|re: foo/bar
                condition: sel
        """
    )
    assert elastalert_backend.convert(rule) == [
        "fieldA:/127\.0\.0\.1:[1-9]\d{3}/ AND fieldB:foo AND fieldC:/foo\\/bar/"
    ]


def test_elastalert_cidr_query(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """
    )
    assert elastalert_backend.convert(rule) == ["field:192.168.0.0\\/16"]


def test_elastalert_cidr_ipv6_query(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 
                        - '::1/128'
                        - 'fc00::/7'
                        - '2603:1080::/25'    
                condition: sel
        """
    )
    assert elastalert_backend.convert(rule) == [
        "field:\:\:1\\/128 OR field:fc00\:\:\/7 OR field:2603\:1080\:\:\/25"
    ]


def test_elastalert_field_name_with_whitespace(elastalert_backend: ElastalertBackend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """
    )
    assert elastalert_backend.convert(rule) == ["field\\ name:value"]


def test_elastalert_not_filter_null_and(elastalert_backend: ElastalertBackend):
    """Test for DSL output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and not filter_1 and not filter_2
        """
    )

    assert elastalert_backend.convert(rule) == [
        'FieldA:*valueA AND _exists_:FieldB AND (NOT FieldB:"")'
    ]


def test_elastalert_filter_null_and(elastalert_backend: ElastalertBackend):
    """Test for DSL output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and filter_1 and not filter_2
        """
    )

    assert elastalert_backend.convert(rule) == [
        'FieldA:*valueA AND (NOT _exists_:FieldB) AND (NOT FieldB:"")'
    ]


def test_elastalert_not_filter_null_or(elastalert_backend: ElastalertBackend):
    """Test for DSL output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and (not filter_1 or not filter_2)
        """
    )

    assert elastalert_backend.convert(rule) == [
        'FieldA:*valueA AND (_exists_:FieldB OR (NOT FieldB:""))'
    ]


def test_elastalert_filter_null_or(elastalert_backend: ElastalertBackend):
    """Test for DSL output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and (filter_1 or not filter_2)
        """
    )

    assert elastalert_backend.convert(rule) == [
        'FieldA:*valueA AND ((NOT _exists_:FieldB) OR (NOT FieldB:""))'
    ]


def test_elastalert_filter_not_or_null(elastalert_backend: ElastalertBackend):
    """Test for DSL output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and not 1 of filter_*
        """
    )

    assert elastalert_backend.convert(rule) == [
        'FieldA:*valueA AND (NOT ((NOT _exists_:FieldB) OR FieldB:""))'
    ]


def test_elastalert_filter_not(elastalert_backend: ElastalertBackend):
    """Test for DSL output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                filter:
                    Field: null
                condition: not filter
        """
    )

    assert elastalert_backend.convert(rule) == ["_exists_:Field"]


def test_elastalert_angle_brackets(elastalert_backend: ElastalertBackend):
    """Test for DSL output with < or > in the values"""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection_cmd:
                    - OriginalFileName: 'Cmd.exe'
                    - Image|endswith: '\cmd.exe'
                selection_cli:
                    - CommandLine|contains: '<'
                    - CommandLine|contains: '>'
                condition: all of selection_*
        """
    )

    assert elastalert_backend.convert(rule) == [
        r"(OriginalFileName:Cmd.exe OR Image:*\\cmd.exe) AND (CommandLine:(*\<* OR *\>*))"
    ]


def test_elastalert_keyword_quotation(elastalert_backend: ElastalertBackend):
    """Test for DSL output with < or > in the values"""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 'Failed to generate curve25519 keys'
                condition: keywords
        """
    )

    assert elastalert_backend.convert(rule) == [
        r"*Failed\ to\ generate\ curve25519\ keys*"
    ]


def test_elastalert_windash(elastalert_backend: ElastalertBackend):
    """Test for DSL output using windash modifier"""
    assert (
        elastalert_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldname|windash:
                        - "-param-name"
                condition: sel
        """
            )
        )
        == ["fieldname:(\\-param\\-name OR \\/param\\-name)"]
    )


def test_elastalert_windash_contains(elastalert_backend: ElastalertBackend):
    """Test for DSL output using windash + contains modifier"""
    assert (
        elastalert_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldname|windash|contains:
                        - " -param-name "
                condition: sel
        """
            )
        )
        == ["fieldname:(*\\ \\-param\\-name\\ * OR *\\ \\/param\\-name\\ *)"]
    )


def test_elastalert_reference_query(elastalert_backend: ElastalertBackend):
    with pytest.raises(
        SigmaFeatureNotSupportedByBackendError,
        match="ES Lucene backend can't handle field references.",
    ):
        elastalert_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|fieldref: somefield
                    condition: sel
            """
            )
        )
