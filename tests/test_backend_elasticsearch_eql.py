import pytest
from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend
from sigma.collection import SigmaCollection


@pytest.fixture(name="eql_backend")
def fixture_eql_backend():
    return EqlBackend()


def test_eql_and_expression(eql_backend: EqlBackend):
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

    assert eql_backend.convert(rule) == [
        'any where fieldA:"valueA" and fieldB:"valueB"'
    ]


def test_eql_and_expression_empty_string(eql_backend: EqlBackend):
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

    assert eql_backend.convert(rule) == ['any where fieldA:"valueA" and fieldB==""']


def test_eql_or_expression(eql_backend: EqlBackend):
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
    assert eql_backend.convert(rule) == ['any where fieldA:"valueA" or fieldB:"valueB"']


def test_eql_and_or_expression(eql_backend: EqlBackend):
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
    assert eql_backend.convert(rule) == [
        'any where (fieldA like~ ("valueA1", "valueA2")) and (fieldB like~ ("valueB1", "valueB2"))'
    ]


def test_eql_or_and_expression(eql_backend: EqlBackend):
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
    assert eql_backend.convert(rule) == [
        'any where (fieldA:"valueA1" and fieldB:"valueB1") or (fieldA:"valueA2" and fieldB:"valueB2")'
    ]


def test_eql_in_expression(eql_backend: EqlBackend):
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
    assert eql_backend.convert(rule) == [
        'any where fieldA like~ ("valueA", "valueB", "valueC*")'
    ]


def test_eql_in_expression_empty_string(eql_backend: EqlBackend):
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
    assert eql_backend.convert(rule) == ['any where fieldA like~ ("valueA", "")']


def test_eql_regex_query(eql_backend: EqlBackend):
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
    assert eql_backend.convert(rule) == [
        'any where fieldA regex~ "foo.*bar" and fieldB:"foo"'
    ]


def test_eql_regex_query_escaped_input(eql_backend: EqlBackend):
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
    assert eql_backend.convert(rule) == [
        'any where fieldA regex~ "127\.0\.0\.1:[1-9]\d{3}" and fieldB:"foo" and fieldC regex~ "foo\\/bar"'
    ]


def test_eql_cidr_query(eql_backend: EqlBackend):
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
    assert eql_backend.convert(rule) == ['any where cidrMatch(field, "192.168.0.0/16")']


def test_eql_field_name_with_whitespace(eql_backend: EqlBackend):
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
    assert eql_backend.convert(rule) == ['any where `field name`:"value"']


def test_eql_not_filter_null_and(eql_backend: EqlBackend):
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

    assert eql_backend.convert(rule) == [
        'any where FieldA:"*valueA" and ?FieldB != null and (not FieldB=="")'
    ]


def test_eql_filter_null_and(eql_backend: EqlBackend):
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

    assert eql_backend.convert(rule) == [
        'any where FieldA:"*valueA" and (?FieldB == null) and (not FieldB=="")'
    ]


def test_eql_not_filter_null_or(eql_backend: EqlBackend):
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

    assert eql_backend.convert(rule) == [
        'any where FieldA:"*valueA" and (?FieldB != null or (not FieldB==""))'
    ]


def test_eql_filter_null_or(eql_backend: EqlBackend):
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

    assert eql_backend.convert(rule) == [
        'any where FieldA:"*valueA" and ((?FieldB == null) or (not FieldB==""))'
    ]


def test_eql_filter_not_or_null(eql_backend: EqlBackend):
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

    assert eql_backend.convert(rule) == [
        'any where FieldA:"*valueA" and (not ((?FieldB == null) or FieldB==""))'
    ]


def test_eql_filter_not(eql_backend: EqlBackend):
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

    assert eql_backend.convert(rule) == ["any where ?Field != null"]


def test_eql_angle_brackets(eql_backend: EqlBackend):
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

    assert eql_backend.convert(rule) == [
        r'any where (OriginalFileName:"Cmd.exe" or Image:"*\\cmd.exe") and (CommandLine like~ ("*<*", "*>*"))'
    ]

def test_elasticsearch_eqlapi(eql_backend: EqlBackend):
    """Test for NDJSON output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            id: c277adc0-f0c4-42e1-af9d-fab062992156
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
    result = eql_backend.convert(rule, output_format="eqlapi")
    assert result[0] == {
        "query": "any where fieldA:\"valueA\" and fieldB:\"valueB\""
    }

def test_elasticsearch_siemrule_eql(eql_backend: EqlBackend):
    """Test for NDJSON output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            id: c277adc0-f0c4-42e1-af9d-fab062992156
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
    result = eql_backend.convert(rule, output_format="siem_rule")
    assert result[0] == {
        "name": "SIGMA - Test",
        "tags": [],
        "consumer": "siem",
        "enabled": True,
        "throttle": None,
        "schedule": {"interval": "5m"},
        "params": {
            "author": [],
            "description": "No description",
            "ruleId": "c277adc0-f0c4-42e1-af9d-fab062992156",
            "falsePositives": [],
            "from": "now-5m",
            "immutable": False,
            "license": "DRL",
            "outputIndex": "",
            "meta": {
                "from": "1m",
            },
            "maxSignals": 100,
            "riskScore": 21,
            "riskScoreMapping": [],
            "severity": "low",
            "severityMapping": [],
            "threat": [],
            "to": "now",
            "references": [],
            "version": 1,
            "exceptionsList": [],
            "relatedIntegrations": [],
            "requiredFields": [],
            "setup": "",
            "type": "query",
            "language": "lucene",
            "index": [
                "apm-*-transaction*",
                "auditbeat-*",
                "endgame-*",
                "filebeat-*",
                "logs-*",
                "packetbeat-*",
                "traces-apm*",
                "winlogbeat-*",
                "-*elastic-cloud-logs-*",
            ],
            "query": 'any where fieldA:"valueA" and fieldB:"valueB"',
            "filters": [],
        },
        "rule_type_id": "siem.queryRule",
        "notify_when": "onActiveAlert",
        "actions": [],
    }


def test_elasticsearch_siemrule_eql_ndjson(eql_backend: EqlBackend):
    """Test for NDJSON output with embedded query string query."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            id: c277adc0-f0c4-42e1-af9d-fab062992156
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
    result = eql_backend.convert(rule, output_format="siem_rule_ndjson")
    assert result[0] == {
        "id": "c277adc0-f0c4-42e1-af9d-fab062992156",
        "name": "SIGMA - Test",
        "tags": [],
        "interval": "5m",
        "enabled": True,
        "description": "No description",
        "risk_score": 21,
        "severity": "low",
        "license": "DRL",
        "output_index": "",
        "meta": {
            "from": "1m",
        },
        "author": [],
        "false_positives": [],
        "from": "now-5m",
        "rule_id": "c277adc0-f0c4-42e1-af9d-fab062992156",
        "max_signals": 100,
        "risk_score_mapping": [],
        "severity_mapping": [],
        "threat": [],
        "to": "now",
        "references": [],
        "version": 1,
        "exceptions_list": [],
        "immutable": False,
        "related_integrations": [],
        "required_fields": [],
        "setup": "",
        "type": "query",
        "language": "lucene",
        "index": [
            "apm-*-transaction*",
            "auditbeat-*",
            "endgame-*",
            "filebeat-*",
            "logs-*",
            "packetbeat-*",
            "traces-apm*",
            "winlogbeat-*",
            "-*elastic-cloud-logs-*",
        ],
        "query": 'any where fieldA:"valueA" and fieldB:"valueB"',
        "filters": [],
        "throttle": "no_actions",
        "actions": [],
    }


def test_elasticsearch_siem_rule_output(eql_backend: EqlBackend):
    """Test for output format siem_rule."""
    # TODO: implement a test for the output format
    pass


def test_elasticsearch_siem_rule_ndjson_output(eql_backend: EqlBackend):
    """Test for output format siem_rule."""
    # TODO: implement a test for the output format
    pass
