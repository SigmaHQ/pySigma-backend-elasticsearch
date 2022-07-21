import pytest
from sigma.backends.elasticsearch import ElasticsearchQueryStringBackend
from sigma.collection import SigmaCollection

@pytest.fixture
def es_qs_backend():
    return ElasticsearchQueryStringBackend()

def test_es_qs_and_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)

    assert es_qs_backend.convert(rule) == ['fieldA:"valueA" AND fieldB:"valueB"']
    assert es_qs_backend.convert(rule, output_format="dsl_qs") == [{
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "fieldA:\"valueA\" AND fieldB:\"valueB\"",
                            "analyze_wildcard": True
                        }
                    }
                ]
            }
        }
    }]

def test_es_qs_or_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)
    assert es_qs_backend.convert(rule) == ['fieldA:"valueA" OR fieldB:"valueB"']
    assert es_qs_backend.convert(rule, output_format="dsl_qs") == [{
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "fieldA:\"valueA\" OR fieldB:\"valueB\"",
                            "analyze_wildcard": True
                        }
                    }
                ]
            }
        }
    }]

def test_es_qs_and_or_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)
    assert es_qs_backend.convert(rule) == ['(fieldA:("valueA1" OR "valueA2")) AND (fieldB:("valueB1" OR "valueB2"))']
    assert es_qs_backend.convert(rule, output_format="dsl_qs") == [{
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "(fieldA:(\"valueA1\" OR \"valueA2\")) AND (fieldB:(\"valueB1\" OR \"valueB2\"))",
                            "analyze_wildcard": True
                        }
                    }
                ]
            }
        }
    }]


def test_es_qs_or_and_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)
    assert es_qs_backend.convert(rule) == ['fieldA:"valueA1" AND fieldB:"valueB1" OR fieldA:"valueA2" AND fieldB:"valueB2"']
    assert es_qs_backend.convert(rule, output_format="dsl_qs") == [{
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "fieldA:\"valueA1\" AND fieldB:\"valueB1\" OR fieldA:\"valueA2\" AND fieldB:\"valueB2\"",
                            "analyze_wildcard": True
                        }
                    }
                ]
            }
        }
    }]

def test_es_qs_in_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)
    assert es_qs_backend.convert(rule) == ['fieldA:("valueA" OR "valueB" OR "valueC*")']
    assert es_qs_backend.convert(rule, output_format="dsl_qs") == [{
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "fieldA:(\"valueA\" OR \"valueB\" OR \"valueC*\")",
                            "analyze_wildcard": True
                        }
                    }
                ]
            }
        }
    }]

def test_es_qs_regex_query(es_qs_backend : ElasticsearchQueryStringBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)
    assert es_qs_backend.convert(rule) == ['fieldA:/foo.*bar/ AND fieldB:"foo"']
    assert es_qs_backend.convert(rule, output_format="dsl_qs") == [{
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "fieldA:/foo.*bar/ AND fieldB:\"foo\"",
                            "analyze_wildcard": True
                        }
                    }
                ]
            }
        }
    }]

def test_es_qs_cidr_query(es_qs_backend : ElasticsearchQueryStringBackend):
    rule = SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    assert es_qs_backend.convert(rule) == ['field:192.168.0.0/16']
    assert es_qs_backend.convert(rule, output_format="dsl_qs") == [{
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "field:192.168.0.0/16",
                            "analyze_wildcard": True
                        }
                    }
                ]
            }
        }
    }]

def test_es_qs_field_name_with_whitespace(es_qs_backend : ElasticsearchQueryStringBackend):
    rule = SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    assert es_qs_backend.convert(rule) == ['field\\ name:"value"']
    assert es_qs_backend.convert(rule, output_format="dsl_qs") == [{
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "field\\ name:\"value\"",
                            "analyze_wildcard": True
                        }
                    }
                ]
            }
        }
    }]

def test_elasticsearch_kibana_output(es_qs_backend : ElasticsearchQueryStringBackend):
    """Test for output format kibana."""
    # TODO: implement a test for the output format
    pass
