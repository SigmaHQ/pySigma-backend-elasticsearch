import pytest
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection

@pytest.fixture
def lucene_backend():
    return LuceneBackend()

def test_lucene_and_expression(lucene_backend : LuceneBackend):
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

    assert lucene_backend.convert(rule) == ['fieldA:valueA AND fieldB:valueB']

def test_lucene_and_expression_empty_string(lucene_backend : LuceneBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)

    assert lucene_backend.convert(rule) == ['fieldA:valueA AND fieldB:""']

def test_lucene_or_expression(lucene_backend : LuceneBackend):
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
    assert lucene_backend.convert(rule) == ['fieldA:valueA OR fieldB:valueB']

def test_lucene_and_or_expression(lucene_backend : LuceneBackend):
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
    assert lucene_backend.convert(rule) == ['(fieldA:(valueA1 OR valueA2)) AND (fieldB:(valueB1 OR valueB2))']

def test_lucene_or_and_expression(lucene_backend : LuceneBackend):
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
    assert lucene_backend.convert(rule) == ['(fieldA:valueA1 AND fieldB:valueB1) OR (fieldA:valueA2 AND fieldB:valueB2)']

def test_lucene_in_expression(lucene_backend : LuceneBackend):
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
    assert lucene_backend.convert(rule) == ['fieldA:(valueA OR valueB OR valueC*)']

def test_lucene_in_expression_empty_string(lucene_backend : LuceneBackend):
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
                        - ''
                condition: sel
        """)
    assert lucene_backend.convert(rule) == ['fieldA:(valueA OR "")']

def test_lucene_regex_query(lucene_backend : LuceneBackend):
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
    assert lucene_backend.convert(rule) == ['fieldA:/foo.*bar/ AND fieldB:foo']

def test_lucene_regex_query_escaped_input(lucene_backend : LuceneBackend):
    rule = SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: 127\.0\.0\.1:[1-9]\d{3}
                    fieldB: foo
                condition: sel
        """)
    assert lucene_backend.convert(rule) == ['fieldA:/127\.0\.0\.1:[1-9]\d{3}/ AND fieldB:foo']

def test_lucene_cidr_query(lucene_backend : LuceneBackend):
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
    assert lucene_backend.convert(rule) == ['field:192.168.0.0\\/16']

def test_lucene_field_name_with_whitespace(lucene_backend : LuceneBackend):
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
    assert lucene_backend.convert(rule) == ['field\\ name:value']

def test_elasticsearch_ndjson_lucene(lucene_backend : LuceneBackend):
    """Test for NDJSON output with embedded query string query."""
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
    result = lucene_backend.convert(rule, output_format="kibana_ndjson")
    assert result[0] == {
            "id": "None",
            "type": "search",
            "attributes": {
                "title": "SIGMA - Test",
                "description": None,
                "hits": 0,
                "columns": [],
                "sort": [
                    "@timestamp",
                    "desc"
                ],
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\": \"beats-*\", \"filter\": [], \"highlight\": {\"pre_tags\": [\"@kibana-highlighted-field@\"], \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fields\": {\"*\": {}}, \"require_field_match\": false, \"fragment_size\": 2147483647}, \"query\": {\"query_string\": {\"query\": \"fieldA:valueA AND fieldB:valueB\", \"analyze_wildcard\": true}}}"
                    }
                },
                "references": [{
                        "id": "beats-*",
                        "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern"
                    }]
            }

def test_elasticsearch_dsl_lucene(lucene_backend : LuceneBackend):
    """Test for DSL output with embedded query string query."""
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
    assert lucene_backend.convert(rule, output_format="dsl_lucene") == [{
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "fieldA:valueA AND fieldB:valueB",
                            "analyze_wildcard": True
                        }
                    }
                ]
            }
        }
    }]

def test_elasticsearch_kibana_output(lucene_backend : LuceneBackend):
    """Test for output format kibana."""
    # TODO: implement a test for the output format
    pass