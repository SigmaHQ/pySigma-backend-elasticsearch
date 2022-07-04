import pytest
from sigma.backends.elasticsearch import ElasticsearchQueryStringBackend
from sigma.collection import SigmaCollection

@pytest.fixture
def es_qs_backend():
    return ElasticsearchQueryStringBackend()

def test_es_qs_and_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['fieldA:"valueA" AND fieldB:"valueB"']

def test_es_qs_or_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['fieldA:"valueA" OR fieldB:"valueB"']

def test_es_qs_and_or_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['fieldA:("valueA1" OR "valueA2") AND fieldB:("valueB1" OR "valueB2")']

def test_es_qs_or_and_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['(fieldA:"valueA1" AND fieldB:"valueB1") OR (fieldA:"valueA2" AND fieldB:"valueB2")']

def test_es_qs_in_expression(es_qs_backend : ElasticsearchQueryStringBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['fieldA:("valueA" OR "valueB" OR "valueC*")']

def test_es_qs_regex_query(es_qs_backend : ElasticsearchQueryStringBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['fieldA:/foo.*bar/ AND fieldB:"foo"']

def test_es_qs_cidr_query(es_qs_backend : ElasticsearchQueryStringBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['field:192.168.0.0/16']

def test_es_qs_field_name_with_whitespace(es_qs_backend : ElasticsearchQueryStringBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['field\\ name:"value"']

def test_elasticsearch_kibana_output(es_qs_backend : ElasticsearchQueryStringBackend):
    """Test for output format kibana."""
    # TODO: implement a test for the output format
    pass

