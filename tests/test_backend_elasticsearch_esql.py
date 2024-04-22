import pytest
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend

@pytest.fixture
def esql_backend():
    return ESQLBackend()

def test_elasticsearch_esql_and_expression(esql_backend : ESQLBackend):
    assert esql_backend.convert(
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
    ) == ['from * | where fieldA=="valueA" and fieldB=="valueB"']

def test_elasticsearch_esql_or_expression(esql_backend : ESQLBackend):
    assert esql_backend.convert(
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
    ) == ['from * | where fieldA=="valueA" or fieldB=="valueB"']

def test_elasticsearch_esql_and_or_expression(esql_backend : ESQLBackend):
    assert esql_backend.convert(
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
    ) == ['from * | where (fieldA in ("valueA1", "valueA2")) and (fieldB in ("valueB1", "valueB2"))']

def test_elasticsearch_esql_or_and_expression(esql_backend : ESQLBackend):
    assert esql_backend.convert(
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
    ) == ['from * | where fieldA=="valueA1" and fieldB=="valueB1" or fieldA=="valueA2" and fieldB=="valueB2"']

def test_elasticsearch_esql_in_expression(esql_backend : ESQLBackend):
    assert esql_backend.convert(
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
                        - valueC
                condition: sel
        """)
    ) == ['from * | where fieldA in ("valueA", "valueB", "valueC")']

def test_elasticsearch_esql_wildcard_expressions(esql_backend : ESQLBackend):
    assert esql_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - "val*A"
                        - "*valueB"
                        - "valueC*"
                condition: sel
        """)
    ) == ['from * | where fieldA like "val*A" or ends_with(fieldA, "valueB") or starts_with(fieldA, "valueC")']

def test_elasticsearch_esql_regex_query(esql_backend : ESQLBackend):
    assert esql_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: "foo.*bar"
                    fieldB: foo
                condition: sel
        """)
    ) == ['from * | where fieldA rlike "foo.*bar" and fieldB=="foo"']

def test_elasticsearch_esql_cidr_query(esql_backend : ESQLBackend):
    assert esql_backend.convert(
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
    ) == ['from * | where cidr_match(field, "192.168.0.0/16")']

def test_elasticsearch_esql_field_name_with_whitespace(esql_backend : ESQLBackend):
    assert esql_backend.convert(
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
    ) == ['from * | where `field name`=="value"']