import time
import pytest
import requests
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection


def es_available_test():
    try:
        requests.get('http://localhost:9200/', timeout=120)
    except requests.exceptions.ConnectionError:
        return False
    return True


@pytest.fixture(scope="class")
@pytest.mark.skipif(es_available_test is False, reason="ES not available... Skipping tests...")
def prepare_es_data():
    if es_available_test():
        requests.delete('http://localhost:9200/test-index', timeout=120)
        requests.put("http://localhost:9200/test-index", timeout=120)
        requests.put("http://localhost:9200/test-index/_mapping", timeout=120, json={
            "properties": {
                "ipfield": {
                    "type": "ip"
                },
            },
            "dynamic_templates": [
                {
                    "default": {
                        "match": "*",
                        "mapping": {
                            "type": "keyword"
                        }
                    }
                }
            ]
        }
        )
        requests.post("http://localhost:9200/test-index/_doc/",
                      json={"fieldA": "valueA", "fieldB": "valueB"}, timeout=120)
        requests.post("http://localhost:9200/test-index/_doc/",
                      json={"fieldA": "otherisempty", "fieldB": ""}, timeout=120)
        requests.post("http://localhost:9200/test-index/_doc/",
                      json={"fieldK": "dot.value"}, timeout=120)
        requests.post("http://localhost:9200/test-index/_doc/",
                      json={"fieldA": "valueA1", "fieldB": "valueB1"}, timeout=120)
        requests.post("http://localhost:9200/test-index/_doc/",
                      json={"fieldA": "valueA2", "fieldB": "valueB2"}, timeout=120)
        requests.post("http://localhost:9200/test-index/_doc/",
                      json={"fieldA": "foosamplebar", "fieldB": "foo"}, timeout=120)
        requests.post("http://localhost:9200/test-index/_doc/",
                      json={"ipfield": "192.168.1.1"}, timeout=120)
        requests.post("http://localhost:9200/test-index/_doc/",
                      json={"ipfield": "10.5.5.5"}, timeout=120)
        requests.post("http://localhost:9200/test-index/_doc/",
                      json={"field name": "value"}, timeout=120)
        # Wait a bit for Documents to be indexed
        time.sleep(1)


@pytest.fixture
def lucene_backend():
    return LuceneBackend()


@pytest.mark.skipif(es_available_test() is False, reason="ES not available")
class TestConnectElasticsearch:
    """
    Test Class for Elasticsearch Backend
    """

    def query_backend_hits(self, query, num_wanted=0):
        result = requests.post(
            'http://localhost:9200/test-index/_search', json=query, timeout=120)
        assert result.status_code == 200
        rjson = result.json()
        assert 'hits' in rjson
        assert 'total' in rjson['hits']
        assert rjson['hits']['total']['value'] == num_wanted
        return rjson

    def test_connect_lucene_and_expression(self, prepare_es_data, lucene_backend: LuceneBackend):
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

        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_and_expression_empty_string(self, prepare_es_data, lucene_backend: LuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA: otherisempty
                        fieldB: ''
                    condition: sel
            """)

        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_or_expression(self, prepare_es_data, lucene_backend: LuceneBackend):
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
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_and_or_expression(self, prepare_es_data, lucene_backend: LuceneBackend):
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
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=2)

    def test_connect_lucene_or_and_expression(self, prepare_es_data, lucene_backend: LuceneBackend):
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
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=2)

    def test_connect_lucene_in_expression(self, prepare_es_data, lucene_backend: LuceneBackend):
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
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_in_expression_empty_string(self, prepare_es_data, lucene_backend: LuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA:
                            - otherisempty
                            - ''
                    condition: sel
            """)
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_regex_query(self, prepare_es_data, lucene_backend: LuceneBackend):
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
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_cidr_query(self, prepare_es_data, lucene_backend: LuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        ipfield|cidr: 192.168.0.0/16
                    condition: sel
            """)

        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_ip_query(self, prepare_es_data, lucene_backend: LuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        ipfield: 192.168.1.1
                    condition: sel
            """)

        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_field_name_with_whitespace(self, prepare_es_data, lucene_backend: LuceneBackend):
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
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_dot_value(self, prepare_es_data, lucene_backend: LuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldK: dot.value
                    condition: sel
            """)

        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)
