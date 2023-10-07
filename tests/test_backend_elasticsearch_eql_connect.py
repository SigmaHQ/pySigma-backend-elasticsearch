import time
import pytest
import requests
import urllib3
from requests.auth import HTTPBasicAuth
from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend
from sigma.collection import SigmaCollection

urllib3.disable_warnings()

pytest.es_url = ""
pytest.es_creds = HTTPBasicAuth("sigmahq", "sigmahq")


def es_available_test():
    state = False
    # Try {es_url} without auth
    try:
        if not state:
            response = requests.get("http://localhost:9200", timeout=120)
            if response.status_code == 200:
                pytest.es_url = "http://localhost:9200"
                pytest.es_creds = False
                state = True
    except requests.exceptions.ConnectionError:
        state = False

    # Try https://localhost:9200 without auth
    try:
        if not state:
            response = requests.get("https://localhost:9200", timeout=120, verify=False)
            if response.status_code == 200:
                pytest.es_url = "https://localhost:9200"
                pytest.es_creds = False
                state = True
    except requests.exceptions.ConnectionError:
        state = False

    # Try https://localhost:9200 with auth
    try:
        if not state:
            response = requests.get(
                "https://localhost:9200",
                timeout=120,
                verify=False,
                auth=("sigmahq", "sigmahq"),
            )
            if response.status_code == 200:
                pytest.es_url = "https://localhost:9200"
                pytest.es_creds = HTTPBasicAuth("sigmahq", "sigmahq")
                state = True
    except requests.exceptions.ConnectionError:
        state = False

    return state


@pytest.fixture(scope="class", name="prepare_es_data")
@pytest.mark.skipif(
    es_available_test is False, reason="ES not available... Skipping tests..."
)
def fixture_prepare_es_data():
    if es_available_test():
        requests.delete(
            f"{pytest.es_url}/test-index",
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.put(
            f"{pytest.es_url}/test-index",
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.put(
            f"{pytest.es_url}/test-index/_mapping",
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
            json={
                "properties": {
                    "ipfield": {"type": "ip"},
                    "textFieldA": {"type": "text"},
                    "keywordFieldA": {"type": "keyword"},
                },
                "dynamic_templates": [
                    {"default": {"match": "*", "mapping": {"type": "keyword"}}}
                ],
            },
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "fieldA": "valueA", "fieldB": "valueB"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "fieldA": "otherisempty", "fieldB": ""},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "fieldK": "dot.value"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "fieldA": "valueA1", "fieldB": "valueB1"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "fieldA": "valueA2", "fieldB": "valueB2"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "@timestamp": "1696587400",
                "fieldA": "foosamplebar",
                "fieldB": "foo",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "ipfield": "192.168.1.1"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "ipfield": "10.5.5.5"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "field name": "value"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "textFieldA": "value with spaces"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "textFieldA": "value2 with spaces"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "keywordFieldA": "value with spaces"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"@timestamp": "1696587400", "keywordFieldA": "value2 with spaces"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "@timestamp": "1696587400",
                "OriginalFileName": "Cmd.exe",
                "Image": "c:\\windows\\system32\\cmd.exe",
                "CommandLine": "something < someother",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "@timestamp": "1696587400",
                "OriginalFileName": "Cmd.exe",
                "Image": "c:\\windows\\system32\\cmd.exe",
                "CommandLine": "something > someother",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "@timestamp": "1696587400",
                "OriginalFileName": "Cmd.exe",
                "Image": "c:\\windows\\system32\\cmd.exe",
                "CommandLine": "without angle bracket",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        # Wait a bit for Documents to be indexed
        time.sleep(1)


@pytest.fixture(name="eql_backend")
def fixture_eql_backend():
    return EqlBackend()


@pytest.mark.skipif(es_available_test() is False, reason="ES not available")
class TestConnectElasticsearch:
    """
    Test Class for Elasticsearch Backend
    """

    def query_backend_hits(self, query, num_wanted=0):
        result = requests.post(
            f"{pytest.es_url}/test-index/_eql/search",
            json=query,
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        assert result.status_code == 200
        rjson = result.json()
        assert "hits" in rjson
        assert "total" in rjson["hits"]
        assert rjson["hits"]["total"]["value"] == num_wanted
        return rjson

    def test_connect_eql_and_expression(self, prepare_es_data, eql_backend: EqlBackend):
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

        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_and_expression_empty_string(
        self, prepare_es_data, eql_backend: EqlBackend
    ):
        rule = SigmaCollection.from_yaml(
            """
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
            """
        )

        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_or_expression(self, prepare_es_data, eql_backend: EqlBackend):
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
        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_and_or_expression(
        self, prepare_es_data, eql_backend: EqlBackend
    ):
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
        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=2)

    def test_connect_eql_or_and_expression(
        self, prepare_es_data, eql_backend: EqlBackend
    ):
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
        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=2)

    def test_connect_eql_in_expression(self, prepare_es_data, eql_backend: EqlBackend):
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
        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_in_expression_empty_string(
        self, prepare_es_data, eql_backend: EqlBackend
    ):
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
                            - otherisempty
                            - ''
                    condition: sel
            """
        )
        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_regex_query(self, prepare_es_data, eql_backend: EqlBackend):
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
        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_cidr_query(self, prepare_es_data, eql_backend: EqlBackend):
        rule = SigmaCollection.from_yaml(
            """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        ipfield|cidr: 192.168.0.0/16
                    condition: sel
            """
        )

        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_ip_query(self, prepare_es_data, eql_backend: EqlBackend):
        rule = SigmaCollection.from_yaml(
            """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        ipfield: 192.168.1.1
                    condition: sel
            """
        )

        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_field_name_with_whitespace(
        self, prepare_es_data, eql_backend: EqlBackend
    ):
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
        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_dot_value(self, prepare_es_data, eql_backend: EqlBackend):
        rule = SigmaCollection.from_yaml(
            """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldK: dot.value
                    condition: sel
            """
        )

        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_space_value_text(
        self, prepare_es_data, eql_backend: EqlBackend
    ):
        """Test for output format siem_rule."""
        # WONTFIX: EQL won't work on text fields!
        # See also: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html#eql-text-fields
        pass

    def test_connect_eql_space_value_keyword(
        self, prepare_es_data, eql_backend: EqlBackend
    ):
        rule = SigmaCollection.from_yaml(
            """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        keywordFieldA: 'value with spaces'
                    condition: sel
            """
        )

        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_eql_angle_brackets(self, prepare_es_data, eql_backend: EqlBackend):
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

        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=2)

    def test_connect_eql_angle_brackets_single(
        self, prepare_es_data, eql_backend: EqlBackend
    ):
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
                        CommandLine|contains: '<'
                    condition: all of selection_*
            """
        )

        result_dsl = eql_backend.convert(rule, output_format="eqlapi")[0]
        self.query_backend_hits(result_dsl, num_wanted=1)
