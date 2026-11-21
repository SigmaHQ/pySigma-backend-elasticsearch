import time
import pytest
import requests
import urllib3
from requests.auth import HTTPBasicAuth
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
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
                    "textFieldA": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword"}},
                    },
                    "keywordFieldA": {"type": "keyword"},
                    "caseTextField": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword"}},
                    },
                    "caseIntField": {"type": "integer"},
                    "caseDateField": {"type": "date"},
                },
                "dynamic_templates": [
                    {"default": {"match": "*", "mapping": {"type": "keyword"}}}
                ],
            },
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"fieldA": "valueA", "fieldB": "valueB"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"fieldA": "otherisempty", "fieldB": ""},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"fieldK": "dot.value"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"fieldA": "valueA1", "fieldB": "valueB1"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"fieldA": "valueA2", "fieldB": "valueB2"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"fieldA": "foosamplebar", "fieldB": "foo"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"fieldA": "foobar", "fieldB": "bar"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"ipfield": "192.168.1.1"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"ipfield": "fe80:0000:0000:0000:0000:0000:0000:beef"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"ipfield": "2603:1080:beef::1"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"ipfield": "10.5.5.5"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"field name": "value"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"textFieldA": "value with spaces"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"textFieldA": "value2 with spaces"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"keywordFieldA": "value with spaces"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"keywordFieldA": "value2 with spaces"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "OriginalFileName": "Cmd.exe",
                "CommandLine": "something < someother",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "OriginalFileName": "Cmd.exe",
                "CommandLine": "something > someother",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "OriginalFileName": "Cmd.exe",
                "CommandLine": "without angle bracket",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "Image": "c:\\windows\\system32\\Sysmon.exe",
                "Description": "System activity monitor",
                "CommandLine": "Sysmon.exe -u",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "Image": "c:\\windows\\system32\\Sysmon.exe",
                "Description": "System activity monitor",
                "CommandLine": "Sysmon.exe /u",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "Image": "c:\\windows\\system32\\nonsysmon.exe",
                "Description": "System idle monitor",
                "CommandLine": "nonsysmon.exe -u",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "Image": "c:\\windows\\system32\\nonsysmon.exe",
                "Description": "System idle monitor",
                "CommandLine": "nonsysmon.exe /u",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "Image": "c:\\windows\\system32\\bitsadmin.exe",
                "CommandLine": "bitsadmin.exe /transfer https://sigmahq.io/",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "Image": "c:\\windows\\system32\\bitsadmin.exe",
                "CommandLine": "bitsadmin.exe /create https://sigmahq.io/ /addfile testdata2",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "Image": "c:\\windows\\system32\\bitsadmin.exe",
                "CommandLine": "bitsadmin.exe /create smbfs://testdatashouldnotmatch",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"quotationMessage": "Failed to generate curve25519 keys"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"literalStarField": "prefix a*b suffix"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"literalStarField": "prefix axb suffix"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        # Mixed-case values of different field types for case-insensitivity tests.
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "mixedCaseField": "GiT.ExE --version",
                "caseTextField": "C:\\Program Files\\IntelliJ IDEA\\bin\\idea64.exe",
                "caseIntField": 42,
                "caseDateField": "2024-01-01T00:00:00Z",
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={
                "mixedCaseField": "PoWeRsHeLl.ExE -Command Invoke-Mimikatz",
                "caseIntField": 7,
            },
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        requests.post(
            f"{pytest.es_url}/test-index/_doc/",
            json={"mixedCaseField": "Path*With?Mark"},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )

        # Wait a bit for Documents to be indexed
        time.sleep(1)


@pytest.fixture(name="esql_backend")
def fixture_esql_backend():
    return ESQLBackend()


@pytest.mark.skipif(es_available_test() is False, reason="ES not available")
class TestConnectElasticsearch:
    """
    Test Class for Elasticsearch Backend
    """

    def query_backend_hits(self, query, num_wanted=0):
        result = requests.post(
            f"{pytest.es_url}/_query",
            json={"query": query},
            timeout=120,
            verify=False,
            auth=pytest.es_creds,
        )
        assert result.status_code == 200
        rjson = result.json()
        assert "values" in rjson
        assert len(rjson["values"]) == num_wanted
        return rjson

    def test_connect_esql_and_expression(
        self, prepare_es_data, esql_backend: ESQLBackend
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
                        fieldA: valueA
                        fieldB: valueB
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_and_expression_empty_string(
        self, prepare_es_data, esql_backend: ESQLBackend
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

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_or_expression(
        self, prepare_es_data, esql_backend: ESQLBackend
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
                        fieldA: valueA
                    sel2:
                        fieldB: valueB
                    condition: 1 of sel*
            """
        )
        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_and_or_expression(
        self, prepare_es_data, esql_backend: ESQLBackend
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
        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=2)

    def test_connect_esql_or_and_expression(
        self, prepare_es_data, esql_backend: ESQLBackend
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
        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=2)

    def test_connect_esql_in_expression(
        self, prepare_es_data, esql_backend: ESQLBackend
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
                            - valueA
                            - valueB
                            - valueC*
                    condition: sel
            """
        )
        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_in_expression_empty_string(
        self, prepare_es_data, esql_backend: ESQLBackend
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
        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_wildcard_expressions(
        self, prepare_es_data, esql_backend: ESQLBackend
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
                            - "valueA*"
                            - "*otherisempty"
                            - "foosamplebar*"
                    condition: sel
            """
        )
        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=5)

    def test_connect_esql_like_backslash(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        Image|contains: '\system32\Sysmon'
                    condition: sel
            """
        )
        result_esql = esql_backend.convert(rule)[0]
        result = self.query_backend_hits(result_esql, num_wanted=2)

        # Ensure we see only the searched Sysmon.exe Images.
        image_col = next(
            i
            for i, column in enumerate(result["columns"])
            if column["name"] == "Image"
        )
        assert all("Sysmon.exe" in entry[image_col] for entry in result["values"])

    def test_connect_esql_like_literal_star(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        literalStarField|contains: 'a\*b'
                    condition: sel
            """
        )
        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_regex_query(self, prepare_es_data, esql_backend: ESQLBackend):
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
        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    @pytest.mark.parametrize(
        "modifiers, regex, num_wanted",
        [
            # Sigma regexes match anywhere in the value (Lucene regexes must match all of it)
            ("re", r"exe\s[-/]u", 4),
            # anchored at the start: excludes nonsysmon.exe
            ("re", r"^Sysmon\.exe", 2),
            # case-insensitive, anchored at both ends
            ("re|i", r"^SYSMON\.EXE\s/U$", 1),
        ],
    )
    def test_connect_esql_regex_search_semantics(
        self, prepare_es_data, esql_backend: ESQLBackend, modifiers, regex, num_wanted
    ):
        rule = SigmaCollection.from_yaml(
            f"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        CommandLine|{modifiers}: '{regex}'
                    condition: sel
            """
        )
        result = esql_backend.convert(rule)[0]
        self.query_backend_hits(result, num_wanted=num_wanted)

    def test_connect_esql_cidr_v4_query(
        self, prepare_es_data, esql_backend: ESQLBackend
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
                        ipfield|cidr: 192.168.0.0/16
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_cidr_v6_query(
        self, prepare_es_data, esql_backend: ESQLBackend
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
                        ipfield|cidr:
                            - 'fe80::/10'
                            - '2603:1080::/25'
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=2)

    def test_connect_esql_ip_query(self, prepare_es_data, esql_backend: ESQLBackend):
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

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_field_name_with_whitespace(
        self, prepare_es_data, esql_backend: ESQLBackend
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
        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_dot_value(self, prepare_es_data, esql_backend: ESQLBackend):
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

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_space_value_text(
        self, prepare_es_data, esql_backend: ESQLBackend
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
                        textFieldA.keyword: 'value with spaces'
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_space_value_keyword(
        self, prepare_es_data, esql_backend: ESQLBackend
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

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_angle_brackets(
        self, prepare_es_data, esql_backend: ESQLBackend
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
                        - CommandLine|contains: '<'
                        - CommandLine|contains: '>'
                    condition: all of selection_*
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=2)

    def test_connect_esql_angle_brackets_single(
        self, prepare_es_data, esql_backend: ESQLBackend
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

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=1)

    def test_connect_esql_windash_double(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection_pe:
                        - Image|endswith: 
                            - '\Sysmon64.exe'
                            - '\Sysmon.exe'
                        - Description: 'System activity monitor'
                    selection_cli:
                        CommandLine|contains|windash: '-u'
                    condition: all of selection_*
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        result = self.query_backend_hits(result_esql, num_wanted=2)

        # Ensure we see only the searched Sysmon.exe Images.
        image_col = next(
            i
            for i, column in enumerate(result["columns"])
            if column["name"] == "Image"
        )
        assert all("Sysmon.exe" in entry[image_col] for entry in result["values"])

    def test_connect_esql_advanced_quotetest(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection_img:
                        - Image|endswith: '\bitsadmin.exe'
                        - OriginalFileName: 'bitsadmin.exe'
                    selection_cmd:
                        CommandLine|contains: ' /transfer '
                    selection_cli_1:
                        CommandLine|contains:
                            - ' /create '
                            - ' /addfile '
                    selection_cli_2:
                        CommandLine|contains: 'http'
                    condition: selection_img and (selection_cmd or all of selection_cli_*)
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        result = self.query_backend_hits(result_esql, num_wanted=2)

        # Ensure we see only the searched bitsadmin.exe Images.
        image_col = next(
            i
            for i, column in enumerate(result["columns"])
            if column["name"] == "Image"
        )
        assert all("bitsadmin.exe" in entry[image_col] for entry in result["values"])

    def test_connect_esql_fieldref_startswith(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|fieldref|startswith: fieldB
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        assert "STARTS_WITH(fieldA,fieldB)" in result_esql
        self.query_backend_hits(result_esql, num_wanted=2)

    def test_connect_esql_fieldref_contains(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|fieldref|contains: fieldB
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        assert "CONTAINS(fieldA,fieldB)" in result_esql
        self.query_backend_hits(result_esql, num_wanted=3)

    def test_connect_esql_fieldref_endswith(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|fieldref|endswith: fieldB
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        assert "ENDS_WITH(fieldA,fieldB)" in result_esql
        self.query_backend_hits(result_esql, num_wanted=2)

    def query_backend_hits_column(self, query, column, num_wanted):
        result = self.query_backend_hits(query, num_wanted=num_wanted)
        column_index = next(
            i for i, col in enumerate(result["columns"]) if col["name"] == column
        )
        return [entry[column_index] for entry in result["values"]]

    @pytest.mark.parametrize(
        "modifier, value, expected",
        [
            # case-insensitive by default, Sigma value in the opposite case
            ("", "git.exe --VERSION", "GiT.ExE --version"),
            ("|contains", "POWERSHELL.EXE", "PoWeRsHeLl.ExE -Command Invoke-Mimikatz"),
            ("|startswith", "powershell", "PoWeRsHeLl.ExE -Command Invoke-Mimikatz"),
            ("|endswith", "INVOKE-MIMIKATZ", "PoWeRsHeLl.ExE -Command Invoke-Mimikatz"),
        ],
    )
    def test_connect_esql_case_insensitive_string(
        self, prepare_es_data, esql_backend: ESQLBackend, modifier, value, expected
    ):
        rule = SigmaCollection.from_yaml(
            f"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        mixedCaseField{modifier}: '{value}'
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        assert self.query_backend_hits_column(result_esql, "mixedCaseField", 1) == [
            expected
        ]

    @pytest.mark.parametrize(
        "modifier, value, num_wanted",
        [
            # |cased must not be lowercased
            ("|cased", "git.exe --version", 0),
            ("|cased", "GiT.ExE --version", 1),
            ("|cased|contains", "powershell.exe", 0),
            ("|cased|contains", "PoWeRsHeLl.ExE", 1),
        ],
    )
    def test_connect_esql_cased_string(
        self, prepare_es_data, esql_backend: ESQLBackend, modifier, value, num_wanted
    ):
        rule = SigmaCollection.from_yaml(
            f"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        mixedCaseField{modifier}: '{value}'
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=num_wanted)

    def test_connect_esql_case_insensitive_in_expression(
        self, prepare_es_data, esql_backend: ESQLBackend
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
                        mixedCaseField:
                            - GIT.EXE --VERSION
                            - POWERSHELL.EXE -COMMAND INVOKE-MIMIKATZ
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=2)

    def test_connect_esql_case_insensitive_text_field(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        caseTextField.keyword: 'c:\PROGRAM FILES\intellij idea\bin\IDEA64.EXE'
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        values = self.query_backend_hits_column(result_esql, "caseTextField.keyword", 1)
        assert values == ["C:\\Program Files\\IntelliJ IDEA\\bin\\idea64.exe"]

    def test_connect_esql_case_insensitive_like_literal_wildcards(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        mixedCaseField|contains: 'path\*with\?mark'
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        assert self.query_backend_hits_column(result_esql, "mixedCaseField", 1) == [
            "Path*With?Mark"
        ]

    def test_connect_esql_case_insensitive_like_backslash(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        rule = SigmaCollection.from_yaml(
            r"""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        Image|contains: '\SYSTEM32\SYSMON'
                    condition: sel
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        assert self.query_backend_hits_column(result_esql, "Image", 2) == [
            "c:\\windows\\system32\\Sysmon.exe",
            "c:\\windows\\system32\\Sysmon.exe",
        ]

    def test_connect_esql_case_insensitive_with_non_string_condition(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        # The lowercased LIKE condition must also match when ES|QL can't push the
        # whole expression down to Lucene.
        rule = SigmaCollection.from_yaml(
            """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel1:
                        mixedCaseField|contains: git.exe
                    sel2:
                        caseIntField: 7
                    condition: sel1 or sel2
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        self.query_backend_hits(result_esql, num_wanted=2)

    def test_connect_esql_non_string_field_types(
        self, prepare_es_data, esql_backend: ESQLBackend
    ):
        # TO_LOWER() only accepts strings: ip, integer and date comparisons must not
        # be wrapped, otherwise Elasticsearch rejects the query.
        rule = SigmaCollection.from_yaml(
            """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel1:
                        ipfield: 'fe80::beef'
                    sel2:
                        caseIntField: 42
                    sel3:
                        # |cased is the escape hatch for non-string fields
                        caseDateField|cased: '2024-01-01'
                    condition: sel1 or sel2 or sel3
            """
        )

        result_esql = esql_backend.convert(rule)[0]
        assert "TO_LOWER(" not in result_esql
        self.query_backend_hits(result_esql, num_wanted=2)
