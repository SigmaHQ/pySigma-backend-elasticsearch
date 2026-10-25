from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.pipelines.elasticsearch.windows import ecs_windows, ecs_windows_old
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def test_ecs_windows():
    assert (
        LuceneBackend(ecs_windows()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    EventID: 123
                    Image: test.exe
                    TestField: test
                condition: sel
        """
            )
        )
        == [
            "winlog.channel:Security AND (event.code:123 AND process.executable.caseless:test.exe AND winlog.event_data.TestField:test)"
        ]
    )

def test_ecs_values_to_str():
    assert (
        ESQLBackend(ecs_windows()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    EventID: 123
                    DestinationIp|cidr: 192.168.0.0/16
                    DestinationPort: 80
                condition: sel
        """
            )
        ) == [
            'from * metadata _id, _index, _version | where winlog.channel=="Security" and event.code=="123" and cidr_match(destination.ip, "192.168.0.0/16") and destination.port==80'
        ]
    )

def test_ecs_network_direction_str_egress():
    assert (
        ESQLBackend(ecs_windows()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                sel:
                    Initiated: true
                condition: sel
        """
            )
        ) == [
            'from * metadata _id, _index, _version | where network.direction=="egress"'
        ]
    )

def test_ecs_network_direction_str_ingress():
    assert (
        ESQLBackend(ecs_windows()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                sel:
                    Initiated: false
                condition: sel
        """
            )
        ) == [
            'from * metadata _id, _index, _version | where network.direction=="ingress"'
        ]
    )


def test_ecs_windows_fields():
    rule = ecs_windows().apply(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    EventID: 123
                    Image: test.exe
                    TestField: test
                condition: sel
            fields:
                - EventID
                - TestField
        """
        )
    )
    assert rule.fields == ["event.code", "winlog.event_data.TestField"]


def test_ecs_windows_variable_mapping():
    assert (
        LuceneBackend(ecs_windows()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    CommandLine: test
                    OriginalFileName: test.exe
                condition: sel
        """
            )
        )
        == ["process.command_line:test AND process.pe.original_file_name:test.exe"]
    )


def test_ecs_windows_old():
    assert (
        LuceneBackend(ecs_windows_old()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    EventID: 123
                    Image: test.exe
                condition: sel
        """
            )
        )
        == ["winlog.channel:Security AND (event_id:123 AND event_data.Image:test.exe)"]
    )


def test_ecs_windows_other_logsource():
    assert (
        LuceneBackend(ecs_windows()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: linux
                service: security
            detection:
                sel:
                    Image: test
                condition: sel
        """
            )
        )
        == ["Image:test"]
    )

def test_ecs_windows_eql_contains_expression_with_trailing_backslash_multivalue():
    eql_backend = EqlBackend(ecs_windows())
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test
            status: test
            logsource:
                product: windows
            detection:
                sel:
                    Image|contains:
                    - 'valueA\'
                    - 'valueB'
                condition: sel
        """
    )
    assert eql_backend.convert(rule) == [
        r'any where process.executable.caseless like~ ("*valueA\\*", "*valueB*")'
    ]

def test_ecs_windows_null_value_handling():
    """regression test for https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/173"""
    rule = SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|endswith: svchost.exe
            filter:
                - ParentImage|endswith: rpcnet.exe
                - CommandLine: null
            condition: selection and not filter
    """)
    result = LuceneBackend(ecs_windows()).convert(rule)
    assert "SigmaNull" not in result[0]

def test_ecs_windows_eql_regex_conversion():
    """regression test for https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/177"""
    eql_backend = EqlBackend(ecs_windows())
    rule = SigmaCollection.from_yaml("""
        title: min re
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine|re: 'foobar[0-9]{3}'
            condition: sel
    """)
    result = eql_backend.convert(rule)
    assert result == ['any where process.command_line regex~ "foobar[0-9]{3}"']

def test_ecs_windows_lucene_regex_conversion():
    """regression test for https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/177"""
    lucene_backend = LuceneBackend(ecs_windows())
    rule = SigmaCollection.from_yaml("""
        title: min re
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine|re: 'foobar[0-9]{3}'
            condition: sel
    """)
    result = lucene_backend.convert(rule)
    assert result == ["process.command_line:/foobar[0-9]{3}/"]
