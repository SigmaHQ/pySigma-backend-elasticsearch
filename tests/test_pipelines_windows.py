from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.pipelines.elasticsearch.windows import ecs_windows, ecs_windows_elastic_defend, ecs_windows_old
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
            "winlog.channel:Security AND (event.code:123 AND process.executable:test.exe AND winlog.event_data.TestField:test)"
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
        r'any where process.executable like~ ("*valueA\\*", "*valueB*")'
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
    assert result == ['any where process.command_line regex ".*(foobar[0-9]{3}).*"']

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
    assert result == ["process.command_line:/.*(foobar[0-9]{3}).*/"]


def test_ecs_windows_elastic_defend_caseless_image():
    """ecs_windows_elastic_defend remaps process.executable to .caseless for Elastic Defend indices."""
    from sigma.pipelines.elasticsearch.windows import ecs_windows_elastic_defend
    pipeline = ecs_windows() + ecs_windows_elastic_defend()
    assert (
        LuceneBackend(pipeline).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image|endswith: '\\powershell.exe'
                    ParentImage|endswith: '\\cmd.exe'
                    SourceImage|endswith: '\\notepad.exe'
                    Destination|endswith: '\\svchost.exe'
                    Application|endswith: '\\explorer.exe'
                    NewProcessName|endswith: '\\calc.exe'
                    ProcessName|endswith: '\\taskmgr.exe'
                    ParentProcessName|endswith: '\\system.exe'
                condition: sel
        """
            )
        )
        == [
            "process.executable.caseless:*\\\\powershell.exe AND process.parent.executable.caseless:*\\\\cmd.exe AND process.executable.caseless:*\\\\notepad.exe AND process.executable.caseless:*\\\\svchost.exe AND process.executable.caseless:*\\\\explorer.exe AND process.executable.caseless:*\\\\calc.exe AND process.executable.caseless:*\\\\taskmgr.exe AND process.parent.name.caseless:*\\\\system.exe"
        ]
    )


def test_ecs_windows_no_caseless_by_default():
    """ecs_windows alone does not produce .caseless fields (Winlogbeat compatibility)."""
    assert (
        LuceneBackend(ecs_windows()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image|endswith: '\\powershell.exe'
                    ParentImage|endswith: '\\cmd.exe'
                condition: sel
        """
            )
        )
        == [
            "process.executable:*\\\\powershell.exe AND process.parent.executable:*\\\\cmd.exe"
        ]
    )


def test_ecs_windows_plus_elastic_defend_caseless_mapping():
    """Test that ecs_windows() + ecs_windows_elastic_defend() produces .caseless field mapping.
    
    This test verifies the combination of both pipelines correctly remaps process executable
    and name fields to their .caseless equivalents for Elastic Defend indices.
    """
    combined_pipeline = ecs_windows() + ecs_windows_elastic_defend()
    
    # Test all field variants that should be mapped to .caseless
    assert (
        LuceneBackend(combined_pipeline).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: test.exe
                    ParentImage: parent.exe
                condition: sel
        """
            )
        )
        == [
            "process.executable.caseless:test.exe AND process.parent.executable.caseless:parent.exe"
        ]
    )


def test_ecs_windows_plus_elastic_defend_process_name():
    """Test that ecs_windows() + ecs_windows_elastic_defend() maps process.name to .caseless.
    
    This test verifies that ProcessName and ParentProcessName fields are properly
    mapped to their .caseless variants.
    """
    combined_pipeline = ecs_windows() + ecs_windows_elastic_defend()
    
    assert (
        LuceneBackend(combined_pipeline).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    ProcessName: notepad.exe
                    ParentProcessName: explorer.exe
                condition: sel
        """
            )
        )
        == [
            "process.name.caseless:notepad.exe AND process.parent.name.caseless:explorer.exe"
        ]
    )
