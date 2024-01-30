from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.pipelines.elasticsearch.windows import ecs_windows, ecs_windows_old
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def test_ecs_windows():
    assert LuceneBackend(ecs_windows()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['winlog.channel:Security AND (event.code:123 AND process.executable:test.exe AND winlog.event_data.TestField:test)']


def test_ecs_windows_fields():
    rule = ecs_windows().apply(SigmaRule.from_yaml("""
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
        """)
                               )
    assert rule.fields == ["event.code", "winlog.event_data.TestField"]


def test_ecs_windows_variable_mapping():
    assert LuceneBackend(ecs_windows()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['process.command_line:test AND process.pe.original_file_name:test.exe']


def test_ecs_windows_old():
    assert LuceneBackend(ecs_windows_old()).convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['winlog.channel:Security AND (event_id:123 AND event_data.Image:test.exe)']


def test_ecs_windows_other_logsource():
    assert LuceneBackend(ecs_windows()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: linux
                service: security
            detection:
                sel:
                    Image: test
                condition: sel
        """)
    ) == ['Image:test']
