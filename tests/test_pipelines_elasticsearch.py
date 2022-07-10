import pytest
from sigma.backends.elasticsearch import ElasticsearchQueryStringBackend
from sigma.pipelines.elasticsearch.ecs import ecs_windows
from sigma.collection import SigmaCollection

def test_ecs_windows():
    assert ElasticsearchQueryStringBackend(ecs_windows()).convert(
        SigmaCollection.from_yaml(f"""
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
    ) == ['winlog.channel:"Security" AND event.code:123 AND process.executable:"test.exe" AND winlog.event_data.TestField:"test"']

def test_ecs_windows_other_logsource():
    assert ElasticsearchQueryStringBackend(ecs_windows()).convert(
        SigmaCollection.from_yaml(f"""
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
    ) == ['Image:"test"']