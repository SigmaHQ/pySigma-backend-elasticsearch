import pytest
from sigma.backends.elasticsearch import ElasticsearchQueryStringBackend
from sigma.pipelines.elasticsearch.zeek import ecs_zeek_beats, ecs_zeek_corelight
from sigma.collection import SigmaCollection

def test_ecs_zeek_beats():
    assert ElasticsearchQueryStringBackend(ecs_zeek_beats()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: proxy
            detection:
                sel:
                    method: POST
                    cs-host: test.invalid
                    username: testuser
                condition: sel
        """)
    ) == ['event.dataset:"zeek.http" AND http.request.method:"POST" AND (url.domain:"test.invalid" OR destination.domain:"test.invalid") AND zeek.\\*.username:"testuser"']

def test_ecs_zeek_corelight():
    assert ElasticsearchQueryStringBackend(ecs_zeek_corelight()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: proxy
            detection:
                sel:
                    method: POST
                    cs-host: test.invalid
                    username: testuser
                condition: sel
        """)
    ) == ['event.dataset:"zeek.http" AND http.request.method:"POST" AND (url.domain:"test.invalid" OR destination.domain:"test.invalid") AND zeek.\\*.username:"testuser"']