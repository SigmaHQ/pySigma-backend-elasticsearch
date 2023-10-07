import pytest
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.pipelines.elasticsearch.zeek import ecs_zeek_beats, ecs_zeek_corelight, zeek_raw
from sigma.collection import SigmaCollection

@pytest.fixture
def sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: proxy
        detection:
            sel:
                cs-method: POST
                cs-host: test.invalid
                username: testuser
            condition: sel
    """)

def test_ecs_zeek_beats(sigma_rule):
    assert LuceneBackend(ecs_zeek_beats()).convert(sigma_rule) == \
        ['event.dataset:zeek.http AND (http.request.method:POST AND (url.domain:test.invalid OR destination.domain:test.invalid) AND zeek.\\*.username:testuser)']

def test_ecs_zeek_corelight(sigma_rule):
    assert LuceneBackend(ecs_zeek_corelight()).convert(sigma_rule) == \
        ['event.dataset:zeek.http AND (http.request.method:POST AND (url.domain:test.invalid OR destination.domain:test.invalid) AND zeek.\\*.username:testuser)']

def test_zeek_raw(sigma_rule):
    assert LuceneBackend(zeek_raw()).convert(sigma_rule) == \
        ['@stream:http AND (method:POST AND host:test.invalid AND username:testuser)']
