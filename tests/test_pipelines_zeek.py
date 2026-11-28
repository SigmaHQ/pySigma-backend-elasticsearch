import pytest
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.pipelines.elasticsearch.zeek import (
    ecs_zeek_beats,
    ecs_zeek_corelight,
    zeek_raw,
)
from sigma.collection import SigmaCollection


@pytest.fixture
def sigma_rule():
    return SigmaCollection.from_yaml(
        """
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
    """
    )


def test_ecs_zeek_beats(sigma_rule):
    assert LuceneBackend(ecs_zeek_beats()).convert(sigma_rule) == [
        "event.dataset:zeek.http AND (http.request.method:POST AND (url.domain:test.invalid OR destination.domain:test.invalid) AND zeek.\\*.username:testuser)"
    ]


def test_ecs_zeek_corelight(sigma_rule):
    assert LuceneBackend(ecs_zeek_corelight()).convert(sigma_rule) == [
        "event.dataset:zeek.http AND (http.request.method:POST AND (url.domain:test.invalid OR destination.domain:test.invalid) AND zeek.\\*.username:testuser)"
    ]


def test_zeek_raw(sigma_rule):
    assert LuceneBackend(zeek_raw()).convert(sigma_rule) == [
        "@stream:http AND (method:POST AND host:test.invalid AND username:testuser)"
    ]


@pytest.mark.parametrize("pipeline", [ecs_zeek_beats, ecs_zeek_corelight])
def test_ecs_zeek_ssl_subject(pipeline):
    rule = SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            product: zeek
            service: ssl
        detection:
            sel:
                ssl_subject: example
            condition: sel
        """
    )
    assert LuceneBackend(pipeline()).convert(rule) == [
        "event.dataset:zeek.ssl AND zeek.ssl.subject:example"
    ]


@pytest.mark.parametrize(
    "pipeline, field",
    [(ecs_zeek_beats, "dns.answers.data"), (ecs_zeek_corelight, "dns.answers.name")],
)
@pytest.mark.parametrize("sigma_field", ["answer", "answers"])
def test_ecs_zeek_dns_answer(pipeline, field, sigma_field):
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test
        status: test
        logsource:
            product: zeek
            service: dns
        detection:
            sel:
                {sigma_field}: 127.0.0.1
            condition: sel
        """
    )
    assert LuceneBackend(pipeline()).convert(rule) == [
        f"event.dataset:zeek.dns AND {field}:127.0.0.1"
    ]


@pytest.mark.parametrize(
    "pipeline, field",
    [(ecs_zeek_beats, "dns.answers.data"), (ecs_zeek_corelight, "dns.answers.name")],
)
def test_ecs_zeek_dns_answer_excluded(pipeline, field):
    rule = SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            product: zeek
            service: dns
        detection:
            sel:
                query: example.invalid
            filter:
                answer: 127.0.0.1
            condition: sel and not filter
        """
    )
    assert LuceneBackend(pipeline()).convert(rule) == [
        f"event.dataset:zeek.dns AND (dns.question.name:example.invalid AND (NOT {field}:127.0.0.1))"
    ]
