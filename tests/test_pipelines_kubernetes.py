import pytest
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.pipelines.elasticsearch.kubernetes import ecs_kubernetes
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def test_ecs_kubernetes():
    assert (
        LuceneBackend(ecs_kubernetes()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                  verb: create
                  resource: pods
                condition: selection
        """
            )
        )
        == [
            "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.resource:pods)"
        ]
    )


def test_ecs_kubernetes_apigroup():
    assert (
        LuceneBackend(ecs_kubernetes()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                  verb: create
                  apiGroup: authorization.k8s.io
                  resource: selfsubjectrulesreviews
                condition: selection
        """
            )
        )
        == [
            "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.apiGroup:authorization.k8s.io AND kubernetes.audit.objectRef.resource:selfsubjectrulesreviews)"
        ]
    )


def test_ecs_kubernetes_capabilities():
    assert (
        LuceneBackend(ecs_kubernetes()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                  verb: create
                  resource: pods
                  capabilities: "*"
                condition: selection
        """
            )
        )
        == [
            "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.resource:pods AND kubernetes.audit.requestObject.spec.containers.securityContext.capabilities.add:*)"
        ]
    )

    def test_ecs_kubernetes_subresource():
        assert (
            LuceneBackend(ecs_kubernetes()).convert(
                SigmaCollection.from_yaml(
                    """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                  verb: create
                  resource: pods
                  subresource: exec
                condition: selection
        """
                )
            )
            == [
                "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.resource:pods AND kubernetes.audit.objectRef.subresource:exec)"
            ]
        )


def test_ecs_kubernetes_fields():
    rule = ecs_kubernetes().apply(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                    verb: create
                    resource: pods
                    hostPath: "*"
                condition: selection
            fields:
                - verb
                - hostPath
        """
        )
    )
    assert rule.fields == [
        "kubernetes.audit.verb",
        "kubernetes.audit.requestObject.spec.volumes.hostPath",
    ]


@pytest.mark.parametrize("prefix", ["", "objectRef."])
@pytest.mark.parametrize(
    "field,value",
    [
        ("apiGroup", "apps"),
        ("resource", "pods"),
        ("subresource", "exec"),
        ("namespace", "default"),
        ("apiGroup", ""),
        ("subresource", ""),
    ],
)
def test_ecs_kubernetes_objectref_alias(prefix, field, value):
    rule = SigmaCollection.from_yaml(
        f"""
        title: Test
        status: test
        logsource:
            product: kubernetes
            service: audit
        detection:
            selection:
                verb: create
                {prefix}{field}: '{value}'
            condition: selection
        """
    )
    expected = "kubernetes.audit.verb:create"
    if value:
        expected += f" AND kubernetes.audit.objectRef.{field}:{value}"
    assert LuceneBackend(ecs_kubernetes()).convert(rule) == [
        f"kubernetes.audit.kind:Event AND ({expected})"
    ]
