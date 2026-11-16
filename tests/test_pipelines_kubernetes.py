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


def test_ecs_kubernetes_objectref_alias():
    rule = SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            product: kubernetes
            service: audit
        detection:
            selection:
                verb: create
                objectRef.apiGroup: apps
            condition: selection
        """
    )
    assert LuceneBackend(ecs_kubernetes()).convert(rule) == [
        "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.apiGroup:apps)"
    ]


def test_ecs_kubernetes_objectref_alias_resource():
    rule = SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            product: kubernetes
            service: audit
        detection:
            selection:
                verb: create
                objectRef.resource: pods
            condition: selection
        """
    )
    assert LuceneBackend(ecs_kubernetes()).convert(rule) == [
        "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.resource:pods)"
    ]


def test_ecs_kubernetes_objectref_alias_subresource():
    rule = SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            product: kubernetes
            service: audit
        detection:
            selection:
                verb: create
                subresource: exec
            condition: selection
        """
    )
    assert LuceneBackend(ecs_kubernetes()).convert(rule) == [
        "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.subresource:exec)"
    ]


def test_ecs_kubernetes_objectref_alias_namespace():
    rule = SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            product: kubernetes
            service: audit
        detection:
            selection:
                verb: create
                namespace: default
            condition: selection
        """
    )
    assert LuceneBackend(ecs_kubernetes()).convert(rule) == [
        "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.namespace:default)"
    ]


def test_ecs_kubernetes_objectref_alias_empty_value():
    rule = SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            product: kubernetes
            service: audit
        detection:
            selection:
                verb: create
                objectRef.apiGroup: ''
            condition: selection
        """
    )
    assert LuceneBackend(ecs_kubernetes()).convert(rule) == [
        "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create)"
    ]
