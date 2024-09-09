from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddConditionTransformation,
    DropDetectionItemTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    IncludeFieldCondition,
    MatchStringCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline


def ecs_kubernetes() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Elastic Common Schema (ECS) Kubernetes audit log mappings",
        priority=30,
        allowed_backends=("elasticsearch", "eql", "lucene"),
        items=[
            ProcessingItem(
                identifier="index_condition",
                transformation=AddConditionTransformation(
                    conditions={"kubernetes.audit.kind": "Event"}, template=False
                ),
                rule_conditions=[
                    LogsourceCondition(product="kubernetes", service="audit"),
                ],
            ),
            ProcessingItem(
                identifier="field_mapping",
                transformation=FieldMappingTransformation(
                    mapping={
                        "verb": ["kubernetes.audit.verb"],
                        "apiGroup": ["kubernetes.audit.objectRef.apiGroup"],
                        "resource": ["kubernetes.audit.objectRef.resource"],
                        "subresource": ["kubernetes.audit.objectRef.subresource"],
                        "namespace": ["kubernetes.audit.objectRef.namespace"],
                        "username": ["kubernetes.audit.user.username"],
                        "capabilities": [
                            "kubernetes.audit.requestObject.spec.containers.securityContext.capabilities.add"
                        ],
                        "privileged": [
                            "kubernetes.audit.responseObject.spec.containers.securityContext.privileged"
                        ],
                        "hostPath": [
                            "kubernetes.audit.requestObject.spec.volumes.hostPath"
                        ],
                    }
                ),
            ),
            ProcessingItem(
                identifier="drop_default_apigroup",
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=["apiGroup", "kubernetes.audit.objectRef.apiGroup"]
                    )
                ],
                detection_item_conditions=[
                    MatchStringCondition(cond="any", pattern="^$")
                ],
            ),
            ProcessingItem(
                identifier="drop_empty_subresource",
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=["subresource", "kubernetes.audit.objectRef.subresource"]
                    )
                ],
                detection_item_conditions=[
                    MatchStringCondition(cond="any", pattern="^$")
                ],
            ),
        ],
    )
