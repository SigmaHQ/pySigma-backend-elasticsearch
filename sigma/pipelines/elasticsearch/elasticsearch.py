from sigma.pipelines.common import logsource_windows
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

windows_logsource_mapping = {       # define mappings and iterate over them in pipeline definitions to get more readable pipeline definitions.
    "security": "WinEventLog:Security",
    "application": "WinEventLog:Application",
    "system": "WinEventLog:System",
    "sysmon": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
}

def elasticsearch_example():      # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="Elasticsearch example pipeline",
        priority=20,            # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                identifier=f"elasticsearch_windows_{service}",
                transformation=AddConditionTransformation({ "source": source}),
                rule_conditions=[logsource_windows(service)],
            )
            for service, source in windows_logsource_mapping.items()
        ] + [
            ProcessingItem(     # Field mappings
                identifier="elasticsearch_field_mapping",
                transformation=FieldMappingTransformation({
                    "EventID": "event_id",      # TODO: define your own field mappings
                })
            )
        ],
    )