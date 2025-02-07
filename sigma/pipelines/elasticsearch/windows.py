from sigma.pipelines.common import generate_windows_logsource_items
from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddFieldnamePrefixTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    IncludeFieldCondition,
    FieldNameProcessingItemAppliedCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

ecs_windows_variable_mappings = {
    "FileVersion": (
        ("category", "process_creation", "process.pe.file_version"),
        ("category", "image_load", "file.pe.file_version"),
    ),
    "Description": (
        ("category", "process_creation", "process.pe.description"),
        ("category", "image_load", "file.pe.description"),
        ("category", "sysmon_error", "winlog.event_data.Description"),
    ),
    "Product": (
        ("category", "process_creation", "process.pe.product"),
        ("category", "image_load", "file.pe.product"),
    ),
    "Company": (
        ("category", "process_creation", "process.pe.company"),
        ("category", "image_load", "file.pe.company"),
    ),
    "OriginalFileName": (
        ("category", "process_creation", "process.pe.original_file_name"),
        ("category", "image_load", "file.pe.original_file_name"),
    ),
    "CommandLine": (
        ("category", "process_creation", "process.command_line"),
        ("service", "security", "process.command_line"),
        ("service", "powershell-classic", "powershell.command.value"),
    ),
    "Protocol": (("category", "network_connection", "network.transport"),),
    "Initiated": (("category", "network_connection", "network.direction"),),
    "Signature": (
        ("category", "driver_loaded", "file.code_signature.subject_name"),
        ("category", "image_loaded", "file.code_signature.subject_name"),
    ),
    "EngineVersion": (("service", "powershell-classic", "powershell.engine.version"),),
    "HostVersion": (
        ("service", "powershell-classic", "powershell.process.executable_version"),
    ),
    "SubjectLogonId": (("service", "security", "winlog.logon.id"),),
    "ServiceName": (("service", "security", "service.name"),),
    "SubjectDomainName": (("service", "security", "user.domain"),),
    "SubjectUserName": (("service", "security", "user.name"),),
    "SubjectUserSid": (("service", "security", "user.id"),),
    "TargetLogonId": (("service", "security", "winlog.logon.id"),),
}


def ecs_windows() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Elastic Common Schema (ECS) Windows log mappings from Winlogbeat from version 7",
        priority=20,
        allowed_backends=("elasticsearch", "eql", "lucene", "opensearch"),
        items=generate_windows_logsource_items("winlog.channel", "{source}")
        + [  # Variable field mapping depending on category/service
            ProcessingItem(
                identifier=f"elasticsearch_windows-{field}-{logsrc_field}-{logsrc}",
                transformation=FieldMappingTransformation({field: mapped}),
                rule_conditions=[
                    LogsourceCondition(
                        **{
                            "product": "windows",
                            logsrc_field: logsrc,
                        }
                    ),
                ],
            )
            for field, mappings in ecs_windows_variable_mappings.items()
            for (logsrc_field, logsrc, mapped) in mappings
        ]
        + [
            ProcessingItem(  # Field mappings
                identifier="ecs_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "event.code",
                        "Channel": "winlog.channel",
                        "Provider_Name": "winlog.provider_name",
                        "ComputerName": "winlog.computer_name",
                        "FileName": "file.path",
                        "ProcessGuid": "process.entity_id",
                        "ProcessId": "process.pid",
                        "Image": "process.executable",
                        "CurrentDirectory": "process.working_directory",
                        "ParentProcessGuid": "process.parent.entity_id",
                        "ParentProcessId": "process.parent.pid",
                        "ParentImage": "process.parent.executable",
                        "ParentCommandLine": "process.parent.command_line",
                        "TargetFilename": "file.path",
                        "SourceIp": "source.ip",
                        "SourceHostname": "source.domain",
                        "SourcePort": "source.port",
                        "DestinationIp": "destination.ip",
                        "DestinationHostname": "destination.domain",
                        "DestinationPort": "destination.port",
                        "DestinationPortName": "network.protocol",
                        "ImageLoaded": "file.path",
                        "Signed": "file.code_signature.signed",
                        "SignatureStatus": "file.code_signature.status",
                        "Imphash": "file.pe.imphash",
                        "SourceProcessGuid": "process.entity_id",
                        "SourceProcessId": "process.pid",
                        "SourceImage": "process.executable",
                        "Device": "file.path",
                        "SourceThreadId": "process.thread.id",
                        "TargetObject": "registry.path",
                        "PipeName": "file.name",
                        "Destination": "process.executable",
                        "QueryName": "dns.question.name",
                        "QueryStatus": "sysmon.dns.status",
                        "IsExecutable": "sysmon.file.is_executable",
                        "Archived": "sysmon.file.archived",
                        "CommandName": "powershell.command.name",
                        "CommandPath": "powershell.command.path",
                        "CommandType": "powershell.command.type",
                        "HostApplication": "process.command_line",
                        "HostId": "process.entity_id",
                        "HostName": "process.title",
                        "NewEngineState": "powershell.engine.new_state",
                        "PipelineId": "powershell.pipeline_id",
                        "PreviousEngineState": "powershell.engine.previous_state",
                        "RunspaceId": "powershell.runspace_id",
                        "ScriptName": "file.path",
                        "SequenceNumber": "event.sequence",
                        "NewProviderState": "powershell.provider.new_state",
                        "ProviderName": "powershell.provider.name",
                        "MessageNumber": "powershell.sequence",
                        "MessageTotal": "powershell.total",
                        "ScriptBlockText": "powershell.file.script_block_text",
                        "ScriptBlockId": "powershell.file.script_block_id",
                        "AccountDomain": "user.domain",
                        "AccountName": "user.name",
                        "Application": "process.executable",
                        "ClientAddress": "source.ip",
                        "ClientName": "source.domain",
                        "DestAddress": "destination.ip",
                        "DestPort": "destination.port",
                        "IpAddress": "source.ip",
                        "IpPort": "source.port",
                        "NewProcessId": "process.pid",
                        "NewProcessName": "process.executable",
                        "ParentProcessName": "process.parent.name",
                        "ProcessName": "process.executable",
                        "SourceAddress": "source.ip",
                        "TargetDomainName": "user.domain",
                        "User": "user.name",
                        "WorkstationName": "source.domain",
                        "Payload": "powershell.file.script_block_text",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows")],
            ),
            ProcessingItem(  # Prepend each field that was not processed by previous field mapping transformation with "winlog.event_data."
                identifier="ecs_windows_winlog_eventdata_prefix",
                transformation=AddFieldnamePrefixTransformation("winlog.event_data."),
                field_name_conditions=[
                    FieldNameProcessingItemAppliedCondition(
                        "ecs_windows_field_mapping"
                    ),
                    IncludeFieldCondition(fields=["\\w+\\."], type="re"),
                ],
                field_name_condition_negation=True,
                field_name_condition_linking=any,
                rule_conditions=[LogsourceCondition(product="windows")],
            ),
        ],
    )


def ecs_windows_old() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Elastic Common Schema (ECS) Windows log mappings from Winlogbeat up to version 6",
        priority=20,
        allowed_backends=("elasticsearch", "eql", "lucene", "opensearch"),
        items=generate_windows_logsource_items("winlog.channel", "{source}")
        + [
            ProcessingItem(  # Field mappings
                identifier="ecs_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "event_id",
                        "Channel": "winlog.channel",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows")],
            ),
            ProcessingItem(  # Prepend each field that was not processed by previous field mapping transformation with "winlog.event_data."
                identifier="ecs_windows_eventdata_prefix",
                transformation=AddFieldnamePrefixTransformation("event_data."),
                field_name_conditions=[
                    FieldNameProcessingItemAppliedCondition(
                        "ecs_windows_field_mapping"
                    ),
                    IncludeFieldCondition(fields=["\\w+\\."], type="re"),
                ],
                field_name_condition_negation=True,
                field_name_condition_linking=any,
                rule_conditions=[LogsourceCondition(product="windows")],
            ),
        ],
    )
