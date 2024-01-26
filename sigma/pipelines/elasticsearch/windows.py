from sigma.pipelines.common import generate_windows_logsource_items
from sigma.processing.transformations import FieldMappingTransformation, AddFieldnamePrefixTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, FieldNameProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

ecs_windows_variable_mappings = {
    "FileVersion": (
        ("category", "process_creation", "process.pe.file_version"),
        ("category", "image_load", "file.pe.file_version"),
    ),
    "Description": (
        ("category", "process_creation", "process.pe.description.keyword"),
        ("category", "image_load", "file.pe.description.keyword"),
        ("category", "sysmon_error", "winlog.event_data.Description.keyword"),
    ),
    "Product": (
        ("category", "process_creation", "process.pe.product.keyword"),
        ("category", "image_load", "file.pe.product.keyword"),
    ),
    "Company": (
        ("category", "process_creation", "process.pe.company.keyword"),
        ("category", "image_load", "file.pe.company.keyword"),
    ),
    "OriginalFileName": (
        ("category", "process_creation", "process.pe.original_file_name.keyword"),
        ("category", "image_load", "file.pe.original_file_name.keyword"),
    ),
    "CommandLine": (
        ("category", "process_creation", "process.command_line.keyword"),
        ("service", "security", "process.command_line.keyword"),
        ("service", "powershell-classic", "powershell.command.value.keyword"),
    ),
    "Protocol": (
        ("category", "network_connection", "network.transport.keyword"),
    ),
    "Initiated": (
        ("category", "network_connection", "network.direction.keyword"),
    ),
    "Signature": (
        ("category", "driver_loaded", "file.code_signature.subject_name.keyword"),
        ("category", "image_loaded", "file.code_signature.subject_name.keyword"),
    ),
    "EngineVersion": (
        ("service", "powershell-classic", "powershell.engine.version"),
    ),
    "HostVersion": (
        ("service", "powershell-classic", "powershell.process.executable_version"),
    ),
    "SubjectLogonId": (
        ("service", "security", "winlog.logon.id"),
    ),
    "ServiceName": (
        ("service", "security", "service.name.keyword"),
    ),
    "SubjectDomainName": (
        ("service", "security", "user.domain.keyword"),
    ),
    "SubjectUserName": (
        ("service", "security", "user.name.keyword"),
    ),
    "SubjectUserSid": (
        ("service", "security", "user.id"),
    ),
    "TargetLogonId": (
        ("service", "security", "winlog.logon.id"),
    ),
}


def ecs_windows() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Elastic Common Schema (ECS) Windows log mappings from Winlogbeat from version 7",
        priority=20,
        allowed_backends=("elasticsearch", "eql", "lucene", "opensearch"),
        items=generate_windows_logsource_items("winlog.channel", "{source}") + [                   # Variable field mappinga depending on category/service
            ProcessingItem(
                identifier=f"elasticsearch_windows-{field}-{logsrc_field}-{logsrc}",
                transformation=FieldMappingTransformation({
                    field: mapped
                }),
                rule_conditions=[
                    LogsourceCondition(**{
                        "product": "windows",
                        logsrc_field: logsrc,
                    }),
                ]
            )
            for field, mappings in ecs_windows_variable_mappings.items()
            for (logsrc_field, logsrc, mapped) in mappings
        ] + [
            ProcessingItem(     # Field mappings
                identifier="ecs_windows_field_mapping",
                transformation=FieldMappingTransformation({
                    "EventID": "event.code",
                    "Channel": "winlog.channel.keyword",
                    "Provider_Name": "winlog.provider_name.keyword",
                    "ComputerName": "winlog.computer_name.keyword",
                    "FileName": "file.path.keyword",
                    "ProcessGuid": "process.entity_id",
                    "ProcessId": "process.pid",
                    "Image": "process.executable.keyword",
                    "CurrentDirectory": "process.working_directory.keyword",
                    "ParentProcessGuid": "process.parent.entity_id",
                    "ParentProcessId": "process.parent.pid",
                    "ParentImage": "process.parent.executable.keyword",
                    "ParentCommandLine": "process.parent.command_line.keyword",
                    "TargetFilename": "file.path.keyword",
                    "SourceIp": "source.ip.keyword",
                    "SourceHostname": "source.domain.keyword",
                    "SourcePort": "source.port",
                    "DestinationIp": "destination.ip.keyword",
                    "DestinationHostname": "destination.domain.keyword",
                    "DestinationPort": "destination.port",
                    "DestinationPortName": "network.protocol.keyword",
                    "ImageLoaded": "file.path.keyword",
                    "Signed": "file.code_signature.signed",
                    "SignatureStatus": "file.code_signature.status",
                    "SourceProcessGuid": "process.entity_id",
                    "SourceProcessId": "process.pid",
                    "SourceImage": "process.executable.keyword",
                    "Device": "file.path.keyword",
                    "SourceThreadId": "process.thread.id",
                    "TargetObject": "registry.path.keyword",
                    "PipeName": "file.name.keyword",
                    "Destination": "process.executable.keyword",
                    "QueryName": "dns.question.name.keyword",
                    "QueryStatus": "sysmon.dns.status.keyword",
                    "IsExecutable": "sysmon.file.is_executable",
                    "Archived": "sysmon.file.archived",
                    "CommandName": "powershell.command.name.keyword",
                    "CommandPath": "powershell.command.path.keyword",
                    "CommandType": "powershell.command.type.keyword",
                    "HostApplication": "process.command_line.keyword",
                    "HostId": "process.entity_id",
                    "HostName": "process.title.keyword",
                    "NewEngineState": "powershell.engine.new_state",
                    "PipelineId": "powershell.pipeline_id",
                    "PreviousEngineState": "powershell.engine.previous_state",
                    "RunspaceId": "powershell.runspace_id",
                    "ScriptName": "file.path.keyword",
                    "SequenceNumber": "event.sequence",
                    "NewProviderState": "powershell.provider.new_state",
                    "ProviderName": "powershell.provider.name.keyword",
                    "MessageNumber": "powershell.sequence",
                    "MessageTotal": "powershell.total",
                    "ScriptBlockText": "powershell.file.script_block_text.keyword",
                    "ScriptBlockId": "powershell.file.script_block_id",
                    "AccountDomain": "user.domain.keyword",
                    "AccountName": "user.name.keyword",
                    "Application": "process.executable.keyword",
                    "ClientAddress": "source.ip.keyword",
                    "ClientName": "source.domain.keyword",
                    "DestAddress": "destination.ip.keyword",
                    "DestPort": "destination.port",
                    "IpAddress": "source.ip.keyword",
                    "IpPort": "source.port",
                    "NewProcessId": "process.pid",
                    "NewProcessName": "process.executable.keyword",
                    "ParentProcessName": "process.parent.name.keyword",
                    "ProcessName": "process.executable.keyword",
                    "SourceAddress": "source.ip.keyword",
                    "TargetDomainName": "user.domain.keyword",
                    "WorkstationName": "source.domain.keyword",
                }),
                rule_conditions=[
                    LogsourceCondition(product="windows")
                ],
            ),
            ProcessingItem(         # Prepend each field that was not processed by previous field mapping transformation with "winlog.event_data."
                identifier="ecs_windows_winlog_eventdata_prefix",
                transformation=AddFieldnamePrefixTransformation(
                    "winlog.event_data."),
                field_name_conditions=[
                    FieldNameProcessingItemAppliedCondition(
                        "ecs_windows_field_mapping"),
                    IncludeFieldCondition(fields=["\\w+\\."], type="re"),
                ],
                field_name_condition_negation=True,
                field_name_condition_linking=any,
                rule_conditions=[
                    LogsourceCondition(product="windows")
                ],
            )
        ],
    )


def ecs_windows_old() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Elastic Common Schema (ECS) Windows log mappings from Winlogbeat up to version 6",
        priority=20,
        allowed_backends=("elasticsearch", "eql", "lucene", "opensearch"),
        items=generate_windows_logsource_items("winlog.channel", "{source}") + [
            ProcessingItem(     # Field mappings
                identifier="ecs_windows_field_mapping",
                transformation=FieldMappingTransformation({
                    "EventID": "event_id",
                    "Channel": "winlog.channel",
                }),
                rule_conditions=[
                    LogsourceCondition(product="windows")
                ],
            ),
            ProcessingItem(         # Prepend each field that was not processed by previous field mapping transformation with "winlog.event_data."
                identifier="ecs_windows_eventdata_prefix",
                transformation=AddFieldnamePrefixTransformation("event_data."),
                field_name_conditions=[
                    FieldNameProcessingItemAppliedCondition(
                        "ecs_windows_field_mapping"),
                    IncludeFieldCondition(fields=["\\w+\\."], type="re"),
                ],
                field_name_condition_negation=True,
                field_name_condition_linking=any,
                rule_conditions=[
                    LogsourceCondition(product="windows")
                ],
            )
        ],
    )
