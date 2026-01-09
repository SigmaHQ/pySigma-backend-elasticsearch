"""
Processing pipeline for macOS Endpoint Security Framework (ESF) events.

This pipeline maps Sigma taxonomy fields to ECS (Elastic Common Schema) fields,
following the same pattern as ecs_windows and ecs_zeek_beats pipelines.

The ESF collector outputs events with ECS-compliant field names that match
Elastic Defend's field naming conventions. This pipeline transforms Sigma
rules (which use Sigma taxonomy like Image, CommandLine, User) to queries
that target the ECS fields in the collected data.

Data Flow:
    eslogger → esf_collector.py → Elasticsearch (ECS fields)
                                        ↑
    Sigma Rule (Sigma taxonomy) → macos.py → Lucene Query (ECS fields)

Field Naming Conventions (matches Elastic Defend):
- Process: process.executable, process.name, process.pid, process.args
- Parent:  process.parent.executable, process.parent.pid
- User:    process.user.id, process.user.name, process.real_user.id
- Group:   process.group.id, process.real_group.id
- File:    file.path, file.name
- Code:    process.code_signature.signing_id, process.code_signature.team_id
"""

from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddConditionTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline


def ecs_macos_esf() -> ProcessingPipeline:
    """
    Elastic Common Schema (ECS) mapping for macOS Endpoint Security Framework (ESF) events.
    
    Maps Sigma taxonomy fields to ECS-compliant fields that match Elastic Defend's
    field naming conventions. This enables Sigma rules written with standard field
    names to query ESF data that has been normalized to ECS format.
    
    The ESF collector (esf_collector.py) outputs data with ECS field names:
    - process.executable, process.pid, process.name
    - process.user.id, process.user.name
    - file.path, etc.
    
    Sigma rules use taxonomy field names:
    - Image, CommandLine, ProcessId, User, TargetFilename
    
    This pipeline transforms: Sigma taxonomy → ECS fields
    """
    
    # ========================================================================
    # FIELD MAPPINGS: Sigma Taxonomy → ECS (Elastic Common Schema)
    # ========================================================================
    # These mappings align with Elastic Defend's ECS field naming conventions.
    # All ECS fields have been verified against the official ECS specification:
    # https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
    #
    # The ESF collector outputs these ECS fields directly, so this pipeline
    # transforms Sigma rule field names to match the collected data.
    # ========================================================================
    
    field_mappings = {
        # ====================================================================
        # PROCESS FIELDS (ECS: process.*)
        # ====================================================================
        # Sigma taxonomy → ECS process fields
        "Image": "process.executable",               # Process executable path
        "ProcessId": "process.pid",                  # Process ID
        "ProcessName": "process.name",               # Process name (basename)
        "CommandLine": "process.command_line",       # Full command line
        "CurrentDirectory": "process.working_directory",  # Working directory
        
        # Parent process fields
        "ParentImage": "process.parent.executable",       # Parent executable
        "ParentProcessId": "process.parent.pid",          # Parent PID
        "ParentProcessName": "process.parent.name",       # Parent name
        "ParentCommandLine": "process.parent.command_line", # Parent command line
        
        # ====================================================================
        # USER FIELDS (ECS: process.user.*, process.real_user.*, user.*)
        # ====================================================================
        # For process context, use process.user.* (effective user/euid)
        "User": "process.user.name",                 # Effective username
        "UserId": "process.user.id",                 # Effective user ID
        "EffectiveUserId": "process.user.id",        # Same as UserId (euid)
        
        # Real user fields use process.real_user.* (real user/ruid)
        "RealUserId": "process.real_user.id",        # Real user ID
        "RealUser": "process.real_user.name",        # Real username
        
        # Target user fields (for setuid/privilege escalation events)
        "TargetUser": "user.target.name",            # Target username
        "TargetUserId": "user.target.id",            # Target user ID
        
        # ====================================================================
        # GROUP FIELDS (ECS: process.group.*, process.real_group.*, group.*)
        # ====================================================================
        # Process group fields (effective group/egid)
        "EffectiveGroupId": "process.group.id",      # Effective group ID
        "GroupId": "process.group.id",               # Same as EffectiveGroupId
        
        # Real group fields (real group/rgid)
        "RealGroupId": "process.real_group.id",      # Real group ID
        
        # Target group fields (for setgid events)
        "TargetGroup": "group.target.name",          # Target group name
        "TargetGroupId": "group.target.id",          # Target group ID
        
        # ====================================================================
        # FILE FIELDS (ECS: file.*)
        # ====================================================================
        "TargetFilename": "file.path",               # Target file path
        "FileName": "file.name",                     # File name
        "FileDirectory": "file.directory",           # File directory
        
        # For rename operations
        "SourceFilename": "file.source.path",        # Source file (rename)
        "DestinationFilename": "file.target.path",   # Destination file (rename)
        
        # ====================================================================
        # NETWORK FIELDS (ECS: source.*, destination.*)
        # ====================================================================
        "DestinationIp": "destination.ip",
        "DestinationPort": "destination.port",
        "SourceIp": "source.ip",
        "SourcePort": "source.port",
        
        # ====================================================================
        # CODE SIGNATURE FIELDS (ECS: process.code_signature.*)
        # ====================================================================
        "SigningID": "process.code_signature.signing_id",
        "TeamID": "process.code_signature.team_id",
        "SignatureStatus": "process.code_signature.status",
        "Signed": "process.code_signature.exists",   # Boolean
        
        # ====================================================================
        # PROCESS ACCESS / INJECTION FIELDS (Standard Sigma taxonomy)
        # ====================================================================
        # These fields align with Sigma's standard taxonomy for process_access
        # (Sysmon Event 10) and create_remote_thread (Sysmon Event 8).
        # 
        # For macOS:
        # - ptrace (event_type 64) is the equivalent of process injection
        # - signal (event_type 27) can be used for defense evasion detection
        
        # Source process (the process performing the injection/access)
        "SourceImage": "process.executable",         # Injecting process
        "SourceProcessId": "process.pid",            # Injecting process PID
        
        # Target process (the process being injected/accessed)
        "TargetImage": "target.process.executable",  # Target process executable
        "TargetProcessId": "target.process.pid",     # Target process PID
        "TargetProcessName": "target.process.name",  # Target process name
        "TargetProcessGUID": "target.process.entity_id",  # Target entity ID
        
        # ====================================================================
        # UNIX/macOS-SPECIFIC FIELDS (No Windows equivalent)
        # ====================================================================
        # Signal fields (ESF event_type 27)
        "SignalNumber": "signal.number",             # Unix signal number
        
        # Ptrace fields (ESF event_type 64)
        "PtraceRequest": "ptrace.request",           # Ptrace request type
        
        # XPC fields (ESF event_type 65)
        "XpcServiceName": "xpc.service_name",        # XPC service name
        
        # Kernel extension fields (ESF event_type 17, 18)
        "KextIdentifier": "driver.name",             # Kext bundle identifier
        "KextPath": "file.path",                     # Kext file path
        
        # Memory protection fields (ESF event_type 20)
        "MemoryProtection": "memory.protection",     # Protection flags
    }
    
    # ========================================================================
    # PROCESSING ITEMS
    # ========================================================================
    
    items = [
        # Field mapping transformation (applies to all ESF rules)
        ProcessingItem(
            identifier="ecs_macos_esf_field_mapping",
            transformation=FieldMappingTransformation(field_mappings),
            rule_conditions=[
                LogsourceCondition(product="macos", service="endpointsecurity")
            ],
        ),
        
        # ====================================================================
        # LOG SOURCE CATEGORY CONDITIONS
        # ====================================================================
        # These add ESF event_type conditions based on the Sigma rule's
        # logsource category. This ensures queries only match the correct
        # event types in Elasticsearch.
        
        # Process creation - ES_EVENT_TYPE_NOTIFY_EXEC (9)
        ProcessingItem(
            identifier="ecs_macos_esf_process_creation",
            transformation=AddConditionTransformation(
                conditions={
                    "event.action": "exec",
                    "esf.event_type": 9,
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="process_creation"
                )
            ]
        ),
        
        # File events - multiple event types
        ProcessingItem(
            identifier="ecs_macos_esf_file_event",
            transformation=AddConditionTransformation(
                conditions={
                    "event.category": "file",
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="file_event"
                )
            ]
        ),
        
        # File creation - ES_EVENT_TYPE_NOTIFY_CREATE (13)
        ProcessingItem(
            identifier="ecs_macos_esf_file_create",
            transformation=AddConditionTransformation(
                conditions={
                    "event.action": "create",
                    "esf.event_type": 13,
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="file_create"
                )
            ]
        ),
        
        # File deletion - ES_EVENT_TYPE_NOTIFY_UNLINK (19)
        ProcessingItem(
            identifier="ecs_macos_esf_file_delete",
            transformation=AddConditionTransformation(
                conditions={
                    "event.action": "unlink",
                    "esf.event_type": 19,
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="file_delete"
                )
            ]
        ),
        
        # File rename - ES_EVENT_TYPE_NOTIFY_RENAME (21)
        ProcessingItem(
            identifier="ecs_macos_esf_file_rename",
            transformation=AddConditionTransformation(
                conditions={
                    "event.action": "rename",
                    "esf.event_type": 21,
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="file_rename"
                )
            ]
        ),
        
        # Authentication - ES_EVENT_TYPE_NOTIFY_AUTHENTICATION (111)
        ProcessingItem(
            identifier="ecs_macos_esf_authentication",
            transformation=AddConditionTransformation(
                conditions={
                    "event.category": "authentication",
                    "esf.event_type": 111,
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="authentication"
                )
            ]
        ),
        
        # Privilege escalation - SETUID (24) and SETGID (25)
        ProcessingItem(
            identifier="ecs_macos_esf_privilege_escalation",
            transformation=AddConditionTransformation(
                conditions={
                    "event.category": "iam",
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="privilege_escalation"
                )
            ]
        ),
        
        # Process injection - ES_EVENT_TYPE_NOTIFY_PTRACE (64)
        ProcessingItem(
            identifier="ecs_macos_esf_process_injection",
            transformation=AddConditionTransformation(
                conditions={
                    "event.action": "ptrace",
                    "esf.event_type": 64,
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="process_injection"
                ),
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="process_access"
                )
            ]
        ),
        
        # Process signal - ES_EVENT_TYPE_NOTIFY_SIGNAL (27)
        ProcessingItem(
            identifier="ecs_macos_esf_process_signal",
            transformation=AddConditionTransformation(
                conditions={
                    "event.action": "signal",
                    "esf.event_type": 27,
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="process_signal"
                )
            ]
        ),
        
        # Kernel extension - KEXTLOAD (17) and KEXTUNLOAD (18)
        ProcessingItem(
            identifier="ecs_macos_esf_kernel_extension",
            transformation=AddConditionTransformation(
                conditions={
                    "event.category": "driver",
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="kernel_extension"
                ),
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="driver_load"
                )
            ]
        ),
        
        # Code signature invalidation (62, 94)
        ProcessingItem(
            identifier="ecs_macos_esf_codesigning",
            transformation=AddConditionTransformation(
                conditions={
                    "event.action": "cs_invalidated",
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="codesigning"
                )
            ]
        ),
        
        # Security policy events (malware, gatekeeper, TCC)
        ProcessingItem(
            identifier="ecs_macos_esf_security_policy",
            transformation=AddConditionTransformation(
                conditions={
                    "event.category": ["malware", "configuration"],
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="security_policy"
                )
            ]
        ),
        
        # Mount events - ES_EVENT_TYPE_NOTIFY_MOUNT (22)
        ProcessingItem(
            identifier="ecs_macos_esf_mount",
            transformation=AddConditionTransformation(
                conditions={
                    "event.action": "mount",
                    "esf.event_type": 22,
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="mount"
                )
            ]
        ),
        
        # Memory protection events - MPROTECT (20)
        ProcessingItem(
            identifier="ecs_macos_esf_memory_protection",
            transformation=AddConditionTransformation(
                conditions={
                    "event.action": "mprotect",
                    "esf.event_type": 20,
                }
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(
                    product="macos",
                    service="endpointsecurity",
                    category="memory_protection"
                )
            ]
        ),
    ]
    
    return ProcessingPipeline(
        name="Elastic Common Schema (ECS) macOS Endpoint Security Framework (ESF) mappings",
        priority=30,
        allowed_backends=("elasticsearch", "eql", "lucene", "opensearch"),
        items=items
    )
