"""
Tests for macOS ESF pipeline.

These tests verify that Sigma rules with macOS ESF logsource are correctly
transformed to ECS-compliant Lucene queries.
"""
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.pipelines.elasticsearch.macos import ecs_macos_esf
from sigma.collection import SigmaCollection


def test_ecs_macos_esf_process_creation():
    """Test macOS ESF pipeline with process_creation logsource."""
    result = LuceneBackend(ecs_macos_esf()).convert(
        SigmaCollection.from_yaml("""
            title: Test Process Creation
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    Image: /usr/bin/curl
                    CommandLine|contains: malicious
                condition: sel
        """)
    )
    
    assert len(result) == 1
    query = result[0]
    print(f"\nQuery: {query}\n")
    
    # Field mapping: Image → process.executable
    assert "process.executable" in query, f"Expected 'process.executable' in query, got: {query}"
    # Field mapping: CommandLine → process.command_line
    assert "process.command_line" in query, f"Expected 'process.command_line' in query, got: {query}"


def test_ecs_macos_esf_file_event():
    """Test macOS ESF pipeline with file_event logsource."""
    result = LuceneBackend(ecs_macos_esf()).convert(
        SigmaCollection.from_yaml("""
            title: Test File Event
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: file_event
            detection:
                sel:
                    TargetFilename|contains: /Library/LaunchDaemons
                condition: sel
        """)
    )
    
    assert len(result) == 1
    query = result[0]
    print(f"\nQuery: {query}\n")
    
    # Field mapping: TargetFilename → file.path
    assert "file.path" in query, f"Expected 'file.path' in query, got: {query}"


def test_ecs_macos_esf_field_mapping():
    """Test comprehensive Sigma → ECS field mappings."""
    result = LuceneBackend(ecs_macos_esf()).convert(
        SigmaCollection.from_yaml("""
            title: Test Field Mapping
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    Image: /usr/bin/test
                    ProcessId: 12345
                    User: testuser
                    ParentImage: /bin/bash
                condition: sel
        """)
    )
    
    assert len(result) == 1
    query = result[0]
    print(f"\nQuery: {query}\n")
    
    # Process fields
    assert "process.executable" in query, f"Expected 'process.executable', got: {query}"
    assert "process.pid" in query, f"Expected 'process.pid', got: {query}"
    assert "process.user.name" in query, f"Expected 'process.user.name', got: {query}"
    assert "process.parent.executable" in query, f"Expected 'process.parent.executable', got: {query}"


def test_ecs_macos_esf_authentication():
    """Test macOS ESF pipeline with authentication logsource."""
    result = LuceneBackend(ecs_macos_esf()).convert(
        SigmaCollection.from_yaml("""
            title: Test Authentication
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: authentication
            detection:
                sel:
                    User: root
                condition: sel
        """)
    )
    
    assert len(result) == 1
    query = result[0]
    print(f"\nQuery: {query}\n")
    
    # User field mapped
    assert "process.user.name" in query, f"Expected 'process.user.name', got: {query}"


def test_ecs_macos_esf_process_injection():
    """Test macOS ESF pipeline with process_injection logsource."""
    result = LuceneBackend(ecs_macos_esf()).convert(
        SigmaCollection.from_yaml("""
            title: Test Process Injection
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_injection
            detection:
                sel:
                    SourceImage: /usr/bin/lldb
                    TargetProcessId: 1234
                condition: sel
        """)
    )
    
    assert len(result) == 1
    query = result[0]
    print(f"\nQuery: {query}\n")
    
    # Injection fields
    assert "process.executable" in query, f"Expected 'process.executable' (from SourceImage), got: {query}"
    assert "target.process.pid" in query, f"Expected 'target.process.pid', got: {query}"


def test_ecs_macos_esf_process_signal():
    """Test macOS ESF pipeline with process_signal logsource."""
    result = LuceneBackend(ecs_macos_esf()).convert(
        SigmaCollection.from_yaml("""
            title: Test Process Signal
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_signal
            detection:
                sel:
                    Image: /usr/bin/pkill
                    SignalNumber: 9
                condition: sel
        """)
    )
    
    assert len(result) == 1
    query = result[0]
    print(f"\nQuery: {query}\n")
    
    # Signal fields
    assert "process.executable" in query, f"Expected 'process.executable', got: {query}"
    assert "signal.number" in query, f"Expected 'signal.number', got: {query}"


def test_ecs_macos_esf_code_signature():
    """Test code signature field mappings."""
    result = LuceneBackend(ecs_macos_esf()).convert(
        SigmaCollection.from_yaml("""
            title: Test Code Signature
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    SigningID: com.apple.Safari
                    Signed: false
                condition: sel
        """)
    )
    
    assert len(result) == 1
    query = result[0]
    print(f"\nQuery: {query}\n")
    
    # Code signature fields
    assert "process.code_signature.signing_id" in query, f"Expected 'process.code_signature.signing_id', got: {query}"
    assert "process.code_signature.exists" in query, f"Expected 'process.code_signature.exists', got: {query}"


def test_ecs_macos_esf_mount():
    """Test macOS ESF pipeline with mount logsource."""
    result = LuceneBackend(ecs_macos_esf()).convert(
        SigmaCollection.from_yaml("""
            title: Test Mount
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: mount
            detection:
                sel:
                    TargetFilename|contains: /Volumes
                condition: sel
        """)
    )
    
    assert len(result) == 1
    query = result[0]
    print(f"\nQuery: {query}\n")
    
    # File path mapping
    assert "file.path" in query, f"Expected 'file.path', got: {query}"
