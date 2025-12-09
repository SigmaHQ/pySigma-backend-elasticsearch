import pytest
from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend
from sigma.collection import SigmaCollection


@pytest.fixture(name="eql_backend")
def fixture_eql_backend():
    return EqlBackend()


def test_eql_contains_trailing_backslash(eql_backend: EqlBackend):
    """Test that trailing backslashes are properly escaped with contains modifier."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test Trailing Backslash with Contains
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    path|contains: '\Desktop\'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # The output should have 4 backslashes total: 2 before Desktop, 2 before final *
    assert result == 'any where path:"*\\\\Desktop\\\\*"'
    # Verify backslash count in actual string (not Python repr)
    assert result.count('\\') == 4


def test_eql_startswith_trailing_backslash(eql_backend: EqlBackend):
    """Test that trailing backslashes are properly escaped with startswith modifier."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test Trailing Backslash with Startswith
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    path|startswith: '\Desktop\'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # The output should have 4 backslashes total: 2 before Desktop, 2 before final *
    assert result == 'any where path:"\\\\Desktop\\\\*"'
    assert result.count('\\') == 4


def test_eql_endswith_trailing_backslash(eql_backend: EqlBackend):
    """Test that trailing backslashes are properly escaped with endswith modifier."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test Trailing Backslash with Endswith
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    path|endswith: '\Desktop\'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # The output should have 4 backslashes total: 2 before Desktop, 2 at the end
    assert result == 'any where path:"*\\\\Desktop\\\\"'
    assert result.count('\\') == 4


def test_eql_contains_multiple_trailing_backslashes(eql_backend: EqlBackend):
    """Test contains modifier with multiple values ending with backslashes."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test Multiple Trailing Backslashes
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    path|contains:
                        - '\Desktop\'
                        - '\Documents\'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # Both values should have properly escaped backslashes
    assert 'path like~ ("*\\\\Desktop\\\\*", "*\\\\Documents\\\\*")' in result
    # Each value should have 4 backslashes
    assert result.count('Desktop') == 1
    assert result.count('Documents') == 1


def test_eql_contains_backslash_without_trailing(eql_backend: EqlBackend):
    """Test contains modifier with backslashes but not trailing."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test Backslash Not Trailing
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    path|contains: '\Desktop\test'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # The backslashes should still be properly escaped
    assert 'path:"*\\\\Desktop\\\\test*"' in result


def test_eql_contains_single_backslash_end(eql_backend: EqlBackend):
    """Test contains with just a single trailing backslash."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test Single Trailing Backslash
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    path|contains: 'test\'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # Should have escaped backslash before wildcard
    assert 'path:"*test\\\\*"' in result


def test_eql_startswith_with_question_mark_wildcard(eql_backend: EqlBackend):
    """Test startswith with single character wildcard after backslash."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test Question Mark Wildcard
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    path|startswith: '\test\'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # Should properly escape backslashes
    assert result == 'any where path:"\\\\test\\\\*"'


def test_eql_no_trailing_backslash(eql_backend: EqlBackend):
    """Test that normal strings without trailing backslashes work correctly."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test No Trailing Backslash
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    path|contains: 'Desktop'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # No backslashes to escape
    assert result == 'any where path:"*Desktop*"'


def test_eql_contains_middle_backslash_only(eql_backend: EqlBackend):
    """Test contains with backslash in the middle but not at the end."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test Middle Backslash
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    path|contains: 'C:\Windows'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # Middle backslash should be escaped but no trailing wildcard issue
    assert 'path:"*C:\\\\Windows*"' in result


def test_eql_contains_literal_asterisk_middle(eql_backend: EqlBackend):
    """Test contains with a literal asterisk in the middle (escaped with backslash in Sigma)."""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test Literal Asterisk in Middle
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|contains: 'test\*value'
                condition: sel
        """
    )
    
    result = eql_backend.convert(rule)[0]
    # The \* means literal asterisk, should be escaped once in EQL
    # Python repr shows \\* but actual string has \*
    assert result == 'any where field:"*test\\*value*"'
    # Verify actual backslash count (not Python repr)
    assert result.count('\\') == 1
