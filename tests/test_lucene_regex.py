import re

import pytest

from sigma.backends.elasticsearch.lucene_regex import (
    LuceneRegexError,
    escape_for_query,
    to_lucene_regex,
)
from sigma.types import SigmaRegularExpressionFlag

I = {SigmaRegularExpressionFlag.IGNORECASE}


@pytest.mark.parametrize(
    "pattern, flags, expected",
    [
        # match anywhere
        ("ping", set(), ".*(ping).*"),
        # anchors drop the matching .*
        ("^ping", set(), "(ping).*"),
        ("ping$", set(), ".*(ping)"),
        ("^ping$", set(), "(ping)"),
        (r"ping\$", set(), r".*(ping\$).*"),
        # anchors per top-level alternative
        ("^a|b$", set(), "((a).*)|(.*(b))"),
        # a group spanning the whole pattern
        ("(^[a-z]{4}$)|(^[a-z]{8}$)", set(), "(([a-z]{4}))|(([a-z]{8}))"),
        ("(^0oa.*|x)", set(), "((0oa.*))|(.*(x).*)"),
        # a first / last group with anchored alternatives
        (r"(^|\/)\.[^.\/]", set(), r"(()|.*(/))(\.[^./]).*"),
        ("a(b|$)", set(), ".*(a)((b).*|())"),
        # (?:...) and lazy quantifiers
        ("(?:a|b)c", set(), ".*((a|b)c).*"),
        ("a+?b*?c??d{1,2}?", set(), ".*(a+b*c?d{1,2}).*"),
        # empty alternatives
        (r"a(\s|)b", set(), r".*(a(\s|())b).*"),
        # Lucene operators are escaped, other escaped characters unescaped
        ('"#@&<>~', set(), r".*(\"\#\@\&\<\>\~).*"),
        (r"a\/b\'c\.d", set(), r".*(a/b'c\.d).*"),
        # literal braces
        (r"\{\d\}", set(), r".*(\{\d\}).*"),
        ("a{b}", set(), r".*(a\{b\}).*"),
        # unbounded "any character" at the start / end needs no extra .*
        (".{1000,}", set(), "(.{1000,})"),
        ("x.*", set(), ".*(x.*)"),
        (r"a\.*", set(), r".*(a\.*).*"),
        # case-insensitive: flag or (?i) at the start
        ("Ab[c-e]", I, ".*([aA][bB][c-eC-E]).*"),
        ("(?i)Ab", set(), ".*([aA][bB]).*"),
        (r"(?i)\d\S[^x]", set(), r".*(\d\S[^xX]).*"),
        # s flag: Lucene's . already matches line breaks
        ("a.b", {SigmaRegularExpressionFlag.DOTALL}, ".*(a.b).*"),
        ("[A-Fx]", I, ".*([A-Fa-fxX]).*"),
    ],
)
def test_to_lucene_regex(pattern, flags, expected):
    assert to_lucene_regex(pattern, flags) == expected


@pytest.mark.parametrize(
    "pattern, flags",
    [
        (r"\bword\b", set()),
        (r"a\nb", set()),
        (r"\x41", set()),
        (r"(a)\1", set()),
        ("a(?=b)", set()),
        ("a(?!b)", set()),
        ("(?<=a)b", set()),
        ("(?P<name>a)", set()),
        ("a(?i)b", set()),
        ("a^b", set()),
        ("a$b", set()),
        ("a++", set()),
        ("a{,3}", set()),
        ("a", {SigmaRegularExpressionFlag.MULTILINE}),
        ("[!-~]", I),
        (r"[!-\~]", set()),
        ("ß", I),
    ],
)
def test_to_lucene_regex_refused(pattern, flags):
    with pytest.raises(LuceneRegexError):
        to_lucene_regex(pattern, flags)


@pytest.mark.parametrize(
    "pattern, flags",
    [
        ("ping", 0),
        ("^C:\\\\Windows", 0),
        ("exe$", 0),
        ("^a|b$", 0),
        (r"(^|/)\.[^./]", 0),
        (r"(?:a|b)+?c", 0),
        (r"a(\s|)b", 0),
        (r"-[a-z]{2,3}\s", re.I),
        (r"\d{2,4}\.x", 0),
    ],
)
def test_to_lucene_regex_same_matches(pattern, flags):
    """Python's re.search on the Sigma regex and a whole-value match of the translation
    (Lucene semantics; the translation is also valid Python regex syntax) agree."""
    values = [
        "",
        "ping",
        "xpingx",
        "PING",
        "C:\\Windows\\x",
        "x C:\\Windows",
        "exe",
        "exe x",
        "a",
        "b",
        "xb",
        "ax",
        ".h",
        "/.h",
        "x/.h",
        "x.h",
        "../",
        "ac",
        "bbc",
        "aac",
        "ab",
        "a b",
        "a  b",
        "-ab ",
        "-ABC x",
        "-a ",
        "12.x",
        "1234.x",
        "1.x",
    ]
    lucene = re.compile(
        to_lucene_regex(
            pattern, {SigmaRegularExpressionFlag.IGNORECASE} if flags else set()
        ),
        re.S,
    )
    python = re.compile(pattern, flags)
    for value in values:
        assert (python.search(value) is not None) == (
            lucene.fullmatch(value) is not None
        ), value


def test_escape_for_query():
    assert escape_for_query(r"a\"b/c", ['"'], "\\", True) == r"a\\\"b/c"
    assert escape_for_query(r"a\.b/c", ["/"], "\\", False) == r"a\.b\/c"
