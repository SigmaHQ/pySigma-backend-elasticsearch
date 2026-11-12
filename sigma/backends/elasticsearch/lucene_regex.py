r"""Translate Sigma regular expressions into Lucene regular expressions.

Sigma's ``re`` modifier follows Python's ``re.search``: the pattern may match
anywhere in the value. Elasticsearch evaluates regular expressions with Lucene
(Lucene query ``field:/.../``, EQL ``regex``/``regex~`` and ES|QL ``RLIKE``), where
the pattern must match the WHOLE value, ``^``/``$`` are not anchors, there are no
inline flags or non-capturing groups, and ``" # @ & < > ~`` are operators.

``to_lucene_regex()`` rewrites a Sigma regex so that Lucene matches exactly the
values Python's ``re.search`` matches:

- ``ping`` becomes ``.*(ping).*`` (match anywhere)
- a leading ``^`` drops the leading ``.*``, a trailing ``$`` the trailing ``.*``;
  this also works per alternative (``^a|b``), for a group spanning the whole
  pattern (``(^a$|b)``) and for a first/last group with anchored alternatives
  (``(^|/)x`` becomes ``(()|.*(/))(x).*``: at the start, or after a ``/``)
- ``(?:...)`` becomes ``(...)`` (Lucene groups don't capture)
- lazy quantifiers (``*?``, ``+?``, ``??``, ``{m,n}?``) lose the ``?``: laziness
  changes which part of the value matches, not whether it matches
- ``(?i)`` at the start of the pattern, or the ``i`` flag, makes every letter
  match both cases (``a`` becomes ``[aA]``)
- the Lucene operator characters are escaped; escaped characters with no special
  meaning in Lucene (``\/``) are unescaped
- the ``s`` flag needs no change: Lucene's ``.`` already matches line breaks

Anything that can't be translated exactly raises ``LuceneRegexError`` instead of
producing a query that silently matches something else: anchors in other places,
lookarounds, back-references, ``\b``, ``\A``, ``\Z``, inline flags elsewhere,
the ``m`` flag, escapes such as ``\n``, ``\t`` or ``\x41``, possessive quantifiers.

Known differences (all about characters rarely found in log values):

- Python's ``.`` doesn't match a line break unless the ``s`` flag is set;
  Lucene's ``.`` always does.
- Python's ``$`` also matches just before a line break at the end of the value.
- Lucene's ``\s``, ``\w`` and ``\d`` are ASCII only (``\s`` is space, tab, CR
  and LF); Python's also match other Unicode whitespace, letters and digits, and
  vertical tab and form feed.
- With ``i``, each letter matches its upper and lower case; Python also matches a
  few special Unicode characters (e.g. the Kelvin sign for ``k``).

Elasticsearch may still reject a translated pattern as "too complex to
determinize" (e.g. a wide bounded repeat such as ``.{6,64}`` after the leading
``.*``). That is reported by Elasticsearch when the query runs.
"""

import re
from typing import ClassVar, List, Set

from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.types import SigmaRegularExpressionFlag


class LuceneRegexError(SigmaFeatureNotSupportedByBackendError):
    """The regular expression can't be translated exactly into a Lucene regular expression.

    A Sigma error, so pySigma reports it for the rule (and skips the rule when the
    backend collects errors) like any other feature the backend doesn't support."""


# Characters that are operators in Lucene regular expressions but plain characters in
# Python's: always written escaped.
LUCENE_OPERATORS = set('"#@&<>~')
# Characters that keep their backslash when escaped in the Sigma regex. Any other
# escaped non-alphanumeric character (e.g. \/ or \') is written without the backslash.
KEEP_ESCAPED = set(".?+*|{}[]()^$\\-") | LUCENE_OPERATORS
# The same inside a character class [...].
CLASS_KEEP_ESCAPED = set("[]^\\-") | LUCENE_OPERATORS
# Escapes for character classes that Lucene supports in the same way as Python.
CLASS_ESCAPES = set("dDsSwW")
# An unbounded "any character" repeat (.* .+ .{n,}) at the start / end of a translated pattern.
_ANY_REPEAT_START = re.compile(r"\.(\*|\+|\{\d+,\})")
_ANY_REPEAT_END = re.compile(r"\.(\*|\+|\{\d+,\})$")


def to_lucene_regex(
    pattern: str, flags: Set[SigmaRegularExpressionFlag] = set()
) -> str:
    """Translate a Sigma (Python re.search) regular expression into a Lucene regular expression."""
    if SigmaRegularExpressionFlag.MULTILINE in flags:
        raise LuceneRegexError(
            f"Regular expression flag m (multi-line) can't be translated for Lucene: {pattern}"
        )
    ignore_case = SigmaRegularExpressionFlag.IGNORECASE in flags
    if pattern.startswith("(?i)"):  # inline flag at the start, same as the i flag
        ignore_case = True
        pattern = pattern[4:]
    return _alternation(pattern, ignore_case)


def _alternation(pattern: str, ignore_case: bool) -> str:
    """Translate a pattern that may contain top-level alternatives (a|b)."""
    branches = _split_top_level(pattern)
    if len(branches) == 1:
        return _branch(branches[0], ignore_case)
    return "|".join("(" + _branch(branch, ignore_case) + ")" for branch in branches)


def _branch(pattern: str, ignore_case: bool) -> str:
    """Translate one alternative: a sequence without top-level |."""
    # A group spanning the whole branch: translate its content as its own pattern,
    # so anchors inside it (e.g. (^a$|b)) are handled per alternative.
    if pattern.startswith("(") and _group_end(pattern, 0) == len(pattern) - 1:
        if not pattern.startswith("(?") or pattern.startswith("(?:"):
            inner = pattern[3:-1] if pattern.startswith("(?:") else pattern[1:-1]
            return _alternation(inner, ignore_case)

    head, tail = ".*", ".*"
    prefix, suffix = "", ""

    # Start of the value
    if pattern.startswith("^"):
        head, pattern = "", pattern[1:]
    elif pattern.startswith("("):
        end = _group_end(pattern, 0)
        group, rest = pattern[: end + 1], pattern[end + 1 :]
        alternatives = _group_alternatives(group)
        if (
            alternatives is not None
            and not _starts_with_quantifier(rest)
            and any(a.startswith("^") for a in alternatives)
        ):
            # (^|x)rest: "at the start, or after x". Each alternative gets its own
            # leading .* unless it is anchored.
            head = ""
            prefix = _group(
                (
                    _body(a[1:], ignore_case)
                    if a.startswith("^")
                    else ".*(" + _body(a, ignore_case) + ")"
                )
                for a in alternatives
            )
            pattern = rest

    # End of the value
    if _ends_with_anchor(pattern):
        tail, pattern = "", pattern[:-1]
    elif pattern.endswith(")") and not _is_escaped(pattern, len(pattern) - 1):
        start = _group_start(pattern)
        group, rest = pattern[start:], pattern[:start]
        alternatives = _group_alternatives(group)
        if alternatives is not None and any(_ends_with_anchor(a) for a in alternatives):
            # rest(x|$): "x follows, or the value ends here".
            tail = ""
            suffix = _group(
                (
                    _body(a[:-1], ignore_case)
                    if _ends_with_anchor(a)
                    else "(" + _body(a, ignore_case) + ").*"
                )
                for a in alternatives
            )
            pattern = rest

    middle = _body(pattern, ignore_case)
    # .* around a pattern that already starts/ends with an unbounded "any character"
    # repeat adds nothing, but can make the pattern too complex for Elasticsearch
    # (e.g. .{1000,}).
    if not prefix and _ANY_REPEAT_START.match(middle):
        head = ""
    end = _ANY_REPEAT_END.search(middle)
    if not suffix and end and not _is_escaped(middle, end.start()):
        tail = ""
    core = "(" + middle + ")" if middle else ""
    return head + prefix + core + suffix + tail


def _group(alternatives) -> str:
    """A group of translated alternatives; Lucene rejects empty alternatives, () is accepted."""
    return "(" + "|".join(a if a else "()" for a in alternatives) + ")"


def _body(pattern: str, ignore_case: bool) -> str:
    """Translate a pattern part without anchors, character by character."""
    out: List[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            out.append(_escape(pattern, i))
            i += 2
        elif c == "[":
            end = _class_end(pattern, i)
            out.append(_char_class(pattern[i : end + 1], ignore_case))
            i = end + 1
        elif c == "(":
            if pattern.startswith("(?:", i):
                out.append("(")
                i += 3
            elif pattern.startswith("(?", i):
                raise LuceneRegexError(
                    f"Regular expression group {pattern[i:i + 4]}... (lookaround, named group or "
                    f"inline flag) can't be translated for Lucene: {pattern}"
                )
            else:
                out.append("(")
                i += 1
        elif c in "^$":
            raise LuceneRegexError(
                f"Regular expression anchor {c} in this position can't be translated for Lucene: {pattern}"
            )
        elif c == "{":
            end = _quantifier_end(pattern, i)
            if end is None:  # literal {, as in Python
                out.append("\\{")
                i += 1
            else:
                out.append(pattern[i : end + 1])
                i = _after_quantifier(pattern, end + 1)
        elif c == "}":  # literal } (quantifier braces are handled above)
            out.append("\\}")
            i += 1
        elif c in "*+?":
            out.append(c)
            i = _after_quantifier(pattern, i + 1)
        elif c in "|)":
            # Lucene rejects or mis-reads empty alternatives such as (a|) or (|a); () is accepted.
            if c == "|" and (not out or out[-1] in ("(", "|")):
                out.append("()")
            elif c == ")" and out and out[-1] == "|":
                out.append("()")
            out.append(c)
            i += 1
        elif c in LUCENE_OPERATORS:
            out.append("\\" + c)
            i += 1
        elif ignore_case and c.isalpha() and c.lower() != c.upper():
            out.append("[" + _both_cases(c, pattern) + "]")
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _after_quantifier(pattern: str, i: int) -> int:
    """Skip a lazy marker after a quantifier; refuse possessive quantifiers."""
    if pattern.startswith("?", i):
        return i + 1  # lazy: same matches for a match / no match decision
    if pattern.startswith("+", i):
        raise LuceneRegexError(
            f"Possessive quantifiers can't be translated for Lucene: {pattern}"
        )
    return i


def _escape(pattern: str, i: int) -> str:
    """Translate an escape sequence starting at pattern[i] (a backslash)."""
    if i + 1 >= len(pattern):
        raise LuceneRegexError(f"Regular expression ends with a backslash: {pattern}")
    c = pattern[i + 1]
    if c in CLASS_ESCAPES:
        return "\\" + c
    if c.isalnum():
        raise LuceneRegexError(
            f"Regular expression escape \\{c} can't be translated for Lucene: {pattern}"
        )
    if c in KEEP_ESCAPED:
        return "\\" + c
    return c  # e.g. \/ or \' : plain characters in Lucene


def _char_class(text: str, ignore_case: bool) -> str:
    """Translate a character class [...]."""
    inner = text[1:-1]
    negate = inner.startswith("^")
    if negate:
        inner = inner[1:]
    out: List[str] = []
    i = 0
    first = True
    while i < len(inner):
        c = inner[i]
        if c == "\\":
            esc = inner[i + 1] if i + 1 < len(inner) else ""
            if inner[i + 2 : i + 3] == "-" and i + 3 < len(inner):
                raise LuceneRegexError(
                    f"Character class range with an escaped bound can't be translated for Lucene: {text}"
                )
            if esc in CLASS_ESCAPES:
                out.append("\\" + esc)
            elif esc.isalnum() or esc == "":
                raise LuceneRegexError(
                    f"Regular expression escape \\{esc} in a character class can't be translated for Lucene: {text}"
                )
            elif esc in CLASS_KEEP_ESCAPED:
                out.append("\\" + esc)
            else:
                out.append(esc)  # e.g. [\/] : a plain character in Lucene
            i += 2
        elif i + 2 < len(inner) and inner[i + 1] == "-":
            low, high = c, inner[i + 2]
            if high == "\\":
                raise LuceneRegexError(
                    f"Character class range with an escaped bound can't be translated for Lucene: {text}"
                )
            out.append(_escape_class_char(low) + "-" + _escape_class_char(high))
            if ignore_case:
                out.append(_other_case_range(low, high, text))
            i += 3
        else:
            if c == "]" and first:  # [] or [^] as Python's literal ]
                out.append("\\]")
            elif c == "-":
                out.append("\\-")
            else:
                if ignore_case and c.isalpha() and c.lower() != c.upper():
                    out.append(_both_cases(c, text))
                else:
                    out.append(_escape_class_char(c))
            i += 1
        first = False
    return "[" + ("^" if negate else "") + "".join(out) + "]"


def _both_cases(c: str, pattern: str) -> str:
    """A letter in lower and upper case, for i (e.g. aA)."""
    if len(c.lower()) != 1 or len(c.upper()) != 1:  # e.g. ß -> SS
        raise LuceneRegexError(
            f"Case-insensitive letter {c} can't be translated for Lucene: {pattern}"
        )
    return c.lower() + c.upper()


def _escape_class_char(c: str) -> str:
    if c in LUCENE_OPERATORS or c in "[]\\^":
        return "\\" + c
    return c


def _other_case_range(low: str, high: str, text: str) -> str:
    """The same range in the other case for i, e.g. a-f -> A-F; empty if no letters."""
    if low.isdigit() and high.isdigit():
        return ""
    if low.islower() and high.islower() and low.isascii() and high.isascii():
        return low.upper() + "-" + high.upper()
    if low.isupper() and high.isupper() and low.isascii() and high.isascii():
        return low.lower() + "-" + high.lower()
    if not (low.isalpha() or high.isalpha()):
        # A range of punctuation can still contain letters (e.g. !-~).
        if any(ch.isalpha() for ch in map(chr, range(ord(low), ord(high) + 1))):
            raise LuceneRegexError(
                f"Case-insensitive character class range {low}-{high} can't be translated for Lucene: {text}"
            )
        return ""
    raise LuceneRegexError(
        f"Case-insensitive character class range {low}-{high} can't be translated for Lucene: {text}"
    )


def _split_top_level(pattern: str) -> List[str]:
    """Split a pattern at | outside groups and character classes."""
    parts, depth, start, i = [], 0, 0, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _class_end(pattern, i) + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            parts.append(pattern[start:i])
            start = i + 1
        i += 1
    parts.append(pattern[start:])
    return parts


def _group_alternatives(group: str):
    """The top-level alternatives of a plain or (?:...) group, or None for other groups."""
    if group.startswith("(?:"):
        return _split_top_level(group[3:-1])
    if group.startswith("(?"):
        return None
    return _split_top_level(group[1:-1])


def _group_end(pattern: str, start: int) -> int:
    """Index of the ) closing the ( at pattern[start]."""
    depth, i = 0, start
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _class_end(pattern, i) + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise LuceneRegexError(f"Unbalanced parentheses in regular expression: {pattern}")


def _group_start(pattern: str) -> int:
    """Index of the ( opening the group that ends at the last character of pattern."""
    for start in range(len(pattern) - 1, -1, -1):
        if (
            pattern[start] == "("
            and not _is_escaped(pattern, start)
            and not _in_class(pattern, start)
        ):
            try:
                if _group_end(pattern, start) == len(pattern) - 1:
                    return start
            except LuceneRegexError:
                pass
    raise LuceneRegexError(f"Unbalanced parentheses in regular expression: {pattern}")


def _class_end(pattern: str, start: int) -> int:
    """Index of the ] closing the character class opened at pattern[start]."""
    i = start + 1
    if pattern.startswith("^", i):
        i += 1
    if pattern.startswith("]", i):  # a ] right after [ or [^ is literal
        i += 1
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "]":
            return i
        i += 1
    raise LuceneRegexError(
        f"Unterminated character class in regular expression: {pattern}"
    )


def _quantifier_end(pattern: str, start: int):
    """Index of the } closing a {m}, {m,} or {m,n} quantifier at pattern[start], else None."""
    end = pattern.find("}", start)
    if end == -1:
        return None
    body = pattern[start + 1 : end]
    parts = body.split(",")
    if len(parts) == 1 and parts[0].isdigit():
        return end
    if (
        len(parts) == 2
        and parts[0].isdigit()
        and (parts[1] == "" or parts[1].isdigit())
    ):
        return end
    if len(parts) == 2 and parts[0] == "" and parts[1].isdigit():
        raise LuceneRegexError(
            f"Quantifier {{,n}} can't be translated for Lucene: {pattern}"
        )
    return None


def _starts_with_quantifier(text: str) -> bool:
    return text[:1] in ("*", "+", "?") or (
        text.startswith("{") and _quantifier_end(text, 0) is not None
    )


def _ends_with_anchor(pattern: str) -> bool:
    return pattern.endswith("$") and not _is_escaped(pattern, len(pattern) - 1)


def _is_escaped(pattern: str, index: int) -> bool:
    """True if the character at index is preceded by an odd number of backslashes."""
    backslashes, i = 0, index - 1
    while i >= 0 and pattern[i] == "\\":
        backslashes += 1
        i -= 1
    return backslashes % 2 == 1


def _in_class(pattern: str, index: int) -> bool:
    """True if index is inside a character class."""
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "[":
            end = _class_end(pattern, i)
            if i < index <= end:
                return True
            i = end + 1
            continue
        i += 1
    return False


class LuceneRegexMixin:
    """Backend mixin: regular expressions are translated with to_lucene_regex() and then
    escaped with the backend's re_escape settings (no (?flags) prefix: flags are part of
    the translation)."""

    # True if the backend matches case-insensitively itself when the i flag is set (e.g. with
    # {flag_i} in re_expression): the pattern is then translated without the i flag.
    re_native_ignore_case: ClassVar[bool] = False

    def convert_value_re(self, r, state):
        flags = r.flags
        if self.re_native_ignore_case:
            flags = flags - {SigmaRegularExpressionFlag.IGNORECASE}
        pattern = to_lucene_regex(str(r.regexp), flags)
        return escape_for_query(
            pattern, self.re_escape, self.re_escape_char, self.re_escape_escape_char
        )


def escape_for_query(
    pattern: str, escaped, escape_char: str, escape_escape_char: bool
) -> str:
    """Escape a translated regex for the query language's string syntax (as
    SigmaRegularExpression.escape does, without adding flags)."""
    targets = set(escaped)
    if escape_escape_char:
        targets.add(escape_char)
    if any(len(t) != 1 for t in targets):
        raise NotImplementedError(
            "Only single characters can be escaped in regular expressions"
        )
    return "".join(escape_char + c if c in targets else c for c in pattern)
