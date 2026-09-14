"""Read C source the way a guard needs to: by structure, not by line count.

WHAT: brace-matched extraction of a C function body, and an ordering question
about two calls inside one.

WHY: a static guard that asserts on raw file text is a guard about spelling.
Several phase-115 findings are about STRUCTURE — a call that must not appear in
one function, a call that must follow another rather than precede it — and those
questions cannot be asked of a substring.  They also cannot each carry their own
brace matcher: the same twenty lines in three suites is exactly the duplication
the absolute `check_duplication` gate exists to stop, and three copies drift.

HOW: `braced_block` walks depth from the opening brace, so a body containing
nested blocks, a `}` inside a string, or a comment holding one is bounded
correctly except for the string/comment case, which no driver table or transfer
function in this tree contains and which a matcher cheap enough to trust cannot
handle anyway.  `function_body` finds the definition by its name at column 0 —
the tree's mandated style — and returns the block after the parameter list.
`calls_in_order` answers "does the first call precede the second", the question
an ordering pin actually asks.  `strip_comments` exists because a prose mention
of a symbol is not a call: the first draft of the PROT P caller census counted
ftp_ev_data_setup.c, whose only mention of `brix_ftp_ev_data_open()` is a
sentence pointing the reader at it.
"""

from __future__ import annotations

import re


def braced_block(text: str, start: int) -> str:
    """The `{...}` block opening at offset `start`, brace-matched."""
    depth = 0
    for index in range(start, len(text)):
        depth += {"{": 1, "}": -1}.get(text[index], 0)
        if depth == 0:
            return text[start:index + 1]
    raise AssertionError(f"unbalanced braces from offset {start}")


# String and character literals come FIRST in this alternation so that a `//`
# inside one is never read as a comment: blanking the tail of
# `"https://%s/.well-known/..."` deleted the very literal a 2.0 pin was asking
# about, and the guard passed by erasing its own evidence.
_C_TOKEN = re.compile(
    r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|/\*.*?\*/|//[^\n]*", re.S)


def strip_comments(text: str) -> str:
    """`text` with C comments blanked out, offsets and line count preserved.

    Whitespace replaces each comment rather than removing it, so a `line = ...`
    offset computed on the result still points into the original.  String and
    character literals are returned verbatim.
    """
    def blank(match: re.Match) -> str:
        token = match.group(0)
        if token[0] != "/":
            return token
        return re.sub(r"\S", " ", token)

    return _C_TOKEN.sub(blank, text)


def function_body(source: str, name: str) -> str:
    """The body of C function `name`, defined with its name at column 0."""
    match = re.search(rf"^{re.escape(name)}\(", source, re.M)
    assert match, f"{name} is gone from the source this guard reads"
    return braced_block(source, source.index("{", match.end()))


def calls_in_order(body: str, first: str, second: str) -> bool:
    """1 iff `body` calls `first` and then calls `second` after it.

    Both must be present: an ordering claim about a call that is not made is
    vacuously true, and a guard that passes vacuously is the failure mode these
    suites exist to prevent.
    """
    head = body.find(f"{first}(")
    tail = body.find(f"{second}(")
    return head >= 0 and tail > head


def driver_tables(text: str) -> dict[str, str]:
    """Every `brix_sd_driver_t` table in one translation unit, by its `.name`."""
    found = {}
    for match in re.finditer(r"brix_sd_driver_t\s+\w+\s*=\s*\{", text):
        body = braced_block(text, match.end() - 1)
        name = re.search(r'\.name\s*=\s*"([^"]+)"', body)
        if name:
            found[name.group(1)] = body
    return found


def conditional_arms(source: str, directive: str) -> tuple[str, str]:
    """Return one #if/#else pair, retaining nested conditional branches."""
    start = source.index(directive) + len(directive)
    depth = 1
    branches = []
    for match in re.finditer(r"^\s*#(if|ifdef|ifndef|else|elif|endif)\b[^\n]*",
                             source[start:], re.M):
        token = match.group(1)
        if token in ("if", "ifdef", "ifndef"):
            depth += 1
        elif token == "endif":
            depth -= 1
            if depth == 0:
                assert len(branches) == 1, "conditional requires exactly one #else"
                branch = branches[0]
                assert branch.group(1) == "else", "#elif needs an explicit additional arm"
                return (source[start:start + branch.start()],
                        source[start + branch.end():start + match.start()])
        elif depth == 1:
            branches.append(match)
    raise AssertionError(f"unclosed conditional: {directive}")
