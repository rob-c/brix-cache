#!/usr/bin/env python3
#
# check_client_flags_doc.py — every command-line flag the docs put after a brix
# client tool must be a flag that tool actually parses.
#
# WHAT: Extracts the ground-truth flag surface from the client C sources (the
#       "--…" literals the argv walks compare against), then scans the docs,
#       the man pages and the phase plans for command lines led by one of the
#       shipped tools, and fails on a flag none of them parses.
#
# WHY:  A flag in a doc is executable in the same way a metric name is: an
#       operator types it. Unlike a metric, a wrong flag does fail loudly — but
#       the expensive case is not the operator, it is the RISK TABLE. Phase-104
#       Appendix L offered `--require-digest` as the mitigation for a registry
#       MITM and Appendix B.7 offered `--paranoid` as the answer to a stale
#       memo; neither existed. A mitigation column naming a control nobody can
#       type reads as closed on review and is worth less than an empty cell,
#       because it stops the next reader looking for the real one. The same
#       sweep found a third row naming `--skip-bad` for behaviour that ships
#       under the opposite spelling (`--strict`). Three defects, two of them
#       load-bearing for security, all invisible to every other guard here.
#
# HOW:  Ground truth = every `"--…"` string literal under client/, minus a
#       trailing `=` (prefix-matched options like `--follow-symlinks=no` are
#       compared with strncmp against a literal that carries it). One union,
#       not one set per tool: brixcvmfs/brixoci/brixrpm are argv[0]
#       personalities of a single binary, so a per-tool split would be a
#       fiction the link map does not support.
#
#       Claims = flags on a command line whose leading word is a shipped tool
#       (names read from client/Makefile, so a new tool is covered the day it
#       is added). Each line is un-continued at a trailing "\", cut down to its
#       inline-code spans where it has any — a doc that marks its commands as
#       code is telling us where they end, and honouring that is what stops a
#       prose sentence ("xrdcp fails, then fsck `--repair` converges") from
#       reading as one command — and then split on shell separators (| && || ;)
#       so `brixcvmfs … | grep --color` does not attribute grep's flag to us.
#       Nothing outside such a segment is looked at: `podman pull
#       --tls-verify=false`, `dnf --installroot`, `./configure --add-module`
#       and `pytest --collect-only` are all somebody else's grammar and are
#       left alone.
#
#       Escape hatch: `client-flags-allow: <reason>` anywhere on the line. A
#       plan proposing a flag it has not built yet is legitimate — it just has
#       to say so, which is exactly the sentence that was missing. There is no
#       backlog file: the tree was brought to zero when the guard landed, so a
#       new finding is new drift and the marker is the only way past it.
#
# USAGE:
#   tools/ci/check_client_flags_doc.py           # verify (CI)
#   tools/ci/check_client_flags_doc.py --dump    # print the flag surface

from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

#: Where the docs live. Plans are IN on purpose: the defects this guard was
#: written for were in a phase document's risk tables.
DOC_GLOBS = ("docs/**/*.md", "client/man/*.1", "README.md")

#: Dated by construction — holding history to today's argv would mean
#: rewriting the past.
EXCLUDED = (
    "docs/_archive/",
    "docs/doxygen/",
    "docs/superpowers/",
    "docs/09-developer-guide/history-",
    "docs/09-developer-guide/development-history.md",
)

ALLOW = "client-flags-allow:"

_FLAG = re.compile(r"(?<![\w-])--([a-z][a-z0-9-]*)")
_LITERAL = re.compile(r'"--([a-z][a-z0-9-]*)=?"')
_GETOPT = re.compile(r'\{\s*"([a-z][a-z0-9-]*)"\s*,\s*(?:no|required|optional)_argument')
_MAKE_LIST = re.compile(
    r"^(?:BINS|CKSUM_LINKS|DIAG_LINKS)\s*:?=((?:[^\n\\]*\\\n)*[^\n]*)", re.M)
_MAKE_BINDIR = re.compile(r"\$\(BINDIR\)/([A-Za-z0-9_.-]+)")
_SEPARATOR = re.compile(r"\|\||&&|[|;]")
_CODE = re.compile(r"`([^`]+)`")
#: Markup that would otherwise hide the leading word: `$ `, list bullets,
#: table cells, backticks, fence markers.
_LEAD = re.compile(r"^[\s>*\-+|`$#]*")


@lru_cache(maxsize=None)
def tools(root: Path) -> frozenset[str]:
    """The shipped client executables, read off the build.

    Names come from the Makefile rather than from client/bin/, which is a
    build artifact and empty on a fresh checkout — the guard has to work
    before anything is compiled.
    """
    text = (root / "client/Makefile").read_text(errors="ignore")
    found = set(_MAKE_BINDIR.findall(text))
    for match in _MAKE_LIST.finditer(text):
        found |= set(match.group(1).replace("\\", " ").split())
    return frozenset(n for n in found if "." not in n and "$" not in n)


@lru_cache(maxsize=None)
def flags(root: Path) -> frozenset[str]:
    """Every long option the client sources compare argv against."""
    found: set[str] = set()
    for path in sorted((root / "client").rglob("*")):
        if path.suffix not in (".c", ".h", ".cpp", ".py"):
            continue
        text = path.read_text(errors="ignore")
        found |= set(_LITERAL.findall(text))
        found |= set(_GETOPT.findall(text))
    return frozenset(found)


def doc_files(root: Path) -> Iterator[Path]:
    seen: set[Path] = set()
    for pattern in DOC_GLOBS:
        for path in sorted(root.glob(pattern)):
            rel = path.relative_to(root).as_posix()
            if path in seen or rel.startswith(EXCLUDED):
                continue
            seen.add(path)
            yield path


def logical_lines(path: Path) -> Iterator[tuple[int, str]]:
    """Source lines with trailing-backslash continuations joined.

    A multi-line invocation is one command; scanning its lines separately
    would lose the tool name before reaching its flags.
    """
    number = 0
    pending = ""
    start = 0
    for number, raw in enumerate(path.read_text(errors="ignore").splitlines(), 1):
        stripped = raw.rstrip()
        if pending == "":
            start = number
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        yield start, pending + stripped
        pending = ""
    if pending:
        yield start, pending


def claims(root: Path, path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line, flag) for every flag written against a client tool."""
    known = tools(root)
    for number, line in logical_lines(path):
        if ALLOW in line:
            continue
        yield from _line_claims(number, line, known)


def _line_claims(number, line, known):
    #: A fenced block is command text throughout and carries no backticks;
    #: anywhere else, the spans ARE the commands and the prose between them
    #: is not one.
    spans = _CODE.findall(line) or [line]
    for segment in (value for span in spans for value in _SEPARATOR.split(span)):
        if _client_segment(segment, known):
            for flag in _FLAG.findall(segment):
                yield number, flag


def _client_segment(segment, known):
    words = _LEAD.sub("", segment).split()
    return bool(words) and words[0].strip("`'\"") in known


def findings(root: Path) -> list[tuple[str, str, int]]:
    """Every unparsed flag reference: (file, human message, line)."""
    known = flags(root)
    out: list[tuple[str, str, int]] = []
    for path in doc_files(root):
        rel = path.relative_to(root).as_posix()
        for number, flag in claims(root, path):
            if flag not in known:
                out.append((rel, f"no client tool parses --{flag}", number))
    return out


def run(root: Path) -> tuple[bool, list[str]]:
    found = findings(root)
    lines = [f"FAIL {rel}:{number}: {message}"
             for rel, message, number in found]
    if found:
        lines += [
            "",
            f"{len(found)} documented flag(s) no client tool parses. Fix the doc,",
            "  build the flag, or — if a plan is proposing one it has not built",
            f"  yet — add `{ALLOW} <reason>` to the line.",
        ]
        return False, lines
    return True, [f"OK client flags: every documented flag is parsed "
                  f"({len(flags(root))} known)"]


def main() -> int:
    if "--dump" in sys.argv[1:]:
        print("\n".join(sorted("--" + f for f in flags(ROOT))))
        return 0
    passed, lines = run(ROOT)
    print("\n".join(lines))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
