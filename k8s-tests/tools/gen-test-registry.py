#!/usr/bin/env python3
"""gen-test-registry — (re)generate k8s-tests/TEST_REGISTRY.md.

Scans the module suite (tests/) for each file's test-function count and a
description (from its docstring), and maps it to the 1:1 fork in the k8s lab
(k8s-tests/remote-suite/tests/) with that fork's run status. Run from anywhere:

    python3 k8s-tests/tools/gen-test-registry.py
"""
import ast
import re
from collections import Counter
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]      # k8s-tests/
REPO = LAB.parent
TESTS = REPO / "tests"
FORK = LAB / "remote-suite" / "tests"
OUT = LAB / "TEST_REGISTRY.md"

MARKER = {"# brix-remote-adapted": "adapted",
          "# brix-remote-ok": "verified-ok",
          "# brix-remote-skip": "remote-skip"}
SRVLOCAL = re.compile(r"DATA_DIR|CACHE_ROOT|os\.listdir|CHAOS_TIER|_ROOT\b")
DEF = re.compile(r"^\s*(?:async\s+)?def\s+test_", re.M)
FNAME = re.compile(r"^(tests/)?test_[\w-]+\.py\b")


def _clean(line):
    line = line.strip().rstrip(".:")
    return re.sub(r"^(tests/)?test_[\w-]+\.py\s*[—-]+\s*", "", line).strip()


def _first_description(lines, minimum=1):
    for raw in lines:
        description = _clean(raw)
        if len(description) >= minimum and not FNAME.match(description):
            return description
    return None


def _comment_description(text):
    for raw in text.splitlines():
        candidate = raw.strip()
        if candidate.startswith("#") and "brix-remote" not in candidate \
                and len(candidate) > 6:
            return _clean(candidate.lstrip("# "))
    return None


def _doc_lines(text):
    try:
        doc = ast.get_docstring(ast.parse(text))
    except SyntaxError:
        doc = None
    return doc.splitlines() if doc else []


def describe(text, stem):
    lines = _doc_lines(text)
    description = _first_description(lines, 12)
    if description:
        return description
    description = _first_description(lines)
    if description:
        return description
    description = _comment_description(text)
    if description:
        return description
    return stem[len("test_"):].replace("_", " ")


def status(fork_path):
    if not fork_path.exists():
        return "not-forked"
    text = fork_path.read_text(errors="replace")
    first = text.splitlines()[0] if text else ""
    if first in MARKER:
        return MARKER[first]
    return "server-local" if SRVLOCAL.search(text) else "pure-remote"


def rows():
    for f in sorted(TESTS.glob("test_*.py")):
        text = f.read_text(errors="replace")
        yield f.name, len(DEF.findall(text)), describe(text, f.stem), status(FORK / f.name)


def _registry_row(index, row):
    name, tests, description, status_name = row
    description = description.replace("|", "\\|").replace("`", "")
    if len(description) > 96:
        description = description[:93] + "…"
    return (f"| {index} | `{name}` | {tests} | {description} | `{name}` | "
            f"`{status_name}` |")


def _status_summary(counts):
    statuses = ("pure-remote", "adapted", "verified-ok", "remote-skip",
                "server-local")
    return " · ".join(f"`{status}` {counts[status]}" for status in statuses
                      if counts.get(status))


def _registry_header(files, tests, counts):
    return [
        "# nginx-xrootd Test Registry", "",
        "Flat registry of every test file in the module's suite (`tests/`): its test-function count, "
        "what it exercises, and the file in the k8s test lab that replicates it. The k8s lab runs a 1:1 "
        "fork of each file at `k8s-tests/remote-suite/tests/<same name>` (conftest REMOTE mode, against a "
        "deployed brix server); the **Status** column says how that fork runs.", "",
        f"**Totals:** {files} files · {tests} test functions (`def test_*`; parametrized cases expand "
        "further at runtime). Regenerate with `python3 k8s-tests/tools/gen-test-registry.py`.", "",
        "**k8s fork status legend:**",
        "- `pure-remote` — runs over the wire unchanged (no edit).",
        "- `adapted` — edited to run remotely; server-side files reached via `klib.svc_*` (`# brix-remote-adapted`).",
        "- `verified-ok` — runs remotely as-is, verified (`# brix-remote-ok`).",
        "- `remote-skip` — needs a multi-server topology the single mega server can't provide (`# brix-remote-skip`).",
        "", "**Status counts:** " + _status_summary(counts), "",
        "| # | Test file (`tests/`) | Tests | What it tests | k8s lab file (`remote-suite/tests/`) | Status |",
        "|---|---|------:|---|---|---|",
    ]


def render(data):
    files = len(data)
    tests = sum(r[1] for r in data)
    counts = Counter(r[3] for r in data)
    lines = _registry_header(files, tests, counts)
    for index, row in enumerate(data, 1):
        lines.append(_registry_row(index, row))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    data = list(rows())
    OUT.write_text(render(data))
    print(f"wrote {OUT} — {len(data)} files, {sum(r[1] for r in data)} test functions")
