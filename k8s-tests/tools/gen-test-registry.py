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


def describe(text, stem):
    try:
        doc = ast.get_docstring(ast.parse(text))
    except SyntaxError:
        doc = None
    lines = doc.splitlines() if doc else []
    for raw in lines:
        s = _clean(raw)
        if len(s) >= 12 and not FNAME.match(s):
            return s
    for raw in lines:
        s = _clean(raw)
        if s and not FNAME.match(s):
            return s
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("#") and "brix-remote" not in s and len(s) > 6:
            return _clean(s.lstrip("# "))
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


def render(data):
    files = len(data)
    tests = sum(r[1] for r in data)
    counts = Counter(r[3] for r in data)
    lines = [
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
        "",
        "**Status counts:** " + " · ".join(
            f"`{k}` {counts[k]}" for k in
            ("pure-remote", "adapted", "verified-ok", "remote-skip", "server-local") if counts.get(k)),
        "",
        "| # | Test file (`tests/`) | Tests | What it tests | k8s lab file (`remote-suite/tests/`) | Status |",
        "|---|---|------:|---|---|---|",
    ]
    for i, (name, n, desc, st) in enumerate(data, 1):
        desc = desc.replace("|", "\\|").replace("`", "")
        if len(desc) > 96:
            desc = desc[:93] + "…"
        lines.append(f"| {i} | `{name}` | {n} | {desc} | `{name}` | `{st}` |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    data = list(rows())
    OUT.write_text(render(data))
    print(f"wrote {OUT} — {len(data)} files, {sum(r[1] for r in data)} test functions")
