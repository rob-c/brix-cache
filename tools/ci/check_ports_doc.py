#!/usr/bin/env python3
#
# check_ports_doc.py — every named port constant is in the ports registry doc.
#
# WHAT: Fails (exit 1) when a *_PORT* constant assigned in tests/settings.py
#       does not appear (by name) in docs/10-reference/test-fleet-ports.md.
#
# WHY:  settings.py is the machine source of truth; the registry doc is the
#       human map. A constant added without a registry row is undocumented
#       infrastructure — exactly the drift this doc exists to prevent.
#
# HOW:  Extract assigned ALL-CAPS names containing PORT from settings.py,
#       grep each in the doc.
#
# USAGE:
#   tools/ci/check_ports_doc.py

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Assigned ALL-CAPS name containing PORT, at column 0, up to the '=' — the
# faithful analogue of the bash `grep -oE '^[A-Z][A-Z0-9_]*PORT[A-Z0-9_]*[[:space:]]*='`.
_CONST_RE = re.compile(r"^[A-Z][A-Z0-9_]*PORT[A-Z0-9_]*[ \t\f\v\r]*=", re.MULTILINE)


def _port_constants(src: Path) -> list[str]:
    """Assigned *_PORT* names in settings.py, uniqued and sorted — the
    `... | tr -d ' =' | sort -u` tail of the bash extraction."""
    names = {m.group().replace(" ", "").replace("=", "") for m in _CONST_RE.finditer(src.read_text())}
    return sorted(names)


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """(ok, messages): ok is False on any violation; messages are the FAIL
    lines to print, in bash order. An empty message list with ok=True is the
    clean case."""
    doc = root / "docs/10-reference/test-fleet-ports.md"
    src = root / "tests/settings.py"
    doc_rel = doc.relative_to(root)

    if not doc.is_file():
        return False, [f"FAIL registry doc missing: {doc_rel}"]

    doc_text = doc.read_text()
    messages: list[str] = []
    for name in _port_constants(src):
        if name not in doc_text:
            messages.append(f"FAIL undocumented port constant: {name} (add a row to {doc_rel})")

    return not messages, messages


def main() -> int:
    os.chdir(ROOT)
    ok, messages = run()
    for line in messages:
        print(line)
    if ok:
        print("check_ports_doc: OK")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
