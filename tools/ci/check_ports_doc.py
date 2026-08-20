#!/usr/bin/env python3
#
# check_ports_doc.py — every named port constant is in the ports registry doc.
#
# WHAT: Fails (exit 1) when a named port in the suite's port ledger does not
#       appear (by name) in docs/10-reference/test-fleet-ports.md.
#
# WHY:  the ledger is the machine source of truth; the registry doc is the
#       human map. A constant added without a registry row is undocumented
#       infrastructure — exactly the drift this doc exists to prevent.
#
# HOW:  import the canonical settings module and walk
#       `SETTINGS.ports.iter_named_ports()` (testsuite-modernization-plan §12,
#       TS-3), then grep each name in the doc. Before TS-3 this scraped
#       `tests/settings.py` with a regex; that file is now a shim, and a regex
#       over it would find zero constants and pass vacuously — so the ledger is
#       read directly and an implausibly small ledger is itself a failure.
#
# USAGE:
#   tools/ci/check_ports_doc.py

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# A floor, not a target: the ledger held 179 names (178 owners + 1 alias) when
# this guard moved onto it. Ports are only ever added, so a count anywhere near
# this low means the ledger was not really read — the exact silent-pass failure
# mode that regex-scraping a moved file produced.
_MIN_LEDGER_NAMES = 150


def _ledger_names() -> list[str]:
    """Named ports from the canonical settings object, sorted."""
    sys.path.insert(0, str(ROOT / "brixtest" / "src"))
    sys.path.insert(0, str(ROOT / "tests"))
    import brix_suite.settings as settings  # noqa: E402  (path set above)

    ledger = settings.SETTINGS.ports
    if ledger is None:
        raise RuntimeError(
            "settings.SETTINGS.ports is None — the lane's port base is outside "
            "the sane range; refusing to report an empty ledger as clean")
    return [name for name, _port in ledger.iter_named_ports()]


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """(ok, messages): ok is False on any violation; messages are the FAIL
    lines to print. An empty message list with ok=True is the clean case."""
    doc = root / "docs/10-reference/test-fleet-ports.md"
    doc_rel = doc.relative_to(root)

    if not doc.is_file():
        return False, [f"FAIL registry doc missing: {doc_rel}"]

    names = _ledger_names()
    if len(names) < _MIN_LEDGER_NAMES:
        return False, [
            f"FAIL port ledger reported only {len(names)} names (expected at "
            f"least {_MIN_LEDGER_NAMES}) — the guard is not seeing the real "
            f"ledger; fix the guard, do not lower the floor"]

    doc_text = doc.read_text()
    messages: list[str] = []
    for name in names:
        if name not in doc_text:
            messages.append(
                f"FAIL undocumented port constant: {name} (add a row to {doc_rel})")

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
