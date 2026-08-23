#!/usr/bin/env python3
"""Fail CI when any native function exceeds CCN 15. No exemptions, no backlog.

WHAT: every function under ``src/``, ``client/`` and ``shared/`` must measure
      CCN <= 15 (lizard's McCabe analyzer, its own default warning level and the
      threshold ``coding-standards.md`` §7 names).  ``shared/`` is new here: the
      backlog era never covered it, so the CVMFS, CAS and OCI trees had never
      been gated at all.

WHY:  this guard used to be a ratchet — 51 grandfathered functions in
      ``complexity_backlog.txt``, each allowed to keep its recorded CCN forever.
      A ratchet answers "is the tree getting worse?", which is the wrong
      question once the answer to "is the tree clean?" can be yes.  The backlog
      also cost more than it bought: every accepted entry is a line a reviewer
      must decide about, and a frozen ceiling of 90 reads to the next reader as
      a sanctioned 90.  The 51 entries were decomposed rather than re-frozen and
      the backlog file was DELETED; an absolute cap has no ceiling to raise and
      no file to append to, so there is no longer a way to make this guard green
      except by simplifying the code.

HOW:  ``tools/readability.py`` owns lizard invocation, its CSV quirks (the
      signature column contains commas and quotes) and ``CCN_MAX`` — this guard
      imports it in-process so the two can never disagree.  That engine is a
      separate file, which makes one specific CI failure possible: this guard
      committed, ``readability.py`` not, and CI builds from a fresh clone rather
      than a working tree, so it dies on ``ModuleNotFoundError``.  A bare
      traceback reads as "the guard is broken" and sends the reader hunting a
      complexity regression that does not exist, so the cause is named below.
      ``tests/test_guard_dependencies.py`` stops it recurring.

      The Python half of the same contract lives in
      ``tests/test_python_quality.py`` (CCN, cognitive, NPath, Halstead,
      nesting) and is likewise exemption-free.

USAGE:
  tools/ci/check_complexity.py     # check (CI mode); non-zero exit on failure

Requires: lizard  (pip install --user lizard)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))
try:
    import readability
except ModuleNotFoundError as error:  # pragma: no cover - CI-only path
    if error.name != "readability":
        raise
    print(
        f"check_complexity: FAIL — lizard engine {TOOLS / 'readability.py'} is missing",
        file=sys.stderr,
    )
    raise SystemExit(1) from error

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = ("src", "client", "shared")


def gate_rows() -> list[tuple[str, str, int]]:
    """Return every over-limit native function in deterministic order."""
    functions = readability.run_lizard(readability.find_lizard(), list(SOURCE_ROOTS))
    rows = [
        (function["file"], function["func"], function["ccn"])
        for function in functions
        if function["ccn"] > readability.CCN_MAX
    ]
    return sorted(rows, key=lambda row: (row[0], row[1], -row[2]))


def check() -> int:
    """Print every violation and return a conventional guard exit status."""
    rows = gate_rows()
    if not rows:
        print("check_complexity: OK (every native function has CCN <= 15)")
        return 0
    for file, function, ccn in rows:
        print(
            f"FAIL over-complex function: {file}::{function} "
            f"(CCN {ccn} > {readability.CCN_MAX}) — decompose it"
        )
    print(f"check_complexity: FAIL ({len(rows)} function(s) over CCN 15)", file=sys.stderr)
    return 1


def main() -> int:
    """Run from the repository root so analyzer paths remain stable."""
    os.chdir(ROOT)
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
