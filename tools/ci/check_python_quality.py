#!/usr/bin/env python3
"""Fail CI when any Python function exceeds the repository's complexity limits.

WHAT: the Python half of the same contract ``check_complexity.py`` enforces for
      C. Every function under ``tests/``, ``client/``, ``shared/``, ``src/``,
      ``tools/``, ``utils/``, ``k8s-tests/`` and ``docs/`` must measure
      CCN <= 15, cognitive <= 10, NPath <= 15, Halstead difficulty <= 5 and
      maximum nesting <= 10. No backlog, no per-line pragma, no exemption.
      ``brixtest/`` answers to its own equal-or-tighter copy of the contract
      instead; the reason is recorded beside ``SCAN_ROOTS`` in the engine.

WHY:  cyclomatic complexity alone was never the whole story. A function can sit
      at CCN 14 and still be a five-deep nest with tens of thousands of
      execution paths, and the suite had both shapes. NPath and nesting are what
      make the contract bite on the code that is hard to read rather than merely
      branchy.

      This script exists as well as ``tests/test_python_quality.py`` because the
      guards workflow is a bare checkout: no build, no fleet, and the suite's
      ``conftest.py`` starts a server fleet for any pytest invocation under
      ``tests/``. Running the contract through pytest there would fail on the
      missing ``objs/nginx`` rather than on anything about the code. The scoring
      engine is shared, so the two spellings cannot disagree: this is the CI
      gate, the pytest module is the engine's own unit coverage.

HOW:  ``tests/python_quality_lib.py`` owns the scan roots, the limits and the
      three analyzers (lizard, complexipy, radon) plus the AST passes for NPath
      and nesting. This is a CLI over it.

USAGE:
  tools/ci/check_python_quality.py            # check; non-zero exit on failure
  tools/ci/check_python_quality.py --limit N  # show at most N samples per metric
  tools/ci/check_python_quality.py --root DIR # scan DIR instead of the repo

Requires: lizard, complexipy, radon  (all in requirements.txt)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

try:
    import python_quality_lib as quality
except ModuleNotFoundError as error:  # pragma: no cover - CI-only path
    # Same failure mode check_complexity.py documents: the guard is committed,
    # its engine is not, and CI builds from a fresh clone. Name the cause, or a
    # bare traceback reads as "the guard is broken".
    print(
        f"check_python_quality: FAIL — {error.name} is missing "
        f"(engine: {ROOT / 'tests/python_quality_lib.py'}; "
        f"analyzers: pip install -r requirements.txt)",
        file=sys.stderr,
    )
    raise SystemExit(1) from error


def _samples(failed: list[str], limit: int) -> list[str]:
    """At most `limit` violations per metric, so one bad file cannot bury the
    other four metrics under its own output."""
    shown: list[str] = []
    for metric in quality.LIMITS:
        matching = [message for message in failed if message.startswith(f"{metric} ")]
        shown.extend(matching[:limit])
        if len(matching) > limit:
            shown.append(f"{metric} limit: ... and {len(matching) - limit} more")
    return shown


def check(limit: int, root: Path) -> int:
    report = quality.score_repository(root)
    if report.errors:
        print("check_python_quality: FAIL — metric analysis errored:", file=sys.stderr)
        for error in report.errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    failed = quality.violations(report.scores)
    if not failed:
        limits = ", ".join(f"{name} {value:g}" for name, value in quality.LIMITS.items())
        print(f"check_python_quality: OK ({len(report.scores)} function scores, {limits})")
        return 0

    for line in _samples(failed, limit):
        print(f"FAIL {line} — decompose it")
    print(f"check_python_quality: FAIL ({len(failed)} limit(s) exceeded)", file=sys.stderr)
    return 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--limit", type=int, default=25,
                    help="max violations printed per metric (default 25)")
    ap.add_argument("--root", type=Path, default=ROOT,
                    help="tree to scan (the guard's own tests point this at a "
                         "scratch copy; proving a guard fires by damaging the "
                         "live tree is never acceptable)")
    args = ap.parse_args(argv)
    os.chdir(ROOT)
    return check(args.limit, args.root.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
