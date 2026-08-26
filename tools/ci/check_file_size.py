#!/usr/bin/env python3
#
# WHAT: Fail CI when any hand-written C/C++ file under src/, client/, or shared/
#       (source AND headers: .c/.h/.cpp/.cc/.hpp/.hxx) exceeds the size cap (600
#       lines — the enforced backstop; coding-standards.md §1 still *prefers* ~500,
#       one concept per file). client/tests/ (unit harness + fixtures,
#       not shipped code) is carved out, matching the test exemption the coding
#       standard grants. shared/xrdproto/ is NOT exempt (phase-103 §3 decision 2:
#       gate the wire library like project code) — it holds no in-repo source today,
#       so the gate simply applies to anything hand-written that lands there later.
#
# WHY:  The ~500-line rule was documented but human-enforced — reviewers had to
#       notice size drift by eye. Every over-cap file fails directly; there is no
#       exception list or regeneration path.
#
# HOW:  Scan every in-scope file and fail for each line count above CAP.
#
# USAGE:
#   tools/ci/check_file_size.py            # check (CI mode); non-zero exit on failure

import os
import sys
from pathlib import Path

CAP = 600
ROOT = Path(__file__).resolve().parents[2]

# Phase-103 Workstream A (§5.1): C AND C++, source AND headers, across every
# hand-written tree — the pre-phase-103 guard scanned only src/+client/ and only
# .c/.h, silently exempting .cpp/.cc and the whole shared/ library.
_SIZE_SUFFIXES = (".c", ".h", ".cpp", ".cc", ".hpp", ".hxx")
_ROOTS = ("src", "client", "shared")


def _wc_l(path: Path) -> int:
    """Line count the way `wc -l` reports it: the number of newline bytes."""
    return path.read_bytes().count(b"\n")


def _in_scope(path: Path, carve_outs) -> bool:
    """A hand-written C/C++ source or header, outside every carve-out dir."""
    if path.suffix not in _SIZE_SUFFIXES or not path.is_file():
        return False
    return not any(c in path.parents for c in carve_outs)


def _tree_sizes(root: Path, top: str, carve_outs) -> list[tuple[str, int]]:
    """(repo-relative path, loc) for every in-scope file under root/top."""
    base = root / top
    if not base.is_dir():
        return []
    return [(f.relative_to(root).as_posix(), _wc_l(f))
            for f in base.rglob("*") if _in_scope(f, carve_outs)]


def _brixtest_sizes(root: Path) -> list[tuple[str, int]]:
    """brixtest/src/ (the packaged framework tree, testsuite-modernization-plan
    §7.4) is under the cap from day one: no grandfathered anything."""
    return [(f.relative_to(root).as_posix(), _wc_l(f))
            for f in (root / "brixtest" / "src").rglob("*.py") if f.is_file()]


def list_oversized(root: Path = ROOT) -> list[tuple[str, int]]:
    """(repo-relative path, loc) for every src/, client/, and shared/ C/C++ source
    or header — and every brixtest/src/ *.py — above the cap, sorted by codepoint
    (LC_ALL=C) for deterministic diagnostics. Carve-out (§3 decision 1): the
    unit-harness/fixtures under client/tests/ are not shipped code. shared/xrdproto/
    is gated like project code (§3 decision 2 — ratified 'gate it', not exempt)."""
    carve_outs = (
        root / "client" / "tests",
    )
    rows: list[tuple[str, int]] = []
    for top in _ROOTS:
        rows.extend(_tree_sizes(root, top, carve_outs))
    rows.extend(_brixtest_sizes(root))
    rows = [(path, loc) for path, loc in rows if loc > CAP]
    return sorted(rows, key=lambda r: f"{r[0]}\t{r[1]}")


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Return one unconditional failure for every over-cap source file."""
    fail_lines = [
        f"FAIL oversized file: {path} ({loc} > {CAP}) "
        f"— split it (coding-standards §1)"
        for path, loc in list_oversized(root)
    ]
    return (not fail_lines, fail_lines)


def check() -> int:
    ok, fail_lines = run()
    for line in fail_lines:
        print(line)

    if ok:
        print(f"check_file_size: OK (no files over {CAP} LOC)")
        return 0
    return 1


def main() -> int:
    # Run from the repo root so the "src" scan and repo-relative paths line up
    # with the backlog keys regardless of cwd.
    os.chdir(ROOT)
    return check()


if __name__ == "__main__":
    sys.exit(main())
