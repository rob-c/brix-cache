#!/usr/bin/env python3
#
# WHAT: Fail CI when any file under src/ or client/ exceeds the size cap (600
#       lines — the enforced backstop; coding-standards.md §1 still *prefers* ~500,
#       one concept per file), UNLESS the file is an accepted, frozen exception
#       recorded in file_size_backlog.txt. client/tests/ is carved out (unit
#       harness + fixtures are not shipped code), matching the test exemption the
#       coding standard grants elsewhere.
#
# WHY:  The ~500-line rule was documented but human-enforced — reviewers had to
#       notice size drift by eye. This guard ratchets it, mirroring the vfs-seam
#       backlog pattern: existing offenders are grandfathered and may only SHRINK;
#       nothing NEW is allowed to cross the cap, and no existing offender may GROW.
#       That converts "a reviewer must remember to check file size" into red/green.
#
# HOW:  The backlog holds "path<TAB>loc" for every file currently over the cap.
#         - live file over the cap, not in backlog        -> FAIL (new offender)
#         - live file larger than its recorded loc         -> FAIL (grew)
#         - live file <= recorded loc                      -> OK   (shrinking is good)
#       Run with --regen ONLY after a deliberate, reviewed change to lower entries
#       (e.g. after splitting a file) so the frozen ceiling ratchets downward.
#
# USAGE:
#   tools/ci/check_file_size.py            # check (CI mode); non-zero exit on failure
#   tools/ci/check_file_size.py --regen    # rewrite the backlog from the live tree

import os
import sys
from pathlib import Path

CAP = 600
ROOT = Path(__file__).resolve().parents[2]
BACKLOG = ROOT / "tools/ci/file_size_backlog.txt"


def _wc_l(path: Path) -> int:
    """Line count the way `wc -l` reports it: the number of newline bytes."""
    return path.read_bytes().count(b"\n")


def list_oversized(root: Path = ROOT) -> list[tuple[str, int]]:
    """(repo-relative path, loc) for every src/ and client/ *.c/*.h file — and
    every brixtest/src/ *.py file — above the cap, sorted by codepoint
    (LC_ALL=C) so both the ratchet compare and --regen output are deterministic.
    client/tests/ is excluded — its unit harness and fixtures are not shipped
    code and carry the same test exemption src's own tests live under elsewhere.
    brixtest/src/ (the packaged framework tree, testsuite-modernization-plan
    §7.4) is under the cap from day one: it carries no grandfathered backlog."""
    rows = _source_sizes(root)
    rows.extend(_client_sizes(root))
    rows.extend(_brixtest_sizes(root))
    rows = [(path, loc) for path, loc in rows if loc > CAP]
    return sorted(rows, key=lambda r: f"{r[0]}\t{r[1]}")


def _source_sizes(root):
    return [_size_row(root, path) for path in _c_files(root / "src")]


def _client_sizes(root):
    tests = root / "client" / "tests"
    return [_size_row(root, path) for path in _c_files(root / "client") if tests not in path.parents]


def _brixtest_sizes(root):
    return [_size_row(root, path) for path in (root / "brixtest" / "src").rglob("*.py") if path.is_file()]


def _c_files(base):
    return [path for path in base.rglob("*") if path.suffix in (".c", ".h") and path.is_file()]


def _size_row(root, path):
    return path.relative_to(root).as_posix(), _wc_l(path)


def read_backlog() -> dict[str, int]:
    """key "path" -> frozen loc ceiling."""
    frozen: dict[str, int] = {}
    for line in BACKLOG.read_text().splitlines():
        if not line.strip():
            continue
        path, _, loc = line.partition("\t")
        frozen[path] = int(loc)
    return frozen


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Check the live tree against the frozen backlog. Returns (ok, fail_lines);
    fail_lines are the per-offender FAIL messages destined for stdout."""
    frozen = read_backlog()
    fail_lines: list[str] = []
    for path, loc in list_oversized(root):
        recorded = frozen.get(path)
        if recorded is None:
            fail_lines.append(
                f"FAIL new oversized file: {path} ({loc} > {CAP}) "
                f"— split it (coding-standards §1)"
            )
        elif loc > recorded:
            fail_lines.append(
                f"FAIL grew past frozen ceiling: {path} ({loc} > recorded {recorded})"
            )
    return (not fail_lines, fail_lines)


def regen() -> int:
    rows = list_oversized()
    BACKLOG.write_text("".join(f"{path}\t{loc}\n" for path, loc in rows))
    print(f"check_file_size: regenerated {BACKLOG} ({len(rows)} entries)")
    return 0


def check() -> int:
    if not BACKLOG.is_file():
        print(f"check_file_size: FAIL — backlog missing: {BACKLOG}", file=sys.stderr)
        return 1

    ok, fail_lines = run()
    for line in fail_lines:
        print(line)

    if ok:
        print(f"check_file_size: OK (no new or growing files over {CAP} LOC)")
        return 0
    print(
        "check_file_size: to accept a deliberate reduction, run: "
        "tools/ci/check_file_size.py --regen",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    # Run from the repo root so the "src" scan and repo-relative paths line up
    # with the backlog keys regardless of cwd.
    os.chdir(ROOT)
    if "--regen" in sys.argv[1:]:
        return regen()
    return check()


if __name__ == "__main__":
    sys.exit(main())
