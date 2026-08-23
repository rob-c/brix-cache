#!/usr/bin/env python3
#
# WHAT: Fail CI when a source file under src/, client/, or shared/ carries more
#       TODO/FIXME/XXX/HACK markers than it did at freeze time (QUALITY_ROADMAP
#       §3.7, "No TODO/FIXME comments").
#
# WHY:  The 9.5 target bans in-code TODO/FIXME markers, but the tree already has
#       a handful (mostly prose references to XRootD's own documented TODOs). A
#       hard zero-tolerance gate would red-line those existing, reviewed comments.
#       So this ratchets exactly like check_file_size.py / check_complexity.py:
#       existing markers are grandfathered per file and may only DECREASE; no new
#       file may introduce a marker, and no grandfathered file may gain one. New
#       "I'll fix it later" debt is thereby blocked at the gate, and the standing
#       count can only trend to zero.
#
# HOW:  Backlog holds "path<TAB>count" for every file with >0 markers.
#         - live file with markers, not in backlog        -> FAIL (new debt)
#         - live file with more markers than recorded      -> FAIL (grew)
#         - live file with <= recorded markers             -> OK   (paying it down)
#       Run with --regen ONLY after a deliberate, reviewed reduction so the frozen
#       ceiling ratchets downward.
#
# USAGE:
#   tools/ci/check_todo_fixme.py           # check (CI mode); non-zero exit on failure
#   tools/ci/check_todo_fixme.py --regen   # rewrite the backlog from the live tree

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKLOG = ROOT / "tools/ci/todo_fixme_backlog.txt"

# Word-boundary match so "flowlabel" etc. never trips it; case-sensitive on purpose
# (these are conventional all-caps markers, not the English words).
PATTERN = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")


def _read(path: Path) -> str:
    """Byte-tolerant read (grep is byte-based; .c/.h may carry stray bytes)."""
    return path.read_text(errors="ignore")


def list_marked(root: Path = ROOT) -> list[tuple[str, int]]:
    """(path, count) — repo-relative path + matching-line count — for every source
    file under src/, client/, shared/ with >0 markers, sorted by codepoint so the
    output is deterministic (LC_ALL=C equivalent of the shell's `sort`)."""
    rows = [
        row
        for directory in ("src", "client", "shared")
        for path in _source_files(root / directory)
        for row in _marked_row(root, path)
    ]
    return sorted(rows, key=lambda r: r[0])


def _source_files(base):
    if not base.is_dir():
        return []
    return [
        path for path in base.rglob("*")
        if path.suffix in (".c", ".h") and path.is_file()
    ]


def _marked_row(root, path):
    count = sum(1 for line in _read(path).splitlines() if PATTERN.search(line))
    return [(str(path.relative_to(root)), count)] if count > 0 else []


def read_backlog() -> dict[str, int]:
    """key "path" -> frozen marker count."""
    frozen: dict[str, int] = {}
    for line in BACKLOG.read_text().splitlines():
        if not line.strip():
            continue
        path, _, count = line.partition("\t")
        frozen[path] = int(count)
    return frozen


def regen() -> int:
    rows = list_marked()
    BACKLOG.write_text("".join(f"{path}\t{count}\n" for path, count in rows))
    print(f"check_todo_fixme: regenerated {BACKLOG} ({len(rows)} entries)")
    return 0


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Ratchet verdict: (ok, violation_messages). ok False when a file introduces
    new debt or grows past its recorded count."""
    frozen = read_backlog()
    msgs: list[str] = []
    for path, count in list_marked(root):
        recorded = frozen.get(path)
        if recorded is None:
            msgs.append(
                f"FAIL new TODO/FIXME debt: {path} ({count} marker(s)) — "
                "resolve it, don't defer (coding-standards §3.7)"
            )
        elif count > recorded:
            msgs.append(f"FAIL added a TODO/FIXME: {path} ({count} > recorded {recorded})")
    return (not msgs, msgs)


def check() -> int:
    if not BACKLOG.is_file():
        print(f"check_todo_fixme: FAIL — backlog missing: {BACKLOG}", file=sys.stderr)
        return 1

    ok, msgs = run()
    for m in msgs:
        print(m)

    if ok:
        print("check_todo_fixme: OK (no new or growing TODO/FIXME markers)")
        return 0
    print("check_todo_fixme: to accept a deliberate reduction, run: "
          "tools/ci/check_todo_fixme.py --regen", file=sys.stderr)
    return 1


def main() -> int:
    os.chdir(ROOT)
    if "--regen" in sys.argv[1:]:
        return regen()
    return check()


if __name__ == "__main__":
    sys.exit(main())
