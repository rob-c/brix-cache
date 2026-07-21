#!/usr/bin/env python3
#
# WHAT: Fail CI when lizard's copy-paste detector (-Eduplicate) finds a
#       duplicated code block across src/, client/ or shared/ that is NOT an
#       accepted, frozen exception recorded in duplication_backlog.txt.
#
# WHY:  Copy-paste is how helper reimplementation (a HARD BLOCK — see CLAUDE.md
#       HELPERS) actually happens: a block is cloned, then the copies drift.
#       Like the complexity guard (check_complexity.py) this ratchets: existing
#       duplicate blocks are grandfathered; nothing NEW may be pasted, and a
#       fixed duplication may only be ratcheted OUT of the backlog, never back
#       in. That turns "a reviewer must spot 30 cloned lines" into red/green.
#
# HOW:  `lizard -Eduplicate` is run over src/, client/ and shared/ SEPARATELY
#       (one combined invocation over all three trees emits no duplicate output
#       on this box) and the results merged. Each "Duplicate block:" stanza is
#       a set of "path:start ~ end" member lines terminated by a ^^^^ rule.
#       Each block becomes a churn-stable-ish key: member tuples sorted and
#       joined as "path:start-end+path:start-end+...". Then:
#         - live block whose key is not in the backlog -> FAIL (new duplication)
#         - backlog block no longer live               -> OK (fixed; --regen
#           ratchets it out)
#       KNOWN LIMIT (v1): the key embeds line numbers, so unrelated edits that
#       shift a grandfathered block will surface it as "new". That is a signal
#       to look at it (and either fix it or --regen), not a bug in the guard.
#       Run with --regen ONLY after a deliberate, reviewed change so the
#       frozen set ratchets downward.
#
# USAGE:
#   tools/ci/check_duplication.py          # check (CI mode); non-zero exit on failure
#   tools/ci/check_duplication.py --regen  # rewrite the backlog from the live tree
#
# Requires: lizard  (pip install --user lizard)
#
# NOTE: faithful port of check_duplication.sh. The merge/dedup/ordering uses
# deterministic codepoint order (Python sorted(), == `LC_ALL=C sort`) rather
# than the shell's locale-sensitive `sort -u`.

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKLOG = ROOT / "tools/ci/duplication_backlog.txt"
TREES = ("src", "client", "shared")

# A member line inside a stanza: "path:start ~ end".
_MEMBER = re.compile(r"^(.+):([0-9]+) ~ ([0-9]+)$")


def find_lizard() -> str | None:
    """Locate lizard exactly like tools/readability.find_lizard: prefer PATH,
    then the pip --user install dir. Returns None when nothing is found."""
    for c in ("lizard", os.path.expanduser("~/.local/bin/lizard")):
        if shutil.which(c) or os.path.exists(c):
            return c
    return None


def _parse_blocks(text: str) -> list[str]:
    """Turn one lizard -Eduplicate stream into a list of '+'-joined member keys.
    Mirrors the awk state machine: a "Duplicate block:" opens a stanza, member
    lines accumulate, a "^^^^" rule finalises it (members sorted, joined). A new
    "Duplicate block:" or EOF before the rule discards the incomplete stanza."""
    keys: list[str] = []
    inblock = False
    members: list[str] = []
    for line in text.splitlines():
        if line.startswith("Duplicate block:"):
            inblock = True
            members = []
            continue
        if inblock and line.startswith("^^^"):
            members.sort()
            keys.append("+".join(members))
            inblock = False
            continue
        if inblock:
            m = _MEMBER.match(line)
            if m:
                path, start, end = m.group(1), m.group(2), m.group(3)
                members.append(f"{path}:{start}-{end}")
    return keys


def list_duplicates(lizard: str, root: Path = ROOT) -> list[str]:
    """One sorted, de-duplicated key per live duplicate block. lizard is run per
    tree (a combined run emits nothing on this box) with a relative tree path so
    the reported file column matches the backlog; its non-zero CCN-warning exit
    and stderr are ignored, as in the shell guard."""
    keys: list[str] = []
    for tree in TREES:
        result = subprocess.run(
            [lizard, "-Eduplicate", tree],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        keys.extend(_parse_blocks(result.stdout))
    return sorted(set(keys))


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """The check verdict against the frozen backlog. Returns (ok, fail_lines)
    where fail_lines are the stdout lines for each new (un-grandfathered) block:
    a FAIL header followed by its members, each indented four spaces."""
    lizard = find_lizard()
    if lizard is None:
        return False, []
    frozen = set(BACKLOG.read_text().splitlines())
    ok = True
    lines: list[str] = []
    for key in list_duplicates(lizard, root):
        if key not in frozen:
            lines.append("FAIL new duplicated block — extract a shared helper (coding-standards §8):")
            lines.extend(f"    {member}" for member in key.split("+"))
            ok = False
    return ok, lines


def regen() -> int:
    lizard = find_lizard()
    keys = list_duplicates(lizard, ROOT)
    BACKLOG.write_text("".join(f"{key}\n" for key in keys))
    print(f"check_duplication: regenerated {BACKLOG} ({len(keys)} entries)")
    return 0


def check() -> int:
    if not BACKLOG.is_file():
        print(f"check_duplication: FAIL — backlog missing: {BACKLOG}", file=sys.stderr)
        return 1

    ok, lines = run()
    for line in lines:
        print(line)

    if ok:
        print("check_duplication: OK (no duplicate blocks outside the frozen backlog)")
        return 0
    print("check_duplication: if a grandfathered block merely SHIFTED (line-number churn), or after a deliberate reviewed fix, run: tools/ci/check_duplication.py --regen", file=sys.stderr)
    return 1


def main() -> int:
    # lizard presence is checked before dispatching either mode, matching the
    # shell guard's ordering and message.
    if find_lizard() is None:
        print("check_duplication: FAIL — lizard not found (pip install --user lizard)", file=sys.stderr)
        return 1

    # Run from the repo root so lizard's tree paths — and the file column it
    # reports — line up with the backlog keys regardless of cwd.
    os.chdir(ROOT)
    if "--regen" in sys.argv[1:]:
        return regen()
    return check()


if __name__ == "__main__":
    sys.exit(main())
