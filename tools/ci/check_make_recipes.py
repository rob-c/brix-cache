#!/usr/bin/env python3
#
# check_make_recipes.py — no target may carry two recipes.
#
# WHAT: Runs `make --dry-run` over each hand-maintained Makefile in the tree and
#       fails (exit 1) if make reports "overriding recipe" / "ignoring old
#       recipe" for any target. Nothing is compiled: the dry run only parses the
#       Makefile and prints what it would do, so the guard costs milliseconds.
#       If `make` is not installed the guard SKIPs (exit 0, and says so) rather
#       than failing a runner that has no toolchain.
#
# WHY:  make does not treat a second recipe for a target as an error. It keeps
#       the last one, discards the first, and carries on with a warning most
#       people never read because the build still succeeds. What is discarded is
#       not just the commands but the prerequisites attached to that copy, so
#       the object silently stops rebuilding when they change. client/Makefile
#       had exactly that: `apps/fs/brixautofs_ext.o` was covered both by the
#       $(BRIXAUTOFS_OBJS) rule, which depends on apps/fs/brixautofs.h, and by a
#       standalone rule below it that does not — the standalone one won, and an
#       edit to that header left the object stale until someone ran `make
#       clean`. Five brixcvmfs objects were doubly-covered the same way (there
#       the two recipes were identical, so it cost only noise). A stale object
#       linked against a changed header is an ABI mismatch that reaches a test
#       run looking like a logic bug, which is a bad way to spend an afternoon.
#
# HOW:  Collect the Makefiles we own (see MAKEFILES — generated/vendored trees
#       are excluded), run `make -n` in each directory, and scan stderr. The
#       dry run's exit status is deliberately ignored: a Makefile whose default
#       target needs a tool this runner lacks still parses, and parsing is all
#       this guard asks of it. Only the warning lines are the verdict.
#
# USAGE:
#   tools/ci/check_make_recipes.py   # exit 0 = clean, exit 1 = violations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The Makefiles this repo hand-maintains. Deliberately an explicit list, not a
# glob: .rpmbuild/ and .claude/worktrees/ hold copies of these same files, objs/
# and nginx-src/ hold generated ones, and none of them are ours to fix.
MAKEFILES: tuple[str, ...] = (
    "client",
    "tools/pblock-fsck",
    "shared/xrdproto",
)

_WARNINGS = ("overriding recipe for target", "ignoring old recipe for target")


def _dry_run(directory: Path) -> str:
    """stderr of `make -n` in `directory` — parse-time diagnostics, no build."""
    proc = subprocess.run(
        ["make", "--dry-run", "--no-print-directory"],
        cwd=directory,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    return proc.stderr


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Return (ok, messages) — one message per duplicated recipe, in make's order."""
    msgs = [message for rel in MAKEFILES for message in _makefile_messages(root, rel)]
    return (not msgs, msgs)


def _makefile_messages(root, relative):
    directory = root / relative
    if not (directory / "Makefile").is_file():
        return [f"MISSING: {relative}/Makefile — update MAKEFILES in this guard"]
    return [
        f"DUPLICATE RECIPE: {relative}/{line.strip()} — one target, one recipe; "
        "make keeps the last and drops the other's prerequisites"
        for line in _dry_run(directory).splitlines()
        if any(warning in line for warning in _WARNINGS)
    ]


def main() -> int:
    if shutil.which("make") is None:
        print("check_make_recipes: SKIP (no make on this runner)")
        return 0
    ok, msgs = run(ROOT)
    for m in msgs:
        print(m, file=sys.stderr)
    if not ok:
        print("check_make_recipes: FAIL", file=sys.stderr)
        return 1
    print(f"check_make_recipes: OK ({len(MAKEFILES)} Makefile(s), no duplicate recipes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
