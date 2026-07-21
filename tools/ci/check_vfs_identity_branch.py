#!/usr/bin/env python3
#
# phase-71 guard: the VFS layer (src/fs/vfs/*.c) must branch on capabilities
# (brix_sd_caps / brix_sd_supports / brix_sd_cred_accept), never on a concrete
# backend or protocol identity. A new backend becomes primary by setting .caps
# in src/fs/backend/, with zero edits here. Backlog target = 0.
#
# Faithful port of tools/ci/check_vfs_identity_branch.py — byte-identical
# stdout/stderr and exit code on the current tree.

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Identity-branch smells: comparing/strcmp'ing a backend name or hard-coding a
# protocol/driver token inside a conditional. Doc comments (lines starting with
# * or //) are ignored; only real code is flagged.
#
# The config-time factory that maps a `backend "<name>"` config string to a
# driver instance is EXEMPT: the vfs_backend_config*.c / vfs_backend_registry*.c
# family (split by concern in phase-79) is the ONE intended place backend
# identity is named (once, at registration). The ban applies to the runtime op
# path — every other src/fs/vfs/*.c must dispatch on capabilities, never on
# which backend it happens to be talking to.
PATTERN = re.compile(
    r'(strcmp\([^)]*(backend|driver|proto)'
    r'|== *"(posix|s3|http|webdav|remote|ceph|cvmfs)"'
    r'|sd_(http|s3|remote|ceph)_driver)'
)

# Matches the config-time factory files that are EXEMPT from the ban.
EXEMPT = re.compile(r'/vfs_backend_(config|registry)\w*\.c:')

# Matches a doc-comment code line (`path:lineno:` then `*` or `//`).
DOC_COMMENT = re.compile(r'^\S+:[0-9]+: *(\*|//)')


def _grep_hits(vfs: Path) -> list[str]:
    """Reproduce `grep -REn "$pattern" "$vfs"/*.c | grep -vE exempt | grep -vE doc`."""
    hits: list[str] = []
    for path in sorted(str(p) for p in vfs.glob("*.c")):
        data = Path(path).read_bytes().decode("utf-8", "surrogateescape")
        lines = data.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        for lineno, content in enumerate(lines, start=1):
            if not PATTERN.search(content):
                continue
            line = f"{path}:{lineno}:{content}"
            if EXEMPT.search(line):
                continue
            if DOC_COMMENT.search(line):
                continue
            hits.append(line)
    return hits


def _allowed(backlog: Path) -> int:
    """Reproduce `[ -f backlog ] && grep -cE '^[^#]' backlog` (else 0)."""
    if not backlog.is_file():
        return 0
    text = backlog.read_bytes().decode("utf-8", "surrogateescape")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return sum(1 for line in lines if line and line[0] != "#")


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Returns (passed, stdout_lines). All output goes to stdout, matching bash."""
    vfs = root / "src/fs/vfs"
    backlog = root / "tools/ci/vfs_identity_backlog.txt"

    hits = _grep_hits(vfs)
    count = len(hits)
    allowed = _allowed(backlog)

    if count > allowed:
        out = [
            f"check_vfs_identity_branch: {count} backend/proto identity "
            f"branch(es) in src/fs/vfs (allowed {allowed}):",
            *hits,
            "Route the decision through "
            "brix_sd_caps()/brix_sd_supports()/brix_sd_cred_accept() instead.",
        ]
        return False, out

    return True, [f"check_vfs_identity_branch: OK ({count} <= {allowed})"]


def main() -> int:
    os.chdir(ROOT)
    passed, lines = run()
    for line in lines:
        print(line)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
