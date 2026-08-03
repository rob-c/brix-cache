#!/usr/bin/env python3
#
# check_client_build_coverage.py — every client/shared source is built, or says why not.
#
# WHAT: Fails (exit 1) when a `.c` file under client/ (or under the ngx-free
#       shared/ trees that only the client links: shared/cvmfs, shared/cache)
#       is neither
#         (a) named in client/Makefile — as `<stem>.c`, `<stem>.o` or
#             `<stem>.pic.o`, directly or through a $(VAR) list,
#         (b) a standalone-built unit driver (`*_unittest.c`, `*_unit.c`,
#             anything under client/tests/ or client/examples/), nor
#         (c) on the reasoned ALLOWLIST below;
#       There is deliberately no reverse (stale-entry) check: unlike ./config,
#       where an entry for a deleted file is silently ignored, a Makefile
#       prerequisite with no source is already a hard `make` error naming the
#       file. Only the forward direction fails silently.
#
# WHY:  client/Makefile says of itself "every .c must be listed (no wildcards)",
#       and that promise had silently rotted: 33 client TUs and 8 shared CVMFS
#       TUs — every one of them a phase-38/-69 split sibling whose parent WAS
#       listed — were compiled by nothing. The breakage surfaced only as a
#       link-time `undefined reference` in whichever binary happened to call
#       into the orphaned half, so `make` was red on main with no guard naming
#       the cause. This is the client-side twin of check_config_coverage.py,
#       which has guarded the same promise for src/ + ./config since phase-56.
#
# HOW:  Walk the trees, subtract the conventions and the allowlist, and check
#       each remaining stem against the Makefile text. Matching on the STEM
#       (not the whole line) is deliberate: the Makefile reaches sources
#       through $(SHARED_DIR), pattern rules and per-binary _OBJS variables, so
#       a naive line parse would need a make-expander to be right, while a stem
#       hit is exact enough to catch the only failure mode that matters — a
#       file no list mentions at all.
#
# USAGE:
#   tools/ci/check_client_build_coverage.py   # exit 0 = clean, exit 1 = violations
#
# A parallel in-pytest twin lives in tests/source_guards_lib.py
# (client_build_coverage); the verdict is kept in lockstep.

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Trees whose sources the client Makefile is the sole build owner of. shared/
# is deliberately narrowed: shared/xrdproto has its own Makefile, and the rest
# of shared/ is linked by the nginx module via ./config (check_config_coverage).
SCAN = ("client", "shared/cvmfs", "shared/cache")

# --- ALLOWLIST: intentionally-unbuilt sources (path + reason, keep sorted) ----
# Each entry is a file client/Makefile deliberately does NOT name. The reason
# must say where it IS built (or why it is built nowhere yet). Empty today —
# every client source is built; keep it that way rather than growing this list.
ALLOWLIST: tuple[str, ...] = ()


# `*_unit.c` is the client's own standalone-C-driver convention (built + run by
# tools/ci/c_regression_units.py, never linked into a CLI); `*_unittest.c` is
# the repo-wide one. Whole directories of drivers/demos are excused wholesale.
_EXCUSED_DIRS = ("client/tests/", "client/examples/", "client/bin/")


def _is_driver(rel: str, name: str) -> bool:
    return (
        name.endswith("_unittest.c")
        or "_unittest_" in name
        or name.endswith("_unit.c")
        or rel.startswith(_EXCUSED_DIRS)
    )


def _tree_files(root: Path) -> list[str]:
    """Every buildable `.c` under the scanned trees, minus the driver conventions."""
    out = []
    for top in SCAN:
        for p in (root / top).rglob("*.c"):
            rel = str(p.relative_to(root))
            if not _is_driver(rel, p.name):
                out.append(rel)
    return sorted(out)


def _makefile(root: Path) -> str:
    return (root / "client/Makefile").read_text()


def _named(makefile: str, rel: str) -> bool:
    """True when client/Makefile names this source, as .c, .o or .pic.o.

    Paths in the Makefile are relative to client/, and reach shared/ either as
    `../shared/...` or as `$(SHARED_DIR)/...`, so compare on the tail below
    those roots rather than on the repo-relative path."""
    stem = rel[: -len(".c")]
    for prefix in ("client/", "shared/"):
        if stem.startswith(prefix):
            stem = stem[len(prefix) :]
            break
    return any(f"{stem}{ext}" in makefile for ext in (".c", ".o", ".pic.o"))


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Return (ok, messages) — one message per violation, in emission order."""
    makefile = _makefile(root)
    allow_set = set(ALLOWLIST)
    msgs: list[str] = []

    for rel in _tree_files(root):
        if rel not in allow_set and not _named(makefile, rel):
            msgs.append(
                f"NOT BUILT: {rel} — add it to client/Makefile, or allowlist it "
                f"here with a reason"
            )

    for a in ALLOWLIST:
        if not (root / a).is_file():
            msgs.append(
                f"STALE ALLOWLIST: {a} no longer exists — remove it from this script"
            )

    return (not msgs, msgs)


def main() -> int:
    os.chdir(ROOT)
    ok, msgs = run(ROOT)
    for m in msgs:
        print(m, file=sys.stderr)
    if not ok:
        print("check_client_build_coverage: FAIL", file=sys.stderr)
        return 1
    print(
        f"check_client_build_coverage: OK ({len(_tree_files(ROOT))} sources, "
        f"{len(ALLOWLIST)} allowlisted)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
