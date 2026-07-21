#!/usr/bin/env python3
#
# check_config_coverage.py — every module source file is built, or says why not.
#
# WHAT: Fails (exit 1) when a `.c` file under src/ is neither
#         (a) listed in the repo-root `./config` source lists,
#         (b) a `*_unittest.c` (standalone-built unit test, repo convention), nor
#         (c) on the reasoned ALLOWLIST below;
#       and, in the reverse direction, when `./config` references a `.c` file
#       that no longer exists in the tree (stale entry after a move/delete).
#
# WHY:  An auditor reading src/ must be able to tell "compiled into the module"
#       from "intentionally unbuilt" from "forgotten". Unlisted files silently
#       skip every compiler warning, -Werror gate, and reviewer's mental model.
#       The allowlist makes each intentional exception explicit and reviewed —
#       adding to it requires stating a reason in this file, in a PR diff.
#
# HOW:  Diff `find src -name '*.c'` against the `$ngx_addon_dir/src/...` paths
#       extracted from ./config, subtract the conventions and the allowlist,
#       and report anything left in either direction.
#
# USAGE:
#   tools/ci/check_config_coverage.py    # exit 0 = clean, exit 1 = violations
#
# This is a faithful Python port of check_config_coverage.sh — byte-identical
# stdout/stderr/exit code. A parallel in-pytest twin lives in
# tests/source_guards_lib.py (config_coverage); the verdict is kept in lockstep.

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# --- ALLOWLIST: intentionally-unbuilt sources (path + reason, keep sorted) ----
# Each entry is a file that is deliberately NOT in ./config. The reason must
# say where it IS built (or why it is built nowhere yet).
ALLOWLIST = (
    # Client-shared: built into libxrdc via shared/xrdproto/Makefile (ngx-free).
    "src/core/compat/kxr_names.c",
    # Build-time-disabled stub: compiled INSTEAD OF the real cache subsystem
    # when caching is configured out; satisfies the linker (see file header).
    "src/fs/cache/noop.c",
    # Standalone scan-drift reconciler (Ceph follow-on); built only by
    # scan_unittest / tests, not yet wired into the module (src/fs/scan/README.md).
    "src/fs/scan/scan_drift.c",
    # Standalone guard-core test driver (has main); built + run by
    # tests/guard/run_guard_core.sh (plain gcc, no nginx).
    "src/net/guard/guard_test.c",
    # Build-time-disabled stub for a dashboard-less build (see file header).
    "src/observability/dashboard/noop.c",
    # Build-time-disabled stub for a native-TPC-less build (see file header).
    "src/tpc/engine/noop.c",
)

# Mirrors: grep -o '\$ngx_addon_dir/src/[a-zA-Z0-9_/.-]*\.c' | sed 's|\$ngx_addon_dir/||'
_CONFIG_RE = re.compile(r"\$ngx_addon_dir/(src/[a-zA-Z0-9_/.-]*\.c)")


def _tree_files(root: Path) -> list[str]:
    """find src -name '*.c' ! -name '*_unittest.c' | sort."""
    return sorted(
        str(p.relative_to(root))
        for p in (root / "src").rglob("*.c")
        if not p.name.endswith("_unittest.c")
    )


def _config_files(root: Path) -> list[str]:
    """The `src/...c` paths referenced in ./config, deduped and sorted (sort -u)."""
    matches = _CONFIG_RE.findall((root / "config").read_text())
    return sorted(set(matches))


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Return (ok, messages). ok is False with human-readable messages — one per
    violation, in the shell script's emission order — mirroring its stderr."""
    tree_files = _tree_files(root)
    config_files = _config_files(root)
    config_set = set(config_files)
    allow_set = set(ALLOWLIST)
    msgs: list[str] = []

    # forward: tree file missing from ./config and not allowlisted
    for f in tree_files:
        if f not in config_set and f not in allow_set:
            msgs.append(
                f"NOT BUILT: {f} — add it to ./config, or allowlist it here with a reason"
            )

    # allowlist hygiene: entry no longer needed (file gone or now in config)
    for a in ALLOWLIST:
        if not (root / a).is_file():
            msgs.append(
                f"STALE ALLOWLIST: {a} no longer exists — remove it from this script"
            )
        elif a in config_set:
            msgs.append(
                f"STALE ALLOWLIST: {a} is now in ./config — remove it from this script"
            )

    # reverse: ./config references a file that does not exist
    for f in config_files:
        if not (root / f).is_file():
            msgs.append(
                f"STALE CONFIG: ./config lists {f} but the file does not exist"
            )

    return (not msgs, msgs)


def main() -> int:
    # Run from the repo root, like `cd "$(git rev-parse --show-toplevel)"`.
    os.chdir(ROOT)
    ok, msgs = run(ROOT)
    for m in msgs:
        print(m, file=sys.stderr)
    if not ok:
        print("check_config_coverage: FAIL", file=sys.stderr)
        return 1
    print(
        f"check_config_coverage: OK ({len(_tree_files(ROOT))} sources, "
        f"{len(ALLOWLIST)} allowlisted)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
