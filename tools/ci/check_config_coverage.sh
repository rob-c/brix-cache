#!/usr/bin/env bash
#
# check_config_coverage.sh — every module source file is built, or says why not.
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
#   tools/ci/check_config_coverage.sh    # exit 0 = clean, exit 1 = violations

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# --- ALLOWLIST: intentionally-unbuilt sources (path + reason, keep sorted) ----
# Each entry is a file that is deliberately NOT in ./config. The reason must
# say where it IS built (or why it is built nowhere yet).
ALLOWLIST=(
    # Client-shared: built into libxrdc via shared/xrdproto/Makefile (ngx-free).
    "src/core/compat/kxr_names.c"
    # Build-time-disabled stub: compiled INSTEAD OF the real cache subsystem
    # when caching is configured out; satisfies the linker (see file header).
    "src/fs/cache/noop.c"
    # Standalone scan-drift reconciler (Ceph follow-on); built only by
    # scan_unittest / tests, not yet wired into the module (src/fs/scan/README.md).
    "src/fs/scan/scan_drift.c"
    # Standalone guard-core test driver (has main); built + run by
    # tests/guard/run_guard_core.sh (plain gcc, no nginx).
    "src/net/guard/guard_test.c"
    # Build-time-disabled stub for a dashboard-less build (see file header).
    "src/observability/dashboard/noop.c"
    # Build-time-disabled stub for a native-TPC-less build (see file header).
    "src/tpc/engine/noop.c"
)

tree_files=$(find src -name '*.c' ! -name '*_unittest.c' | sort)
config_files=$(grep -o '\$ngx_addon_dir/src/[a-zA-Z0-9_/.-]*\.c' config \
                   | sed 's|\$ngx_addon_dir/||' | sort -u)

fail=0

# --- forward: tree file missing from ./config and not allowlisted -------------
missing=$(comm -23 <(echo "$tree_files") <(echo "$config_files"))
for f in $missing; do
    allowed=0
    for a in "${ALLOWLIST[@]}"; do
        [ "$f" = "$a" ] && allowed=1 && break
    done
    if [ "$allowed" -eq 0 ]; then
        echo "NOT BUILT: $f — add it to ./config, or allowlist it here with a reason" >&2
        fail=1
    fi
done

# --- allowlist hygiene: entry no longer needed (file gone or now in config) ---
for a in "${ALLOWLIST[@]}"; do
    if [ ! -f "$a" ]; then
        echo "STALE ALLOWLIST: $a no longer exists — remove it from this script" >&2
        fail=1
    elif echo "$config_files" | grep -qx "$a"; then
        echo "STALE ALLOWLIST: $a is now in ./config — remove it from this script" >&2
        fail=1
    fi
done

# --- reverse: ./config references a file that does not exist ------------------
for f in $config_files; do
    if [ ! -f "$f" ]; then
        echo "STALE CONFIG: ./config lists $f but the file does not exist" >&2
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "check_config_coverage: FAIL" >&2
    exit 1
fi
echo "check_config_coverage: OK ($(echo "$tree_files" | wc -l) sources, ${#ALLOWLIST[@]} allowlisted)"
