#!/usr/bin/env bash
#
# WHAT: Verify every storage driver declared in the fs_list.h registry actually
#       ships a conforming brix_sd_driver_t, and emit a driver x vtable-op
#       coverage matrix so a reviewer can see at a glance which backends
#       implement which operations (and diff drivers concern-by-concern).
#
# WHY:  The SD backends (fs/backend/*/sd_*.c) are a structurally-parallel cluster
#       — 10+ files, ~900-1500 LOC each, all implementing the same vtable.
#       Reviewing "did this new/changed driver wire up the registry correctly and
#       implement the ops it claims?" was an eyeball exercise across the whole
#       cluster.  This turns it red/green:
#         - fs_list.h row  ->  brix_sd_<sym>_driver struct MUST exist
#         - the struct's .name MUST match the registry name (INVARIANT #8:
#           low-cardinality, stable backend names)
#         - a registered driver MUST implement at least one data op (.open or
#           .stat) — a driver that wires up nothing is a bug
#       The coverage matrix is informational (printed always); the gates fail CI.
#
# HOW:  Parse BRIX_FS_DRIVER_LIST_* rows from fs_list.h for (sym, name); for each,
#       locate `brix_sd_<sym>_driver = {` in fs/backend/<dir>/sd_<sym>.c and scan
#       its initializer for `.<slot> =` assignments.  No compiler needed.
#
# USAGE: tools/ci/check_sd_driver_conformance.sh
#
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
FS_LIST="$ROOT/src/core/types/fs_list.h"
BACKEND="$ROOT/src/fs/backend"

# Use GNU grep explicitly: some dev shells alias `grep` to ugrep, which mishandles
# the recursive + brace patterns below.  /usr/bin/grep is GNU in CI and locally.
GREP="grep"; [ -x /usr/bin/grep ] && GREP="/usr/bin/grep"

# vtable ops shown in the matrix (a representative, high-signal subset of the 31).
MATRIX_OPS="init open close pread preadv pwrite copy_range read_sendfile_fd fstat stat opendir readdir getxattr setxattr staged_open staged_commit recall"

# Rows: "SYM sym name" from every X(SYM, sym, "name", KIND) in the driver lists.
rows="$("$GREP" -oE 'X\([A-Z0-9_]+, *[a-z0-9_]+, *"[a-z0-9_]+", *(BACKEND|ORIGIN|DECORATOR|NEARLINE)\)' "$FS_LIST" \
        | sed -E 's/X\(([A-Z0-9_]+), *([a-z0-9_]+), *"([a-z0-9_]+)".*/\2 \3/')"

[ -n "$rows" ] || { echo "check_sd_driver_conformance: FAIL — no driver rows parsed from $FS_LIST" >&2; exit 1; }

fail=0
printf '%-11s %-10s %-6s' "driver" "name" "#ops"
for op in $MATRIX_OPS; do printf ' %s' "$(printf '%.3s' "$op")"; done
printf '\n'

while read -r sym name; do
    [ -n "$sym" ] || continue
    file="$("$GREP" -rlE "brix_sd_${sym}_driver[[:space:]]*=[[:space:]]*\{" "$BACKEND" --include='*.c' 2>/dev/null | head -1)"
    if [ -z "$file" ]; then
        echo "FAIL driver '$sym' (name=$name): registered in fs_list.h but no brix_sd_${sym}_driver struct defined"
        fail=1
        continue
    fi
    # Initializer block: from the `= {` line to the closing `};`.
    block="$(awk "/brix_sd_${sym}_driver[[:space:]]*=[[:space:]]*\{/{f=1} f{print} f&&/^\};/{exit}" "$file")"
    slots="$(printf '%s\n' "$block" | "$GREP" -oE '\.[a-z_]+[[:space:]]*=' | tr -d ' =.' | sort -u)"
    nops="$(printf '%s\n' "$slots" | "$GREP" -cE '.' || true)"
    # .name must be set and match the registry name.
    name_val="$(printf '%s\n' "$block" | "$GREP" -oE '\.name[[:space:]]*=[[:space:]]*"[^"]*"' | "$GREP" -oE '"[^"]*"' | tr -d '"' | head -1)"
    namestat="ok"
    if [ -z "$name_val" ]; then namestat="NO-NAME"; fail=1
    elif [ "$name_val" != "$name" ]; then namestat="!=${name_val}"; fail=1
    fi
    # A registered driver must implement at least one data operation (namespace
    # ops open/stat OR raw-fd ops for a namespace-less block device OR a staged
    # decorator).  A struct that wires up nothing is a bug.
    if ! printf '%s\n' "$slots" | "$GREP" -qxE 'open|stat|pread|preadv|pwrite|fstat|opendir|staged_open|recall'; then
        echo "FAIL driver '$sym': implements no data/namespace op (dead driver struct)"
        fail=1
    fi
    printf '%-11s %-10s %-6s' "$sym" "$namestat" "$nops"
    for op in $MATRIX_OPS; do
        if printf '%s\n' "$slots" | "$GREP" -qxF "$op"; then printf ' %3s' " x"; else printf ' %3s' " ."; fi
    done
    printf '\n'
done <<< "$rows"

echo
if [ "$fail" -eq 0 ]; then
    echo "check_sd_driver_conformance: OK (every registered driver has a matching struct + a data op)"
else
    echo "check_sd_driver_conformance: FAILED — see lines above" >&2
    exit 1
fi
