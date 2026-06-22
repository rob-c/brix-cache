#!/bin/sh
# check-ngx-free.sh — fail the build if libxrdproto contains any nginx coupling.
#
# Enforces phase-37 invariant #2: the shared protocol core is nginx-free, so the
# native clients never need nginx to link. We inspect the *built archive* (not just
# the sources) because that is what the clients actually consume: any ngx_* symbol
# — referenced (U) or defined (T/D/B/R) — means an ngx dependency crept in.
#
# Usage: check-ngx-free.sh [libxrdproto.a]
set -eu

LIB="${1:-libxrdproto.a}"

if [ ! -f "$LIB" ]; then
    echo "check-ngx-free: archive not found: $LIB" >&2
    exit 2
fi

# All symbols in all members. On Linux symbols have no leading underscore; on
# Mach-O they do — match both with the optional '_'.
matches="$(nm "$LIB" 2>/dev/null | grep -E '[[:space:]][A-Za-z][[:space:]]+_?ngx_' || true)"

if [ -n "$matches" ]; then
    echo "FAIL: libxrdproto references ngx_* symbols:" >&2
    echo "$matches" >&2
    exit 1
fi

defined="$(nm "$LIB" 2>/dev/null | grep -cE '[[:space:]]T[[:space:]]' || true)"
echo "OK: $LIB is ngx-free (${defined} defined text symbols, 0 ngx_* references)"
exit 0
