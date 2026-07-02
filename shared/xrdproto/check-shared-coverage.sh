#!/bin/sh
#
# check-shared-coverage.sh — guard against pure logic being stranded in the module.
#
# WHAT: Every ngx-free (no `ngx_` token) source file under src/core/compat/ must be
#       EITHER compiled into libxrdproto.a (so the native client shares it) OR
#       listed in the allowlist below with a one-line reason.  A new pure helper
#       that is neither fails this check.
# WHY:  shared/xrdproto is the single source of truth for raw protocol logic.
#       Without this guard, the next dependency-free helper silently lands only in
#       the module and the client re-implements it (the exact drift that produced
#       the old fragile JSON parser).  This makes "share it or justify not sharing
#       it" a required, reviewed decision instead of an accident.
# HOW:  For each ngx-free src/core/compat/*.c, pass iff its object is in the archive
#       (ar t) or its basename is allowlisted.  Run from `make check`.
#
# Usage: check-shared-coverage.sh [path/to/libxrdproto.a]
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
compat="$repo/src/core/compat"
lib="${1:-$here/libxrdproto.a}"

# Pure (ngx-free) compat files that are INTENTIONALLY module-only.  Keep this list
# short and justified — adding to it is a deliberate, reviewable decision.
#   etag — server emits ETag response headers; no native-client consumer.
#   time — server emits ISO8601; no consumer, and the filename shadows the system
#          <time.h> when src/core/compat is on the include path in a standalone build.
#   xml  — server-side WebDAV/SRR XML generation (libxml2); the client only parses.
#   path — depends on src/fs/path/beneath.h (ngx-coupled); not standalone-extractable.
allowlist="etag time xml path"

if [ ! -f "$lib" ]; then
    echo "check-shared-coverage: archive not found: $lib" >&2
    exit 2
fi

archive_objs="$(ar t "$lib" 2>/dev/null || true)"

in_archive() { printf '%s\n' "$archive_objs" | grep -qx "$1.o"; }
allowlisted() {
    for x in $allowlist; do
        [ "$x" = "$1" ] && return 0
    done
    return 1
}

fail=0
for f in "$compat"/*.c; do
    base="$(basename "$f" .c)"

    # Only consider files that COULD be shared: no ngx_ token anywhere.
    if grep -q 'ngx_' "$f"; then
        continue
    fi
    if in_archive "$base"; then
        continue
    fi
    if allowlisted "$base"; then
        continue
    fi

    echo "STRANDED: src/core/compat/$base.c is ngx-free but neither in $(basename "$lib") nor allowlisted."
    echo "  -> add '$base' to NAMES in shared/xrdproto/Makefile (share it with the client),"
    echo "     or add '$base' to the allowlist in check-shared-coverage.sh with a one-line reason."
    fail=1
done

if [ "$fail" -eq 0 ]; then
    echo "OK: every ngx-free src/core/compat/*.c is shared in $(basename "$lib") or explicitly allowlisted."
fi
exit "$fail"
