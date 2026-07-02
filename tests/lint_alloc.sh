#!/usr/bin/env bash
#
# lint_alloc.sh — Phase 27 W8: allocation/free invariant lint (heuristic).
#
# Cheap grep-based CI check that makes the *next* F1/F2-class gap visible in
# review.  It is deliberately heuristic, not sound: its job is to surface
# suspicious patterns, not to prove correctness.  Exits 0 by default (advisory);
# pass --strict to exit non-zero when any finding is reported (gate a merge).
#
# Checks:
#   1. Wire-driven `<expr> * sizeof(...)` / `malloc(... * ...)` allocations that
#      do not have an overflow-checked helper or a cap keyword within N lines.
#   2. Raw malloc/free in HTTP request handlers (src/protocols/webdav, src/protocols/s3) that should
#      use r->pool.
#   3. ngx_alloc in stream files without a matching ngx_free /
#      ngx_pool_cleanup_add in the same file (lifetime smell).
#   4. Per-file OpenSSL *_new vs *_free token-count imbalance (advisory).
#
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"
STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1
findings=0

note() { printf '%s\n' "$*"; findings=$((findings + 1)); }

# --- 1. wire-driven multiply allocations without an overflow-checked helper ---
echo "== [1] unchecked size-multiply allocations =="
grep -rnE '(malloc|ngx_alloc|ngx_palloc|realloc)\([^;]*\*[^;]*sizeof' "$SRC" \
    --include='*.c' 2>/dev/null \
  | grep -vE 'xrootd_(p?alloc|alloc)_array|xrootd_size_mul|safe_size' \
  | while IFS=: read -r file line rest; do
        # Skip if a checked-multiply helper is used within 3 lines above.
        ctx=$(sed -n "$((line>3?line-3:1)),${line}p" "$file" 2>/dev/null)
        echo "$ctx" | grep -q 'xrootd_size_mul\|xrootd_.*_array' && continue
        printf '  %s:%s  %s\n' "${file#$ROOT/}" "$line" \
            "$(echo "$rest" | sed 's/^[[:space:]]*//')"
    done

# --- 2. raw malloc/free in HTTP handlers (should use r->pool) ---
echo "== [2] raw malloc/free in HTTP handlers (prefer r->pool) =="
grep -rnE '\b(malloc|free)\s*\(' "$SRC/webdav" "$SRC/s3" --include='*.c' 2>/dev/null \
  | grep -vE 'curl_|json_|EVP_|OPENSSL_|_free_all|ngx_' \
  | while IFS=: read -r file line rest; do
        note "  ${file#$ROOT/}:$line  $(echo "$rest" | sed 's/^[[:space:]]*//')"
    done

# --- 3. ngx_alloc in stream files without a free/cleanup in the same file ---
echo "== [3] ngx_alloc without ngx_free/cleanup in same file (stream path) =="
for d in connection session cms manager handshake read write tpc; do
    for f in "$SRC/$d"/*.c; do
        [ -e "$f" ] || continue
        grep -q '\bngx_alloc\s*(' "$f" || continue
        if ! grep -qE '\bngx_free\s*\(|ngx_pool_cleanup_add' "$f"; then
            note "  ${f#$ROOT/}  (ngx_alloc with no ngx_free/cleanup in file)"
        fi
    done
done

# --- 4. OpenSSL *_new vs *_free imbalance (advisory) ---
echo "== [4] OpenSSL new/free token imbalance (advisory) =="
for f in $(grep -rlE '_new\s*\(' "$SRC/gsi" "$SRC/tpc" "$SRC/crypto" "$SRC/token" \
            "$SRC/s3" "$SRC/sss" --include='*.c' 2>/dev/null); do
    n=$(grep -oE '[A-Za-z0-9_]+_new\s*\(' "$f" | wc -l)
    fr=$(grep -oE '[A-Za-z0-9_]+_free(_all)?\s*\(' "$f" | wc -l)
    if [ "$n" -gt 0 ] && [ "$fr" -lt "$n" ]; then
        printf '  %s  new=%s free=%s\n' "${f#$ROOT/}" "$n" "$fr"
    fi
done

echo
echo "lint_alloc: $findings hard finding(s) (checks 2 & 3); checks 1 & 4 advisory."
if [ "$STRICT" = 1 ] && [ "$findings" -gt 0 ]; then
    exit 1
fi
exit 0
