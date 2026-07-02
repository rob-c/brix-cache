#!/usr/bin/env bash
#
# run_xmeta.sh — xmeta unified-metadata record P1: codec unit tests plus the
# STOCK CROSS-CHECK: a record we encode must parse as a normal cinfo v4 in
# stock XrdPfc tooling (xrdpfc_print), proving the byte-compatible prefix.
#
# Usage: tests/run_xmeta.sh
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
UT=/tmp/xmeta_ut
SAMPLE=/tmp/xmeta_sample.cinfo
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

echo "== codec unit tests =="
gcc -Wall -Wextra -Werror -I "$HERE/src" -o "$UT" \
    "$HERE/src/fs/meta/xmeta_unittest.c" "$HERE/src/fs/meta/xmeta.c" \
    "$HERE/src/core/compat/crc32c.c" || { bad "unittest build"; exit 1; }
"$UT" "$SAMPLE" || { bad "codec unit tests"; exit 1; }
ok "codec unit tests (22 checks)"

echo "== stock cross-check (xrdpfc_print) =="
if ! command -v xrdpfc_print >/dev/null; then
    echo "  SKIP xrdpfc_print not installed"
    exit "$fail"
fi
OUT=$(xrdpfc_print -v "$SAMPLE" 2>&1)
echo "$OUT" | grep -q "version 4"            && ok "stock reads version 4"      || bad "version not read: $OUT"
echo "$OUT" | grep -q "file_size 2560 kB"    && ok "stock reads file_size"      || bad "file_size wrong"
echo "$OUT" | grep -q "buffer_size 1024 kB"  && ok "stock reads buffer_size"    || bad "buffer_size wrong"
echo "$OUT" | grep -q "n_blocks 3"           && ok "stock reads n_blocks"       || bad "n_blocks wrong"
echo "$OUT" | grep -q "n_downloaded 2"       && ok "stock reads bitmap (2 set)" || bad "bitmap wrong"
echo "$OUT" | grep -q "^0 x.x"               && ok "stock bit order matches"    || bad "bit order wrong"
echo "$OUT" | grep -qE "N_acc_total=3"       && ok "stock reads access count"   || bad "access count wrong"
rm -f "$SAMPLE" "$UT"

[ "$fail" = 0 ] && echo "run_xmeta: ALL PASS" || echo "run_xmeta: FAILURES"
exit "$fail"
