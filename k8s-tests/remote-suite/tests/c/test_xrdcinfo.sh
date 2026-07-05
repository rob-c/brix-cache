#!/usr/bin/env bash
# test_xrdcinfo.sh — unit check for client/bin/xrdcinfo: craft .cinfo records
# (v3 header + trailing present-bitmap) with python, then assert the JSON dump.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
XRDCINFO="$REPO/client/bin/xrdcinfo"
TMP="$(mktemp -d)"; fail=0
trap 'rm -rf "$TMP"' EXIT
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
[ -x "$XRDCINFO" ] || { echo "xrdcinfo not built: $XRDCINFO"; exit 2; }

# Craft a v3 cinfo: magic XCI1, version 3, flags PARTIAL(2), block_size 65536,
# size 300000, nblocks 5, bitmap = 1 byte with bits 1 and 2 set (0b00000110 = 6).
python3 - "$TMP/p.cinfo" <<'PY'
import struct, sys
hdr = struct.pack("<IHHIIQQQ", 0x58434931, 3, 0x2, 65536, 0, 300000, 0, 5)
# pad past the fixed low-offset region the tool reads (nblocks ends at 40);
# the tool locates the bitmap as the trailing ceil(nblocks/8) bytes, so append
# arbitrary middle bytes then the 1-byte bitmap 0b00000110.
open(sys.argv[1], "wb").write(hdr + b"\x00"*64 + bytes([0b00000110]))
PY
out="$($XRDCINFO "$TMP/p.cinfo")"
echo "$out" | grep -q '"flags":\["PARTIAL"\]' && ok "PARTIAL flag" || bad "flags ($out)"
echo "$out" | grep -q '"present_blocks":\[1,2\]' && ok "present_blocks [1,2]" || bad "blocks ($out)"
echo "$out" | grep -q '"complete":false' && ok "not complete" || bad "complete ($out)"

# COMPLETE record: flags 1, nblocks 3, bitmap 0b00000111 = all 3 present.
python3 - "$TMP/c.cinfo" <<'PY'
import struct, sys
hdr = struct.pack("<IHHIIQQQ", 0x58434931, 3, 0x1, 65536, 0, 150000, 0, 3)
open(sys.argv[1], "wb").write(hdr + b"\x00"*64 + bytes([0b00000111]))
PY
out="$($XRDCINFO "$TMP/c.cinfo")"
echo "$out" | grep -q '"complete":true' && ok "complete" || bad "complete ($out)"
echo "$out" | grep -q '"present_count":3' && ok "count 3" || bad "count ($out)"

# absent
$XRDCINFO "$TMP/nope.cinfo" | grep -q '"absent":true' && ok "absent json" || bad "absent"
[ "$fail" = 0 ] && echo "test_xrdcinfo: ALL PASS" || echo "test_xrdcinfo: FAIL"
exit "$fail"
