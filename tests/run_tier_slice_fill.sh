#!/usr/bin/env bash
#
# run_tier_slice_fill.sh — phase-64 §6.5 slice/partial fill: with a non-zero
# cache_slice_size, a cache MISS fills only the BLOCKS a read touches (not the
# whole object). A small Range GET of a large file therefore leaves the cache
# store object SPARSE — its allocated (on-disk) size is a few blocks, far below
# the logical file size — and the returned bytes are exact. A second read of a
# different range fills more blocks; a full read completes the object.
#
# Topology: origin O (root://) → WebDAV cache node B with a LOCAL posix cache
# store and xrootd_webdav_cache_slice_size set.
#
# Usage: tests/run_tier_slice_fill.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11712
BPORT=8507
PFX="$(mktemp -d /tmp/tier_slice.XXXXXX)"
U="http://127.0.0.1:${BPORT}"
BLK=65536            # 64 KiB slice blocks
SIZE=4194304         # 4 MiB origin file (64 blocks)
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/slice_*.got
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/cache" "$PFX/b/tmp" "$PFX/b/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log error; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; xrootd_root $PFX/o/root; xrootd_auth none; } }
EOF

cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    client_body_temp_path $PFX/b/tmp;
    server {
        listen 127.0.0.1:${BPORT};
        location / {
            xrootd_webdav on;
            xrootd_webdav_root $PFX/b/export;
            xrootd_webdav_auth none;
            xrootd_webdav_storage_backend root://127.0.0.1:${OPORT};
            xrootd_webdav_cache_store posix:$PFX/b/cache;
            xrootd_webdav_cache_slice_size ${BLK};
        }
    }
}
EOF

head -c "$SIZE" /dev/urandom > "$PFX/o/root/big.bin"
chmod 0444 "$PFX/o/root/big.bin"   # read-only source: exercises partial-cinfo mode fidelity

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

alloc_kb() { du -k "$1" 2>/dev/null | cut -f1; }

# The strongest single-block proof: a FRESH cache, one Range GET of a MIDDLE block.
# Only that block must be filled → the cache object is sparse (~1 block allocated).
echo "== fresh Range GET of a middle block: fills ONLY that block (sparse object) =="
MID=$((SIZE / 2))                       # block 32 of 64
code=$(curl -s -o /tmp/slice_a.got -w '%{http_code}' -r ${MID}-$((MID + BLK - 1)) "$U/big.bin")
{ [ "$code" = 206 ] || [ "$code" = 200 ]; } && ok "range GET ($code)" || { bad "range GET status=$code"; grep -iE 'slice|partial|cache|error' "$PFX/b/logs/e.log" | tail -8; }
dd if="$PFX/o/root/big.bin" bs=1 skip="$MID" count="$BLK" of=/tmp/slice_exp 2>/dev/null
cmp -s /tmp/slice_a.got /tmp/slice_exp && ok "middle-block bytes exact" || bad "middle-block bytes differ"

if [ -f "$PFX/b/cache/big.bin" ]; then
    a=$(alloc_kb "$PFX/b/cache/big.bin"); logical_kb=$((SIZE / 1024))
    ok "cache object present ($PFX/b/cache/big.bin)"
    # Allocated size should be a small number of blocks, NOT the whole 4 MiB.
    [ -n "$a" ] && [ "$a" -lt $((logical_kb / 4)) ] \
      && ok "cache object is SPARSE after 1 middle-block read (${a} KiB allocated ≪ ${logical_kb} KiB logical)" \
      || bad "cache object not sparse (${a} KiB allocated of ${logical_kb} KiB — whole-file filled, not sliced)"
else
    bad "no cache object created for the slice fill"
fi

# Re-opening the PARTIAL object for a NEW range must add ONLY that block (the
# object stays sparse across re-opens) — it must not fall back to a whole-file fill.
echo "== second range on the re-opened partial object adds just one block =="
a1=$(alloc_kb "$PFX/b/cache/big.bin")
code=$(curl -s -o /tmp/slice_b.got -w '%{http_code}' -r 0-$((BLK - 1)) "$U/big.bin")
dd if="$PFX/o/root/big.bin" bs=1 skip=0 count="$BLK" of=/tmp/slice_exp2 2>/dev/null
cmp -s /tmp/slice_b.got /tmp/slice_exp2 && ok "first-block bytes exact" || bad "first-block bytes differ"
a2=$(alloc_kb "$PFX/b/cache/big.bin")
{ [ -n "$a1" ] && [ -n "$a2" ] && [ "$a2" -le $((a1 + BLK / 1024 + 8)) ]; } \
  && ok "re-open added ~1 block (${a1}→${a2} KiB) — sparse preserved across re-opens" \
  || bad "re-open over-filled (${a1}→${a2} KiB — fell back to whole-file fill)"

echo "== full GET completes the object, byte-exact =="
code=$(curl -s -o /tmp/slice_full.got -w '%{http_code}' "$U/big.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/big.bin" /tmp/slice_full.got; } \
  && ok "full GET byte-exact (all blocks filled)" || bad "full GET failed (status=$code)"

echo "== partial-cinfo mode fidelity: the partial cinfo records the origin 0444 =="
# The physical partial object is forced owner-writable (0644) for incremental
# re-open; the ORIGIN's read-only mode must still be recorded in the partial cinfo
# (mode field at byte offset 12, u32 LE) so it can be served back.
if command -v python3 >/dev/null 2>&1; then
    pmode=$(python3 - "$PFX/b/cache/big.bin.cinfo" <<'PY'
import sys, struct
try:
    d = open(sys.argv[1], 'rb').read()
    print(oct(struct.unpack_from('<I', d, 12)[0] & 0o777) if len(d) >= 16 else "none")
except Exception:
    print("none")
PY
)
    [ "$pmode" = "0o444" ] \
      && ok "partial cinfo mode field records the origin 0444" \
      || bad "partial cinfo mode = $pmode (expected 0o444 — mode not recorded on the partial path)"
else
    ok "partial-cinfo mode check skipped (python3 not available)"
fi

[ "$fail" = 0 ] && echo "run_tier_slice_fill: ALL PASS" || echo "run_tier_slice_fill: FAILURES"
exit "$fail"
