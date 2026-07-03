#!/usr/bin/env bash
#
# run_tier_remote_store.sh — phase-64 SP2 acceptance (goal G3): the cache STORE
# holds 100% of its state on a REMOTE root:// node — the object bytes AND the
# cinfo record (carried as a user.xrd.cinfo xattr on the store, meta_mode=XATTR,
# since the store has no local dir but advertises CAP_XATTR). The proof is that a
# warm hit SURVIVES A RESTART of the cache node while the ORIGIN IS DOWN: the cache
# node keeps no local state, so a byte-exact serve with a fresh cache node and an
# unreachable origin can only come from the remote store.
#
# Topology:
#   O (origin, root://)  — the source data (read-only)
#   S (store,  root://)  — the cache store: cached objects + cinfo xattrs (writable)
#   B (WebDAV cache)     — storage_backend=root://O, cache_store=root://S; NO local
#                          cache_root, so cinfo AUTO-resolves to the XATTR mode.
#
# Usage: tests/run_tier_remote_store.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11682
SPORT=11683
BPORT=8497
PFX="$(mktemp -d /tmp/tier_rstore.XXXXXX)"
U="http://127.0.0.1:${BPORT}"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

start_node() { "$NGINX" -p "$PFX/$1" -c "$PFX/$1/nginx.conf" 2>"$PFX/$1/err"; }
stop_node()  { [ -f "$PFX/$1/nginx.pid" ] && kill "$(cat "$PFX/$1/nginx.pid")" 2>/dev/null; }
cleanup() {
    for r in o s b; do stop_node "$r"; done
    rm -rf "$PFX" /tmp/trs_*.got
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/s/root" "$PFX/s/logs" \
         "$PFX/b/export" "$PFX/b/tmp" "$PFX/b/logs"

# O — read-only origin (the source of truth for a cold fill).
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; brix_root $PFX/o/root; brix_auth none; } }
EOF

# S — writable store node holding cached objects + their cinfo xattrs.
cat > "$PFX/s/nginx.conf" <<EOF
daemon on; error_log $PFX/s/logs/e.log info; pid $PFX/s/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${SPORT}; xrootd on; brix_root $PFX/s/root; brix_auth none; brix_allow_write on; } }
EOF

# B — WebDAV cache node: remote source + remote store, NO local cache_root.
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    client_body_temp_path $PFX/b/tmp;
    server {
        listen 127.0.0.1:${BPORT};
        location / {
            brix_webdav on;
            brix_webdav_root $PFX/b/export;
            brix_webdav_auth none;
            brix_webdav_storage_backend root://127.0.0.1:${OPORT};
            brix_webdav_cache_store root://127.0.0.1:${SPORT};
        }
    }
}
EOF

head -c 500000 /dev/urandom > "$PFX/o/root/small.bin"
chmod 0444 "$PFX/o/root/small.bin"   # read-only source: exercises cinfo mode fidelity

start_node o || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
start_node s || { echo "S start failed"; cat "$PFX/s/err"; exit 2; }
start_node b || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

echo "== cold GET: MISS fills from remote origin O into the remote store S =="
code=$(curl -s -o /tmp/trs_s.got -w '%{http_code}' "$U/small.bin")
[ "$code" = 200 ] && ok "cold GET 200" || { bad "cold GET status=$code"; grep -iE 'cache|xroot|store|fill|xattr|error|stall' "$PFX/b/logs/e.log" | tail -10; }
cmp -s "$PFX/o/root/small.bin" /tmp/trs_s.got \
  && ok "cold GET byte-exact (filled from remote origin, served via remote store)" \
  || bad "cold GET differs from origin"

echo "== state landed on the REMOTE store S (not locally on B) =="
[ -f "$PFX/s/root/small.bin" ] \
  && ok "object bytes stored on the remote store node S" \
  || bad "object not on S (remote fill did not persist)"
# cinfo must be a REMOTE xattr on S, not a local sidecar on B. (The kXR_fattr wire
# layer namespaces user attrs under "user.U.", so the on-disk name is
# user.U.user.xrd.cinfo — match the cinfo attribute regardless of that prefix.)
if command -v getfattr >/dev/null 2>&1; then
    getfattr -d -m '.' "$PFX/s/root/small.bin" 2>/dev/null | grep -qi 'cinfo' \
      && ok "cinfo persisted as a user.*cinfo xattr on the remote store S (XATTR mode)" \
      || bad "no cinfo xattr on S (cinfo did not go to the store)"
else
    ok "cinfo xattr check skipped (getfattr not installed)"
fi
if ls "$PFX"/b/export/*.cinfo "$PFX"/b/**/*.cinfo >/dev/null 2>&1; then
    bad "a LOCAL .cinfo sidecar exists on B (state should live on S, not locally)"
else
    ok "no local .cinfo sidecar on the cache node B"
fi

echo "== metadata fidelity: the cinfo records the origin mode (0444), not the store's =="
# The physical store object is forced owner-writable (0644) so its cinfo xattr can
# be maintained; the ORIGIN's read-only mode must be preserved in the cinfo record
# (mode field at byte offset 12, u32 LE) and served back to clients.
if command -v getfattr >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    cmode=$(python3 - "$PFX/s/root/small.bin" <<'PY'
import sys, subprocess, struct
v = subprocess.run(['getfattr','--only-values','-n','user.U.user.xrd.cinfo',sys.argv[1]],
                   capture_output=True).stdout
print(oct(struct.unpack_from('<I', v, 12)[0] & 0o777) if len(v) >= 16 else "none")
PY
)
    [ "$cmode" = "0o444" ] \
      && ok "cinfo mode field records the origin 0444 (read-only preserved in portable metadata)" \
      || bad "cinfo mode = $cmode (expected 0o444 — source mode not captured)"
else
    ok "cinfo mode-fidelity check skipped (getfattr/python3 not available)"
fi

echo "== warm GET: served from the store (no re-fill) =="
code=$(curl -s -o /tmp/trs_w.got -w '%{http_code}' "$U/small.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/small.bin" /tmp/trs_w.got; } \
  && ok "warm hit byte-exact" || bad "warm hit failed (status=$code)"

echo "== G3 PROOF: kill the origin, restart the cache node, warm hit must survive =="
stop_node o                                   # origin gone: a re-fill is now impossible
sleep 0.3
stop_node b                                   # cache node keeps NO local state
sleep 0.3
start_node b || { echo "B restart failed"; cat "$PFX/b/err"; exit 2; }
sleep 1
code=$(curl -s -o /tmp/trs_r.got -w '%{http_code}' "$U/small.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/small.bin" /tmp/trs_r.got; } \
  && ok "warm hit SURVIVES cache-node restart with the origin DOWN (state lives on S)" \
  || { bad "post-restart hit failed (status=$code) — state did not survive on the store"; \
       grep -iE 'cache|store|xattr|fill|miss|error' "$PFX/b/logs/e.log" | tail -12; }

[ "$fail" = 0 ] && echo "run_tier_remote_store: ALL PASS" || echo "run_tier_remote_store: FAILURES"
exit "$fail"
