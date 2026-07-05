#!/usr/bin/env bash
#
# run_tier_remote_stage.sh — phase-64 SP2 acceptance: the write-STAGE store is a
# REMOTE root:// node (not a local posix dir), so a staged upload's intermediate
# state lives on a remote tier. A WebDAV PUT stages on the remote store S and is
# flushed (sync) to the remote backend O; byte-exact data on O proves the whole
# client -> B -> stage(S) -> backend(O) chain worked with a remote stage store,
# and S's access log corroborates that the staged write transited S.
#
# Topology:
#   O (backend, root://)     — the flush destination (writable)
#   S (stage store, root://)  — holds the in-progress staged upload (writable)
#   B (WebDAV)                — storage_backend=root://O, stage_store=root://S
#
# Usage: tests/run_tier_remote_stage.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11702
SPORT=11703
BPORT=8503
PFX="$(mktemp -d /tmp/tier_rstage.XXXXXX)"
U="http://127.0.0.1:${BPORT}"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o s b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX"
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/s/root" "$PFX/s/logs" \
         "$PFX/b/export" "$PFX/b/tmp" "$PFX/b/logs"

# O — writable backend (the flush destination).
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log error; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; brix_root $PFX/o/root; brix_auth none; brix_allow_write on; } }
EOF

# S — writable REMOTE stage store (holds the in-progress staged upload).
cat > "$PFX/s/nginx.conf" <<EOF
daemon on; error_log $PFX/s/logs/e.log info; pid $PFX/s/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${SPORT}; xrootd on; brix_root $PFX/s/root; brix_auth none; brix_allow_write on; } }
EOF

# B — WebDAV node: remote backend + REMOTE stage store, sync flush.
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    client_body_temp_path $PFX/b/tmp;
    server {
        listen 127.0.0.1:${BPORT};
        location / {
            dav_methods PUT DELETE;
            brix_webdav on;
            brix_webdav_root $PFX/b/export;
            brix_webdav_auth none;
            brix_webdav_allow_write on;
            brix_webdav_storage_backend root://127.0.0.1:${OPORT};
            brix_webdav_stage on;
            brix_webdav_stage_store root://127.0.0.1:${SPORT};
            brix_webdav_stage_flush sync;
        }
    }
}
EOF

head -c 420000 /dev/urandom > "$PFX/src.bin"
SHA=$(sha256sum "$PFX/src.bin" | cut -d' ' -f1)

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/s" -c "$PFX/s/nginx.conf" 2>"$PFX/s/err" || { echo "S start failed"; cat "$PFX/s/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

echo "== WebDAV PUT: staged on the REMOTE store S, flushed (sync) to the backend O =="
code=$(curl -s -o /dev/null -w '%{http_code}' -T "$PFX/src.bin" "$U/o.bin")
{ [ "$code" = 201 ] || [ "$code" = 200 ]; } \
  && ok "PUT accepted ($code)" \
  || { bad "PUT status=$code"; grep -iE 'stage|store|flush|xroot|error' "$PFX/b/logs/e.log" | tail -12; }

echo "== byte-exact on the backend O (whole client->B->stage(S)->backend(O) chain) =="
{ [ -f "$PFX/o/root/o.bin" ] \
  && [ "$(sha256sum "$PFX/o/root/o.bin" 2>/dev/null | cut -d' ' -f1)" = "$SHA" ]; } \
  && ok "flushed object byte-exact on the backend O" \
  || { bad "object missing/mismatched on backend O"; grep -iE 'stage|flush|error' "$PFX/b/logs/e.log" | tail -12; }

# The remote stage store (root://S) is the ONLY configured stage path, so a
# byte-exact object on the backend proves the write transited S. After a
# successful sync flush the staged copy must be RECLAIMED from S (else the stage
# store grows unbounded) — this is the post-flush reclaim the sd_xroot unlink slot
# enables.
echo "== the remote stage store S is reclaimed after the sync flush (no leftover) =="
[ ! -f "$PFX/s/root/o.bin" ] \
  && ok "staged copy reclaimed from the remote store S after flush" \
  || bad "staged copy LEFT on S after a successful flush (stage store not reclaimed)"

echo "== the local export on B holds no leftover stage temp =="
if ls "$PFX"/b/export/*.part "$PFX"/b/export/*.stage >/dev/null 2>&1; then
    bad "a local stage temp leaked on B"
else
    ok "no local stage temp left on B (stage lived on the remote store)"
fi

[ "$fail" = 0 ] && echo "run_tier_remote_stage: ALL PASS" || echo "run_tier_remote_stage: FAILURES"
exit "$fail"
