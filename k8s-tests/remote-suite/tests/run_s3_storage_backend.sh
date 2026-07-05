#!/usr/bin/env bash
# run_s3_storage_backend.sh — phase-63: an S3 export backed by a COMPOSABLE source
# backend (brix_s3_storage_backend). S3 GetObject goes through brix_vfs_open, so
# with a remote root:// source the object is served from the origin via sd_xroot —
# the same composable stack the stream/WebDAV exports use, now reaching S3. Also
# proves the §14 credential at S3 scope against a token-auth origin.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OPORT=11702; SPORT=9013; TPORT=11703; CPORT=9014; PFX="$(mktemp -d /tmp/s3_be.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o s t c; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/s/root" "$PFX/s/logs" "$PFX/t/root" "$PFX/t/logs" "$PFX/c/root" "$PFX/c/logs"

# --- anonymous root:// origin O + an S3 export S backed by it ---
head -c 400000 /dev/urandom > "$PFX/o/root/obj.bin"
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; brix_root $PFX/o/root; brix_auth none; } }
EOF
cat > "$PFX/s/nginx.conf" <<EOF
daemon on; error_log $PFX/s/logs/e.log info; pid $PFX/s/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { server { listen 127.0.0.1:${SPORT}; location / {
    brix_s3 on; brix_s3_root $PFX/s/root; brix_s3_bucket testbucket;
    brix_s3_storage_backend root://127.0.0.1:${OPORT};
    brix_s3_cache_root $PFX/s/cache;
} } }
EOF
mkdir -p "$PFX/s/cache"

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/s" -c "$PFX/s/nginx.conf" 2>"$PFX/s/err" || { echo "S start failed"; cat "$PFX/s/err"; exit 2; }
sleep 1

echo "== S3 GetObject served from the remote root:// backend (sd_xroot via VFS) =="
SPORT=$SPORT PFX="$PFX" python3 - <<'PY'
import os, requests, sys
sp, pfx = os.environ['SPORT'], os.environ['PFX']
fail = 0
try:
    r = requests.get(f"http://127.0.0.1:{sp}/testbucket/obj.bin", timeout=30)
    body = open(f"{pfx}/o/root/obj.bin","rb").read()
    if r.status_code == 200 and r.content == body:
        print("  ok   GET byte-exact from the composable backend")
    else:
        fail = 1; print(f"  FAIL GET status={r.status_code} len={len(r.content)} want={len(body)}")
except Exception as e:
    fail = 1; print(f"  FAIL GET raised {e!r}")
sys.exit(fail)
PY
[ $? -eq 0 ] || { fail=1; grep -iE 's3|backend|xroot|vfs|origin|error' "$PFX/s/logs/e.log" | tail -8; }

# --- token-auth origin T + S3 export C with the §14 credential ---
if python3 "$HERE/utils/make_token.py" init "$PFX/tok" >/dev/null 2>&1 \
   && python3 "$HERE/utils/make_token.py" gen --scope "storage.read:/ storage.modify:/" \
        --output "$PFX/token.jwt" "$PFX/tok" >/dev/null 2>&1; then
    head -c 200000 /dev/urandom > "$PFX/t/root/sec.bin"
    cat > "$PFX/t/nginx.conf" <<EOF
daemon on; error_log $PFX/t/logs/e.log info; pid $PFX/t/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${TPORT}; xrootd on; brix_root $PFX/t/root;
    brix_auth token; brix_token_jwks $PFX/tok/jwks.json;
    brix_token_issuer https://test.example.com; brix_token_audience nginx-xrootd; } }
EOF
    cat > "$PFX/c/nginx.conf" <<EOF
daemon on; error_log $PFX/c/logs/e.log info; pid $PFX/c/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    brix_credential origin { token_file $PFX/token.jwt; }
    server { listen 127.0.0.1:${CPORT}; location / {
        brix_s3 on; brix_s3_root $PFX/c/root; brix_s3_bucket testbucket;
        brix_s3_storage_backend    root://127.0.0.1:${TPORT};
        brix_s3_storage_credential origin;
        brix_s3_cache_root $PFX/c/cache;
    } }
}
EOF
    mkdir -p "$PFX/c/cache"
    "$NGINX" -p "$PFX/t" -c "$PFX/t/nginx.conf" 2>"$PFX/t/err" || { echo "T start failed"; cat "$PFX/t/err"; }
    "$NGINX" -p "$PFX/c" -c "$PFX/c/nginx.conf" 2>"$PFX/c/err" || { echo "C start failed"; cat "$PFX/c/err"; }
    sleep 1
    echo "== S3 GetObject over a TOKEN-AUTH origin via the §14 S3-scope credential =="
    code=$(curl -s -o "$PFX/sec.got" -w '%{http_code}' "http://127.0.0.1:${CPORT}/testbucket/sec.bin")
    if [ "$code" = 200 ] && cmp -s "$PFX/t/root/sec.bin" "$PFX/sec.got"; then
        ok "GET byte-exact (ztn-authenticated S3 source)"
    else
        bad "authenticated S3 GET failed (code=$code)"; grep -iE 'ztn|token|auth|backend|error' "$PFX/c/logs/e.log" | tail -6
    fi
else
    echo "  (skip token-auth S3 variant: make_token unavailable)"
fi

[ "$fail" = 0 ] && echo "run_s3_storage_backend: ALL PASS" || echo "run_s3_storage_backend: FAILURES"
exit "$fail"
