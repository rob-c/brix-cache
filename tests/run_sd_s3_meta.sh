#!/usr/bin/env bash
#
# run_sd_s3_meta.sh — end-to-end proof of the shared sd_s3 driver's object
# metadata surface (get_meta / set_meta / advisory unix-attr) against a live S3
# endpoint (the module's own anonymous S3 server). Seeds an object carrying
# x-amz-meta-foo: bar, then drives the C smoke harness (client/bin/sd_s3_meta_smoke)
# which reads it, replaces it via copy-self REPLACE, and round-trips the advisory
# POSIX-attr blob — closing the loop server (usermeta.c) ↔ driver (sd_s3.c).
#
# Usage: tests/run_sd_s3_meta.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SMOKE="$HERE/client/bin/sd_s3_meta_smoke"
PORT=9012
PFX="$(mktemp -d /tmp/sd_s3_meta.XXXXXX)"
cleanup() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/s3root" "$PFX/logs"

if [ ! -x "$SMOKE" ]; then
    echo "building sd_s3_meta_smoke..."
    ( cd "$HERE/client" && make sd-s3-meta-smoke ) >/dev/null 2>&1 \
        || { echo "harness build failed — run: (cd client && make sd-s3-meta-smoke)"; exit 2; }
fi

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    server {
        listen 127.0.0.1:${PORT};
        location / {
            xrootd_s3             on;
            xrootd_s3_root        $PFX/s3root;
            xrootd_s3_bucket      testbucket;
            xrootd_s3_allow_write on;
        }
    }
}
EOF

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/err" || { echo "s3 start failed"; cat "$PFX/err"; exit 2; }
sleep 1

# Seed the object with user metadata the driver will read back.
PORT=$PORT python3 - <<'PY'
import os, requests
base = f"http://127.0.0.1:{os.environ['PORT']}/testbucket"
r = requests.put(f"{base}/obj.txt", data=b"payload",
                 headers={"x-amz-meta-foo": "bar"}, timeout=10)
assert r.status_code == 200, f"seed PUT failed: {r.status_code}"
PY

"$SMOKE" 127.0.0.1 "$PORT" /testbucket/obj.txt
rc=$?
[ "$rc" = 0 ] && echo "run_sd_s3_meta: ALL PASS" || echo "run_sd_s3_meta: FAILURES"
exit "$rc"
