#!/usr/bin/env bash
#
# run_s3_usermeta.sh — end-to-end proof of S3 user-defined object metadata
# (x-amz-meta-*): an anonymous S3 server stores the metadata a client sends on
# PutObject / CopyObject and echoes it back on GET/HEAD, including the
# metadata-directive REPLACE copy-self update that the sd_s3 driver's set-meta
# uses. Self-contained (own nginx on a high port), driven with python requests.
#
# Usage: tests/run_s3_usermeta.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PORT=9011
PFX="$(mktemp -d /tmp/s3_usermeta.XXXXXX)"
cleanup() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/s3root" "$PFX/logs"

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    server {
        listen 127.0.0.1:${PORT};
        location / {
            brix_s3             on;
            brix_s3_storage_backend        posix:$PFX/s3root;
            brix_s3_bucket      testbucket;
            brix_s3_allow_write on;
        }
    }
}
EOF

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/err" || { echo "s3 start failed"; cat "$PFX/err"; exit 2; }
sleep 1

PORT=$PORT python3 - <<'PY'
import os, sys, requests
base = f"http://127.0.0.1:{os.environ['PORT']}/testbucket"
fail = 0
def ok(m):  print(f"  ok   {m}")
def bad(m):
    global fail; fail = 1; print(f"  FAIL {m}")

obj  = f"{base}/obj.txt"
copy = f"{base}/copy.txt"

print("== PutObject stores x-amz-meta-*, HEAD/GET echo it ==")
r = requests.put(obj, data=b"hello world", headers={
    "x-amz-meta-foo": "bar", "x-amz-meta-Color": "Blue"}, timeout=10)
ok("PUT 200") if r.status_code == 200 else bad(f"PUT status {r.status_code}")

r = requests.head(obj, timeout=10)
(ok("HEAD echoes x-amz-meta-foo=bar") if r.headers.get("x-amz-meta-foo") == "bar"
 else bad(f"HEAD foo={r.headers.get('x-amz-meta-foo')!r}"))
# AWS lowercases metadata key names.
(ok("HEAD echoes x-amz-meta-color=Blue (key lowercased)")
 if r.headers.get("x-amz-meta-color") == "Blue"
 else bad(f"HEAD color={r.headers.get('x-amz-meta-color')!r}"))

r = requests.get(obj, timeout=10)
(ok("GET echoes the metadata and body")
 if r.headers.get("x-amz-meta-foo") == "bar" and r.content == b"hello world"
 else bad(f"GET foo={r.headers.get('x-amz-meta-foo')!r} body={r.content!r}"))

print("== CopyObject (default COPY) carries the source metadata across ==")
r = requests.put(copy, headers={"x-amz-copy-source": "/testbucket/obj.txt"}, timeout=10)
ok("COPY 200") if r.status_code == 200 else bad(f"COPY status {r.status_code}")
r = requests.head(copy, timeout=10)
(ok("copied object carries x-amz-meta-foo=bar")
 if r.headers.get("x-amz-meta-foo") == "bar"
 else bad(f"copy foo={r.headers.get('x-amz-meta-foo')!r}"))

print("== CopyObject REPLACE (copy-self) updates metadata without touching bytes ==")
r = requests.put(obj, headers={
    "x-amz-copy-source": "/testbucket/obj.txt",
    "x-amz-metadata-directive": "REPLACE",
    "x-amz-meta-foo": "baz"}, timeout=10)
ok("REPLACE copy-self 200") if r.status_code == 200 else bad(f"REPLACE status {r.status_code}")
r = requests.head(obj, timeout=10)
(ok("metadata replaced: foo=baz") if r.headers.get("x-amz-meta-foo") == "baz"
 else bad(f"after REPLACE foo={r.headers.get('x-amz-meta-foo')!r}"))
(ok("old key dropped on REPLACE: color absent")
 if r.headers.get("x-amz-meta-color") is None
 else bad(f"color still present={r.headers.get('x-amz-meta-color')!r}"))
r = requests.get(obj, timeout=10)
(ok("bytes intact after metadata-only REPLACE")
 if r.content == b"hello world" else bad(f"bytes changed={r.content!r}"))

sys.exit(fail)
PY
rc=$?
[ "$rc" = 0 ] && echo "run_s3_usermeta: ALL PASS" || echo "run_s3_usermeta: FAILURES"
exit "$rc"
