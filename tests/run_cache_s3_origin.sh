#!/usr/bin/env bash
#
# run_cache_s3_origin.sh — end-to-end proof of the S3 read-through cache origin
# (Phase A): a stream root:// cache fronts an S3 origin via the new sd_remote
# driver (→ shared sd_s3 → server libcurl transport, SigV4). The module's OWN S3
# server is the origin; a cache miss fills the object from it, byte-exact.
#
# One nginx process runs both: an HTTP S3 server (the origin) and a stream xrootd
# cache server. The fill worker (thread pool) makes a blocking libcurl GET to the
# local S3 listener, which the event loop serves concurrently.
#
# Usage: tests/run_cache_s3_origin.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
S3_PORT=11628
NODE_PORT=11629
AKID=AKIDTEST
SECRET=SECRETTESTKEY0123456789
PFX="$(mktemp -d /tmp/cache_s3.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX" /tmp/cache_s3_*.bin /tmp/cache_s3_*.got; }
trap cleanup EXIT

mkdir -p "$PFX/s3root" "$PFX/export" "$PFX/cache" "$PFX/logs"

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }

# The S3 origin (object store).
http {
    server {
        listen 127.0.0.1:${S3_PORT};
        location / {
            xrootd_s3            on;
            xrootd_s3_root       $PFX/s3root;
            xrootd_s3_bucket     testbucket;
            xrootd_s3_access_key ${AKID};
            xrootd_s3_secret_key ${SECRET};
            xrootd_s3_region     us-east-1;
            xrootd_s3_allow_write on;
        }
    }
}

# The root:// cache node fronting the S3 origin (TIER grammar: the S3 bucket is the
# storage_backend, its SigV4 keys carried by a named xrootd_credential, the local
# read cache is a posix cache_store).
stream {
    xrootd_credential s3origin {
        s3_access_key ${AKID};
        s3_secret_key ${SECRET};
        s3_region     us-east-1;
    }
    server {
        listen 127.0.0.1:${NODE_PORT};
        xrootd on;
        xrootd_root $PFX/export;
        xrootd_auth none;
        xrootd_storage_backend    s3://127.0.0.1:${S3_PORT}/testbucket;
        xrootd_storage_credential s3origin;
        xrootd_cache_store posix:$PFX/cache; xrootd_cache_root /;
    }
}
EOF

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/logs/start.err" || { echo "nginx start failed"; cat "$PFX/logs/start.err"; exit 2; }
sleep 1

# Seed an S3 object: the s3 server maps bucket/key -> <s3root>/key.
head -c 700000 /dev/urandom > "$PFX/s3root/hello.bin"          # < 1 MiB fill chunk

echo "== cold read: cache miss fills /hello.bin from the S3 origin =="
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /hello.bin > /tmp/cache_s3_1.got 2>"$PFX/logs/cat1.err"
if cmp -s "$PFX/s3root/hello.bin" /tmp/cache_s3_1.got; then
    ok "S3 origin fill byte-exact"
else
    bad "S3 fill DIFFERS (src=$(stat -c%s "$PFX/s3root/hello.bin") got=$(stat -c%s /tmp/cache_s3_1.got 2>/dev/null))"
    grep -iE 's3|sigv4|origin|curl|fill' "$PFX/logs/e.log" | tail -8
fi
[ -f "$PFX/cache/hello.bin" ] && ok "object landed in the local cache" || bad "no cache entry created"

echo "== warm read: served from cache, still byte-exact =="
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /hello.bin > /tmp/cache_s3_2.got 2>/dev/null
cmp -s "$PFX/s3root/hello.bin" /tmp/cache_s3_2.got && ok "warm cache hit byte-exact" || bad "warm hit DIFFERS"

echo "== multi-chunk object: fills across several Range GETs (> 1 MiB fill chunk) =="
head -c 2750000 /dev/urandom > "$PFX/s3root/big.bin"          # ~2.6 fill chunks
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /big.bin > /tmp/cache_s3_big.got 2>"$PFX/logs/catbig.err"
cmp -s "$PFX/s3root/big.bin" /tmp/cache_s3_big.got \
    && ok "multi-chunk S3 fill byte-exact (sequential Range GETs)" \
    || bad "multi-chunk fill DIFFERS (got=$(stat -c%s /tmp/cache_s3_big.got 2>/dev/null))"

echo "== missing object: origin 404 surfaces as not-found =="
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /nope.bin >/dev/null 2>"$PFX/logs/cat3.err"
grep -qiE 'not.?found|no such|3011|error' "$PFX/logs/cat3.err" && ok "missing object reported as error" || bad "missing object not reported (got: $(cat "$PFX/logs/cat3.err"))"

[ "$fail" = 0 ] && echo "run_cache_s3_origin: ALL PASS" || echo "run_cache_s3_origin: FAILURES"
exit "$fail"
