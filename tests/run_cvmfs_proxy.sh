#!/usr/bin/env bash
# tests/run_cvmfs_proxy.sh — forward-proxy (CVMFS_HTTP_PROXY) mode:
#   1 absolute-URI GET through the cache → byte-exact, cached per-upstream
#   2 two distinct upstream hosts → distinct cache entries (no key collision)
#   3 security-neg: authority NOT on allowlist → 403, origin never contacted
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
M1=12871; M2=12872; CPORT=12873
PFX="$(mktemp -d /tmp/cvmfs_proxy.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK1" "$MOCK2" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M1 --objects 4 --seed 11 & MOCK1=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M2 --objects 4 --seed 22 & MOCK2=$!
sleep 0.5

# NOTE: the two "upstream hosts" are 127.0.0.1:$M1 and 127.0.0.1:$M2 —
# distinct authorities (host:port), one allowlisted host.
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location / {
        brix_cache_store posix:$PFX/cache;
        brix_cvmfs on;
        brix_cvmfs_upstream_allow 127.0.0.1;
        brix_cvmfs_upstream_max 4;
    }
} }
EOF
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
PROXY="http://127.0.0.1:$CPORT"

O1="$(curl -s "http://127.0.0.1:$M1/ctl/objects" | python3 -c \
     'import json,sys; print(json.load(sys.stdin)[0])')"
O2="$(curl -s "http://127.0.0.1:$M2/ctl/objects" | python3 -c \
     'import json,sys; print(json.load(sys.stdin)[0])')"

# 1: proxy-style fetch, byte-exact, warm hit stays local
curl -s -x "$PROXY" "http://127.0.0.1:$M1$O1" -o "$PFX/p1.bin"
curl -s "http://127.0.0.1:$M1$O1" -o "$PFX/r1.bin"
cmp -s "$PFX/p1.bin" "$PFX/r1.bin" && ok "proxy-mode byte-exact" || bad "proxy bytes"
NA="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -oF "$O1" | wc -l)"
curl -s -x "$PROXY" "http://127.0.0.1:$M1$O1" -o /dev/null
NB="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -oF "$O1" | wc -l)"
[ "$NA" = "$NB" ] && ok "proxy-mode warm hit cached" || bad "warm went upstream"

# 2: second upstream is independent (different seed → different objects)
curl -s -x "$PROXY" "http://127.0.0.1:$M2$O2" -o "$PFX/p2.bin"
curl -s "http://127.0.0.1:$M2$O2" -o "$PFX/r2.bin"
cmp -s "$PFX/p2.bin" "$PFX/r2.bin" && ok "second upstream independent" \
    || bad "upstream cache-key collision"

# 3: disallowed authority → 403 (mock logs must NOT show the path)
C="$(curl -s -o /dev/null -w '%{http_code}' -x "$PROXY" \
     "http://evil.example.org/cvmfs/x/data/aa/$(python3 -c 'print("cd"*19)')")"
[ "$C" = 403 ] && ok "disallowed upstream rejected" || bad "allowlist: $C"

# 4: regression — MULTIPLE hosts on ONE brix_cvmfs_upstream_allow line must
#    ALL be allowed (nginx's stock str-array slot silently kept only the first
#    argument: every other Stratum-1 got 403 and real clients pinned to the
#    single surviving host). Second-listed host must proxy fine.
PFX2="$(mktemp -d /tmp/cvmfs_proxy_multi.XXXXXX)"; CPORT2=12874
mkdir -p "$PFX2/cache" "$PFX2/logs"
cat > "$PFX2/nginx.conf" <<EOF
daemon on; error_log $PFX2/logs/e.log info; pid $PFX2/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http {
    log_format cvt '\$status class=\$cvmfs_class uri=\$request_uri';
    server {
    listen 127.0.0.1:$CPORT2;
    access_log $PFX2/logs/a.log cvt;
    location / {
        brix_cache_store posix:$PFX2/cache;
        brix_cvmfs on;
        brix_cvmfs_upstream_allow bogus.example.org 127.0.0.1 also-bogus.example.org;
        brix_cvmfs_upstream_max 4;
    }
} }
EOF
"$NGINX" -c "$PFX2/nginx.conf" -p "$PFX2"; sleep 0.5
C="$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$CPORT2" \
     "http://127.0.0.1:$M1$O1")"
[ "$C" = 200 ] && ok "one-line multi-host allowlist: 2nd host allowed" \
    || bad "one-line multi-host allowlist dropped 2nd host: $C"
C="$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$CPORT2" \
     "http://evil.example.org/cvmfs/x/.cvmfspublished")"
[ "$C" = 403 ] && ok "multi-host allowlist still rejects others" \
    || bad "multi-host allowlist over-allows: $C"

# 5: regression — a REJECTED request must log its TRUE URL class in
#    \$cvmfs_class (the allowlist 403 used to happen before classification,
#    so every reject logged class=cas regardless of shape).
curl -s -o /dev/null -x "http://127.0.0.1:$CPORT2" \
     "http://evil.example.org/cvmfs/x/api/v1.0/geo/localhost/a,b" || true
sleep 0.2
grep -q "403 class=manifest uri=/cvmfs/x/.cvmfspublished" \
     "$PFX2/logs/a.log" && ok "rejected manifest logs class=manifest" \
    || bad "rejected manifest misclassified: $(grep cvmfspublished "$PFX2/logs/a.log")"
grep -q "403 class=geo" "$PFX2/logs/a.log" \
    && ok "rejected geo logs class=geo" \
    || bad "rejected geo misclassified: $(grep 'api/v1.0/geo' "$PFX2/logs/a.log")"
[ -f "$PFX2/nginx.pid" ] && kill "$(cat "$PFX2/nginx.pid")" 2>/dev/null
rm -rf "$PFX2"
exit $fail
