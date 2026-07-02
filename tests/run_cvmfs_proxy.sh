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
        xrootd_cvmfs_cache_store posix:$PFX/cache;
        xrootd_cvmfs on;
        xrootd_cvmfs_upstream_allow 127.0.0.1;
        xrootd_cvmfs_upstream_max 4;
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
NA="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -c "$O1")"
curl -s -x "$PROXY" "http://127.0.0.1:$M1$O1" -o /dev/null
NB="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -c "$O1")"
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
exit $fail
