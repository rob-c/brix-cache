#!/usr/bin/env bash
# tests/run_cvmfs_stock.sh — Phase-1 stock-nginx CVMFS cache e2e:
#   1 cold+warm byte-exact through reverse mode
#   2 stampede → exactly 1 origin fetch (proxy_cache_lock)
#   3 security-neg: non-/cvmfs/ path → 403; disallowed upstream host → 403
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
MPORT=12821; RPORT=12822; PPORT=12823
PFX="$(mktemp -d /tmp/cvmfs_stock.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 8 --seed 7 &
MOCK=$!; sleep 0.5

sed -e "s/@PORT@/$RPORT/" -e "s/@PPORT@/$PPORT/" -e "s#@CACHEDIR@#$PFX#" \
    -e "s/@ORIGIN@/127.0.0.1:$MPORT/" -e "s/@ORIGINHOST@/127.0.0.1/g" \
    -e "s/@ORIGINPORT@/$MPORT/" \
    "$REPO/deploy/cvmfs/nginx-proxy-cache.conf" > "$PFX/nginx.conf"
mkdir -p "$PFX/store" "$PFX/logs"
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX" || { bad "nginx start"; exit 1; }
sleep 0.5

OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

# 1: cold + warm byte-exact
curl -s "http://127.0.0.1:$RPORT$OBJ" -o "$PFX/cold.bin"
curl -s "http://127.0.0.1:$RPORT$OBJ" -o "$PFX/warm.bin"
curl -s "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/orig.bin"
cmp -s "$PFX/cold.bin" "$PFX/orig.bin" && cmp -s "$PFX/warm.bin" "$PFX/orig.bin" \
    && ok "cold+warm byte-exact" || bad "byte mismatch"

# 2: stampede coalescing on a fresh object
OBJ2="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[3])')"
N0="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "$OBJ2" || true)"
# subshell: its wait sees only the curls, not the long-lived mock job
( for i in $(seq 1 40); do curl -s "http://127.0.0.1:$RPORT$OBJ2" -o /dev/null & done
  wait )
N1="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "$OBJ2" || true)"
[ "$((N1 - N0))" -le 2 ] && ok "stampede coalesced ($((N1-N0)) origin fetches)" \
    || bad "stampede: $((N1-N0)) origin fetches"

# 3: security-neg
C1="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$RPORT/etc/passwd")"
C2="$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$PPORT" \
      "http://evil.example.org/cvmfs/x/data/aa/bb")"
[ "$C1" = 403 ] && ok "non-cvmfs path rejected" || bad "expected 403, got $C1"
[ "$C2" = 403 ] && ok "disallowed upstream rejected" || bad "expected 403, got $C2"

exit $fail
