#!/usr/bin/env bash
# tests/run_cvmfs_verify.sh — CAS verify-on-fill:
#   1 corrupt origin response → NOT admitted, client gets 502, quarantine file
#   2 clean retry afterwards → fills and serves byte-exact (cache not poisoned)
#   3 security-neg: verify=off admits the corrupt object (documents the squid
#     failure mode this feature closes)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12841; CPORT=12842
PFX="$(mktemp -d /tmp/cvmfs_verify.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/quarantine" "$PFX/logs"

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 4 --seed 3 &
MOCK=$!; sleep 0.5

conf() {   # $1 = verify mode
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT;
        xrootd_cvmfs_cache_store posix:$PFX/cache;
        xrootd_cache_verify $1;
        xrootd_cvmfs on;
        xrootd_cvmfs_quarantine_dir $PFX/quarantine;
    }
} }
EOF
}

OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[1])')"

conf cvmfs-cas
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5

# 1: corrupt fill rejected
curl -s -o /dev/null -X POST -d '{"mode":"corrupt","count":1}' "http://127.0.0.1:$MPORT/ctl/fault"
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$OBJ")"
[ "$C" = 502 ] && ok "corrupt fill → 502, not admitted" || bad "corrupt fill: $C"
[ -n "$(ls -A "$PFX/quarantine")" ] && ok "corrupt part quarantined" \
    || bad "quarantine empty"

# 2: clean retry fills and matches
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/got.bin"
curl -s "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/orig.bin"
cmp -s "$PFX/got.bin" "$PFX/orig.bin" && ok "clean retry byte-exact" \
    || bad "retry mismatch"

# 3: with verify off, the same corruption IS admitted (the squid failure mode)
kill "$(cat "$PFX/nginx.pid")"; rm -rf "$PFX/cache"; mkdir -p "$PFX/cache"
conf off
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
curl -s -o /dev/null -X POST -d '{"mode":"corrupt","count":1}' "http://127.0.0.1:$MPORT/ctl/fault"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/poison1.bin"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/poison2.bin"   # warm: from cache
cmp -s "$PFX/poison1.bin" "$PFX/orig.bin" && bad "verify=off unexpectedly clean" \
    || ok "verify=off admits corruption (documented gap)"
cmp -s "$PFX/poison1.bin" "$PFX/poison2.bin" && ok "poisoned cache re-serves it" \
    || bad "warm read differs from poisoned fill"
exit $fail
