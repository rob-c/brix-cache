#!/usr/bin/env bash
# tests/run_cvmfs_reverse.sh — module CVMFS personality e2e (built up over
# Tasks 8/9). Task-8 scope: the directives parse and merge.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PFX="$(mktemp -d /tmp/cvmfs_rev.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
MPORT=12831; CPORT=12832
mkdir -p "$PFX/cache" "$PFX/logs"

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http {
    access_log off;
    server {
        listen 127.0.0.1:$CPORT;
        location /cvmfs/ {
            xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT;
            xrootd_cvmfs_cache_store posix:$PFX/cache;
            xrootd_cvmfs on;
            xrootd_cvmfs_manifest_ttl 1;
        }
        # nginx normalizes dot-segments before location match, so a traversal
        # like /cvmfs/../etc/passwd arrives here as /etc/passwd — refuse it.
        location / { return 403; }
    }
}
EOF
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && ok "cvmfs directives parse" || bad "nginx -t rejected cvmfs config"

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 8 --seed 9 &
MOCK=$!; sleep 0.5
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5

OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

# success: cold fill + warm hit, byte-exact, second read served without origin
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/cold.bin"
N_AFTER_COLD="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF "$OBJ" | wc -l)"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/warm.bin"
N_AFTER_WARM="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF "$OBJ" | wc -l)"
curl -s "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/orig.bin"
cmp -s "$PFX/cold.bin" "$PFX/orig.bin" && cmp -s "$PFX/warm.bin" "$PFX/orig.bin" \
    && ok "cold+warm byte-exact" || bad "byte mismatch"
[ "$N_AFTER_WARM" = "$N_AFTER_COLD" ] && ok "warm hit served from cache" \
    || bad "warm read went to origin"

# stampede: exactly 1 origin fetch (module fill-lock, stricter than stock's <=2)
OBJ2="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[4])')"
( for i in $(seq 1 40); do curl -s "http://127.0.0.1:$CPORT$OBJ2" -o /dev/null & done
  wait )
N2="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF "$OBJ2" | wc -l)"
[ "$N2" = 1 ] && ok "stampede: exactly 1 origin fetch" || bad "stampede: $N2 fetches"

# manifest: cached with a 1s TTL — a bump becomes visible after expiry (T12)
curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/.cvmfspublished" -o "$PFX/m1"
curl -s "http://127.0.0.1:$MPORT/ctl/manifest/bump" >/dev/null
sleep 2
curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/.cvmfspublished" -o "$PFX/m2"
cmp -s "$PFX/m1" "$PFX/m2" && bad "manifest stale past TTL (cached forever!)" \
    || ok "expired manifest revalidated (TTL)"

# geo passthrough
G="$(curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/api/v1.0/geo/x/a,b")"
[ -n "$G" ] && ok "geo passthrough" || bad "geo empty"

# security-neg: rejects (403) for non-CVMFS shapes; 405 for writes
C1="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT/cvmfs/../etc/passwd")"
C2="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT/cvmfs/repo/random.txt")"
C3="$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data x \
      "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/.cvmfspublished")"
[ "$C1" = 403 ] && ok "traversal rejected" || bad "traversal: $C1"
[ "$C2" = 403 ] && ok "non-class path rejected" || bad "non-class: $C2"
[ "$C3" = 405 ] && ok "write method rejected" || bad "PUT: $C3"

# negative cache: 2 misses for the same bogus CAS name → 1 origin probe
# (origin existence probes are HEADs; the mock logs them at /ctl/heads)
BOGUS="/cvmfs/test.cern.ch/data/aa/$(python3 -c 'print("ab"*19)')"
CN1="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$BOGUS")"
NB1="$(curl -s "http://127.0.0.1:$MPORT/ctl/heads" | grep -oF "$BOGUS" | wc -l)"
CN2="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$BOGUS")"
NB2="$(curl -s "http://127.0.0.1:$MPORT/ctl/heads" | grep -oF "$BOGUS" | wc -l)"
[ "$CN1" = 404 ] && [ "$CN2" = 404 ] && [ "$NB1" -ge 1 ] && [ "$NB1" = "$NB2" ] \
    && ok "negative cache absorbed repeat 404" \
    || bad "negative cache: codes=$CN1/$CN2 origin-probes=$NB1→$NB2"

exit $fail
