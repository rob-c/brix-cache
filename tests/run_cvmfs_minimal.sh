#!/usr/bin/env bash
# tests/run_cvmfs_minimal.sh — the 3-line-config headline promise.
#
# A cvmfs cache node whose location block carries ONLY the three unified
# directives:
#
#     brix_cvmfs on;
#     brix_cache_store  posix:<dir>;
#     brix_storage_backend http://<origin>;
#
# No verify directive, no quarantine dir, no manifest TTL, nothing else. This
# proves the unified grammar's defaults do the right thing out of the box:
#   1 (success)      a CAS object round-trips byte-exact AND lands in the store;
#   2 (security-neg) a corrupt origin object is REJECTED (cvmfs-cas verify is the
#                    built-in default — the operator wrote no verify directive)
#                    and never poisons the cache;
#   3 (error)        an unknown CAS name returns 404 and the negative result is
#                    cached (a repeat miss does NOT re-probe the origin).
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12871; CPORT=12872
PFX="$(mktemp -d /tmp/cvmfs_min.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 6 --seed 7 &
MOCK=$!; sleep 0.5

# The whole config: the location block is EXACTLY the three unified directives.
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        brix_cvmfs on;
        brix_cache_store posix:$PFX/cache;
        brix_storage_backend http://127.0.0.1:$MPORT;
    }
} }
EOF
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && ok "3-directive cvmfs config parses" || bad "nginx -t rejected 3-line config"
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5

OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[1])')"

# 1 success: cold fill byte-exact + the object materialises in the posix store.
N_STORE0="$(find "$PFX/cache" -type f | wc -l)"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/got.bin"
curl -s "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/orig.bin"
cmp -s "$PFX/got.bin" "$PFX/orig.bin" && ok "cold fill byte-exact" || bad "byte mismatch"
N_STORE1="$(find "$PFX/cache" -type f | wc -l)"
[ "$N_STORE1" -gt "$N_STORE0" ] && ok "object landed in the posix cache store" \
    || bad "cache store still empty after fill ($N_STORE0->$N_STORE1)"

# warm hit: second read served from the store (no extra origin fetch).
NB_COLD="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF "$OBJ" | wc -l)"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o /dev/null
NB_WARM="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF "$OBJ" | wc -l)"
[ "$NB_WARM" = "$NB_COLD" ] && ok "warm read served from store (no origin refetch)" \
    || bad "warm read went back to origin ($NB_COLD->$NB_WARM)"

# 2 security-neg: a PERSISTENTLY corrupt origin object must be rejected by the
# built-in cvmfs-cas verify (no verify directive present) → 502, and must NOT
# poison the store. A fresh object is used so verify runs on the fill.
OBJ2="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[3])')"
curl -s -o /dev/null -X POST -d '{"mode":"corrupt","count":8}' "http://127.0.0.1:$MPORT/ctl/fault"
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$OBJ2")"
[ "$C" = 502 ] && ok "default verify rejects corrupt fill (502)" \
    || bad "corrupt fill admitted ($C) — cvmfs-cas is not the default"
curl -s -o /dev/null -X POST -d '{"mode":"none","count":0}' "http://127.0.0.1:$MPORT/ctl/fault"
# clean retry now fills and matches — proving the corrupt attempt left no poison.
curl -s "http://127.0.0.1:$CPORT$OBJ2" -o "$PFX/got2.bin"
curl -s "http://127.0.0.1:$MPORT$OBJ2" -o "$PFX/orig2.bin"
cmp -s "$PFX/got2.bin" "$PFX/orig2.bin" && ok "clean retry byte-exact (cache not poisoned)" \
    || bad "post-corruption retry mismatch (cache poisoned)"

# 3 error: an unknown CAS name → 404, and the negative result is cached — a
# repeat miss must NOT re-probe the origin (origin existence probes are HEADs).
BOGUS="/cvmfs/test.cern.ch/data/aa/$(python3 -c 'print("cd"*19)')"
CN1="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$BOGUS")"
NH1="$(curl -s "http://127.0.0.1:$MPORT/ctl/heads" | grep -oF "$BOGUS" | wc -l)"
CN2="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$BOGUS")"
NH2="$(curl -s "http://127.0.0.1:$MPORT/ctl/heads" | grep -oF "$BOGUS" | wc -l)"
[ "$CN1" = 404 ] && [ "$CN2" = 404 ] && ok "unknown CAS name → 404 (both misses)" \
    || bad "unknown name codes=$CN1/$CN2 (expected 404/404)"
[ "$NH1" -ge 1 ] && [ "$NH1" = "$NH2" ] \
    && ok "negative result cached (repeat 404 did not re-probe origin)" \
    || bad "negative cache leaked: origin probes $NH1->$NH2"

exit $fail
