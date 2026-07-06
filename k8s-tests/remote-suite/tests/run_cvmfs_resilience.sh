#!/usr/bin/env bash
# tests/run_cvmfs_resilience.sh — e2e for the 2026-07-03 "absorb upstream
# flakiness" work: (A) fast stall detection + force-primary retry, and
# (B) server-side RTT-ranked geo answer with the port/count probe guard.
# Spec: docs/superpowers/specs/2026-07-03-cvmfs-proxy-absorb-upstream-flakiness-design.md
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PFX="$(mktemp -d /tmp/cvmfs_res.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null
           [ -n "${SINK:-}" ] && kill "$SINK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
MPORT=12841; CPORT=12842
mkdir -p "$PFX/cache" "$PFX/logs" "$PFX/sink"

# Connection-count sinks: 8000 (allowed → must be probed), 2222 (disallowed →
# must NEVER be connected). If 8000 is busy we skip the ranking asserts.
if ss -tlnp 2>/dev/null | grep -q ':8000 '; then
    echo "  SKIP geo ranking asserts: port 8000 already in use"; SINK=""
else
    python3 "$HERE/cvmfs/probe_sink.py" "$PFX/sink" 8000 2222 & SINK=$!
    for _ in $(seq 1 50); do [ -f "$PFX/sink/ready" ] && break; sleep 0.1; done
fi

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=4;
events { worker_connections 128; }
http {
    server {
        listen 127.0.0.1:$CPORT;
        location /cvmfs/ {
            brix_storage_backend http://127.0.0.1:$MPORT;
            brix_cache_store posix:$PFX/cache;
            brix_cvmfs on;
            brix_cvmfs_manifest_ttl 1;
            # Part A: fast-fail a stuck origin, force the primary through.
            brix_cvmfs_origin_connect_timeout 1;
            brix_cvmfs_origin_stall_timeout   2;
            brix_cvmfs_origin_stall_bytes     1;
            brix_cvmfs_fill_retry_policy       force-primary;
            brix_cvmfs_client_hold             20;
            # Part B: answer the geo API locally, RTT-ranked.
            brix_cvmfs_geo_answer      rtt;
            brix_cvmfs_geo_cache_ttl   60;
            brix_cvmfs_geo_max_servers 8;
        }
        location / { return 403; }
    }
}
EOF

# --- Part A/B config parse -------------------------------------------------
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && ok "new resilience+geo directives parse" \
    || { bad "nginx -t rejected config"; "$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX"; }

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 8 --seed 7 &
MOCK=$!; sleep 0.5
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5

# --- Part A: stuck-before-data origin → force-through, not a stall ---------
# The mock 'stall' fault sends 64 bytes then sleeps 30s. With stall_timeout=2s
# the fill aborts in ~2s (not 60s), and force-primary retries the SAME origin;
# the fault is one-shot, so the retry serves the object. The client must get a
# byte-exact 200 well inside its hold, never a 504 and never a 60s hang.
OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"
curl -s "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/orig.bin"
curl -s -o /dev/null -X POST -d '{"mode":"stall","count":1}' "http://127.0.0.1:$MPORT/ctl/fault"
T0=$(date +%s)
CODE="$(curl -s -m 15 -o "$PFX/got.bin" -w '%{http_code}' "http://127.0.0.1:$CPORT$OBJ")"
T1=$(date +%s); DT=$((T1 - T0))
if [ "$CODE" = 200 ] && cmp -s "$PFX/got.bin" "$PFX/orig.bin"; then
    ok "stalled origin forced through (200 byte-exact in ${DT}s, no 504/hang)"
else
    bad "force-through: code=$CODE dt=${DT}s (expected 200 byte-exact)"
fi
[ "$DT" -lt 12 ] && ok "stall detected fast (${DT}s « the 60s default ceiling)" \
    || bad "stall not fast: ${DT}s"
curl -s -o /dev/null -X POST -d '{"mode":"none","count":0}' "http://127.0.0.1:$MPORT/ctl/fault"

# --- Part B: RTT-ranked geo answer ----------------------------------------
if [ -n "$SINK" ]; then
    # List order: [unreachable allowed, reachable allowed, disallowed port].
    # Expect the reachable one first, the unreachable one next, the disallowed
    # one LAST (it is bucketed unprobed) → permutation "2,1,3".
    GL="192.0.2.2:8000,127.0.0.1:8000,127.0.0.1:2222"
    G="$(curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/api/v1.0/geo/x/$GL")"
    G="$(printf '%s' "$G" | tr -d '[:space:]')"
    [ "$G" = "2,1,3" ] && ok "geo RTT rank: reachable<unreachable<disallowed ($G)" \
        || bad "geo RTT rank: got '$G' (expected 2,1,3)"

    # security-neg: the disallowed :2222 entry was NEVER connected to; the
    # allowed :8000 one WAS probed.
    H8000=$( [ -f "$PFX/sink/8000.hits" ] && wc -c < "$PFX/sink/8000.hits" || echo 0 )
    H2222=$( [ -f "$PFX/sink/2222.hits" ] && wc -c < "$PFX/sink/2222.hits" || echo 0 )
    [ "$H8000" -ge 1 ] && ok "guard: allowed port 8000 was probed ($H8000)" \
        || bad "guard: allowed port never probed"
    [ "$H2222" -eq 0 ] && ok "guard: disallowed port 2222 never connected" \
        || bad "guard: disallowed port 2222 got $H2222 connects (SSRF/scan risk!)"

    # well-formed permutation for a longer list (never drops/duplicates a server)
    GL2="127.0.0.1:2222,127.0.0.1:8000,192.0.2.2:8000,127.0.0.1:22,127.0.0.1:8000"
    G2="$(curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/api/v1.0/geo/x/$GL2" | tr -d '[:space:]')"
    SORTED="$(printf '%s' "$G2" | tr ',' '\n' | sort -n | tr '\n' ',' | sed 's/,$//')"
    [ "$SORTED" = "1,2,3,4,5" ] \
        && ok "geo answer is a complete permutation of 1..5 ($G2)" \
        || bad "geo answer not a clean permutation: '$G2' (sorted '$SORTED')"
fi

# robustness: an unresolvable-hostname list still yields a well-formed answer
# (both unreachable → original order), never an empty body or a crash.
GF="$(curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/api/v1.0/geo/x/a,b" | tr -d '[:space:]')"
[ -n "$GF" ] && ok "geo answer/fallback returns non-empty for name list ($GF)" \
    || bad "geo answer empty for hostname list"

exit $fail
