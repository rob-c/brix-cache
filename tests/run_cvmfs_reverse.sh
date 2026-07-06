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
MPORT=12831; CPORT=12832; XPORT=12833; DPORT=12834
mkdir -p "$PFX/cache" "$PFX/logs"

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http {
    # T16 canonical cvmfs access-log format (class / cache disposition / origin)
    log_format cvmfs '\$remote_addr [\$time_local] "\$request" \$status '
                     '\$body_bytes_sent \$request_time '
                     'class=\$cvmfs_class cache=\$cvmfs_cache origin=\$cvmfs_origin';
    access_log $PFX/logs/cvmfs_access.log cvmfs;
    # T21 canonical connection-durability block (proven by run_cvmfs_keepalive.sh)
    keepalive_timeout 3600s; keepalive_requests 1000000;
    send_timeout 300s; client_header_timeout 300s;
    reset_timedout_connection off;
    server {
        listen 127.0.0.1:$CPORT so_keepalive=60s:10s:6 backlog=2048;
        location /cvmfs/ {
            brix_storage_backend http://127.0.0.1:$MPORT;
            brix_cache_store posix:$PFX/cache;
            brix_cvmfs on;
            brix_cvmfs_manifest_ttl 1;
        }
        # nginx normalizes dot-segments before location match, so a traversal
        # like /cvmfs/../etc/passwd arrives here as /etc/passwd — refuse it.
        location / { return 403; }
    }
    server {   # T16: metrics + healthz scrape listener
        listen 127.0.0.1:$XPORT;
        access_log off;
        location /metrics { brix_metrics on; }
        location /healthz { brix_health on; }
    }
    server {   # T16: operator dashboard (live-transfer visibility check)
        listen 127.0.0.1:$DPORT;
        access_log off;
        location /brix/ { brix_dashboard on; brix_dashboard_password "t16"; }
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

# manifest: cached with a 1s TTL — a bump becomes visible after expiry (T12).
# Under load a refill hiccup legitimately serves the stale copy once
# (bounded stale-if-error), so poll a few TTL windows for the new content.
curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/.cvmfspublished" -o "$PFX/m1"
curl -s "http://127.0.0.1:$MPORT/ctl/manifest/bump" >/dev/null
MREV=0
for _ in 1 2 3; do
    sleep 2
    curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/.cvmfspublished" -o "$PFX/m2"
    cmp -s "$PFX/m1" "$PFX/m2" || { MREV=1; break; }
done
[ "$MREV" = 1 ] && ok "expired manifest revalidated (TTL)" \
    || bad "manifest stale past TTL (cached forever!)"

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

# T16: the dashboard sees an IN-FLIGHT cvmfs fill (stalled origin) with the
# cvmfs protocol tag and the client-visible path
OBJ6="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[6])')"
curl -s -o /dev/null -X POST -d '{"mode":"stall","count":1}' "http://127.0.0.1:$MPORT/ctl/fault"
# Keep the fill in flight long enough to observe: a 6s client timeout gives a
# generous window, and we POLL the transfers API rather than scrape once at a
# fixed instant — under load the slot can take >1s to appear, and a single
# timed scrape raced it (flaky "no live cvmfs slot" on a busy box).
timeout 6 curl -s "http://127.0.0.1:$CPORT$OBJ6" -o /dev/null & STALLPID=$!
DJ=""; slot=0
for _ in $(seq 1 25); do
    DTS="$(date +%s)"; DH="$(printf '%s' "$DTS" | openssl dgst -sha256 -hmac "t16" -hex | sed 's/^.*= //')"
    DJ="$(curl -s -H "Cookie: xrd_dashboard=${DH}.${DTS}" \
          "http://127.0.0.1:$DPORT/brix/api/v1/transfers")"
    if printf '%s' "$DJ" | grep -q '"protocol":"cvmfs"' \
       && printf '%s' "$DJ" | grep -qF "\"path\":\"$OBJ6\""; then
        slot=1; break
    fi
    sleep 0.3
done
[ "$slot" = 1 ] && ok "dashboard: in-flight cvmfs fill visible (proto+path)" \
    || bad "dashboard: no live cvmfs slot"
printf '%s' "$DJ" | grep -q '"cvmfs_bytes_tx":' \
    && ok "dashboard: totals carry the cvmfs bucket" \
    || bad "dashboard: no cvmfs totals"
wait "$STALLPID" 2>/dev/null   # only the stalled curl — never the mock job
curl -s -o /dev/null -X POST -d '{"mode":"none","count":0}' "http://127.0.0.1:$MPORT/ctl/fault"

# T17: reject lines are guard/fail2ban-parsable (convention #4 shape)
grep -q 'cvmfs-reject: method=GET uri=.*client=.*class=reject' "$PFX/logs/e.log" \
    && ok "reject line guard-parsable" || bad "no cvmfs-reject log line"

# T16: the three visibility surfaces
M="$(curl -s "http://127.0.0.1:$XPORT/metrics")"
CASN="$(printf '%s' "$M" | sed -n 's/^brix_cvmfs_requests_total{class="cas"} //p')"
[ "${CASN:-0}" -ge 1 ] && ok "metrics: cas requests counted ($CASN)" \
    || bad "metrics: cas counter missing/zero"
printf '%s' "$M" | grep -q 'proto="cvmfs"' \
    && ok "metrics: proto=cvmfs on module-wide families" \
    || bad "metrics: no proto=cvmfs label"
FILLB="$(printf '%s' "$M" | sed -n 's/^brix_cvmfs_bytes_served_total{source="fill"} //p')"
[ "${FILLB:-0}" -ge 1 ] && ok "metrics: fill bytes counted" || bad "metrics: fill bytes zero"
grep -q 'class=cas cache=fill' "$PFX/logs/cvmfs_access.log" \
    && ok "access log: cold read logged as class=cas cache=fill" \
    || bad "access log: no fill line"
grep -q 'class=cas cache=hit' "$PFX/logs/cvmfs_access.log" \
    && ok "access log: warm read logged as cache=hit" \
    || bad "access log: no hit line"
curl -s "http://127.0.0.1:$XPORT/healthz?verbose" | grep -q '"cvmfs_origins":\[{"host"' \
    && ok "healthz: cvmfs_origins present" || bad "healthz: no cvmfs_origins"

# per-repository families (bounded fqrn label set)
RREQ="$(printf '%s' "$M" | sed -n 's/^brix_cvmfs_repo_requests_total{repo="test.cern.ch",class="cas"} //p')"
[ "${RREQ:-0}" -ge 1 ] && ok "repo metrics: per-fqrn cas requests ($RREQ)" \
    || bad "repo metrics: no test.cern.ch cas row"
RFA="$(printf '%s' "$M" | sed -n 's/^brix_cvmfs_repo_files_accessed_total{repo="test.cern.ch"} //p')"
[ "${RFA:-0}" -ge 1 ] && ok "repo metrics: files_accessed counted ($RFA)" \
    || bad "repo metrics: files_accessed zero"
RHIT="$(printf '%s' "$M" | sed -n 's/^brix_cvmfs_repo_cache_hits_total{repo="test.cern.ch"} //p')"
RFILL="$(printf '%s' "$M" | sed -n 's/^brix_cvmfs_repo_bytes_served_total{repo="test.cern.ch",source="fill"} //p')"
ROB="$(printf '%s' "$M" | sed -n 's/^brix_cvmfs_repo_origin_bytes_total{repo="test.cern.ch"} //p')"
[ "${RHIT:-0}" -ge 1 ] && [ "${RFILL:-0}" -ge 1 ] && [ "${ROB:-0}" -ge 1 ] \
    && ok "repo metrics: hits/bytes-served/origin-bytes all counted" \
    || bad "repo metrics: hit=$RHIT fillbytes=$RFILL originbytes=$ROB"

# cardinality bound: 40 distinct (bogus) fqrns must NOT mint 40 label values —
# past the 31 named slots everything folds into repo="_other"
BOG="$(python3 -c 'print("ab"*19)')"
for i in $(seq 1 40); do
    curl -s -o /dev/null "http://127.0.0.1:$CPORT/cvmfs/flood$i.example.org/data/aa/$BOG"
done
M2="$(curl -s "http://127.0.0.1:$XPORT/metrics")"
NREPO="$(printf '%s' "$M2" | grep -c '^brix_cvmfs_repo_files_accessed_total{')"
printf '%s' "$M2" | grep -q 'repo="_other"' && [ "$NREPO" -le 32 ] \
    && ok "repo metrics: label set bounded ($NREPO repos, overflow → _other)" \
    || bad "repo metrics: cardinality bound broken (repos=$NREPO)"

exit $fail
