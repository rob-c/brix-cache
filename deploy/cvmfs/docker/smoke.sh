#!/usr/bin/env bash
# deploy/cvmfs/docker/smoke.sh — end-to-end proof of the demo container.
#
#   ./deploy/cvmfs/docker/smoke.sh [--mock] [--keep] [--no-build]
#
# --mock      use the bundled mock Stratum-1 inside the container (offline;
#             exercises every cache path, but a real client can't mount it)
# --keep      leave the container running afterwards (for manual poking /
#             pointing a real CVMFS client at it)
# --no-build  reuse the existing image
#
# Checks: cold fill + warm hit through :3128, cvmfs Prometheus counters on
# :3130, /healthz, dashboard login on :3129, a classifier reject producing
# the fail2ban-parsable log line, a 25-request reject storm tripping the
# nginx-xrootd-cvmfs jail (real nftables ban with NET_ADMIN), and a
# guard-signature probe tripping the xrootd-guard-signature jail.
set -u

IMAGE=nginx-xrootd-cvmfs
NAME=cvmfs-demo-smoke
MOCK=0; KEEP=0; BUILD=1
for a in "$@"; do case "$a" in
    --mock) MOCK=1 ;; --keep) KEEP=1 ;; --no-build) BUILD=0 ;;
    *) echo "usage: $0 [--mock] [--keep] [--no-build]" >&2; exit 2 ;;
esac; done

HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../../.." && pwd)"
fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cexec(){ docker exec "$NAME" "$@"; }
# fail2ban's polling backend needs a few seconds to see appended lines;
# poll the jail (2s cadence, 30s budget) instead of guessing a sleep.
wait_banned(){ # $1 = jail; echoes the banned count, 0 on timeout
    local n=0 t
    for t in $(seq 1 15); do
        n="$(cexec fail2ban-client status "$1" 2>/dev/null \
             | sed -n 's/.*Currently banned:\s*//p' | head -1)"
        [ "${n:-0}" -ge 1 ] 2>/dev/null && break
        sleep 2
    done
    echo "${n:-0}"
}
cleanup(){ [ "$KEEP" = 1 ] && { echo "keeping container $NAME"; return; }
           docker rm -f "$NAME" >/dev/null 2>&1; }
trap cleanup EXIT

# --- build + run ------------------------------------------------------------
if [ "$BUILD" = 1 ]; then
    docker build -t "$IMAGE" -f "$HERE/Dockerfile" "$REPO" || exit 1
fi
docker rm -f "$NAME" >/dev/null 2>&1 || true
RUNARGS=(-d --name "$NAME" --cap-add=NET_ADMIN
         -p 3128:3128 -p 3129:3129 -p 3130:3130)
[ "$MOCK" = 1 ] && RUNARGS+=(-e MOCK_STRATUM1=1)
docker run "${RUNARGS[@]}" "$IMAGE" >/dev/null || exit 1

for _ in $(seq 1 60); do
    curl -fsS --max-time 2 http://127.0.0.1:3130/healthz >/dev/null 2>&1 && break
    sleep 1
done
curl -fsS --max-time 2 http://127.0.0.1:3130/healthz >/dev/null \
    && ok "container up, /healthz answering" || { bad "container never became healthy"
        docker logs "$NAME" | tail -30; exit 1; }

# --- pick repo + upstream ---------------------------------------------------
PROXY=http://127.0.0.1:3128
if [ "$MOCK" = 1 ]; then
    S1=127.0.0.1:8000; REPONAME=test.cern.ch
else
    S1=cvmfs-stratum-one.cern.ch; REPONAME=cvmfs-config.cern.ch
fi
BASE="http://$S1/cvmfs/$REPONAME"

# --- 1: manifest through the cache ------------------------------------------
M="$(curl -fsS --max-time 30 -x "$PROXY" "$BASE/.cvmfspublished" | head -c1)"
[ "$M" = C ] && ok "manifest fetched through :3128 (starts with 'C')" \
             || bad "manifest fetch (got '${M:-nothing}')"

# --- 2: CAS object cold fill + warm hit -------------------------------------
if [ "$MOCK" = 1 ]; then
    OBJ="$(cexec python3 -c 'import json,urllib.request;
print(json.load(urllib.request.urlopen("http://127.0.0.1:8000/ctl/objects"))[0])')"
else
    # root catalog hash from the manifest: line "C<40hex>" → data/xx/yyy...C
    H="$(curl -fsS --max-time 30 -x "$PROXY" "$BASE/.cvmfspublished" \
         | sed -n 's/^C\([0-9a-f]\{40\}\)$/\1/p' | head -1)"
    [ -n "$H" ] || { bad "no catalog hash in manifest"; H=deadbeef; }
    OBJ="/cvmfs/$REPONAME/data/${H:0:2}/${H:2}C"
fi
curl -fsS --max-time 60 -x "$PROXY" "http://$S1$OBJ" -o /tmp/smoke_cold.bin \
    && ok "CAS object cold fill" || bad "CAS cold fetch"
curl -fsS --max-time 10 -x "$PROXY" "http://$S1$OBJ" -o /tmp/smoke_warm.bin \
    && cmp -s /tmp/smoke_cold.bin /tmp/smoke_warm.bin \
    && ok "CAS warm refetch byte-exact" || bad "CAS warm refetch"

# --- 2b: the cached object is visible in the posix cache folder -------------
NFILES="$(cexec find /var/cache/cvmfs -type f 2>/dev/null | wc -l)"
[ "${NFILES:-0}" -ge 1 ] 2>/dev/null \
    && ok "cached data present in /var/cache/cvmfs ($NFILES file(s))" \
    || bad "posix cache folder empty after fill"

# --- 3: Prometheus counters -------------------------------------------------
MET="$(curl -fsS http://127.0.0.1:3130/metrics)"
echo "$MET" | grep -q 'xrootd_cvmfs_requests_total{class="cas"} [1-9]' \
    && ok "metrics: cas requests counted" || bad "metrics: cas counter"
echo "$MET" | grep -q 'xrootd_cvmfs_requests_total{class="manifest"} [1-9]' \
    && ok "metrics: manifest requests counted" || bad "metrics: manifest counter"
echo "$MET" | grep -q 'xrootd_cvmfs_bytes_served_total{source="hit"} [1-9]' \
    && ok "metrics: warm hit bytes counted" || bad "metrics: hit bytes"

# --- 4: dashboard -----------------------------------------------------------
DC="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3129/xrootd/)"
case "$DC" in 200|302) ok "dashboard answering on :3129 ($DC)" ;;
              *) bad "dashboard on :3129 (got $DC)" ;; esac

# --- 5: classifier reject → 403 + fail2ban-parsable line --------------------
RC="$(curl -s -o /dev/null -w '%{http_code}' -x "$PROXY" \
      "http://$S1/cvmfs/$REPONAME/not-a-cvmfs-shape.txt")"
[ "$RC" = 403 ] && ok "non-CVMFS shape rejected with 403" \
                || bad "reject status (got $RC)"
cexec grep -q "cvmfs-reject:" /var/log/nginx-xrootd/error.log \
    && ok "cvmfs-reject line in error log" || bad "cvmfs-reject log line"

# --- 6: reject storm trips the cvmfs jail -----------------------------------
for i in $(seq 1 25); do
    curl -s -o /dev/null --max-time 5 -x "$PROXY" \
        "http://$S1/cvmfs/$REPONAME/probe-$i.txt" || true
done
BANNED="$(wait_banned nginx-xrootd-cvmfs)"
[ "${BANNED:-0}" -ge 1 ] 2>/dev/null \
    && ok "fail2ban nginx-xrootd-cvmfs jail banned the storm source" \
    || bad "cvmfs jail did not ban (banned='$BANNED')"
if cexec nft list tables 2>/dev/null | grep -q f2b; then
    sleep 1     # let the set-element insert land before probing
    BC="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -x "$PROXY" \
          "$BASE/.cvmfspublished" || true)"
    if [ "$BC" != 200 ]; then
        ok "banned client really blocked on :3128 (got '$BC')"
    else
        bad "ban did not block traffic (got 200)"
        cexec nft list ruleset 2>&1 | sed 's/^/      | /'
    fi
else
    ok "no NET_ADMIN: ban is log-only (dummy action) — skipping block check"
fi
cexec fail2ban-client unban --all >/dev/null 2>&1 || true

# --- 7: guard signature probe trips the guard jail ---------------------------
curl -s -o /dev/null --max-time 5 -x "$PROXY" "http://$S1/wp-login.php" || true
GB="$(wait_banned xrootd-guard-signature)"
[ "${GB:-0}" -ge 1 ] 2>/dev/null \
    && ok "guard signature probe banned instantly" \
    || bad "guard-signature jail did not ban (banned='$GB')"
cexec fail2ban-client unban --all >/dev/null 2>&1 || true

echo
[ "$fail" = 0 ] && echo "SMOKE: ALL CHECKS PASSED" || echo "SMOKE: FAILURES (see above)"
exit $fail
