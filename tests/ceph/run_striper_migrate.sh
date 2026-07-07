#!/usr/bin/env bash
# run_striper_migrate.sh — build + smoke-test the Glasgow/RAL→CephFS migrator
# (xrdceph_striper_migrate) inside xrd-ceph-work against the demo cluster. Covers:
#   - REDIRECT (zero-move) migrate + checksum verify, source left intact
#   - durability: redirect survives MDS journal flush + cache drop (re-verify)
#   - ROLLBACK: overlay removed, source intact, then re-migrate (round-trip)
#   - COPY mode regression (+ --delete-source)
#   - guard: --delete-source refused in redirect mode
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK="${WORK:-xrd-ceph-work}"
# CephFS data pool: quay.io/ceph/demo used "cephfs_data"; a stock `ceph fs volume
# create cephfs` names it "cephfs.cephfs.data". Autodetect from `ceph fs ls`
# ("... data pools: [pool ]"); override with DPOOL=... if needed.
if [ -z "${DPOOL:-}" ]; then
    DPOOL="$(docker exec "$WORK" bash -lc 'ceph fs ls 2>/dev/null' \
             | sed -n 's/.*data pools: \[\([^] ]*\).*/\1/p' | head -1 || true)"
fi
DPOOL="${DPOOL:-cephfs_data}"
echo "using CephFS data pool: $DPOOL"

docker ps --format '{{.Names}}' | grep -qx "$WORK" \
    || { echo "work container '$WORK' not running" >&2; exit 1; }
docker exec "$WORK" mkdir -p /work/repo/tests/ceph /work/repo/client/apps/ceph
for f in tests/ceph/striper_seed.c client/apps/ceph/xrdceph_striper_migrate.cpp \
         client/apps/ceph/xrdceph_migrate_config.h; do
    docker cp "$REPO/$f" "$WORK:/work/repo/$f" >/dev/null
done

docker exec -e CEPH_CONF=/etc/ceph/ceph.conf "$WORK" bash -lc '
set -e
cd /work/repo
gcc -Wall -D_FILE_OFFSET_BITS=64 tests/ceph/striper_seed.c -lradosstriper -lrados -o /tmp/striper_seed
g++ -std=c++17 -Wall -D_FILE_OFFSET_BITS=64 client/apps/ceph/xrdceph_striper_migrate.cpp \
    -lrados -lcephfs -lpthread -o /tmp/migtool
M=/tmp/migtool
echo "build: ok"

# fresh sources under a known prefix
for g in "rm/a 10485760 4194304 4194304 1" "rm/b 18874368 4194304 4194304 2" "rm/c 41943040 8388608 4194304 4"; do
  set -- $g; /tmp/striper_seed xrdtest "$1" "$2" "$3" "$4" "$5" >/dev/null
done
printf "rm/a\nrm/b\nrm/c\n" > /tmp/L
src_count() { rados -p xrdtest ls 2>/dev/null | grep -c "^$1\." || true; }

echo "== DRY-RUN wall-clock estimate (sample-migrate calibration) =="
$M xrdtest '"$DPOOL"' /zm --dry-run --list /tmp/L --threads 3 2>&1 \
    | grep -E "inventory:|calibration @|mode redirect|mode copy" \
    || { echo "ESTIMATE FAIL: no estimate lines in dry-run output"; exit 1; }
# the estimate sample-migrates then rolls back — the source must survive it
for f in rm/a rm/b rm/c; do
  [ "$(src_count $f)" -ge 1 ] || { echo "ESTIMATE FAIL: sample calibration lost source $f"; exit 1; }
done

echo "== REDIRECT migrate (zero-move) + verify =="
$M xrdtest '"$DPOOL"' /zm --mode redirect --list /tmp/L --verify --threads 3 2>&1 | grep -E "OK|done:"
echo "source objects still present (zero-move): rm/a=$(src_count rm/a) rm/b=$(src_count rm/b) rm/c=$(src_count rm/c)"

echo "== durability: MDS flush + cache drop, then re-verify (force) =="
ceph tell mds.demo flush journal >/dev/null 2>&1 || true
ceph tell mds.demo cache drop   >/dev/null 2>&1 || true
$M xrdtest '"$DPOOL"' /zm --mode redirect --list <(echo rm/b) --force --verify 2>&1 | grep -E "OK|FAIL|done:"

echo "== idempotent re-run (expect SKIP) =="
$M xrdtest '"$DPOOL"' /zm --mode redirect --list /tmp/L --verify 2>&1 | grep -E "SKIP|done:"

echo "== ROLLBACK (remove overlay, keep source) =="
$M xrdtest '"$DPOOL"' /zm --rollback --list /tmp/L 2>&1 | grep -E "ROLLBACK|done:"
sleep 3   # let the async MDS purge run — delete-through (if any) shows up here
a=$(src_count rm/a); b=$(src_count rm/b); c=$(src_count rm/c)
echo "source after rollback: rm/a=$a rm/b=$b rm/c=$c (expect 3/5/6)"
if [ "$a" != 3 ] || [ "$b" != 5 ] || [ "$c" != 6 ]; then
  echo "SOURCE LOSS: striper objects were destroyed (delete-through) — FAIL"; exit 1
fi

echo "== re-migrate after rollback (round-trip; expect OK not SKIP) =="
$M xrdtest '"$DPOOL"' /zm --mode redirect --list <(echo rm/a) --verify 2>&1 | grep -E "OK|SKIP|done:"

echo "== --force re-migrate must NOT delete-through to the source =="
$M xrdtest '"$DPOOL"' /zm --mode redirect --list <(echo rm/a) --force --verify 2>&1 | grep -E "OK|FAIL|done:"
sleep 3   # async purge of the unlinked old file would destroy the source if not detached
fa=$(src_count rm/a)
echo "rm/a source objects after --force re-migrate: $fa (expect 3)"
if [ "$fa" != 3 ]; then
  echo "SOURCE LOSS: --force re-migrate destroyed the source via delete-through — FAIL"; exit 1
fi

echo "== COPY mode regression + delete-source =="
$M xrdtest '"$DPOOL"' /cp --rollback --list <(echo cp/x) >/dev/null 2>&1 || true  # clean dest
/tmp/striper_seed xrdtest cp/x 5242880 4194304 4194304 1 >/dev/null
$M xrdtest '"$DPOOL"' /cp --mode copy --list <(echo cp/x) --verify --delete-source 2>&1 | grep -E "OK|done:"
cpx=$(src_count cp/x)
echo "cp/x source after copy+delete: $cpx (expect 0)"
if [ "$cpx" != 0 ]; then echo "COPY FAIL: --delete-source left $cpx source object(s)"; exit 1; fi

echo "== guard: --delete-source refused in redirect mode =="
if $M xrdtest '"$DPOOL"' /zm --mode redirect --list /tmp/L --delete-source >/dev/null 2>&1; then
  echo "GUARD FAIL: redirect+delete-source was accepted"
else
  echo "guard ok: redirect + --delete-source refused"
fi

echo "== CONFIG: site-profile file (--config, zero positionals) =="
cat > /tmp/cxxsite.conf <<EOF
striper_pool = xrdtest
data_pool    = '"$DPOOL"'
client       = admin
dest_prefix  = /zm
EOF
$M --config /tmp/cxxsite.conf --list <(echo rm/a) --force --verify 2>&1 | grep -E "^OK" \
  || { echo "CONFIG FAIL: zero-positional migrate did not OK"; exit 1; }
if $M xrdtest --config /tmp/cxxsite.conf >/dev/null 2>&1; then
  echo "CONFIG GUARD FAIL: partial positionals accepted"; exit 1
fi
echo "bad_key = x" > /tmp/cxxbad.conf
if $M --config /tmp/cxxbad.conf >/dev/null 2>&1; then
  echo "CONFIG GUARD FAIL: unknown key accepted"; exit 1
fi
echo "config ok: zero-positional migrate + both guards"

echo "run_striper_migrate: checks complete"
'
