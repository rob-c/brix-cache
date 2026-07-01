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

docker ps --format '{{.Names}}' | grep -qx "$WORK" \
    || { echo "work container '$WORK' not running" >&2; exit 1; }
for f in tests/ceph/striper_seed.c tests/ceph/xrdceph_striper_migrate.cpp; do
    docker cp "$REPO/$f" "$WORK:/work/repo/$f" >/dev/null
done

docker exec -e CEPH_CONF=/etc/ceph/ceph.conf "$WORK" bash -lc '
set -e
cd /work/repo
gcc -Wall -D_FILE_OFFSET_BITS=64 tests/ceph/striper_seed.c -lradosstriper -lrados -o /tmp/striper_seed
g++ -std=c++17 -Wall -D_FILE_OFFSET_BITS=64 tests/ceph/xrdceph_striper_migrate.cpp \
    -lrados -lcephfs -lpthread -o /tmp/migtool
M=/tmp/migtool
echo "build: ok"

# fresh sources under a known prefix
for g in "rm/a 10485760 4194304 4194304 1" "rm/b 18874368 4194304 4194304 2" "rm/c 41943040 8388608 4194304 4"; do
  set -- $g; /tmp/striper_seed xrdtest "$1" "$2" "$3" "$4" "$5" >/dev/null
done
printf "rm/a\nrm/b\nrm/c\n" > /tmp/L
src_count() { rados -p xrdtest ls 2>/dev/null | grep -c "^$1\." || true; }

echo "== REDIRECT migrate (zero-move) + verify =="
$M xrdtest cephfs_data /zm --mode redirect --list /tmp/L --verify --threads 3 2>&1 | grep -E "OK|done:"
echo "source objects still present (zero-move): rm/a=$(src_count rm/a) rm/b=$(src_count rm/b) rm/c=$(src_count rm/c)"

echo "== durability: MDS flush + cache drop, then re-verify (force) =="
ceph tell mds.demo flush journal >/dev/null 2>&1 || true
ceph tell mds.demo cache drop   >/dev/null 2>&1 || true
$M xrdtest cephfs_data /zm --mode redirect --list <(echo rm/b) --force --verify 2>&1 | grep -E "OK|FAIL|done:"

echo "== idempotent re-run (expect SKIP) =="
$M xrdtest cephfs_data /zm --mode redirect --list /tmp/L --verify 2>&1 | grep -E "SKIP|done:"

echo "== ROLLBACK (remove overlay, keep source) =="
$M xrdtest cephfs_data /zm --rollback --list /tmp/L 2>&1 | grep -E "ROLLBACK|done:"
echo "source after rollback: rm/a=$(src_count rm/a) rm/b=$(src_count rm/b) rm/c=$(src_count rm/c)"

echo "== re-migrate after rollback (round-trip; expect OK not SKIP) =="
$M xrdtest cephfs_data /zm --mode redirect --list <(echo rm/a) --verify 2>&1 | grep -E "OK|SKIP|done:"

echo "== COPY mode regression + delete-source =="
/tmp/striper_seed xrdtest cp/x 5242880 4194304 4194304 1 >/dev/null
$M xrdtest cephfs_data /cp --mode copy --list <(echo cp/x) --verify --delete-source 2>&1 | grep -E "OK|done:"
echo "cp/x source after copy+delete: $(src_count cp/x) (expect 0)"

echo "== guard: --delete-source refused in redirect mode =="
if $M xrdtest cephfs_data /zm --mode redirect --list /tmp/L --delete-source >/dev/null 2>&1; then
  echo "GUARD FAIL: redirect+delete-source was accepted"
else
  echo "guard ok: redirect + --delete-source refused"
fi

echo "run_striper_migrate: checks complete"
'
