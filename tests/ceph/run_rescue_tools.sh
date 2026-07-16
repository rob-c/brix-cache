#!/usr/bin/env bash
# run_rescue_tools.sh — build + smoke-test the three operator tools inside the
# xrd-ceph-work build container:
#   xrdcephfs_rescue  — recover from a CephFS via pure RADOS (uses the cephfsro core)
#   xrdrados_rescue   — recover from a flat RADOS pool
#   xrdceph_migrate   — copy a flat pool into a filesystem tree (copy-through-mount)
#
# Prereqs: a seeded+flushed CephFS (cephfs_seed.c/seed2.c) for the cephfs tool;
# a flat pool (default xrdtest) for the rados/migrate tools; build_in_container.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK="${WORK:-xrd-ceph-work}"
POOL="${CEPH_POOL:-xrdtest}"
META="${CEPHFS_META:-cephfs_metadata}"
DATA="${CEPHFS_DATA:-cephfs_data}"

docker ps --format '{{.Names}}' | grep -qx "$WORK" \
    || { echo "work container '$WORK' not running — run tests/ceph/build_in_container.sh" >&2; exit 1; }

docker exec "$WORK" mkdir -p /work/repo/src/fs/backend/rados /work/repo/client/apps/ceph
# Keep in step with client/Makefile's CEPH_CORE_SRCS / CEPHFS_RO_SRCS — that is the
# build's source of truth (the RPM drives it too); this list only has to carry the
# same TUs, plus the headers they include, into the container.
for f in src/fs/backend/sd.h \
         src/fs/backend/rados/sd_ceph.c src/fs/backend/rados/sd_ceph.h \
         src/fs/backend/rados/sd_ceph_internal.h \
         src/fs/backend/rados/sd_ceph_io.c \
         src/fs/backend/rados/sd_ceph_cred.c \
         src/fs/backend/rados/sd_ceph_object.c \
         src/fs/backend/rados/sd_ceph_striper.h \
         src/fs/backend/rados/sd_ceph_compat.c src/fs/backend/rados/sd_ceph_compat.h \
         src/fs/backend/rados/cephfs_denc.c src/fs/backend/rados/cephfs_denc.h \
         src/fs/backend/rados/cephfs_layout.c src/fs/backend/rados/cephfs_layout.h \
         src/fs/backend/rados/sd_cephfs_ro.c \
         src/fs/backend/rados/sd_cephfs_ro_internal.h \
         src/fs/backend/rados/sd_cephfs_ro_dir.c \
         src/fs/backend/rados/sd_cephfs_ro_resolve.c \
         client/apps/ceph/ngx_shim.h client/apps/ceph/xrdcephfs_rescue.c \
         client/apps/ceph/xrdrados_rescue.c client/apps/ceph/xrdceph_migrate.c; do
    docker cp "$REPO/$f" "$WORK:/work/repo/$f" >/dev/null
done

docker exec -e CEPH_CONF=/etc/ceph/ceph.conf -e POOL="$POOL" -e META="$META" -e DATA="$DATA" \
    "$WORK" bash -lc '
set -e
cd /work/repo
# Mirrors client/Makefile CEPH_CORE_SRCS / CEPHFS_RO_SRCS.  The tools compile the
# driver TUs directly, so these lists are a symbol closure: when a TU is split,
# omitting the new sibling here fails at LINK ("undefined reference to sd_ceph_*"),
# not at compile.  sd_ceph_striper.c is deliberately absent — unreferenced here,
# and it would drag in libradosstriper.
FLAT_SRCS="src/fs/backend/rados/sd_ceph.c src/fs/backend/rados/sd_ceph_compat.c
           src/fs/backend/rados/sd_ceph_io.c src/fs/backend/rados/sd_ceph_cred.c
           src/fs/backend/rados/sd_ceph_object.c"
CEPHFS_SRCS="src/fs/backend/rados/sd_cephfs_ro.c
             src/fs/backend/rados/sd_cephfs_ro_dir.c
             src/fs/backend/rados/sd_cephfs_ro_resolve.c
             src/fs/backend/rados/cephfs_layout.c
             src/fs/backend/rados/cephfs_denc.c $FLAT_SRCS"
CC="gcc -Wall -Wextra -Werror -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH
    -I src -I src/fs/backend -I src/fs/backend/rados -include client/apps/ceph/ngx_shim.h"

$CC client/apps/ceph/xrdcephfs_rescue.c $CEPHFS_SRCS -lrados -o /tmp/xrdcephfs_rescue
$CC client/apps/ceph/xrdrados_rescue.c  $FLAT_SRCS   -lrados -o /tmp/xrdrados_rescue
$CC client/apps/ceph/xrdceph_migrate.c  $FLAT_SRCS   -lrados -o /tmp/xrdceph_migrate
echo "build: ok"

echo "== xrdcephfs_rescue cp -r / =="
rm -rf /tmp/cfs_rescued
/tmp/xrdcephfs_rescue "$META" "$DATA" cp -r / /tmp/cfs_rescued >/dev/null
[ "$(head -c8 /tmp/cfs_rescued/dir1/sub/big.bin)" = BIGSTART ] && echo "  ok cephfs cp big.bin" || { echo "  FAIL cephfs cp"; exit 1; }

echo "== xrdrados_rescue =="
printf payload | rados -p "$POOL" put /rr/x.txt /dev/stdin
/tmp/xrdrados_rescue "$POOL" ls /rr | grep -q /rr/x.txt && echo "  ok rados ls" || { echo "  FAIL rados ls"; exit 1; }

echo "== xrdceph_migrate =="
printf migdata | rados -p "$POOL" put /mg/a.bin /dev/stdin
rm -rf /tmp/mig_out
/tmp/xrdceph_migrate "$POOL" /tmp/mig_out >/dev/null
[ "$(cat /tmp/mig_out/mg/a.bin)" = migdata ] && echo "  ok migrate layout+content" || { echo "  FAIL migrate"; exit 1; }

echo "run_rescue_tools: ALL PASS"
'
