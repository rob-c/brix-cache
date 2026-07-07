#!/usr/bin/env bash
# run_cephfs_ro_live.sh — compile + run the LIVE read-only CephFS-via-RADOS driver
# test inside the xrd-ceph-work build container against the seeded CephFS.
#
# Prereqs:
#   1. a CephFS on the demo cluster (pools cephfs_metadata / cephfs_data, an MDS).
#   2. seed the tree:   gcc -D_FILE_OFFSET_BITS=64 cephfs_seed.c  -lcephfs && ./a.out
#                       gcc -D_FILE_OFFSET_BITS=64 cephfs_seed2.c -lcephfs && ./a.out
#   3. flush so the omaps are on RADOS:  ceph tell mds.<id> flush journal
#   4. tests/ceph/build_in_container.sh  (creates xrd-ceph-work w/ librados-devel + conf)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK="${WORK:-xrd-ceph-work}"

docker ps --format '{{.Names}}' | grep -qx "$WORK" \
    || { echo "work container '$WORK' not running — run tests/ceph/build_in_container.sh" >&2; exit 1; }

docker exec "$WORK" mkdir -p /work/repo/src/fs/backend/rados /work/repo/tests/ceph /work/repo/client/apps/ceph
for f in src/fs/backend/sd.h \
         src/fs/backend/rados/sd_ceph.c src/fs/backend/rados/sd_ceph.h \
         src/fs/backend/rados/sd_ceph_striper.h \
         src/fs/backend/rados/sd_ceph_compat.h src/fs/backend/rados/sd_ceph_compat.c \
         src/fs/backend/rados/cephfs_denc.c src/fs/backend/rados/cephfs_denc.h \
         src/fs/backend/rados/cephfs_layout.c src/fs/backend/rados/cephfs_layout.h \
         src/fs/backend/rados/sd_cephfs_ro.c \
         client/apps/ceph/ngx_shim.h tests/ceph/sd_cephfs_ro_live_test.c; do
    docker cp "$REPO/$f" "$WORK:/work/repo/$f" >/dev/null
done

docker exec -e CEPH_CONF=/etc/ceph/ceph.conf "$WORK" bash -lc '
    cd /work/repo &&
    gcc -Wall -Wextra -Werror -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH \
        -I src -I src/fs/backend -I src/fs/backend/rados \
        -include client/apps/ceph/ngx_shim.h \
        tests/ceph/sd_cephfs_ro_live_test.c \
        src/fs/backend/rados/sd_cephfs_ro.c src/fs/backend/rados/sd_ceph.c \
        src/fs/backend/rados/sd_ceph_compat.c \
        src/fs/backend/rados/cephfs_layout.c src/fs/backend/rados/cephfs_denc.c \
        -lrados -o /tmp/cephfsro_live &&
    /tmp/cephfsro_live'
