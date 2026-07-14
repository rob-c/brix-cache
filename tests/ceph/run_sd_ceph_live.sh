#!/usr/bin/env bash
# run_sd_ceph_live.sh — compile + run the LIVE sd_ceph driver test inside the
# xrd-ceph-work build container against the tests/ceph_harness.sh pool.
#
# Prereqs: tests/ceph_harness.sh start  &&  tests/ceph/build_in_container.sh
# (the latter creates xrd-ceph-work with the source + librados-devel + conf).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK="${WORK:-xrd-ceph-work}"
POOL="${CEPH_POOL:-xrdtest}"

docker ps --format '{{.Names}}' | grep -qx "$WORK" \
    || { echo "work container '$WORK' not running — run tests/ceph/build_in_container.sh" >&2; exit 1; }

# Refresh the driver + test sources into the container.
docker exec "$WORK" mkdir -p /work/repo/tests/ceph /work/repo/src/fs/backend/rados /work/repo/client/apps/ceph
docker cp "$REPO/src/fs/backend/rados/sd_ceph.c"   "$WORK:/work/repo/src/fs/backend/rados/sd_ceph.c"
# phase-79 file-size split: sd_ceph.c's ops moved into these siblings + internal header.
docker cp "$REPO/src/fs/backend/rados/sd_ceph_io.c"       "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_io.c"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_object.c"   "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_object.c"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_cred.c"     "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_cred.c"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_internal.h" "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_internal.h"
docker cp "$REPO/src/fs/backend/rados/sd_ceph.h"   "$WORK:/work/repo/src/fs/backend/rados/sd_ceph.h"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_striper.h" "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_striper.h"
docker cp "$REPO/tests/ceph/sd_ceph_live_test.c"   "$WORK:/work/repo/tests/ceph/sd_ceph_live_test.c"
docker cp "$REPO/client/apps/ceph/ngx_shim.h"      "$WORK:/work/repo/client/apps/ceph/ngx_shim.h"

docker exec -e CEPH_POOL="$POOL" -e CEPH_CONF=/etc/ceph/ceph.conf "$WORK" bash -lc '
    cd /work/repo &&
    gcc -Wall -Wextra -Werror -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH \
        -I src -I src/fs/backend -I src/fs/backend/rados \
        -include client/apps/ceph/ngx_shim.h \
        tests/ceph/sd_ceph_live_test.c src/fs/backend/rados/sd_ceph.c \
        src/fs/backend/rados/sd_ceph_io.c \
        src/fs/backend/rados/sd_ceph_object.c \
        src/fs/backend/rados/sd_ceph_cred.c \
        src/fs/backend/rados/sd_ceph_compat.c \
        -lrados -o /tmp/sd_ceph_live &&
    /tmp/sd_ceph_live'
