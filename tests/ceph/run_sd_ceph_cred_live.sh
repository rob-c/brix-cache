#!/usr/bin/env bash
# run_sd_ceph_cred_live.sh — compile + run the LIVE per-user CephX credential
# test (ceph-peruser item, sd_ceph's open_cred slot) inside the xrd-ceph-work
# build container against the tests/ceph_harness.sh pool.
#
# Prereqs:
#   tests/ceph_harness.sh start
#   tests/ceph/build_in_container.sh
#   two CephX users provisioned in the xrd-ceph-demo container:
#     docker exec xrd-ceph-demo ceph auth get-or-create client.bob \
#       mon 'allow r' osd 'allow rwx pool=xrdtest' -o /tmp/ceph.client.bob.keyring
#     docker exec xrd-ceph-demo ceph auth get-or-create client.readonly \
#       mon 'allow r' osd 'allow r pool=xrdtest' -o /tmp/ceph.client.readonly.keyring
#   ...then copied into the WORK container's /etc/ceph/ (this script does that).
#
#   Also provisions 10 extra read-only CephX users (client.u0..client.u9) used
#   ONLY to force LRU eviction pressure on the sd_ceph per-user cred-conn
#   cache (SD_CEPH_CRED_CONN_CACHE_MAX=8 slots) while bob's write handle from
#   case (a)/(d) stays open — this is the regression test for the UAF where
#   the LRU evictor used to destroy a still-in-use connection (fixed via
#   sd_ceph_conn_t refcount/pin; see sd_ceph_conn_pin/_unpin in sd_ceph.c).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK="${WORK:-xrd-ceph-work}"
DEMO="${DEMO:-xrd-ceph-demo}"
POOL="${CEPH_POOL:-xrdtest}"

docker ps --format '{{.Names}}' | grep -qx "$WORK" \
    || { echo "work container '$WORK' not running — run tests/ceph/build_in_container.sh" >&2; exit 1; }
docker ps --format '{{.Names}}' | grep -qx "$DEMO" \
    || { echo "demo cluster container '$DEMO' not running — run tests/ceph_harness.sh start" >&2; exit 1; }

echo "run_sd_ceph_cred_live: provisioning bob (rwx) + readonly (r) CephX users"
docker exec "$DEMO" bash -lc '
    ceph auth get-or-create client.bob mon "allow r" osd "allow rwx pool='"$POOL"'" \
        -o /tmp/ceph.client.bob.keyring
    ceph auth get-or-create client.readonly mon "allow r" osd "allow r pool='"$POOL"'" \
        -o /tmp/ceph.client.readonly.keyring
'
docker exec "$DEMO" cat /tmp/ceph.client.bob.keyring      | docker exec -i "$WORK" tee /etc/ceph/ceph.client.bob.keyring      >/dev/null
docker exec "$DEMO" cat /tmp/ceph.client.readonly.keyring | docker exec -i "$WORK" tee /etc/ceph/ceph.client.readonly.keyring >/dev/null

echo "run_sd_ceph_cred_live: provisioning 10 extra CephX users (client.u0..u9) for cred-conn LRU eviction-pressure regression test"
docker exec "$DEMO" bash -lc '
    for i in $(seq 0 9); do
        ceph auth get-or-create client.u$i mon "allow r" osd "allow r pool='"$POOL"'" \
            -o /tmp/ceph.client.u$i.keyring
    done
'
for i in $(seq 0 9); do
    docker exec "$DEMO" cat /tmp/ceph.client.u$i.keyring \
        | docker exec -i "$WORK" tee /etc/ceph/ceph.client.u$i.keyring >/dev/null
done

echo "run_sd_ceph_cred_live: refreshing driver + test sources into the container"
docker exec "$WORK" mkdir -p /work/repo/tests/ceph /work/repo/src/fs/backend/rados /work/repo/client/apps/ceph
docker cp "$REPO/src/fs/backend/rados/sd_ceph.c"          "$WORK:/work/repo/src/fs/backend/rados/sd_ceph.c"
# phase-79 file-size split: sd_ceph.c's ops moved into these siblings + internal header.
docker cp "$REPO/src/fs/backend/rados/sd_ceph_io.c"       "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_io.c"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_object.c"   "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_object.c"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_cred.c"     "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_cred.c"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_internal.h" "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_internal.h"
docker cp "$REPO/src/fs/backend/rados/sd_ceph.h"          "$WORK:/work/repo/src/fs/backend/rados/sd_ceph.h"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_compat.c"   "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_compat.c"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_compat.h"   "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_compat.h"
docker cp "$REPO/src/fs/backend/rados/sd_ceph_striper.h"  "$WORK:/work/repo/src/fs/backend/rados/sd_ceph_striper.h"
docker cp "$REPO/src/fs/backend/ucred.h"                  "$WORK:/work/repo/src/fs/backend/ucred.h"
docker cp "$REPO/tests/ceph/sd_ceph_cred_live_test.c"     "$WORK:/work/repo/tests/ceph/sd_ceph_cred_live_test.c"
docker cp "$REPO/client/apps/ceph/ngx_shim.h"             "$WORK:/work/repo/client/apps/ceph/ngx_shim.h"

docker exec \
    -e CEPH_POOL="$POOL" \
    -e CEPH_CONF=/etc/ceph/ceph.conf \
    -e CEPH_BOB_KEYRING=/etc/ceph/ceph.client.bob.keyring \
    -e CEPH_READONLY_KEYRING=/etc/ceph/ceph.client.readonly.keyring \
    -e CEPH_UN_KEYRING_DIR=/etc/ceph \
    "$WORK" bash -lc '
    cd /work/repo &&
    gcc -Wall -Wextra -Werror -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH \
        -I src -I src/fs/backend -I src/fs/backend/rados \
        -include client/apps/ceph/ngx_shim.h \
        tests/ceph/sd_ceph_cred_live_test.c src/fs/backend/rados/sd_ceph.c \
        src/fs/backend/rados/sd_ceph_io.c src/fs/backend/rados/sd_ceph_object.c \
        src/fs/backend/rados/sd_ceph_cred.c \
        src/fs/backend/rados/sd_ceph_compat.c \
        -lrados -o /tmp/sd_ceph_cred_live &&
    /tmp/sd_ceph_cred_live'
