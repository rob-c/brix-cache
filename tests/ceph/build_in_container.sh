#!/usr/bin/env bash
#
# build_in_container.sh — build the nginx-xrootd module WITH the Ceph backend
# inside the xrd-ceph-build image, against the tests/ceph_harness.sh cluster.
#
# WHY: this host is Docker Desktop (WSL2) — the Ceph MON lives in the DD VM and
#      is only reachable from `--network host` containers, and librados-devel is
#      not installable on the (RHEL) host. So we build + run the module in a
#      CentOS-Stream container that has librados-devel and shares the DD VM net.
#
# Bind mounts from this WSL2 distro don't surface in the DD VM, so the source is
# delivered as a tar stream via `docker cp` (works regardless of file sharing).
#
#   tests/ceph/build_in_container.sh            # build the module (+ ceph)
#   docker exec -it xrd-ceph-work bash          # poke around / run nginx
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
IMAGE="${IMAGE:-xrd-ceph-build}"
WORK="${WORK:-xrd-ceph-work}"
CEPH_DIR="${CEPH_DIR:-/tmp/ceph-harness}"

command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || { echo "build the image first: docker build -f tests/ceph/Dockerfile.build -t $IMAGE tests/ceph" >&2; exit 1; }

# The cluster must be up (its conf/keyring feed the in-container nginx ceph export).
[ -f "${CEPH_DIR}/ceph.conf" ] \
    || { echo "start the cluster first: tests/ceph_harness.sh start" >&2; exit 1; }

echo "build_in_container: (re)starting work container '$WORK' on host net"
docker rm -f "$WORK" >/dev/null 2>&1 || true
docker run -d --name "$WORK" --network host "$IMAGE" -c 'sleep infinity' >/dev/null

echo "build_in_container: delivering source (tar → docker exec, volatile dirs excluded)"
docker exec "$WORK" mkdir -p /work/repo
TARBALL="$(mktemp /tmp/xrd-src.XXXXXX.tgz)"
# Tar to a file first so a volatile "file changed as we read it" (the live test
# tree) is a tolerable exit 1, not a broken pipe. Exclude build/junk/volatile.
tar czf "$TARBALL" \
    --exclude=./.git --exclude=./.tmp --exclude=./client/bin \
    --exclude='*.o' --exclude='*.pic.o' --exclude='*.pyc' \
    --exclude='__pycache__' --exclude=./tests/.pytest_cache \
    -C "$REPO" . || [ "$?" -le 1 ]
docker exec -i "$WORK" tar xzf - -C /work/repo < "$TARBALL"
rm -f "$TARBALL"

echo "build_in_container: wiring this cluster's ceph.conf/keyring into the container"
docker cp "${CEPH_DIR}/ceph.conf" "$WORK:/etc/ceph/ceph.conf"
docker cp "${CEPH_DIR}/ceph.client.admin.keyring" "$WORK:/etc/ceph/ceph.client.admin.keyring"

echo "build_in_container: configure + make (BRIX_HAVE_CEPH expected)"
docker exec "$WORK" bash -lc '
    set -e
    cd /opt/nginx-src
    ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
                --with-http_dav_module --with-threads \
                --add-module=/work/repo 2>&1 | tee /tmp/configure.log | tail -3
    grep -q "BRIX_HAVE_CEPH" objs/ngx_auto_config.h objs/Makefile 2>/dev/null \
        && echo "==> BRIX_HAVE_CEPH detected" \
        || echo "==> WARNING: Ceph NOT detected (sd_ceph compiled out)"
    make -j"$(nproc)" 2>&1 | tail -5
    ls -l objs/nginx
'
echo "build_in_container: done. nginx binary is at /opt/nginx-src/objs/nginx inside '$WORK'."
