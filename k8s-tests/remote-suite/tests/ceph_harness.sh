#!/usr/bin/env bash
#
# ceph_harness.sh — single-node Ceph (RADOS) test cluster in Docker.
#
# WHAT: brings up the all-in-one `quay.io/ceph/demo` container (MON+MGR+OSD) on
#       the host network, creates the test pool, and extracts a ceph.conf +
#       admin keyring so host-side librados clients (the nginx sd_ceph driver and
#       the standalone tests) can connect. Drives the phase-60 Ceph backend.
# WHY:  phase-60 / scan phase-4b need a real RADOS pool to exercise the catalog
#       enumerate verb + inventory/drift orphan detection cross-backend.
# HOW:  `ceph_harness.sh start|stop|status|env|pool-reset`. `env` prints the
#       shell exports (TEST_CEPH=1, CEPH_CONF, CEPH_KEYRING, CEPH_POOL,
#       CEPH_MON_HOST) for `eval "$(tests/ceph_harness.sh env)"`.
#
# Overridable: CEPH_IMAGE, CEPH_POOL, CEPH_CONTAINER, CEPH_DIR, MON_IP.
set -euo pipefail

CEPH_IMAGE="${CEPH_IMAGE:-quay.io/ceph/demo:latest-reef}"
CEPH_CONTAINER="${CEPH_CONTAINER:-xrd-ceph-demo}"
CEPH_POOL="${CEPH_POOL:-xrdtest}"
CEPH_DIR="${CEPH_DIR:-/tmp/ceph-harness}"
CEPH_CONF="${CEPH_DIR}/ceph.conf"
CEPH_KEYRING="${CEPH_DIR}/ceph.client.admin.keyring"

PROBE_IMAGE="${PROBE_IMAGE:-alpine}"

# The container-visible primary IPv4 CIDR (e.g. 192.168.65.3/24). Probed from
# INSIDE a host-net container so it is correct whether the daemon shares the real
# host network (native Docker) or the Docker-Desktop VM. Skips lo and /32 addrs.
detect_container_cidr() {
    docker run --rm --network host "$PROBE_IMAGE" ip -4 -o addr show 2>/dev/null \
      | awk '$2!="lo" && $4 !~ /\/32$/ && $4 !~ /^172\.1[0-9]\./ {print $4; exit}'
}

# Network of a CIDR, e.g. 192.168.65.3/24 → 192.168.65.0/24.
cidr_net() {
    python3 -c "import ipaddress; print(ipaddress.ip_network('$1', strict=False))"
}
cidr_ip() { echo "${1%/*}"; }

# The MON's reachable address — the container IP (for the ceph.conf mon_host).
detect_ip() {
    if [ -n "${MON_IP:-}" ]; then echo "$MON_IP"; return; fi
    cidr_ip "$(detect_container_cidr)"
}

wait_health() {
    local i
    for i in $(seq 1 90); do
        if docker exec "$CEPH_CONTAINER" ceph -s 2>/dev/null \
             | grep -qE 'HEALTH_OK|HEALTH_WARN'; then
            return 0
        fi
        sleep 2
    done
    echo "ceph_harness: cluster did not become healthy in time" >&2
    docker logs --tail 40 "$CEPH_CONTAINER" >&2 || true
    return 1
}

cmd_start() {
    if docker ps --format '{{.Names}}' | grep -qx "$CEPH_CONTAINER"; then
        echo "ceph_harness: $CEPH_CONTAINER already running"
    else
        docker rm -f "$CEPH_CONTAINER" >/dev/null 2>&1 || true
        # The demo image needs an explicit MON_IP + CEPH_PUBLIC_NETWORK. Derive
        # both from the container-visible interface (correct on native Docker AND
        # the Docker-Desktop VM). An explicit MON_IP override still wins.
        local cidr mon net
        if [ -n "${MON_IP:-}" ]; then
            mon="$MON_IP"; net="${CEPH_PUBLIC_NETWORK:-$(cidr_net "$MON_IP/24")}"
        else
            cidr="$(detect_container_cidr)"
            [ -n "$cidr" ] || { echo "ceph_harness: cannot detect container IP" >&2; exit 1; }
            mon="$(cidr_ip "$cidr")"; net="$(cidr_net "$cidr")"
        fi
        echo "ceph_harness: starting $CEPH_IMAGE  MON_IP=$mon  NET=$net"
        docker run -d --name "$CEPH_CONTAINER" --network host \
            -e MON_IP="$mon" -e CEPH_PUBLIC_NETWORK="$net" \
            -e CEPH_DAEMON=demo -e DEMO_DAEMONS="mon,mgr,osd" \
            -e RGW_NAME=localhost \
            "$CEPH_IMAGE" >/dev/null
        wait_health
    fi

    mkdir -p "$CEPH_DIR"
    docker cp "$CEPH_CONTAINER:/etc/ceph/ceph.conf" "$CEPH_CONF"
    docker cp "$CEPH_CONTAINER:/etc/ceph/ceph.client.admin.keyring" "$CEPH_KEYRING"

    # Idempotent test pool.
    if ! docker exec "$CEPH_CONTAINER" ceph osd pool ls 2>/dev/null | grep -qx "$CEPH_POOL"; then
        docker exec "$CEPH_CONTAINER" ceph osd pool create "$CEPH_POOL" 32 32 >/dev/null
        docker exec "$CEPH_CONTAINER" ceph osd pool application enable "$CEPH_POOL" rados >/dev/null 2>&1 || true
        # single-OSD demo: 1 replica so the test pool is fully active (HEALTH_OK
        # for its PGs; the demo's own default pools may still warn — harmless).
        docker exec "$CEPH_CONTAINER" ceph osd pool set "$CEPH_POOL" size 1 >/dev/null 2>&1 || true
        docker exec "$CEPH_CONTAINER" ceph osd pool set "$CEPH_POOL" min_size 1 >/dev/null 2>&1 || true
    fi
    echo "ceph_harness: pool '$CEPH_POOL' ready; conf=$CEPH_CONF keyring=$CEPH_KEYRING"
    cmd_env
}

cmd_env() {
    local ip; ip="$(detect_ip)"
    echo "export TEST_CEPH=1"
    echo "export CEPH_CONF='$CEPH_CONF'"
    echo "export CEPH_KEYRING='$CEPH_KEYRING'"
    echo "export CEPH_POOL='$CEPH_POOL'"
    echo "export CEPH_MON_HOST='$ip'"
}

cmd_status() { docker exec "$CEPH_CONTAINER" ceph -s; }

cmd_pool_reset() {
    docker exec "$CEPH_CONTAINER" ceph osd pool delete "$CEPH_POOL" "$CEPH_POOL" \
        --yes-i-really-really-mean-it >/dev/null 2>&1 || true
    docker exec "$CEPH_CONTAINER" ceph osd pool create "$CEPH_POOL" 32 32 >/dev/null
    docker exec "$CEPH_CONTAINER" ceph osd pool application enable "$CEPH_POOL" rados >/dev/null 2>&1 || true
    echo "ceph_harness: pool '$CEPH_POOL' recreated"
}

cmd_stop() { docker rm -f "$CEPH_CONTAINER" >/dev/null 2>&1 || true; echo "ceph_harness: stopped"; }

case "${1:-}" in
    start)       cmd_start ;;
    stop)        cmd_stop ;;
    status)      cmd_status ;;
    env)         cmd_env ;;
    pool-reset)  cmd_pool_reset ;;
    *) echo "usage: $0 {start|stop|status|env|pool-reset}" >&2; exit 2 ;;
esac
