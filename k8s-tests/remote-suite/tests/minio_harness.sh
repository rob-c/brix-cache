#!/usr/bin/env bash
# minio_harness.sh — docker-managed MinIO for the S3 credential-forwarding tests
# (tests/test_minio_s3_forward.py). Mirrors ceph_harness.sh: {start|stop|status|env}.
#
# The container is the KNOWN-WORKING S3 backend the brix node forwards to; the
# harness only guarantees a healthy MinIO — bucket creation and data seeding are
# the test's job (signed SigV4 calls, no mc dependency).
#
# Idempotent start: an already-running healthy container is reused, so parallel
# test runs and manual `start` calls do not fight.
set -u

MINIO_CONTAINER="${MINIO_CONTAINER:-brix-test-minio}"
MINIO_IMAGE="${MINIO_IMAGE:-minio/minio:latest}"
MINIO_PORT="${MINIO_PORT:-29000}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:-minioadmin}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-minioadmin}"
HEALTH_URL="http://127.0.0.1:${MINIO_PORT}/minio/health/ready"

have_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

running() {
    [ "$(docker inspect -f '{{.State.Running}}' "$MINIO_CONTAINER" 2>/dev/null)" = "true" ]
}

healthy() { curl -sf -o /dev/null --max-time 2 "$HEALTH_URL"; }

wait_healthy() {
    local i
    for i in $(seq 1 30); do
        healthy && return 0
        sleep 1
    done
    return 1
}

cmd_start() {
    have_docker || { echo "minio_harness: docker unavailable" >&2; exit 3; }
    if running; then
        wait_healthy && { echo "minio_harness: already running on :${MINIO_PORT}"; return 0; }
        echo "minio_harness: container running but unhealthy — recreating" >&2
        docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
    else
        docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
    fi
    docker run -d --name "$MINIO_CONTAINER" \
        -p "127.0.0.1:${MINIO_PORT}:9000" \
        -e MINIO_ROOT_USER="$MINIO_ROOT_USER" \
        -e MINIO_ROOT_PASSWORD="$MINIO_ROOT_PASSWORD" \
        "$MINIO_IMAGE" server /data >/dev/null || exit 2
    wait_healthy || { echo "minio_harness: never became healthy" >&2; docker logs --tail 20 "$MINIO_CONTAINER" >&2; exit 2; }
    echo "minio_harness: started on :${MINIO_PORT}"
}

cmd_stop() {
    docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
    echo "minio_harness: stopped"
}

cmd_status() {
    if running && healthy; then echo "running healthy :${MINIO_PORT}"; exit 0; fi
    if running; then echo "running UNHEALTHY"; exit 1; fi
    echo "not running"; exit 1
}

cmd_env() {
    echo "export MINIO_PORT=${MINIO_PORT}"
    echo "export MINIO_ROOT_USER=${MINIO_ROOT_USER}"
    echo "export MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}"
}

case "${1:-}" in
    start)  cmd_start  ;;
    stop)   cmd_stop   ;;
    status) cmd_status ;;
    env)    cmd_env    ;;
    *) echo "usage: $0 {start|stop|status|env}" >&2; exit 1 ;;
esac
