#!/usr/bin/env bash
# fixed-ip.sh — Setup the specialized fixed-IP dual-stack environment.
set -euo pipefail

K8S_TESTS_DIR="$(cd "$(dirname "$0")/.." && pwd)"

log() { echo "[fixed-ip] $*" >&2; }

setup() {
    log "Starting cluster and building images..."
    NODES=1 bash "$K8S_TESTS_DIR/scripts/cluster.sh" start
    bash "$K8S_TESTS_DIR/scripts/build.sh" all

    log "Applying fixed-IP manifests..."
    kubectl apply -f "$K8S_TESTS_DIR/k8s-manifests/fixed-ip-vms.yaml"

    log "Waiting for environment..."
    kubectl wait --for=condition=ready pod -l app=nginx-xrootd -n xrootd-fixed-ip --timeout=300s
    kubectl wait --for=condition=ready pod -l app=official-xrootd -n xrootd-fixed-ip --timeout=300s
    kubectl wait --for=condition=ready pod -l app=test-runner -n xrootd-fixed-ip --timeout=300s

    log "Fixed-IP Dual-Stack Environment Ready:"
    echo "  nginx-xrootd     : 172.16.0.2  / fd00:172:16::2"
    echo "  official-xrootd  : 172.16.0.50 / fd00:172:16::50"
    echo "  test-runner      : 172.16.0.100/ fd00:172:16::100"
}

setup
