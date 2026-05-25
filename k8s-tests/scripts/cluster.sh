#!/usr/bin/env bash
# cluster.sh — Manage the minikube cluster for nginx-xrootd testing.
set -euo pipefail

NODES="${NODES:-2}"
CPUS="${CPUS:-4}"
MEMORY="${MEMORY:-8192}"
PROFILE="${MINIKUBE_PROFILE:-xrootd-integration}"

log() { echo "[cluster] $*" >&2; }

start() {
    log "Starting minikube profile '$PROFILE' ($NODES nodes, $CPUS CPUs, ${MEMORY}MB)..."
    minikube start \
        --profile="$PROFILE" \
        --nodes="$NODES" \
        --cpus="$CPUS" \
        --memory="${MEMORY}m" \
        --driver=docker \
        --kubernetes-version=v1.28.3 \
        --extra-config=kubeadm.pod-network-cidr=10.244.0.0/16,fd00:10:244::/64 \
        --extra-config=kubeadm.service-cluster-ip-range=172.16.0.0/16,fd00:172:16::/112 \
        --feature-gates=IPv6DualStack=true \
        --wait=all
    
    minikube addons enable ingress --profile="$PROFILE"
    minikube addons enable metrics-server --profile="$PROFILE"
    log "Cluster ready."
}

stop() {
    log "Stopping minikube profile '$PROFILE'..."
    minikube stop --profile="$PROFILE"
}

delete() {
    log "Deleting minikube profile '$PROFILE'..."
    minikube delete --profile="$PROFILE"
}

status() {
    minikube status --profile="$PROFILE"
}

case "${1:-}" in
    start)  start ;;
    stop)   stop ;;
    delete) delete ;;
    status) status ;;
    *)      echo "Usage: $0 {start|stop|delete|status}"; exit 1 ;;
esac
