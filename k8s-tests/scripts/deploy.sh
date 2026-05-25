#!/usr/bin/env bash
# deploy.sh — Deploy nginx-xrootd stack to minikube.
set -euo pipefail

NAMESPACE="${NAMESPACE:-k8s-tests-dev}"
PROFILE="${PROFILE:-dev}"
AUTH_MODE="${AUTH_MODE:-anonymous}"
K8S_TESTS_DIR="$(cd "$(dirname "$0")/.." && pwd)"

log() { echo "[deploy] $*" >&2; }

deploy_infra() {
    log "Deploying test infrastructure to namespace '$NAMESPACE'..."
    helm upgrade --install cert-manager jetstack/cert-manager \
        --namespace cert-manager --create-namespace \
        --set crds.enabled=true || true
    
    helm upgrade --install test-infra "$K8S_TESTS_DIR/test-infra-helm" \
        --namespace "$NAMESPACE" --create-namespace \
        -f "$K8S_TESTS_DIR/test-infra-helm/values.yaml"
}

deploy_servers() {
    log "Deploying servers to namespace '$NAMESPACE' (profile: $PROFILE)..."
    helm upgrade --install xrootd-servers "$K8S_TESTS_DIR/server-helm" \
        --namespace "$NAMESPACE" --create-namespace \
        -f "$K8S_TESTS_DIR/server-helm/values.$PROFILE.yaml"
}

uninstall_servers() {
    log "Uninstalling servers from namespace '$NAMESPACE'..."
    helm uninstall xrootd-servers --namespace "$NAMESPACE" || true
}

uninstall_infra() {
    log "Uninstalling test infrastructure from namespace '$NAMESPACE'..."
    helm uninstall test-infra --namespace "$NAMESPACE" || true
    helm uninstall cert-manager --namespace cert-manager || true
}

case "${1:-}" in
    infra)   deploy_infra ;;
    servers) deploy_servers ;;
    all)     deploy_infra; deploy_servers ;;
    servers-uninstall) uninstall_servers ;;
    infra-uninstall)   uninstall_infra ;;
    all-uninstall)     uninstall_servers; uninstall_infra ;;
    *)       echo "Usage: $0 {infra|servers|all|servers-uninstall|infra-uninstall|all-uninstall}"; exit 1 ;;
esac
