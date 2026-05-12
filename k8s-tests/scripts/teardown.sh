#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${1:-k8s-tests-dev}"
MODE="${2:-helm-only}"

echo "=== Teardown nginx-xrootd K8s Test Infrastructure ==="
echo "Namespace: $NAMESPACE | Mode: $MODE"

echo "Uninstalling Helm releases..."
for release in xrootd-servers test-infra cert-manager; do
    kubectl --namespace "$NAMESPACE" delete job/test-job 2>/dev/null || true
    helm uninstall "$release" --namespace "$NAMESPACE" 2>/dev/null || echo "  $release: not found"
done

if [ "$MODE" = "cluster" ] || [ "$MODE" = "--all" ]; then
    echo "Deleting namespace and resources..."
    kubectl delete namespace "$NAMESPACE" --wait --timeout=120s 2>/dev/null || true
fi

if [ "$MODE" = "cluster" ] || [ "$MODE" = "--all" ]; then
    echo "Tearing down cluster..."
    if command -v kind &>/dev/null; then
        kind delete cluster --name nginx-xrootd-test 2>/dev/null || true
    elif command -v minikube &>/dev/null; then
        minikube delete --all 2>/dev/null || true
    fi
fi

echo "=== Teardown complete ==="
