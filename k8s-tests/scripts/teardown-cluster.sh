#!/usr/bin/env bash
# Clean up all Kubernetes resources created by setup-minikube.sh and related deployment scripts.
set -euo pipefail

CLUSTER_NAME="${1:-hep-tests}"
NAMESPACE="hep-tests-dev"

echo "=== Teardown: Removing K8s test infrastructure ==="

case "$(command -v kind 2>/dev/null && echo kind || command -v minikube 2>/dev/null && echo minikube)" in
    *kind*)
        if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
            echo "Deleting Kind cluster: $CLUSTER_NAME"
            kind delete cluster --name "$CLUSTER_NAME"
        else
            echo "Kind cluster '$CLUSTER_NAME' not found, skipping."
        fi
        ;;
    *minikube*)
        if minikube status &>/dev/null 2>&1; then
            echo "Deleting Minikube cluster"
            minikube delete --all
        else
            echo "Minikube not running, skipping."
        fi
        ;;
esac

echo "Done."
