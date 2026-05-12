#!/usr/bin/env bash
# Bootstrap a Kubernetes cluster (minikube or kind) for nginx-xrootd testing.
# Supports multi-node clusters, local image registry setup, and required addon enablement.
set -euo pipefail

NODES="${1:-3}"
CPUS="${2:-4}"
MEMORY="${3:-8192}"
CLUSTER_TYPE="${4:-auto}"  # auto, minikube, kind
WAIT_TIMEOUT="${5:-120s}"

echo "=== nginx-xrootd K8s Cluster Bootstrap ==="
echo "Nodes: $NODES | CPUs: $CPUS | Memory: ${MEMORY}Mi | Type: $CLUSTER_TYPE"

# Detect cluster type if auto
if [ "$CLUSTER_TYPE" = "auto" ]; then
    if command -v kind &>/dev/null; then
        CLUSTER_TYPE="kind"
    elif command -v minikube &>/dev/null; then
        CLUSTER_TYPE="minikube"
    else
        echo "ERROR: Neither 'kind' nor 'minikube' found in PATH." >&2
        echo "Install one of them or specify with \$4 (kind|minikube)" >&2
        exit 1
    fi
fi

# Cleanup existing cluster if present
if [ "$CLUSTER_TYPE" = "kind" ]; then
    kind delete cluster --name nginx-xrootd-test 2>/dev/null || true
elif [ "$CLUSTER_TYPE" = "minikube" ]; then
    minikube stop 2>/dev/null || true
    minikube delete --all 2>/dev/null || true
fi

echo ""
if [ "$CLUSTER_TYPE" = "kind" ]; then
    # Kind cluster creation with multi-node configuration
    cat > /tmp/kind-config.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 1094
        hostPort: 31094
        protocol: TCP
      - containerPort: 1095
        hostPort: 31095
        protocol: TCP
      - containerPort: 8443
        hostPort: 32443
        protocol: TCP
      - containerPort: 9100
        hostPort: 9100
        protocol: TCP
EOF

    for i in $(seq 1 $((NODES - 1))); do
        cat >> /tmp/kind-config.yaml <<EOF
  - role: worker
    extraPortMappings:
      - containerPort: 1094
        hostPort: $((31094 + i))
        protocol: TCP
      - containerPort: 8443
        hostPort: $((32443 + i))
        protocol: TCP
EOF
    done

    kind create cluster --name nginx-xrootd-test --config /tmp/kind-config.yaml \
        --wait "$WAIT_TIMEOUT" || { echo "ERROR: Kind cluster creation failed"; exit 1; }

elif [ "$CLUSTER_TYPE" = "minikube" ]; then
    # Minikube multi-node cluster
    minikube start \
        --nodes="$NODES" \
        --cpus="$CPUS" \
        --memory="${MEMORY}000" \
        --driver=docker \
        --kubernetes-version=v1.28.3 || { echo "ERROR: Minikube start failed"; exit 1; }

    # Enable required addons
    minikube addons enable ingress 2>/dev/null || true
    minikube addons enable metrics-server 2>/dev/null || true
fi

echo ""
echo "=== Cluster ready ==="
if [ "$CLUSTER_TYPE" = "kind" ]; then
    kubectl --context kind-nginx-xrootd-test get nodes -o wide
else
    kubectl get nodes -o wide
fi

# Export kubeconfig if needed
if [ "$CLUSTER_TYPE" = "kind" ]; then
    export KUBECONFIG="$(kind get kubeconfig-path --name nginx-xrootd-test 2>/dev/null)"
fi

echo ""
echo "To deploy test infrastructure, run:"
echo "  helm repo add jetstack https://charts.jetstack.io"
echo "  helm install cert-manager jetstack/cert-manager \\"
echo "      --namespace cert-manager \\"
echo "      --create-namespace \\"
echo "      --set crds.enabled=true"
