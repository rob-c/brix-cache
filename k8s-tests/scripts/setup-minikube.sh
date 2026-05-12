#!/usr/bin/env bash
#
# Bootstrap a multi-node Kubernetes cluster for nginx-xrootd testing.
# Supports both minikube (legacy) and Kind (recommended).
#
# Usage:
#   scripts/setup-minikube.sh [OPTIONS]
#
# Options:
#   --cluster-type KIND|MINIKUBE  Cluster type (default: auto-detect)
#   --nodes N                      Number of worker nodes (default: 2, total = control + N)
#   --cpus N                       CPUs per node (default: 4)
#   --memory M                     Memory in MB per node (default: 8192)
#   --k8s-version VERSION          Kubernetes version to use
#   --wait SECONDS                 Max seconds to wait for cluster readiness (default: 300)
#   --no-cni                       Skip CNI installation (for testing without network policies)
#   --help                         Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CLUSTER_TYPE=""
NODES=2
CPUS=4
MEMORY=8192
K8S_VERSION=""
WAIT_SECS=300
NO_CNI=false
CLUSTER_NAME="hep-tests"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Bootstrap a multi-node Kubernetes cluster for nginx-xrootd testing.

Options:
  --cluster-type KIND|MINIKUBE  Cluster type (default: auto-detect)
  --nodes N                      Number of worker nodes (default: 2, total = control + N)
  --cpus N                       CPUs per node (default: 4)
  --memory M                     Memory in MB per node (default: 8192)
  --k8s-version VERSION          Kubernetes version to use
  --wait SECONDS                 Max seconds to wait for cluster readiness (default: 300)
  --no-cni                       Skip CNI installation (for testing without network policies)
  --help                         Show this help message

Examples:
  # Default Kind with auto-detection
  $(basename "$0")

  # Minikube with 3 nodes, 8GB RAM each
  $(basename "$0") --cluster-type minikube --nodes 2 --memory 8192

  # Kind with explicit version
  $(basename "$0") --k8s-version v1.29.2
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cluster-type) CLUSTER_TYPE="$2"; shift 2 ;;
        --nodes) NODES="$2"; shift 2 ;;
        --cpus) CPUS="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --k8s-version) K8S_VERSION="$2"; shift 2 ;;
        --wait) WAIT_SECS="$2"; shift 2 ;;
        --no-cni) NO_CNI=true; shift ;;
        --help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# Auto-detect cluster type if not specified
if [[ -z "$CLUSTER_TYPE" ]]; then
    if command -v kind &>/dev/null && ! command -v minikube &>/dev/null; then
        CLUSTER_TYPE="kind"
    elif command -v minikube &>/dev/null && ! command -v kind &>/dev/null; then
        CLUSTER_TYPE="minikube"
    else
        echo "ERROR: Neither 'kind' nor 'minikube' found on PATH." >&2
        echo "Install one of them to proceed:" >&2
        echo "  Kind (recommended): https://kind.sigs.k8s.io/docs/user/quick-start/" >&2
        echo "  Minikube:           https://minikube.sigs.k8s.io/docs/start/" >&2
        exit 1
    fi
fi

# Check required tools
for tool in kubectl; do
    if ! command -v "$tool" &>/dev/null; then
        echo "ERROR: '$tool' not found on PATH. Please install it." >&2
        exit 1
    fi
done

echo "=== nginx-xrootd K8s Cluster Bootstrap ==="
echo "Cluster type : $CLUSTER_TYPE"
echo "Nodes        : control-plane + $NODES worker(s)"
echo "CPUs/node    : $CPUS"
echo "Memory/node  : ${MEMORY}MB"
if [[ -n "$K8S_VERSION" ]]; then
    echo "K8s version  : $K8S_VERSION"
fi

# Kill existing cluster if present
echo ""
echo "--- Stopping any existing cluster ---"
case "$CLUSTER_TYPE" in
    kind)
        if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
            echo "Deleting existing Kind cluster: $CLUSTER_NAME"
            kind delete cluster --name "$CLUSTER_NAME" || true
        fi
        ;;
    minikube)
        if minikube status &>/dev/null 2>&1; then
            echo "Stopping existing Minikube cluster"
            minikube stop || true
            minikube delete || true
        fi
        ;;
esac

# Create the cluster
echo ""
echo "--- Creating new cluster ---"

case "$CLUSTER_TYPE" in
    kind)
        # Build Kind config from parameters
        KIND_CONFIG="/tmp/kind-config-$$"
        
        CNI_ARGS=""
        if [[ "$NO_CNI" != "true" ]]; then
            echo "Installing Calico CNI (recommended for network policies)..."
            kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
            echo "Waiting for Calico to be ready..."
            kubectl wait --for=condition=ready pod -l k8s-app=calico-node \
                --namespace=kube-system --timeout="${WAIT_SECS}s" || true
        fi
        
        cat > "$KIND_CONFIG" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
networking:
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.96.0.0/12"
nodes:
- role: control-plane
  extraPortMappings:
    - containerPort: 1094
      hostPort: 1094
      protocol: TCP
    - containerPort: 1095
      hostPort: 1095
      protocol: TCP
    - containerPort: 8443
      hostPort: 8443
      protocol: TCP
    - containerPort: 9100
      hostPort: 9100
      protocol: TCP
$(for i in $(seq 1 $NODES); do
cat <<EOF
- role: worker
  extraPortMappings:
    - containerPort: 1094
      hostPort: 1094
      protocol: TCP
    - containerPort: 8443
      hostPort: 8443
      protocol: TCP
$(if [[ "$i" -gt 1 ]]; then echo "    - containerPort: 1095"; echo "      hostPort: 1095"; echo "      protocol: TCP"; fi)
EOF
done)
EOF

        KIND_ARGS="--config $KIND_CONFIG"
        if [[ -n "$K8S_VERSION" ]]; then
            KIND_ARGS="$KIND_ARGS --image kindest/node:${K8S_VERSION}"
        fi
        
        kind create cluster \
            --name "$CLUSTER_NAME" \
            $KIND_ARGS \
            --wait "${WAIT_SECS}s" || { echo "ERROR: Cluster creation failed"; rm -f "$KIND_CONFIG"; exit 1; }
        
        rm -f "$KIND_CONFIG"
        ;;

    minikube)
        MINIKUBE_ARGS="--nodes=$NODES --cpus=$CPUS --memory=${MEMORY}000 --driver=docker"
        if [[ -n "$K8S_VERSION" ]]; then
            MINIKUBE_ARGS="$MINIKUBE_ARGS --kubernetes-version=$K8S_VERSION"
        fi
        
        minikube start $MINIKUBE_ARGS || { echo "ERROR: Cluster creation failed"; exit 1; }
        
        if [[ "$NO_CNI" != "true" ]]; then
            echo "Enabling minikube addons..."
            minikube addons enable metrics-server || true
            # Ingress not needed for testing but can be enabled if external access is required
        fi
        ;;
esac

# Verify cluster readiness
echo ""
echo "--- Verifying cluster ---"
echo "Waiting for nodes to become Ready..."

READY_TIMEOUT=$((WAIT_SECS / 2))
kubectl wait --for=condition=Ready node --all \
    --timeout="${READY_TIMEOUT}s" || { echo "WARNING: Not all nodes ready after ${READY_TIMEOUT}s"; }

echo ""
echo "--- Cluster Nodes ---"
kubectl get nodes -o wide

echo ""
echo "--- Namespace Setup ---"
# Create the test namespace with appropriate labels
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: hep-tests-dev
  labels:
    app.kubernetes.io/managed-by: nginx-xrootd-k8s-tests
    environment: development
EOF

echo ""
echo "--- Cluster bootstrap complete ---"
echo ""
echo "Next steps:"
echo "  1. Deploy test infrastructure (PKI, cert-manager):"
echo "     helm upgrade --install test-infra ./test-infra-helm \\"
echo "         --namespace hep-tests-dev --create-namespace"
echo ""
echo "  2. Deploy nginx-xrootd servers:"
echo "     helm upgrade --install xrootd-servers ./server-helm \\"
echo "         --namespace hep-tests-dev -f ./server-helm/values.dev.yaml"
echo ""
echo "  3. Run tests:"
echo "     make test namespace=hep-tests-dev profile=dev"
echo ""
