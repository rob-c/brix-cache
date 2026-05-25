#!/usr/bin/env bash
# test.sh — Run integration tests in the minikube cluster.
set -euo pipefail

NAMESPACE="${NAMESPACE:-k8s-tests-dev}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
AUTH_MODE="${AUTH_MODE:-anonymous}"
K8S_TESTS_DIR="$(cd "$(dirname "$0")/.." && pwd)"

log() { echo "[test] $*" >&2; }

run_tests() {
    log "Waiting for servers in '$NAMESPACE'..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=server \
        -n "$NAMESPACE" --timeout=300s || true

    log "Starting test-job (auth: $AUTH_MODE)..."
    helm upgrade --install test-job "$K8S_TESTS_DIR/test-infra-helm" \
        --namespace "$NAMESPACE" \
        --set job.image="nginx-xrootd-test-runner:$IMAGE_TAG" \
        --set job.imagePullPolicy=Never \
        --set job.authMode="$AUTH_MODE"

    log "Waiting for test completion..."
    kubectl wait --for=condition=complete job/test-job \
        -n "$NAMESPACE" --timeout=1800s || true

    log "Collecting results..."
    mkdir -p /tmp/k8s-test-results
    kubectl cp "$NAMESPACE/test-runner:/test-results/*.xml" /tmp/k8s-test-results/ 2>/dev/null || true
    
    if ls /tmp/k8s-test-results/*.xml &>/dev/null; then
        python3 "$K8S_TESTS_DIR/test-runner/aggregate_results.py" \
            --results-dir /tmp/k8s-test-results \
            -o /tmp/test-summary.json
        cat /tmp/test-summary.json
    else
        log "No XML results found. Streaming logs instead:"
        kubectl logs -l app.kubernetes.io/component=test-runner -n "$NAMESPACE" --tail=-1 || true
    fi
}

run_tests
