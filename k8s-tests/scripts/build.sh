#!/usr/bin/env bash
# build.sh — Build RPM and Docker images for nginx-xrootd.
set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-latest}"
K8S_TESTS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_DIR="$(cd "$K8S_TESTS_DIR/.." && pwd)"

log() { echo "[build] $*" >&2; }

build_rpm() {
    log "Building nginx-mod-xrootd RPM..."
    mkdir -p "$K8S_TESTS_DIR/rpms"
    docker build -t nginx-xrootd-rpm-builder -f "$K8S_TESTS_DIR/Dockerfiles/rpm-builder/Dockerfile" "$ROOT_DIR"
    
    local id
    id=$(docker create nginx-xrootd-rpm-builder)
    docker cp "$id:/artifacts/." "$K8S_TESTS_DIR/rpms/"
    docker rm "$id"
    log "RPM built and copied to k8s-tests/rpms/"
}

build_images() {
    local rpm_file
    rpm_file=$(ls "$K8S_TESTS_DIR/rpms"/nginx-mod-xrootd-*.rpm | head -n 1 | xargs basename)
    
    log "Building images using RPM: $rpm_file"
    for img in server client test-runner xrootd-reference; do
        if [ "$img" = "xrootd-reference" ]; then
            docker build -t "xrootd-reference:$IMAGE_TAG" \
                -f "$K8S_TESTS_DIR/Dockerfiles/xrootd-reference/Dockerfile" "$ROOT_DIR"
        else
            docker build -t "nginx-xrootd-$img:$IMAGE_TAG" \
                --build-arg "RPM_FILE=$rpm_file" \
                -f "$K8S_TESTS_DIR/Dockerfiles/$img/Dockerfile" "$ROOT_DIR"
        fi
        log "Built image: $img:$IMAGE_TAG"
    done
}

case "${1:-}" in
    rpm)    build_rpm ;;
    images) build_images ;;
    all)    build_rpm; build_images ;;
    *)      echo "Usage: $0 {rpm|images|all}"; exit 1 ;;
esac
