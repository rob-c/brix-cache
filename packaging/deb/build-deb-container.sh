#!/usr/bin/env bash
# build-deb-container.sh — build the .deb set inside a container to avoid
# polluting the host and to support cross-release builds (Ubuntu 22.04 and
# 24.04).  Mirrors packaging/rpm/build-rpm-container.sh.
#
# Usage:
#   packaging/deb/build-deb-container.sh [options]
#
# Options:
#   -v VERSION   Version string embedded in the packages (default: derived
#                from BRIX_SERVER_VERSION_BARE in src/core/ident.h)
#   -d DISTRO    Target release: ubuntu22 or ubuntu24 (default: ubuntu24)
#   -f FLAVOR    Target nginx flavor: org (nginx.org packages; default) or
#                distro (Ubuntu-archive nginx + libnginx-mod-stream)
#   -n NGXVER    nginx version override (default: resolved from apt inside
#                the container — the nginx.org repo for org, the Ubuntu
#                archive for distro)
#   -o OUTDIR    Directory to copy built .debs into (default: dist/)
#   -e ENGINE    Container engine: docker or podman (auto-detected)
#   -h           Print this help
#
# Examples:
#   # Ubuntu 24.04 against nginx.org stable (default):
#   packaging/deb/build-deb-container.sh
#
#   # Ubuntu 24.04 against the Ubuntu-archive nginx (1.24.0 on noble):
#   packaging/deb/build-deb-container.sh -f distro
#
#   # Ubuntu 22.04, explicit version override:
#   packaging/deb/build-deb-container.sh -d ubuntu22 -v 1.2.3 -o /tmp/debs

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"

version=""
distro="ubuntu24"
flavor="org"
nginx_version=""
outdir="$repo_root/dist"
engine=""

usage() {
    sed -n '/^# Usage:/,/^set -euo/{ /^set -euo/d; s/^# \{0,1\}//; p }' "$0"
    exit 0
}

while getopts "v:d:f:n:o:e:h" opt; do
    case "$opt" in
        v) version="$OPTARG" ;;
        d) distro="$OPTARG" ;;
        f) flavor="$OPTARG" ;;
        n) nginx_version="$OPTARG" ;;
        o) outdir="$OPTARG" ;;
        e) engine="$OPTARG" ;;
        h) usage ;;
        *) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
    esac
done

# Default the version to the one baked into the source, unless -v overrides.
if [[ -z "$version" ]]; then
    version="$(sed -n 's/#define BRIX_SERVER_VERSION_BARE[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$repo_root/src/core/ident.h")"
    if [[ -z "$version" ]]; then
        echo "error: could not derive version from src/core/ident.h (BRIX_SERVER_VERSION_BARE)" >&2
        exit 1
    fi
fi

# Auto-detect container engine.
if [[ -z "$engine" ]]; then
    if command -v podman &>/dev/null; then
        engine="podman"
    elif command -v docker &>/dev/null; then
        engine="docker"
    else
        echo "error: neither podman nor docker found in PATH" >&2
        exit 1
    fi
fi

dockerfile="$script_dir/Dockerfile.${distro}"
if [[ ! -f "$dockerfile" ]]; then
    echo "error: no Dockerfile found for distro '${distro}' (expected: $dockerfile)" >&2
    echo "Available distros: ubuntu22, ubuntu24" >&2
    exit 1
fi

image_tag="brix-deb-builder:${distro}-${flavor}-${version}"
container_name="brix-deb-extract-$$"

echo "==> Building .debs for ${distro} (${flavor} nginx flavor), version ${version}"
echo "    Engine    : ${engine}"
echo "    Dockerfile: ${dockerfile}"
echo "    Image tag : ${image_tag}"
echo "    Output    : ${outdir}"
echo ""

# Build from the repo root so the full source tree is the build context,
# matching the COPY . . instruction in the Dockerfiles (filtered by the
# repo-root .dockerignore whitelist).
"$engine" build \
    --file "$dockerfile" \
    --build-arg "VERSION=${version}" \
    --build-arg "NGINX_FLAVOR=${flavor}" \
    --build-arg "NGINX_VERSION=${nginx_version}" \
    --tag "$image_tag" \
    "$repo_root"

mkdir -p "$outdir"

# Create a temporary container, copy artifacts, then remove it.
"$engine" create --name "$container_name" "$image_tag" >/dev/null
"$engine" cp "${container_name}:/artifacts/." "$outdir/"
"$engine" rm "$container_name" >/dev/null

echo ""
echo "==> Packages written to: ${outdir}"
find "$outdir" -name "*.deb" -printf "    %f\n" | sort
