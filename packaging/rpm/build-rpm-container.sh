#!/usr/bin/env bash
# build-rpm-container.sh — build RPM(s) inside a container to avoid polluting
# the host and to support cross-distro builds (AlmaLinux 9 and 10).
#
# Usage:
#   packaging/rpm/build-rpm-container.sh [options]
#
# Options:
#   -v VERSION   Version string embedded in the RPM (default: 0.1.0)
#   -d DISTRO    Target distro: alma9 or alma10 (default: alma9)
#   -o OUTDIR    Directory to copy built RPMs into (default: dist/)
#   -e ENGINE    Container engine: docker or podman (auto-detected)
#   -h           Print this help
#
# Examples:
#   # Build for AlmaLinux 9 (default):
#   packaging/rpm/build-rpm-container.sh
#
#   # Build for AlmaLinux 10, version 1.2.3:
#   packaging/rpm/build-rpm-container.sh -d alma10 -v 1.2.3 -o /tmp/rpms

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"

version="0.1.0"
distro="alma9"
outdir="$repo_root/dist"
engine=""

usage() {
    sed -n '/^# Usage:/,/^[^#]/{ /^[^#]/d; s/^# \{0,1\}//; p }' "$0"
    exit 0
}

while getopts "v:d:o:e:h" opt; do
    case "$opt" in
        v) version="$OPTARG" ;;
        d) distro="$OPTARG" ;;
        o) outdir="$OPTARG" ;;
        e) engine="$OPTARG" ;;
        h) usage ;;
        *) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
    esac
done

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
    echo "Available distros: alma8, alma9, alma10, alma11" >&2
    exit 1
fi

image_tag="nginx-xrootd-rpm-builder:${distro}-${version}"
container_name="nginx-xrootd-rpm-extract-$$"

echo "==> Building RPM for ${distro}, version ${version}"
echo "    Engine   : ${engine}"
echo "    Dockerfile: ${dockerfile}"
echo "    Image tag : ${image_tag}"
echo "    Output    : ${outdir}"
echo ""

# Build the image from the repo root so the full source tree is the build
# context, matching the COPY . . instruction in the Dockerfiles.
"$engine" build \
    --file "$dockerfile" \
    --build-arg "VERSION=${version}" \
    --tag "$image_tag" \
    "$repo_root"

mkdir -p "$outdir"

# Create a temporary container, copy artifacts, then remove it.
"$engine" create --name "$container_name" "$image_tag" >/dev/null
"$engine" cp "${container_name}:/artifacts/." "$outdir/"
"$engine" rm "$container_name" >/dev/null

echo ""
echo "==> RPMs written to: ${outdir}"
find "$outdir" -name "*.rpm" -printf "    %f\n"
