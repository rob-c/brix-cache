#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"

# Version defaults to the one baked into the source (BRIX_SERVER_VERSION_BARE
# in src/core/ident.h); an explicit argument overrides it.
version="${1:-$(sed -n 's/#define BRIX_SERVER_VERSION_BARE[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$repo_root/src/core/ident.h")}"
if [[ -z "$version" ]]; then
    echo "error: could not derive version from src/core/ident.h (BRIX_SERVER_VERSION_BARE)" >&2
    exit 1
fi

topdir="${RPMBUILD_TOPDIR:-$repo_root/.rpmbuild}"
# Must match the spec's %%{upstream_name}-%%{version} unpack dir.
source_name="brix-$version"
source_archive="$topdir/SOURCES/$source_name.tar.gz"
spec_src="${RPM_SPEC:-$repo_root/packaging/rpm/nginx-mod-brix-cache.spec}"
spec_dst="$topdir/SPECS/$(basename "$spec_src")"
rpm_defines=()

# Alma-built packages carry a one-per-install platform notice package. It is
# quiet on AlmaLinux and warns when those RPMs are installed on Rocky Linux.
if [[ -r /etc/os-release ]]; then
    platform_id="$(sed -n 's/^ID=//p' /etc/os-release | tr -d "\"'" | sed -n '1p')"
    if [[ "$platform_id" == "almalinux" ]]; then
        rpm_defines+=(--define "brix_vendor_alma 1")
    fi
fi

if [[ ! -f "$spec_src" ]]; then
    echo "error: RPM spec not found: $spec_src" >&2
    exit 1
fi

mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,tmp}

tar \
    --exclude-vcs \
    --exclude='./.rpmbuild' \
    --exclude='./.debbuild' \
    --exclude='./.agents' \
    --exclude='./.tmp' \
    --exclude='./.claude' \
    --exclude='./.codex' \
    --exclude='./.pytest_cache' \
    --exclude='./.venv' \
    --exclude='./.venv*' \
    --exclude='./build' \
    --exclude='./__pycache__' \
    --exclude='./*.pyc' \
    --exclude='./davs:*' \
    --exclude='./tests/davs:*' \
    --exclude='./tests/nginx-bin' \
    --exclude='./tests/__pycache__' \
    --exclude='./client/bin' \
    --exclude='./client/*.dylib' \
    --exclude='*.o' \
    --exclude='*.a' \
    --exclude='./client/*.d' \
    --exclude='*.so' \
    --exclude='*.pc' \
    --exclude='./shared/xrdproto/build' \
    --exclude='./dist' \
    --exclude='./*.rpm' \
    --exclude='./*.src.rpm' \
    --transform "s,^\.,$source_name," \
    -czf "$source_archive" \
    -C "$repo_root" .

install -Dpm0644 "$spec_src" "$spec_dst"

rpmbuild \
    --define "_topdir $topdir" \
    --define "_tmppath $topdir/tmp" \
    --define "version_override $version" \
    "${rpm_defines[@]}" \
    -ba "$spec_dst"
