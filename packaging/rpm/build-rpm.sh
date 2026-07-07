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
spec_src="$repo_root/packaging/rpm/nginx-mod-brix-cache.spec"
spec_dst="$topdir/SPECS/nginx-mod-brix-cache.spec"

mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,tmp}

tar \
    --exclude-vcs \
    --exclude='./.rpmbuild' \
    --exclude='./.tmp' \
    --exclude='./.claude' \
    --exclude='./.codex' \
    --exclude='./.pytest_cache' \
    --exclude='./.venv' \
    --exclude='./.venv*' \
    --exclude='./__pycache__' \
    --exclude='./*.pyc' \
    --exclude='./davs:*' \
    --exclude='./tests/davs:*' \
    --exclude='./tests/nginx-bin' \
    --exclude='./tests/__pycache__' \
    --exclude='*.o' \
    --exclude='*.a' \
    --exclude='./client/*.d' \
    --exclude='*.so' \
    --exclude='*.pc' \
    --exclude='./shared/xrdproto/build' \
    --exclude='./tools' \
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
    -ba "$spec_dst"
