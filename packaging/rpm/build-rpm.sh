#!/usr/bin/env bash
set -euo pipefail

version="${1:-0.1.0}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
topdir="${RPMBUILD_TOPDIR:-$repo_root/.rpmbuild}"
source_name="nginx-xrootd-$version"
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
