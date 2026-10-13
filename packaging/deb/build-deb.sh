#!/usr/bin/env bash
# build-deb.sh — build the BriX-Cache .deb set on a Debian/Ubuntu host.
# The deb counterpart of packaging/rpm/build-rpm.sh: stages a filtered copy
# of the source tree, drops packaging/deb/debian/ in as ./debian, generates
# debian/changelog from the version baked into src/core/ident.h, unpacks the
# nginx source/SDK the module must be built against, and runs dpkg-buildpackage.
#
# Usage:
#   packaging/deb/build-deb.sh [options]
#
# Options:
#   -v VERSION   Package version (default: BRIX_SERVER_VERSION_BARE from
#                src/core/ident.h)
#   -f FLAVOR    Target nginx flavor: org (nginx.org packages; default) or
#                distro (Ubuntu-archive nginx + libnginx-mod-stream)
#   -n NGXVER    nginx version to build against (default: resolved from apt —
#                see resolve_nginx_version below; dynamic modules only load
#                into the EXACT nginx version they were built against)
#   -o OUTDIR    Directory to copy built .debs into (default: dist/)
#   -h           Print this help
#
# Build prerequisites (see debian/control Build-Depends):
#   apt-get build-dep ./packaging/deb   # or install the list by hand
#
# Examples:
#   # Build against nginx.org stable (version auto-resolved if the nginx.org
#   # apt repo is configured, else the pinned fallback below):
#   packaging/deb/build-deb.sh
#
#   # Build for the Ubuntu-archive nginx on this host:
#   packaging/deb/build-deb.sh -f distro
#
#   # Explicit nginx version (e.g. reproducing a site's pin):
#   packaging/deb/build-deb.sh -f org -n 1.28.0

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"

# Fallback when the nginx.org apt repo is not configured on the build host.
# Keep on the nginx.org *stable* branch — the same line the RPM builders'
# nginx.org repo tracks on EL.  (The container builds never use this: they
# resolve the live version from the nginx.org repo via apt-cache madison.)
org_nginx_fallback="1.30.4"

version=""
flavor="org"
nginx_version=""
outdir="$repo_root/dist"

usage() {
    sed -n '/^# Usage:/,/^set -euo/{ /^set -euo/d; s/^# \{0,1\}//; p }' "$0"
    exit 0
}

while getopts "v:f:n:o:h" opt; do
    case "$opt" in
        v) version="$OPTARG" ;;
        f) flavor="$OPTARG" ;;
        n) nginx_version="$OPTARG" ;;
        o) outdir="$OPTARG" ;;
        h) usage ;;
        *) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
    esac
done

case "$flavor" in
    org|distro) ;;
    *) echo "error: -f must be 'org' or 'distro' (got: $flavor)" >&2; exit 1 ;;
esac

# --- package version: single source of truth is src/core/ident.h ---
if [[ -z "$version" ]]; then
    version="$(sed -n 's/#define BRIX_SERVER_VERSION_BARE[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$repo_root/src/core/ident.h")"
    if [[ -z "$version" ]]; then
        echo "error: could not derive version from src/core/ident.h (BRIX_SERVER_VERSION_BARE)" >&2
        exit 1
    fi
fi

# --- nginx version the module is built against (exact-match at dlopen) ---
strip_deb_version() {
    # 1:1.24.0-2ubuntu7.15 -> 1.24.0
    local v="$1"
    v="${v#*:}"
    printf '%s\n' "${v%%-*}"
}

resolve_nginx_version() {
    local cand
    if [[ "$flavor" == "distro" ]]; then
        # Prefer the installed nginx, then the apt candidate.
        if cand="$(dpkg-query -W -f '${Version}' nginx 2>/dev/null)" && [[ -n "$cand" ]]; then
            strip_deb_version "$cand"; return
        fi
        cand="$(apt-cache policy nginx 2>/dev/null | sed -n 's/^ *Candidate: //p')"
        if [[ -n "$cand" && "$cand" != "(none)" ]]; then
            strip_deb_version "$cand"; return
        fi
        echo "error: cannot resolve the Ubuntu-archive nginx version (is apt configured?); pass -n" >&2
        exit 1
    fi
    # org flavor: only trust versions that actually come from nginx.org
    # (apt-cache madison prints the repo URL per candidate line).
    cand="$(apt-cache madison nginx 2>/dev/null | awk -F'|' '/nginx\.org/ { gsub(/ /,"",$2); print $2; exit }')"
    if [[ -n "$cand" ]]; then
        strip_deb_version "$cand"; return
    fi
    echo "warning: nginx.org apt repo not configured; falling back to nginx ${org_nginx_fallback}" >&2
    printf '%s\n' "$org_nginx_fallback"
}

resolve_distro_package_version() {
    local cand
    if cand="$(dpkg-query -W -f '${Version}' nginx 2>/dev/null)" && [[ -n "$cand" ]]; then
        printf '%s\n' "$cand"
        return
    fi
    cand="$(apt-cache policy nginx 2>/dev/null | sed -n 's/^ *Candidate: //p')"
    if [[ -n "$cand" && "$cand" != "(none)" ]]; then
        printf '%s\n' "$cand"
        return
    fi
    echo "error: cannot resolve the Ubuntu-archive nginx package version" >&2
    exit 1
}

if [[ -z "$nginx_version" ]]; then
    nginx_version="$(resolve_nginx_version)"
fi

codename="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}")"
deb_version="${version}-1"
if [[ -n "$codename" ]]; then
    deb_version="${version}-1~${codename}1"
fi

stage="${BRIX_DEBBUILD_DIR:-$repo_root/.debbuild}/${flavor}"
cache="${BRIX_DEBBUILD_DIR:-$repo_root/.debbuild}/cache"
srcdir="$stage/nginx-mod-brix-cache-$version"
nginx_src="$stage/nginx-$nginx_version"

echo "==> Building .debs: brix ${deb_version}, nginx ${nginx_version} (${flavor} flavor)"

rm -rf "$stage"
mkdir -p "$srcdir" "$cache" "$outdir"

# --- nginx source ----------------------------------------------------------
# Ubuntu may carry ABI-affecting patches without changing NGINX_VERSION or the
# dynamic-module signature.  In particular, resolute added a field to
# ngx_http_request_t; a module built from the same-version vanilla tarball
# loaded successfully and then misread request flags.  Distro builds therefore
# use the exact, version-locked nginx-dev SDK.  nginx.org builds continue to use
# the matching upstream tarball.
if [[ "$flavor" == "distro" ]]; then
    distro_package_version="$(resolve_distro_package_version)"
    sdk_version="$(dpkg-query -W -f '${Version}' nginx-dev 2>/dev/null || true)"
    sdk_source="/usr/share/nginx/src"
    if [[ "$sdk_version" != "$distro_package_version" ]]; then
        echo "error: distro builds require nginx-dev=$distro_package_version" >&2
        echo "       installed nginx-dev version: ${sdk_version:-not installed}" >&2
        echo "       install the exact candidate with: apt-get install nginx-dev=$distro_package_version" >&2
        exit 1
    fi
    if [[ ! -x "$sdk_source/configure" ]]; then
        echo "error: nginx-dev did not provide $sdk_source/configure" >&2
        exit 1
    fi
    sdk_nginx_version="$(sed -n 's/^#define NGINX_VERSION *"\([^"]*\)".*/\1/p' \
        "$sdk_source/src/core/nginx.h")"
    if [[ "$sdk_nginx_version" != "$nginx_version" ]]; then
        echo "error: nginx-dev SDK version $sdk_nginx_version does not match requested nginx $nginx_version" >&2
        exit 1
    fi
    echo "==> Copying patched Ubuntu nginx SDK ${sdk_version}"
    mkdir -p "$nginx_src"
    cp -a "$sdk_source/." "$nginx_src/"
else
    tarball="$cache/nginx-$nginx_version.tar.gz"
    if [[ ! -s "$tarball" ]]; then
        echo "==> Downloading nginx-$nginx_version.tar.gz"
        curl -fL --retry 3 -o "$tarball.tmp" \
            "https://nginx.org/download/nginx-$nginx_version.tar.gz"
        mv "$tarball.tmp" "$tarball"
    fi
    tar -xzf "$tarball" -C "$stage"
fi

# --- staged source tree: same exclude set as build-rpm.sh's tar ---
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
    --exclude='./*.deb' \
    -cf - -C "$repo_root" . | tar -xf - -C "$srcdir"

cp -a "$script_dir/debian" "$srcdir/debian"
chmod 0755 "$srcdir/debian/rules"

# --- debian/changelog: generated, version-locked to ident.h ---
cat > "$srcdir/debian/changelog" <<EOF
nginx-mod-brix-cache (${deb_version}) ${codename:-unstable}; urgency=medium

  * Automated package build of BriX-Cache ${version} for ${codename:-this host}
    against nginx ${nginx_version} (${flavor} flavor).  Release notes:
    docs/10-reference/CHANGELOG.md; package history: packaging/rpm/nginx-mod-brix-cache.spec.

 -- Rob Currie <rob.currie@ed.ac.uk>  $(date -R)
EOF

# --- build ---
(
    cd "$srcdir"
    NGINX_SRC_DIR="$nginx_src" BRIX_NGINX_FLAVOR="$flavor" \
        dpkg-buildpackage -b -us -uc
)

# dpkg-buildpackage drops artifacts into the stage dir (parent of srcdir).
# .ddeb are the Ubuntu-named dbgsym packages.
find "$stage" -maxdepth 1 \( -name '*.deb' -o -name '*.ddeb' \
    -o -name '*.changes' -o -name '*.buildinfo' \) -exec cp -p {} "$outdir/" \;

echo ""
echo "==> Packages written to: ${outdir}"
find "$outdir" -name "*.deb" -newer "$srcdir/debian/changelog" -printf "    %f\n" | sort
