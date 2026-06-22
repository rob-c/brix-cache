#!/usr/bin/env bash
#
# build_dynamic_modules.sh — phase-42 build-matrix: prove the modules build as
# REAL dynamic modules (--with-compat --add-dynamic-module) and that the
# compression codec libraries are correctly linked into the dynamic .so and
# resolve at load time.  This is the phase-42 concern from the plan: the codec
# libs live only in the STREAM module's ngx_module_libs (NOT CORE_LIBS), which is
# exactly what a DYNAMIC module build needs — CORE_LIBS links the nginx binary,
# but a .so must carry its own DT_NEEDED records.
#
# It is deliberately heavyweight: a full isolated --with-compat nginx build in its
# OWN tree so it NEVER touches the running test harness binary
# (/tmp/nginx-1.28.3/objs/nginx, a static --add-module build).
#
# phase-47 W1: the DYNAMIC build now emits ONE combined .so containing every
# non-filter module (the HTTP AUX filter stays its own .so), so the former
# cross-.so symbol cycle (stream <-> dashboard <-> webdav <-> metrics) resolves at
# LINK time and `nginx -t` dlopens cleanly.  This script therefore asserts the
# FULL dlopen succeeds — codec libs (incl. lz4) linked into the combined .so as
# DT_NEEDED + resolving, AND nginx -t loading the module set without error.  An
# unresolved CODEC symbol (LZ4F_*/ZSTD_*/lzma_*/Brotli*/BZ2_*/inflate/deflate) or
# any dlopen failure is a real FAILURE.
#
# Exit codes: 0 = built + codec libs resolve + dlopen OK;
# 75 (EX_TEMPFAIL) = environment can't build (missing source/tools) -> SKIP;
# 1 = a real regression (codec wiring or dlopen).
#
# Usage:  tests/build_dynamic_modules.sh [nginx-source-dir]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NGSRC="${1:-/tmp/nginx-1.28.3}"
BUILD="${XRD_BUILD_MATRIX_DIR:-/tmp/xrd-build-matrix}"
DST="${BUILD}/nginx"
JOBS="$(nproc 2>/dev/null || echo 4)"

# lz4's header is not always on the system include path (e.g. conda-only here).
# Pass it via the same env-hint the main build uses, linking the SYSTEM soname
# (never a conda -L, which would poison the OTHER codec links). Honour any value
# already exported; otherwise probe a couple of common locations.
if [[ -z "${XROOTD_LZ4_CFLAGS:-}" ]]; then
    for inc in /usr/include "${HOME}/miniconda3/include" /opt/conda/include; do
        if [[ -f "${inc}/lz4frame.h" ]]; then
            [[ "${inc}" != /usr/include ]] && export XROOTD_LZ4_CFLAGS="-I${inc}"
            break
        fi
    done
fi
export XROOTD_LZ4_LIBS="${XROOTD_LZ4_LIBS:--l:liblz4.so.1}"

skip() { echo "SKIP: $*" >&2; exit 75; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -f "${NGSRC}/configure" && -f "${NGSRC}/src/core/nginx.c" ]] \
    || skip "nginx source not found at ${NGSRC}"
command -v rsync >/dev/null 2>&1 || skip "rsync not available"

echo "== isolated --with-compat dynamic build of the xrootd modules =="
echo "   nginx source : ${NGSRC}"
echo "   build tree   : ${DST}  (harness binary is never touched)"

rm -rf "${BUILD}"
mkdir -p "${DST}"
# Clone the SOURCE only (no objs/Makefile) so configure starts clean.
rsync -a --exclude objs --exclude Makefile "${NGSRC}/" "${DST}/" \
    || skip "rsync of nginx source failed"

cd "${DST}" || skip "cannot cd to ${DST}"

# Dynamic stream module + our addon as a DYNAMIC module, ABI-compatible (--with-compat).
if ! ./configure \
        --with-compat \
        --with-threads \
        --with-stream=dynamic \
        --with-stream_ssl_module \
        --with-http_ssl_module \
        --with-http_dav_module \
        --add-dynamic-module="${REPO}" \
        >"${BUILD}/configure.log" 2>&1
then
    echo "---- configure.log (tail) ----" >&2
    tail -25 "${BUILD}/configure.log" >&2
    skip "configure --add-dynamic-module failed (toolchain/headers?)"
fi

# Build the nginx binary AND the dynamic .so modules.
if ! make -j"${JOBS}" >"${BUILD}/make.log" 2>&1; then
    echo "---- make.log (tail) ----" >&2; tail -25 "${BUILD}/make.log" >&2
    fail "nginx binary build failed"
fi
if ! make modules -j"${JOBS}" >"${BUILD}/modules.log" 2>&1; then
    echo "---- modules.log (tail) ----" >&2; tail -25 "${BUILD}/modules.log" >&2
    fail "dynamic module build (make modules) failed"
fi

mapfile -t SOS < <(ls objs/*.so 2>/dev/null)
[[ ${#SOS[@]} -gt 0 ]] || fail "no .so produced by 'make modules'"
echo "== built dynamic modules =="
for so in "${SOS[@]}"; do
    echo "   $(basename "${so}")"
done

# --- PHASE-42 PRIMARY ASSERTION: codec libs are linked into the dynamic stream
# .so as DT_NEEDED records and every one resolves to a real path. This is the
# whole point of putting XROOTD_CODEC_LIBS in ngx_module_libs (not just
# CORE_LIBS): a dynamic .so must carry its own NEEDED records. ---
STREAM_SO="objs/ngx_stream_xrootd_module.so"
[[ -f "${STREAM_SO}" ]] || fail "stream module .so not produced"

echo "== codec libs linked into the stream module .so =="
NEEDED="$(readelf -d "${STREAM_SO}" 2>/dev/null | grep NEEDED || true)"
echo "${NEEDED}" | grep -iE "libz\.|zstd|lzma|brotli|bz2|lz4" | sed 's/^/   /'

# zlib is mandatory; the optional codecs are present on this host (the main build
# links them), so each MUST appear as a NEEDED record in the dynamic .so.
for want in "libz\.so" "libzstd" "liblzma" "libbrotlienc" "libbrotlidec" "libbz2"; do
    echo "${NEEDED}" | grep -qiE "${want}" \
        || fail "codec lib '${want}' missing from ${STREAM_SO} DT_NEEDED (ngx_module_libs wiring broken for dynamic build)"
done
# lz4 (phase-42 extension): present only when its header was found at build time.
if echo "${NEEDED}" | grep -qiE "liblz4"; then
    echo "   (lz4 linked into the dynamic .so)"
else
    echo "   NOTE: lz4 not linked (header not found at build; set XROOTD_LZ4_CFLAGS) — it degrades to available=0"
fi

# Every NEEDED shared library of the .so must resolve (no dangling soname). ldd
# of a dynamic module reports its own deps; 'not found' here = a real link bug.
if ldd "${STREAM_SO}" 2>/dev/null | grep -i "not found"; then
    fail "stream module .so has an unresolved shared library (codec soname not on loader path)"
fi
echo "   all NEEDED shared libraries of the stream .so resolve"

# phase-47 W1 should emit ONE combined non-filter .so; the per-module split is gone.
COMBINED="objs/ngx_stream_xrootd_module.so"
NADDON=0
for so in "${SOS[@]}"; do
    case "$(basename "${so}")" in
        ngx_stream_module.so) ;;                 # nginx's own dynamic stream core
        *) NADDON=$((NADDON + 1)) ;;
    esac
done
echo "== addon .so count: ${NADDON} (phase-47 expects 2: combined + HTTP AUX filter) =="
if [[ ${NADDON} -gt 2 ]]; then
    echo "   NOTE: ${NADDON} addon .so produced — phase-47 combining may be inactive;"
    echo "         a per-module split can hit the cross-.so RTLD_NOW symbol cycle."
fi

# --- Full dlopen: load nginx's stream core first, then the combined module (its
# symbols back the HTTP AUX filter via RTLD_GLOBAL), then the filter. ---
mkdir -p "${DST}/logs"
CONF="${BUILD}/dlopen.conf"
{
    [[ -f objs/ngx_stream_module.so ]] && echo "load_module objs/ngx_stream_module.so;"
    [[ -f "${COMBINED}" ]] && echo "load_module ${COMBINED};"
    for so in "${SOS[@]}"; do
        b="$(basename "${so}")"
        case "${b}" in
            ngx_stream_module.so|ngx_stream_xrootd_module.so) ;;   # already emitted
            *) echo "load_module objs/${b};" ;;
        esac
    done
    cat <<'EOF'
events { worker_connections 64; }
http    { server { listen 127.0.0.1:65199; location / { return 204; } } }
stream  { server { listen 127.0.0.1:65198; return ""; } }
EOF
} > "${CONF}"

echo "== nginx -t (full dlopen of the module set) =="
if objs/nginx -p "${DST}" -c "${CONF}" -t >"${BUILD}/nginx_t.log" 2>&1; then
    sed 's/^/   /' "${BUILD}/nginx_t.log"
    echo "ALL DYNAMIC-MODULE CHECKS PASSED (codec wiring + full dlopen)"
    exit 0
fi

# Any dlopen failure is now a real regression (phase-47 fixed the cross-.so cycle).
echo "---- nginx_t.log ----" >&2; cat "${BUILD}/nginx_t.log" >&2
UNDEF="$(grep -oiE "undefined symbol: [A-Za-z0-9_]+" "${BUILD}/nginx_t.log" | head -1 | awk '{print $3}')"
if echo "${UNDEF}" | grep -qiE "^(LZ4F_|LZ4_|ZSTD_|lzma_|Brotli|BZ2_|inflate|deflate|crc32|adler32)"; then
    fail "dlopen failed on a CODEC symbol '${UNDEF}' — phase-42 codec wiring regression"
fi
fail "nginx -t dlopen failed (symbol '${UNDEF:-?}'); phase-47 combined-.so build should load cleanly"
