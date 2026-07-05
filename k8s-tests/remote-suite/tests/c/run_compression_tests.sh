#!/usr/bin/env bash
#
# run_compression_tests.sh — compile and run the phase-42 compression C-unit
# tests (codec kernel + ZIP reader/writer + zcrc32). No running server needed:
# the codec tests link the shared libxrdproto.a (the same codec kernel the module
# and client use); the ZIP tests link client/lib/zip.c directly.
#
# Usage:  tests/c/run_compression_tests.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
PROTO="${REPO}/shared/xrdproto/libxrdproto.a"
ZIPC="${REPO}/client/lib/zip.c"

if [[ ! -f "${PROTO}" ]]; then
    echo "ERROR: ${PROTO} not found — build the client/shared lib first" >&2
    echo "  (make -C ${REPO}/client -j1   builds shared/xrdproto too)" >&2
    exit 2
fi

# codec_libs: zlib is mandatory; the others are present on this build host. If a
# codec dev lib is absent, drop its -l flag here AND the backend reports
# available=0 (the tests only exercise available codecs).
# lz4 (phase-42 extension): link the bare soname from the default loader path (no
# conda -L, which would pull conda's other codec sonames). -I (header) is taken
# from pkg-config so a non-system header is still found at compile.
LZ4_CFLAGS="$(pkg-config --cflags liblz4 2>/dev/null || true)"
CODEC_LIBS="-lz -lzstd -llzma -lbrotlienc -lbrotlidec -lbz2 -l:liblz4.so.1 -lcrypto"
CC="${CC:-cc}"
CFLAGS="-std=c11 -O2 -Wall -Wextra"

rc=0
run() {  # name  <compile args...>
    local name="$1"; shift
    local bin; bin="$(mktemp "/tmp/${name}.XXXXXX")"
    if ! ${CC} ${CFLAGS} "$@" -o "${bin}" 2>"/tmp/${name}.cc.log"; then
        echo "  ${name}: COMPILE FAILED"; sed 's/^/    /' "/tmp/${name}.cc.log" | head -8
        rc=1; return
    fi
    if "${bin}" >/tmp/${name}.run.log 2>&1; then
        echo "  ${name}: $(tail -1 /tmp/${name}.run.log)"
    else
        echo "  ${name}: FAILED"; tail -5 /tmp/${name}.run.log | sed 's/^/    /'
        rc=1
    fi
    rm -f "${bin}"
}

echo "phase-42 codec/zip/zcrc32 C-unit tests:"
run codec_test      -I "${REPO}/src/core/compat" "${HERE}/codec_test.c"      "${PROTO}" ${CODEC_LIBS}
run codec_edge_test -I "${REPO}/src/core/compat" "${HERE}/codec_edge_test.c" "${PROTO}" ${CODEC_LIBS}
run zcrc32_test     -D_GNU_SOURCE -I "${REPO}/src/core/compat" "${HERE}/zcrc32_test.c" "${PROTO}" ${CODEC_LIBS}
run zip_test        -D_GNU_SOURCE -I "${REPO}/client/lib" "${HERE}/zip_test.c"      "${ZIPC}" -lz
run zip_fuzz_test   -D_GNU_SOURCE -I "${REPO}/client/lib" "${HERE}/zip_fuzz_test.c" "${ZIPC}" -lz
run zip_write_test  -D_GNU_SOURCE -I "${REPO}/client/lib" "${HERE}/zip_write_test.c" "${ZIPC}" -lz

# Build matrix — graceful degradation when optional codec libs are ABSENT.
# Compile the kernel + zlib backend (mandatory) but every optional backend with
# its -DBRIX_HAVE_* UNDEFINED, so each links as its available=0 stub and NO
# optional lib is linked.  Proves the build still succeeds and unavailable codecs
# degrade cleanly (open() -> NULL) instead of leaving a table hole or failing.
CM="${REPO}/src/core/compat"
run codec_nolib_test -DBRIX_HAVE_ZLIB -I "${CM}" "${HERE}/codec_nolib_test.c" \
    "${CM}/codec_core.c" "${CM}/codec_zlib.c" \
    "${CM}/codec_zstd.c" "${CM}/codec_lzma.c" "${CM}/codec_brotli.c" \
    "${CM}/codec_bzip2.c" "${CM}/codec_lz4.c" -lz

[[ ${rc} -eq 0 ]] && echo "ALL COMPRESSION C-UNIT TESTS PASSED" || echo "SOME TESTS FAILED"
exit ${rc}
