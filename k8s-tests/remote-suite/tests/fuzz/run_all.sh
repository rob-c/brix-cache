#!/usr/bin/env bash
# tests/fuzz/run_all.sh — build + short-run every libFuzzer target under ASan/UBSan.
#
# WHAT: CI entry point for the fuzz suite.  Builds each target from source and
#       runs it for FUZZ_TIME seconds.  Exits nonzero on the first crash.
# WHY:  Encodes each target's real build recipe (includes, extra TUs, libs) so
#       the CI command is a single line: FUZZ_TIME=60 tests/fuzz/run_all.sh
# HOW:  Per-target build functions (build_fuzz_<name>) capture the full recipe;
#       set -e propagates any fuzzer crash immediately.  Add a 4th target by
#       writing build_fuzz_<name> and appending the name to TARGETS.
#
# Usage:
#   tests/fuzz/run_all.sh              # default 60 s per target
#   FUZZ_TIME=15 tests/fuzz/run_all.sh # shorter run (CI smoke)
set -euo pipefail

cd "$(dirname "$0")"

FUZZ_TIME="${FUZZ_TIME:-60}"
SAN="-O1 -g -fsanitize=fuzzer,address,undefined"

# ---------------------------------------------------------------------------
# Per-target build recipes.
#
# Each function compiles the binary from source.  They are the canonical
# record of each target's include paths, extra TUs, and link libraries.
# Unity-build targets (fuzz_zip_dir) #include their source TUs directly and
# need neither extra TU arguments nor -I flags — the build function captures
# that distinction without forcing all targets into a single rigid template.
# ---------------------------------------------------------------------------

build_fuzz_safe_size() {
    # Standalone — fuzz_safe_size.c carries its own nginx shims.
    # safe_size.h lives in src/core/compat/; no extra TUs or libs needed.
    # shellcheck disable=SC2086
    clang $SAN \
        -I ../../src \
        -I ../../src/core/compat \
        fuzz_safe_size.c \
        -o fuzz_safe_size
}

build_fuzz_b64url() {
    # Links the real b64url TU.  b64url.c uses EVP_ENCODE_CTX so -lcrypto
    # is required; the brief omitted it but the Task-6 build confirmed the dep.
    # shellcheck disable=SC2086
    clang $SAN \
        -I ../../src \
        -I ../../src/auth/token \
        fuzz_b64url.c \
        ../../src/auth/token/b64url.c \
        -lcrypto \
        -o fuzz_b64url
}

build_fuzz_zip_dir() {
    # Unity build: fuzz_zip_dir.c #includes zip_kernel.c, sd_posix.c, and
    # zip_dir.c directly. Since phase-66 the included TUs use src-rooted
    # quoted includes (e.g. "fs/backend/sd.h"), so the src root must be on
    # the quoted-include path.  -lz for zlib.
    # shellcheck disable=SC2086
    clang $SAN \
        -iquote ../../src \
        fuzz_zip_dir.c \
        -lz \
        -o fuzz_zip_dir
}

# ---------------------------------------------------------------------------
# Ordered target list.  Each name must have a matching build_<name> function.
# ---------------------------------------------------------------------------
TARGETS=(
    fuzz_safe_size
    fuzz_b64url
    fuzz_zip_dir
)

# ---------------------------------------------------------------------------
# Build + run loop.
#
# Crash propagation: set -e aborts the script the moment any command returns
# nonzero.  libFuzzer exits nonzero (rc=1 or signal) whenever it writes a
# crash-* artifact, so a crash in "./$target ..." immediately terminates this
# script with the same nonzero status.  No extra error-check plumbing needed.
#
# Corpus warm (-runs=0): replays existing corpus inputs without generating new
# ones.  The "|| true" suppresses the benign nonzero exit that libFuzzer emits
# when the corpus dir is empty.  The real fuzz run that follows does NOT have
# "|| true" — crashes propagate.
# ---------------------------------------------------------------------------
for target in "${TARGETS[@]}"; do
    echo ""
    echo "=== ${target}: building ==="
    "build_${target}"

    corpus="corpus_${target#fuzz_}"
    mkdir -p "${corpus}"

    echo "=== ${target}: warming corpus (${corpus}/) ==="
    "./${target}" -runs=0 "${corpus}/" >/dev/null 2>&1 || true

    echo "=== ${target}: fuzzing for ${FUZZ_TIME}s ==="
    "./${target}" -max_total_time="${FUZZ_TIME}" "${corpus}/"

    echo "=== ${target}: DONE ==="
done

echo ""
echo "all fuzz targets clean (FUZZ_TIME=${FUZZ_TIME}s each)"
