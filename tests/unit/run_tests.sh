#!/bin/bash
set -e
cd "$(dirname "$0")"

SRC=../../src
CC=${CC:-gcc}
CFLAGS="-Wall -Wextra -I$SRC -I$SRC/token -I$SRC/crypto -I$SRC/compat -g"
LDFLAGS="-lssl -lcrypto"

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libxml-2.0; then
    CFLAGS="$CFLAGS $(pkg-config --cflags libxml-2.0) -DXROOTD_HAVE_LIBXML2=1"
    LDFLAGS="$LDFLAGS $(pkg-config --libs libxml-2.0)"
fi

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists jansson; then
    CFLAGS="$CFLAGS $(pkg-config --cflags jansson)"
    LDFLAGS="$LDFLAGS $(pkg-config --libs jansson)"
else
    echo "ERROR: jansson library is required but was not found." >&2
    exit 1
fi



fail=0

for test in test_*.c; do
    exe="${test%.c}"
    impl=""
    case $test in
        test_b64url.c) impl="../../src/token/b64url.c" ;;
        test_crc32c.c) impl="../../src/compat/crc32c.c" ;;
        test_crc64.c) impl="../../src/compat/crc64.c" ;;
        test_json.c) impl="../../src/token/json.c" ;;
        test_scopes.c) impl="../../src/token/scopes.c" ;;
        test_xml_compat.c) impl="../../src/compat/xml.c" ;;
        # test_pki_check.c intentionally left without impl for now
    esac
    echo "Compiling $test..."
    $CC $CFLAGS $test $impl -o $exe $LDFLAGS || fail=1
    echo "Running $exe..."
    ./$exe || fail=1
    echo
    rm -f $exe
done

if [ $fail -eq 0 ]; then
    echo "All unit tests passed."
else
    echo "Some unit tests failed." >&2
    exit 1
fi
