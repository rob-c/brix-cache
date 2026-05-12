#!/bin/bash
set -e
cd "$(dirname "$0")"

SRC=../../src
CC=${CC:-gcc}
CFLAGS="-Wall -Wextra -I$SRC -I$SRC/token -I$SRC/crypto -g"
LDFLAGS="-lssl -lcrypto"



fail=0

for test in test_*.c; do
    exe="${test%.c}"
    impl=""
    case $test in
        test_b64url.c) impl="../../src/token/b64url.c" ;;
        test_json.c) impl="../../src/token/json.c" ;;
        test_scopes.c) impl="../../src/token/scopes.c" ;;
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
