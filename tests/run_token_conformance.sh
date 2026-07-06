#!/usr/bin/env bash
# Layer-1 WLCG token conformance: compile the ngx-free token core standalone
# and run the two unit binaries. Mirrors tests/run_cvmfs_core_unit.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
CC=${CC:-gcc}
FLAGS="-Wall -Wextra -Werror -I src"
DEPS_SCOPE="src/auth/token/scopes.c"
DEPS_SIG="src/auth/token/b64url.c src/auth/token/json.c"

echo "== token_scope_unittest =="
$CC $FLAGS -o /tmp/token_scope_ut tests/c/token_scope_unittest.c $DEPS_SCOPE -lcrypto
/tmp/token_scope_ut

echo "== token_conformance_test =="
$CC $FLAGS -o /tmp/token_conformance_ut tests/c/token_conformance_test.c $DEPS_SIG -lcrypto -ljansson
/tmp/token_conformance_ut

echo "ALL TOKEN CONFORMANCE UNIT TESTS PASSED"
