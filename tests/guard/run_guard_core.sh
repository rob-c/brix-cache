#!/usr/bin/env bash
# Build + run the standalone guard-core unit test (no nginx).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
gcc -Wall -Wextra -std=c99 -Isrc/net/guard src/net/guard/guard_*.c \
    -o /tmp/guard_test
exec /tmp/guard_test
