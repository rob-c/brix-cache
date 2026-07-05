#!/usr/bin/env bash
# run_cache_unit.sh — build+run the shared content-addressed store unit tests.
set -euo pipefail
cd "$(dirname "$0")/.."
gcc -Wall -Wextra -Werror -I shared -o /tmp/cas_ut \
    shared/cache/cas_store_unittest.c shared/cache/cas_store.c
/tmp/cas_ut
