#!/usr/bin/env bash
# run_proxy_env_unit.sh — env-proxy resolver + no_proxy matching unit tests.
set -euo pipefail
cd "$(dirname "$0")/.."
gcc -Wall -Wextra -Werror -I shared -o /tmp/proxy_env_ut \
    shared/net/proxy_env_unittest.c shared/net/proxy_env.c
/tmp/proxy_env_ut
