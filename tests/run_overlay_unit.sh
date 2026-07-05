#!/usr/bin/env bash
# run_overlay_unit.sh — unit tests for the brixMount writable-overlay core
# (client/lib/fs/overlay.c): classify/whiteout/opaque, mutations, copy-up,
# readdir nameset, and the --overlay-list/--overlay-reset CLI cores.
set -euo pipefail
cd "$(dirname "$0")/.."
gcc -Wall -Wextra -Werror -I client/lib -o /tmp/overlay_ut \
    client/lib/fs/overlay_unittest.c client/lib/fs/overlay.c
/tmp/overlay_ut
