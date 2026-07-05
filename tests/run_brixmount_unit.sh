#!/usr/bin/env bash
# run_brixmount_unit.sh — unit tests for the brixMount dispatch core (mock drivers).
set -euo pipefail
cd "$(dirname "$0")/.."
gcc -Wall -Wextra -Werror -I shared -DBRIXMOUNT_NO_MAIN -o /tmp/brixmount_ut \
    client/apps/fs/brixmount_unittest.c client/apps/fs/brixmount.c
/tmp/brixmount_ut
