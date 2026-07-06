#!/usr/bin/env bash
# run_mu_unit.sh — build + run the multi-user permission C unit tests.
#
# Currently: idmap_collapse_test (F6 — principal->uid collapse guards; threat T6).
# The F7 decision-cache key isolation is verified at the e2e layer instead, because
# auth_gate.c's cache-key derivation is a static function with heavy nginx deps and is
# not cleanly linkable standalone (see docs plan Task 16).
#
# Flags mirror tests/test_impersonate_idmap.py (-O2 -D_GNU_SOURCE + the nginx include set).
# Set MU_CLEAN_USER=<clean non-privileged account> to exercise the collapse-SUCCESS cases
# (the MU fleet provisions brixtest_* accounts for exactly this); otherwise only the
# account-independent guard cases run.
set -euo pipefail
cd "$(dirname "$0")/../.."

NGX_SRC="${NGX_SRC:-/tmp/nginx-1.28.3}"
CC="${CC:-gcc}"
INCS=(-I"${NGX_SRC}/src/core" -I"${NGX_SRC}/src/event" -I"${NGX_SRC}/src/event/modules"
      -I"${NGX_SRC}/src/os/unix" -I"${NGX_SRC}/objs" -I./src)

run() {
  local name="$1"; shift
  echo "== ${name} =="
  "${CC}" -O2 -D_GNU_SOURCE -Wall -Wextra "${INCS[@]}" -o "/tmp/${name}" "$@"
  "/tmp/${name}"
}

run idmap_collapse_test tests/c/idmap_collapse_test.c src/auth/impersonate/idmap.c
