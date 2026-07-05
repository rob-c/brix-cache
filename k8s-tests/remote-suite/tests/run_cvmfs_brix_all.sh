#!/usr/bin/env bash
# run_cvmfs_brix_all.sh — the whole CVMFS-brix / brixMount gate in one shot.
#
# Runs every standalone unit suite (no fleet needed) and, when FUSE + python3 are
# available, the live mount tests. Prints a summary; non-zero exit on any failure.
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0 fail=0
run() {  # <label> <script...>
    local label=$1; shift
    if "$@" >/tmp/brixall.$$ 2>&1; then
        printf "  PASS  %-26s %s\n" "$label" "$(tail -1 /tmp/brixall.$$)"
        pass=$((pass+1))
    else
        printf "  FAIL  %-26s\n" "$label"; sed 's/^/        /' /tmp/brixall.$$ | tail -8
        fail=$((fail+1))
    fi
    rm -f /tmp/brixall.$$
}

echo "== unit suites (pure C, no fleet) =="
run "grammar/classify (server)" bash tests/run_cvmfs_classify.sh
run "shared core"               bash tests/run_cvmfs_core_unit.sh
run "cas store"                 bash tests/run_cache_unit.sh
run "object+fetch"              bash tests/run_cvmfs_fetch_unit.sh
run "catalog (sqlite)"          bash tests/run_cvmfs_catalog_unit.sh
run "client assembler"          bash tests/run_cvmfs_client_unit.sh
run "CVMFS_* config parse"      bash tests/run_cvmfs_conf_unit.sh
run "brixMount dispatch"        bash tests/run_brixmount_unit.sh
run "env-proxy resolver"        bash tests/run_proxy_env_unit.sh

if pkg-config --exists fuse3 && command -v python3 >/dev/null && [ -w /dev/fuse ]; then
    echo "== live FUSE mounts =="
    run "brixcvmfs live mount"   bash tests/run_brixcvmfs_live.sh
    run "brixMount umbrella live" bash tests/run_brixmount_live.sh
    run "mount.cvmfs helper live" bash tests/run_mount_cvmfs_live.sh
    run "brixcvmfs --check"       bash tests/run_brixcvmfs_check.sh
    run "clever overlay + DPI"    bash tests/run_brixcvmfs_clever_live.sh
    run "env-proxy (tunnel+use)"  bash tests/run_proxy_env_live.sh
else
    echo "== live FUSE mounts: SKIPPED (need fuse3 + python3 + writable /dev/fuse) =="
fi

echo
echo "brix cvmfs gate: $pass passed, $fail failed"
exit $((fail > 0 ? 1 : 0))
