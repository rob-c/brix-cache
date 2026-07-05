#!/usr/bin/env bash
# Full reset of all test state — run after a test session or before a clean run.
# Kills all servers, removes all generated data, PKI, tokens, and dedicated dirs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"

echo "=== BRUTAL TEAR DOWN ==="
echo "Target: ${TEST_ROOT}"

# Kill all remaining servers (belt and suspenders)
echo "[1/4] Stopping all servers..."
"${SCRIPT_DIR}/manage_test_servers.sh" stop-all 2>/dev/null || true

# stop-all only knows the servers it launched via its own pidfiles.  Test
# fixtures also spawn nginx/brix directly via subprocess on fixed ports
# (conformance topologies under /tmp/xrd_conf_topo, the mirror under
# /tmp/xrd-mirror*, perf servers under /tmp/xrd-perf*, handshake probes under
# /tmp/hsproto_test, reference xrootd under /tmp/xrd-test/ref).  When a pytest
# run is interrupted those leak and hold ports, which makes the NEXT
# `start-all` fail to bind (the classic "start-all returned exit 1 ->
# INTERNALERROR, no tests ran" symptom).  Reap any nginx/brix whose command
# line references a test path so this is a true full reset.  Matched by
# inspecting each candidate's own cmdline (never a broad `pkill -f`, which would
# also match this script's shell).
reap_test_servers() {
    local sig="$1" p cmd
    # Also reap a leaked test KDC: the krb5 tier launches a self-daemonising
    # krb5kdc (and one-shot kadmin.local, never a kadmind daemon) whose argv
    # carries the test pidfile path under ${TEST_ROOT}; an interrupted run can
    # orphan it past stop_krb5_tier's pidfile-based stop.  Match it the same
    # cmdline-scoped way as nginx/brix (never a broad pkill).
    for p in $(pgrep -x nginx 2>/dev/null) $(pgrep -x xrootd 2>/dev/null) \
             $(pgrep -x krb5kdc 2>/dev/null) $(pgrep -x kadmind 2>/dev/null); do
        cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null) || continue
        case "$cmd" in
            *"/tmp/xrd"*|*"/tmp/hsproto"*|*"${TEST_ROOT}"*)
                kill "$sig" "$p" 2>/dev/null || true ;;
        esac
    done
}
echo "[1b/4] Reaping leaked subprocess/topology test servers..."
reap_test_servers -TERM
sleep 1
reap_test_servers -KILL

# Remove all generated data and state directories
echo "[2/4] Removing generated directories..."
for dir in data pki tokens logs tmp krb5; do
    if [[ -d "${TEST_ROOT}/${dir}" ]]; then
        rm -rf "${TEST_ROOT:?}/${dir}"
        echo "  Removed ${TEST_ROOT}/${dir}/"
    fi
done

# Remove dedicated-server data dirs (data-cluster-ds, data-gsi-bridge, etc.)
for dir in "${TEST_ROOT}"/data-*; do
    if [[ -d "${dir}" ]]; then
        rm -rf "${dir}"
        echo "  Removed ${dir}/"
    fi
done

# Remove stale PID and config files
echo "[3/4] Removing stale PID and conf files..."
find "${TEST_ROOT}" -maxdepth 3 \( -name "*.pid" -o -name "*.conf" \) -type f -delete 2>/dev/null || true

# Verify clean state
echo "[4/4] Verifying..."
if [[ -d "${TEST_ROOT}" ]]; then
    remaining=$(find "${TEST_ROOT}" -mindepth 1 -maxdepth 1 | wc -l)
    echo "  ${remaining} items remaining in ${TEST_ROOT}"
else
    echo "  ${TEST_ROOT} does not exist"
fi

echo ""
echo "=== CLEAN ==="
echo "Test root is reset. Run 'PYTHONPATH=tests pytest tests/ -v' to start fresh."
