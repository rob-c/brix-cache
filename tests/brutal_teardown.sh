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

# Remove all generated data and state directories
echo "[2/4] Removing generated directories..."
for dir in data pki tokens logs tmp; do
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
