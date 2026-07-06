#!/usr/bin/env bash
# run_multiuser_authz.sh — the multi-user permission conformance suite (spec/plan 2026-07-06).
#
# Requires root: the suite provisions real brixtest_* accounts and runs the fleet with the
# privileged impersonation broker (spec D4). Brings up nothing itself — the mu_fleet fixture
# provisions accounts, renders backends+configs, starts the paired direct+cache fleet, and
# reaps everything on teardown.
#
# Usage:
#   sudo -E env PYTHONPATH=tests tests/run_multiuser_authz.sh [pytest-args...]
#   sudo -E env PYTHONPATH=tests tests/run_multiuser_authz.sh -m leak     # the leak ledger
#   sudo -E env PYTHONPATH=tests tests/run_multiuser_authz.sh -m "not leak"  # green subset
set -uo pipefail
cd "$(dirname "$0")/.."

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: the multi-user conformance suite requires root (real accounts + setfsuid)." >&2
    echo "Run: sudo -E env PYTHONPATH=tests tests/run_multiuser_authz.sh $*" >&2
    exit 2
fi

export PYTHONPATH="${PYTHONPATH:-tests}"

# Ensure the test PKI (CA + server cert) exists before the fixtures mint per-principal creds.
python3 -c "from pki_helpers import blitz_test_pki; blitz_test_pki()" || true

# Build the F6 mapping C unit against a clean provisioned account, if present.
if command -v gcc >/dev/null 2>&1; then
    MU_CLEAN_USER=brixtest_alice tests/c/run_mu_unit.sh || true
fi

exec pytest tests/test_mu_*.py "$@"
