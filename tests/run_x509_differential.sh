#!/usr/bin/env bash
# run_x509_differential.sh — replay the x509 conformance matrix against our
# module and stock XRootD, asserting ours==spec and recording XRootD
# divergences into docs/10-reference/wlcg-x509-differential-findings.md.
#
# Opt-in: set TEST_X509_DIFF=1.  Skip-clean (exit 0) otherwise.  The stock
# XRootD leg is best-effort; a missing/undriveable `xrootd` records
# "unavailable" cells rather than failing the run.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${TEST_X509_DIFF:-0}" != "1" ]; then
    echo "run_x509_differential: set TEST_X509_DIFF=1 to run (skipping)."
    exit 0
fi

OUT="${1:-/tmp/x509diff}"
rm -rf "$OUT"
PYTHONPATH=tests python3 tests/x509_differential.py "$OUT"
