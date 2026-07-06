#!/usr/bin/env bash
# run_x509_matrix_differential.sh — replay the davs clause matrix against our
# module and stock XRootD (XrdHttp); assert ours==spec and record XRootD
# divergences into docs/10-reference/conformance/differential-findings.md.
#
# Opt-in: set TEST_X509_DIFF=1. Skip-clean otherwise. Best-effort stock XRootD
# (records "unavailable" if no xrootd binary / XrdHttp won't come up).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${TEST_X509_DIFF:-0}" != "1" ]; then
    echo "run_x509_matrix_differential: set TEST_X509_DIFF=1 to run (skipping)."
    exit 0
fi

OUT="${1:-/tmp/x509matrixdiff}"
PYTHONPATH=tests python3 tests/x509_matrix_differential.py "$OUT"
