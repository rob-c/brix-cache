#!/usr/bin/env bash
#
# WLCG token conformance — Layer 3 differential tier (opt-in).
#
# Always asserts OUR root:// verdicts match the spec for a representative set of
# token scenarios. When a SciTokens-configured stock XRootD port is supplied
# (STOCK_XROOTD_PORT), it also populates an xrootd comparison column and records
# any stock divergences from spec. Skips cleanly when disabled.
#
# Usage:
#   TEST_TOKEN_DIFF=1 tests/run_token_differential.sh
#   TEST_TOKEN_DIFF=1 STOCK_XROOTD_PORT=11260 tests/run_token_differential.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${TEST_TOKEN_DIFF:-0}" != "1" ]; then
    echo "differential tier disabled (set TEST_TOKEN_DIFF=1 to run)"
    exit 0
fi

XROOTD_BIN="${XROOTD_BIN:-${BRIX_BIN:-/usr/bin/xrootd}}"
STOCK_PORT="${STOCK_XROOTD_PORT:-}"

# Capability note: server-side JWT validation in stock XRootD needs the
# XrdAccSciTokens authz plugin plus a site-specific issuer config. We do not
# auto-provision that here (it is deployment-specific); pass STOCK_XROOTD_PORT
# pointing at a running SciTokens-configured xrootd to populate the comparison.
if [ -n "$STOCK_PORT" ]; then
    if ! command -v xrdfs >/dev/null 2>&1; then
        echo "STOCK_XROOTD_PORT set but xrdfs not found; running ours-vs-spec only"
        STOCK_PORT=""
    elif [ ! -x "$XROOTD_BIN" ]; then
        echo "stock xrootd ($XROOTD_BIN) not executable; running ours-vs-spec only"
        STOCK_PORT=""
    fi
fi

echo "== WLCG token differential (ours-vs-spec$( [ -n "$STOCK_PORT" ] && echo " + stock xrootd @ $STOCK_PORT"))"
if [ -n "$STOCK_PORT" ]; then
    PYTHONPATH=tests python3 tests/token_differential.py "$STOCK_PORT"
else
    PYTHONPATH=tests python3 tests/token_differential.py
fi

echo "findings: docs/10-reference/wlcg-token-differential-findings.md"
