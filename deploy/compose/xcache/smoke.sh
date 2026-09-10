#!/bin/sh
# xcache — smoke test.
# Runs inside the `client` compose service (docker compose --profile smoke up
# client) or on a developer host against a local nginx: every endpoint comes
# from the environment so tests/test_phase115_example_configs.py can reuse it.
set -eu
: "${BRIX_HOST:=localhost}"
: "${CACHE_PORT:=1094}"
: "${ORIGIN_HOST:=$BRIX_HOST}"
: "${ORIGIN_PORT:=1095}"
: "${OBS_PORT:=9100}"
: "${XRDCP:=xrdcp}"
: "${BRIX_PKI_DIR:=/etc/brix/pki}"
: "${SMOKE_TMP:=/tmp/brix-smoke}"
mkdir -p "$SMOKE_TMP"
head -c 1048576 /dev/urandom > "$SMOKE_TMP/payload.bin"
WANT="$(sha256sum "$SMOKE_TMP/payload.bin" | cut -d' ' -f1)"
fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
check_sha() { [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$WANT" ] || fail "$2: payload differs"; }
export X509_CERT_DIR="$BRIX_PKI_DIR/ca" X509_USER_PROXY="$BRIX_PKI_DIR/userproxy.pem"
CURL="curl -fsS --max-time 30 --cacert $BRIX_PKI_DIR/ca/ca.pem"

$CURL "http://$BRIX_HOST:$OBS_PORT/healthz" >/dev/null || fail "healthz"
"$XRDCP" -f "$SMOKE_TMP/payload.bin" "root://$ORIGIN_HOST:$ORIGIN_PORT//smoke/cached.bin" || fail "seed origin"
# Cold read fills the cache; warm read is served locally. Both must be exact.
"$XRDCP" -f "root://$BRIX_HOST:$CACHE_PORT//smoke/cached.bin" "$SMOKE_TMP/cold.bin" || fail "cold read"
check_sha "$SMOKE_TMP/cold.bin" "cold (fill) read"
"$XRDCP" -f "root://$BRIX_HOST:$CACHE_PORT//smoke/cached.bin" "$SMOKE_TMP/warm.bin" || fail "warm read"
check_sha "$SMOKE_TMP/warm.bin" "warm (hit) read"
# Security negative: the cache is read-only towards clients.
if "$XRDCP" -f "$SMOKE_TMP/payload.bin" "root://$BRIX_HOST:$CACHE_PORT//smoke/not-allowed.bin" 2>/dev/null; then
    fail "cache accepted a client write"
fi
echo "SMOKE OK: xcache"
