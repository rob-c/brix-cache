#!/bin/sh
# xrootd-proxy — smoke test.
# Runs inside the `client` compose service (docker compose --profile smoke up
# client) or on a developer host against a local nginx: every endpoint comes
# from the environment so tests/test_phase115_example_configs.py can reuse it.
set -eu
: "${BRIX_HOST:=localhost}"
: "${ROOT_PORT:=1094}"
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
"$XRDCP" -f "$SMOKE_TMP/payload.bin" "root://$BRIX_HOST:$ROOT_PORT//smoke/proxied.bin" || fail "put via proxy"
# The bytes landed on the origin, not on the proxy.
"$XRDCP" -f "root://$ORIGIN_HOST:$ORIGIN_PORT//smoke/proxied.bin" "$SMOKE_TMP/origin-back.bin" || fail "get from origin"
check_sha "$SMOKE_TMP/origin-back.bin" "origin copy"
"$XRDCP" -f "root://$BRIX_HOST:$ROOT_PORT//smoke/proxied.bin" "$SMOKE_TMP/proxy-back.bin" || fail "get via proxy"
check_sha "$SMOKE_TMP/proxy-back.bin" "proxied read"
echo "SMOKE OK: xrootd-proxy"
