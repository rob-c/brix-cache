#!/bin/sh
# Standalone — smoke test.
# Runs inside the `client` compose service (docker compose --profile smoke up
# client) or on a developer host against a local nginx: every endpoint comes
# from the environment so tests/test_phase115_example_configs.py can reuse it.
set -eu
: "${BRIX_HOST:=localhost}"
: "${ROOT_PORT:=1094}"
: "${DAV_PORT:=8443}"
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

"$XRDCP" -f "$SMOKE_TMP/payload.bin" "root://$BRIX_HOST:$ROOT_PORT//smoke/root.bin" || fail "xrdcp put"
"$XRDCP" -f "root://$BRIX_HOST:$ROOT_PORT//smoke/root.bin" "$SMOKE_TMP/root-back.bin" || fail "xrdcp get"
check_sha "$SMOKE_TMP/root-back.bin" "root://"

# The same object is visible over WebDAV: one export, every protocol.
$CURL -o "$SMOKE_TMP/dav-back.bin" "https://$BRIX_HOST:$DAV_PORT/smoke/root.bin" || fail "dav get of root-written file"
check_sha "$SMOKE_TMP/dav-back.bin" "webdav read of root:// write"
$CURL -T "$SMOKE_TMP/payload.bin" "https://$BRIX_HOST:$DAV_PORT/smoke/dav.bin" || fail "dav put"
"$XRDCP" -f "root://$BRIX_HOST:$ROOT_PORT//smoke/dav.bin" "$SMOKE_TMP/dav-via-root.bin" || fail "root read of dav write"
check_sha "$SMOKE_TMP/dav-via-root.bin" "root:// read of WebDAV write"

$CURL -o "$SMOKE_TMP/metrics.txt" "http://$BRIX_HOST:$OBS_PORT/metrics" || fail "metrics fetch"
grep -q '^brix_' "$SMOKE_TMP/metrics.txt" || fail "metrics exposition"
echo "SMOKE OK: standalone"
