#!/bin/sh
# webdav-edge — smoke test.
# Runs inside the `client` compose service (docker compose --profile smoke up
# client) or on a developer host against a local nginx: every endpoint comes
# from the environment so tests/test_phase115_example_configs.py can reuse it.
set -eu
: "${BRIX_HOST:=localhost}"
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
URL="https://$BRIX_HOST:$DAV_PORT/smoke/edge.bin"
AUTH="--cert $BRIX_PKI_DIR/userproxy.pem --key $BRIX_PKI_DIR/userproxy.pem"

# Security negative FIRST: no certificate → refused, nothing written.
code="$(curl -sS --max-time 30 --cacert "$BRIX_PKI_DIR/ca/ca.pem" -o /dev/null -w '%{http_code}' -T "$SMOKE_TMP/payload.bin" "$URL")"
case "$code" in 401|403) ;; *) fail "anonymous PUT was not refused (HTTP $code)";; esac

# WebDAV PUT needs its parent collection (RFC 4918 §9.7.1: 409 otherwise).
code="$(curl -sS --max-time 30 --cacert "$BRIX_PKI_DIR/ca/ca.pem" $AUTH -o /dev/null -w '%{http_code}' -X MKCOL "https://$BRIX_HOST:$DAV_PORT/smoke/")"
case "$code" in 201|405) ;; *) fail "MKCOL /smoke/ (HTTP $code)";; esac
$CURL $AUTH -T "$SMOKE_TMP/payload.bin" "$URL" || fail "authenticated PUT"
$CURL $AUTH -o "$SMOKE_TMP/edge-back.bin" "$URL" || fail "authenticated GET"
check_sha "$SMOKE_TMP/edge-back.bin" "x509 round trip"
echo "SMOKE OK: webdav-edge"
