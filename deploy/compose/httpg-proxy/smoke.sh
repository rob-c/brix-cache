#!/bin/sh
# httpg-proxy — smoke test.
# Runs inside the `client` compose service (docker compose --profile smoke up
# client) or on a developer host against a local nginx: every endpoint comes
# from the environment so tests/test_phase115_example_configs.py can reuse it.
set -eu
: "${BRIX_HOST:=localhost}"
: "${FRONT_PORT:=8443}"
: "${BACKEND_HOST:=$BRIX_HOST}"
: "${BACKEND_PORT:=8444}"
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
AUTH="--cert $BRIX_PKI_DIR/userproxy.pem --key $BRIX_PKI_DIR/userproxy.pem"
FRONT="https://$BRIX_HOST:$FRONT_PORT"

# 1. delegate: deposit the caller's proxy so the front can act as the caller.
$CURL $AUTH -T "$BRIX_PKI_DIR/userproxy.pem" "$FRONT/.well-known/brix-delegation" || fail "delegation PUT"
# 2. forwarded requests reach the backend authenticated as the caller. The
#    object sits at the export root: the xrdhttp guard grammar classifies
#    only GET HEAD PUT POST DELETE PROPFIND OPTIONS, so there is no MKCOL to
#    create a collection through the front.
$CURL $AUTH -T "$SMOKE_TMP/payload.bin" "$FRONT/httpg-smoke.bin" || fail "forwarded PUT"
$CURL $AUTH -o "$SMOKE_TMP/front-back.bin" "$FRONT/httpg-smoke.bin" || fail "forwarded GET"
check_sha "$SMOKE_TMP/front-back.bin" "httpg round trip"
# 3. the bytes live on the backend.
$CURL $AUTH -o "$SMOKE_TMP/backend-back.bin" "https://$BACKEND_HOST:$BACKEND_PORT/httpg-smoke.bin" || fail "direct backend GET"
check_sha "$SMOKE_TMP/backend-back.bin" "backend copy"
# Security negatives: a verb outside the guard grammar and a scanner
# signature (/wp-login.php) are both bounced without a response
# (brix_guard_bounce_status 444, curl exit 52). Without a client certificate
# `ssl_verify_client on` refuses the caller at the front — TLS 1.2 aborts the
# handshake (curl exit 35, code 000), TLS 1.3 completes it and nginx answers
# 400 "No required SSL certificate was sent" — and nothing reaches the backend.
if curl -sS --max-time 30 --cacert "$BRIX_PKI_DIR/ca/ca.pem" $AUTH -o /dev/null -X MKCOL "$FRONT/smoke/" 2>/dev/null; then
    fail "front forwarded a verb outside the guard grammar"
fi
if curl -sS --max-time 30 --cacert "$BRIX_PKI_DIR/ca/ca.pem" $AUTH -o /dev/null "$FRONT/wp-login.php" 2>/dev/null; then
    fail "front answered a scanner signature instead of bouncing it"
fi
code="$(curl -sS --max-time 30 --cacert "$BRIX_PKI_DIR/ca/ca.pem" -o /dev/null -w '%{http_code}' "$FRONT/httpg-smoke.bin" 2>/dev/null || true)"
case "$code" in 000|400) ;; *) fail "front answered a request without a client certificate (HTTP $code)";; esac
echo "SMOKE OK: httpg-proxy"
