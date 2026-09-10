#!/bin/sh
# s3-frontend — smoke test.
# Runs inside the `client` compose service (docker compose --profile smoke up
# client) or on a developer host against a local nginx: every endpoint comes
# from the environment so tests/test_phase115_example_configs.py can reuse it.
set -eu
: "${BRIX_HOST:=localhost}"
: "${S3_PORT:=9000}"
: "${DAV_PORT:=8443}"
: "${OBS_PORT:=9100}"
: "${S3_ACCESS_KEY:=AKIAEXAMPLEDEMO00001}"
: "${S3_SECRET_KEY:=demo-secret-change-me-0123456789abcdef}"
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
# SigV4 through the bundled client (xrdcp speaks s3://). curl's --aws-sigv4
# before 7.80 signs a canonical request brix rejects as SignatureDoesNotMatch;
# awscli, boto3, rclone and xrdcp all interoperate, so the smoke uses xrdcp.
export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY" AWS_SECRET_ACCESS_KEY="$S3_SECRET_KEY" AWS_DEFAULT_REGION=us-east-1
OBJ="s3://$BRIX_HOST:$S3_PORT/data/smoke/object.bin"

# Security negatives first: a wrong secret and no credentials are refused.
if AWS_SECRET_ACCESS_KEY=wrong "$XRDCP" -f "$SMOKE_TMP/payload.bin" "$OBJ" >/dev/null 2>&1; then
    fail "bad-secret PUT was not refused"
fi
if env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY "$XRDCP" -f "$SMOKE_TMP/payload.bin" "$OBJ" >/dev/null 2>&1; then
    fail "anonymous PUT was not refused"
fi

"$XRDCP" -f "$SMOKE_TMP/payload.bin" "$OBJ" || fail "s3 PUT"
"$XRDCP" -f "$OBJ" "$SMOKE_TMP/s3-back.bin" || fail "s3 GET"
check_sha "$SMOKE_TMP/s3-back.bin" "s3 round trip"
if env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY "$XRDCP" -f "$OBJ" "$SMOKE_TMP/anon.bin" >/dev/null 2>&1; then
    fail "anonymous GET was not refused"
fi
# The object is the same file under WebDAV, and the WebDAV listing shows it.
$CURL -o "$SMOKE_TMP/dav-back.bin" "https://$BRIX_HOST:$DAV_PORT/smoke/object.bin" || fail "dav GET of s3 object"
check_sha "$SMOKE_TMP/dav-back.bin" "webdav view of the s3 object"
$CURL -X PROPFIND -H 'Depth: 1' -o "$SMOKE_TMP/list.xml" "https://$BRIX_HOST:$DAV_PORT/smoke/" || fail "PROPFIND"
grep -q 'object.bin' "$SMOKE_TMP/list.xml" || fail "PROPFIND did not list the object"
echo "SMOKE OK: s3-frontend"
