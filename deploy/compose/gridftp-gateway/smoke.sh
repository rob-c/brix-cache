#!/bin/sh
# gridftp-gateway — smoke test.
# Runs inside the `client` compose service (docker compose --profile smoke up
# client) or on a developer host against a local nginx: every endpoint comes
# from the environment so tests/test_phase115_example_configs.py can reuse it.
set -eu
: "${BRIX_HOST:=localhost}"
: "${GSIFTP_PORT:=2811}"
: "${FTP_PORT:=2121}"
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

# Anonymous ftp:// door with plain curl (passive mode). --ftp-create-dirs
# makes curl MKD the missing directory after the CWD 550, as globus-url-copy -cd
# does; the door must refuse a CWD into a directory that does not exist.
curl -fsS --max-time 60 --ftp-create-dirs -T "$SMOKE_TMP/payload.bin" "ftp://$BRIX_HOST:$FTP_PORT/smoke/ftp.bin" || fail "ftp put"
curl -fsS --max-time 60 -o "$SMOKE_TMP/ftp-back.bin" "ftp://$BRIX_HOST:$FTP_PORT/smoke/ftp.bin" || fail "ftp get"
check_sha "$SMOKE_TMP/ftp-back.bin" "ftp round trip"

# GSI door with the bundled xrdcp (gsiftp:// scheme, delegated proxy).
"$XRDCP" -f "$SMOKE_TMP/payload.bin" "gsiftp://$BRIX_HOST:$GSIFTP_PORT/smoke/gsi.bin" || fail "gsiftp put"
"$XRDCP" -f "gsiftp://$BRIX_HOST:$GSIFTP_PORT/smoke/gsi.bin" "$SMOKE_TMP/gsi-back.bin" || fail "gsiftp get"
check_sha "$SMOKE_TMP/gsi-back.bin" "gsiftp round trip"
# Both doors terminate on the same export.
curl -fsS --max-time 60 -o "$SMOKE_TMP/cross.bin" "ftp://$BRIX_HOST:$FTP_PORT/smoke/gsi.bin" || fail "ftp read of gsiftp write"
check_sha "$SMOKE_TMP/cross.bin" "cross-door read"
echo "SMOKE OK: gridftp-gateway"
