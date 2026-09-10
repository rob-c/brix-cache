#!/bin/sh
# cms-cluster — smoke test.
# Runs inside the `client` compose service (docker compose --profile smoke up
# client) or on a developer host against a local nginx: every endpoint comes
# from the environment so tests/test_phase115_example_configs.py can reuse it.
set -eu
: "${BRIX_HOST:=localhost}"
: "${MANAGER_PORT:=1094}"
: "${DS1_HOST:=$BRIX_HOST}"
: "${DS1_PORT:=1095}"
: "${DS2_HOST:=$BRIX_HOST}"
: "${DS2_PORT:=1096}"
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

$CURL "http://$BRIX_HOST:$OBS_PORT/healthz" >/dev/null || fail "manager healthz"
# Give the data servers one cms interval to join before the first open.
sleep 3
"$XRDCP" -f "$SMOKE_TMP/payload.bin" "root://$BRIX_HOST:$MANAGER_PORT//smoke/cms.bin" || fail "put via redirector"
"$XRDCP" -f "root://$BRIX_HOST:$MANAGER_PORT//smoke/cms.bin" "$SMOKE_TMP/cms-back.bin" || fail "get via redirector"
check_sha "$SMOKE_TMP/cms-back.bin" "redirected round trip"
# Exactly one data server holds the bytes (the redirector never stores).
have=0
for ep in "$DS1_HOST:$DS1_PORT" "$DS2_HOST:$DS2_PORT"; do
    if "$XRDCP" -f "root://$ep//smoke/cms.bin" "$SMOKE_TMP/ds-back.bin" 2>/dev/null; then
        check_sha "$SMOKE_TMP/ds-back.bin" "copy on $ep"; have=$((have+1))
    fi
done
[ "$have" -ge 1 ] || fail "no data server holds the file"
echo "SMOKE OK: cms-cluster ($have data server copy)"
