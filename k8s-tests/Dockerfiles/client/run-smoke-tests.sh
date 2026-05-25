#!/usr/bin/env bash
# Smoke-test suite that exercises the XRootD reference server using all
# major client tools.  Run from inside the client pod:
#
#   kubectl exec -it xrootd-client -- xrd-smoke-tests
#
# Environment variables:
#   XROOTD_SERVER     host:port of the XRootD server   (default: xrootd-reference:1094)
#   AUTH_MODE         anonymous | gsi | token           (default: anonymous)
#   PROXY_FILE        Path to x509 proxy                (default: /tmp/x509up_u0)
#   BEARER_TOKEN      JWT bearer token (for token mode)
#   CA_DIR            Trusted CA directory
set -euo pipefail

SERVER="${XROOTD_SERVER:-xrootd-reference:1094}"
AUTH_MODE="${AUTH_MODE:-anonymous}"
PROXY_FILE="${PROXY_FILE:-/tmp/x509up_u0}"
CA_DIR="${CA_DIR:-/etc/grid-security/certificates}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0

run_test() {
    local name="$1"; shift
    printf "  %-55s " "$name"
    if "$@" &>/dev/null; then
        echo "PASS"
        (( PASS++ )) || true
    else
        echo "FAIL"
        (( FAIL++ )) || true
    fi
}

# Build common xrdcp / xrdfs auth flags.
AUTH_FLAGS=()
case "$AUTH_MODE" in
    gsi)
        export X509_USER_PROXY="$PROXY_FILE"
        AUTH_FLAGS=(--cadir "$CA_DIR")
        ;;
    token)
        [ -n "${BEARER_TOKEN:-}" ] || BEARER_TOKEN="$(xrd-gen-token 2>/dev/null)" || true
        export BEARER_TOKEN
        AUTH_FLAGS=()
        ;;
    anonymous|*)
        AUTH_FLAGS=(--nopbar --noProgressBar)
        ;;
esac

ROOT="root://${SERVER}"

echo "=== XRootD smoke tests ==="
echo "  server    : $SERVER"
echo "  auth mode : $AUTH_MODE"
echo ""

# ---- xrdfs stat / ls --------------------------------------------------------
run_test "xrdfs stat /"          xrdfs "$SERVER" stat /
run_test "xrdfs ls /"            xrdfs "$SERVER" ls /

# ---- xrdcp upload & download ------------------------------------------------
UPLOAD_SRC="${TMPDIR}/upload.dat"
DOWNLOAD_DST="${TMPDIR}/download.dat"
dd if=/dev/urandom bs=4K count=256 of="$UPLOAD_SRC" 2>/dev/null

run_test "xrdcp upload (4 MB)"   xrdcp "${AUTH_FLAGS[@]}" "$UPLOAD_SRC" "${ROOT}//smoke-upload.dat"
run_test "xrdcp download"        xrdcp "${AUTH_FLAGS[@]}" "${ROOT}//smoke-upload.dat" "$DOWNLOAD_DST"
run_test "upload == download"    cmp "$UPLOAD_SRC" "$DOWNLOAD_DST"

# ---- xrdfs namespace operations ---------------------------------------------
run_test "xrdfs mkdir"           xrdfs "$SERVER" mkdir /smoke-dir
run_test "xrdfs stat (dir)"      xrdfs "$SERVER" stat /smoke-dir
run_test "xrdfs mv"              xrdfs "$SERVER" mv  /smoke-upload.dat /smoke-dir/moved.dat
run_test "xrdfs ls (dir)"        xrdfs "$SERVER" ls /smoke-dir
run_test "xrdfs rm"              xrdfs "$SERVER" rm /smoke-dir/moved.dat
run_test "xrdfs rmdir"           xrdfs "$SERVER" rmdir /smoke-dir

# ---- xrdcp -T third-party-copy to self (requires allow_tpc on server) -------
run_test "xrdcp stat hello.txt"  xrdfs "$SERVER" stat /hello.txt

# ---- curl WebDAV (only when server is also serving WebDAV) ------------------
WEBDAV_URL="${WEBDAV_URL:-}"
if [ -n "$WEBDAV_URL" ]; then
    echo ""
    echo "--- WebDAV checks (WEBDAV_URL=$WEBDAV_URL) ---"
    run_test "curl WebDAV OPTIONS"  curl -sf -X OPTIONS "$WEBDAV_URL/" -o /dev/null
    run_test "davix-ls WebDAV root" davix-ls "$WEBDAV_URL/"
fi

# ---- Summary ----------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
