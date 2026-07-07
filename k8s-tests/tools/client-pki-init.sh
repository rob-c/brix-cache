#!/usr/bin/env bash
# client-pki-init.sh — lay out the client PKI + token material that the pytest
# suite (tests/settings.py) expects, from the authority-provisioned files. Run
# in the test-runner before pytest so gsi/token tests find client certs, a
# proxy, the CA trust, and the token signing key / JWKS.
#
# Inputs (mounted from the authority plane):
#   PKI_SRC   dir with ca.pem, usercert.pem, userkey.pem, hostcert.pem,
#             hostkey.pem, signing_key.pem   (the <rel>-pki Secret)
#   JWKS_SRC  path to jwks.json               (the <rel>-jwks ConfigMap)
#   UTILS     dir with make_proxy.py          (default /opt/brix/utils)
# Output layout under $TEST_ROOT (settings.py: PKI_DIR=$TEST_ROOT/pki).
set -euo pipefail

: "${TEST_ROOT:?TEST_ROOT must be set}"
PKI_SRC="${PKI_SRC:-/auth/pki}"
JWKS_SRC="${JWKS_SRC:-/auth/jwks/jwks.json}"
UTILS="${UTILS:-/opt/brix/utils}"

PKI="$TEST_ROOT/pki"
TOK="$TEST_ROOT/tokens"
mkdir -p "$PKI/ca" "$PKI/user" "$PKI/server" "$PKI/vomsdir" "$TOK"

install -m 0644 "$PKI_SRC/ca.pem" "$PKI/ca/ca.pem"
# OpenSSL CA hash link so the trust dir resolves the issuer.
hash="$(openssl x509 -in "$PKI/ca/ca.pem" -noout -hash)"
ln -sf ca.pem "$PKI/ca/$hash.0"

install -m 0644 "$PKI_SRC/usercert.pem" "$PKI/user/usercert.pem"
install -m 0400 "$PKI_SRC/userkey.pem"  "$PKI/user/userkey.pem"
[ -f "$PKI_SRC/hostcert.pem" ] && install -m 0644 "$PKI_SRC/hostcert.pem" "$PKI/server/hostcert.pem"
[ -f "$PKI_SRC/hostkey.pem" ]  && install -m 0400 "$PKI_SRC/hostkey.pem"  "$PKI/server/hostkey.pem"

install -m 0400 "$PKI_SRC/signing_key.pem" "$TOK/signing_key.pem"
install -m 0644 "$JWKS_SRC" "$TOK/jwks.json"

# Generate the standard GSI proxy (settings.py PROXY_STD) from the user cert/key.
python3 "$UTILS/make_proxy.py" "$PKI" >/dev/null

echo "client PKI ready at $PKI (user cert + proxy_std, CA trust, tokens)"
