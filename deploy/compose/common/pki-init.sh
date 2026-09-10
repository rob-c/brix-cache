#!/usr/bin/env bash
# deploy/compose/common/pki-init.sh — mint a self-contained demo PKI.
#
#   OUT=/etc/brix/pki HOSTS="brix origin manager" ./pki-init.sh
#
# Produces, idempotently (a populated $OUT/ca/ca.pem short-circuits):
#   $OUT/ca/ca.pem + <hash>.0 + <hash>.signing_policy   trust dir for
#         brix_trusted_ca_dir / brix_client_ca_store / X509_CERT_DIR
#   $OUT/ca.key                       CA private key — deliberately OUTSIDE
#         $OUT/ca: the trust dir is scanned file-by-file and a key in it is
#         logged as "PEM no start line, Expecting: CERTIFICATE" on every load
#   $OUT/hostcert.pem hostkey.pem     SAN = every name in $HOSTS + localhost
#   $OUT/usercert.pem userkey.pem     CN=Demo User (client-cert smoke paths)
#   $OUT/userproxy.pem                usercert+key concatenated, 0600
#
# Both end-entity certs carry keyUsage digitalSignature: RFC 3820 lets a
# certificate issue a proxy only when it may sign, so a user cert without it
# fails every gsiftp / TPC delegation with "signer lacks keyUsage".  The
# signing_policy names the CA in OpenSSL's slash form (/DC=demo/DC=brix/CN=...),
# the only form the Globus access_id_CA match understands — RFC 2253 order
# ("CN=...,DC=brix,DC=demo") makes the CA unable to sign anything.
#
# Demo material only: a 2048-bit RSA CA valid for 30 days, private keys on a
# shared volume. tools/ci/check_example_configs.py mints the same layout into
# a scratch tree to validate every example configuration with `nginx -t`.
set -euo pipefail

OUT="${OUT:-/etc/brix/pki}"
HOSTS="${HOSTS:-localhost brix server origin manager ds1 ds2 gateway backend proxy cache}"
DAYS="${DAYS:-30}"

if [ -s "$OUT/ca/ca.pem" ]; then
    echo "pki-init: $OUT already populated"; exit 0
fi
mkdir -p "$OUT/ca"
cd "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -sha256 \
    -subj "/DC=demo/DC=brix/CN=BriX Demo CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout ca.key -out ca/ca.pem >/dev/null 2>&1

san=""
for h in $HOSTS; do san="${san:+$san,}DNS:$h"; done
san="$san,IP:127.0.0.1"
openssl req -newkey rsa:2048 -nodes -sha256 -subj "/DC=demo/DC=brix/CN=${HOSTS%% *}" \
    -keyout hostkey.pem -out host.csr >/dev/null 2>&1
openssl x509 -req -in host.csr -CA ca/ca.pem -CAkey ca.key -CAcreateserial \
    -days "$DAYS" -sha256 -out hostcert.pem \
    -extfile <(printf 'subjectAltName=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n' "$san") >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -sha256 -subj "/DC=demo/DC=brix/CN=Demo User" \
    -keyout userkey.pem -out user.csr >/dev/null 2>&1
openssl x509 -req -in user.csr -CA ca/ca.pem -CAkey ca.key -CAcreateserial \
    -days "$DAYS" -sha256 -out usercert.pem \
    -extfile <(printf 'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n') >/dev/null 2>&1
cat usercert.pem userkey.pem > userproxy.pem
rm -f host.csr user.csr ca/ca.srl

# OpenSSL hash link + Globus signing policy, so GSI tooling that scans a
# CA directory (globus-url-copy, gfal) accepts the issuer too.
hash="$(openssl x509 -in ca/ca.pem -noout -hash)"
ln -sf ca.pem "ca/$hash.0"
printf "access_id_CA  X509  '%s'\npos_rights    globus CA:sign\ncond_subjects globus '\"/DC=demo/DC=brix/*\"'\n" \
    "$(openssl x509 -in ca/ca.pem -noout -subject -nameopt compat | sed 's/^subject=//')" \
    > "ca/$hash.signing_policy"

chmod 0644 hostcert.pem usercert.pem ca/ca.pem
chmod 0600 hostkey.pem userkey.pem userproxy.pem ca.key
# nginx workers read the host key after dropping privileges.
chmod 0644 hostkey.pem
echo "pki-init: wrote demo PKI to $OUT (CA hash $hash)"
