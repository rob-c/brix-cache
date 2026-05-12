set -euo pipefail

OUTPUT_DIR="${1:-/etc/grid-security/user}"
CA_CERT="${2:-${OUTPUT_DIR}/../certificates/ca.crt}"
CA_KEY="${3:-${OUTPUT_DIR}/../certificates/ca-key.pem}"
USER_SUBJECT="${4:-/DC=test/DC=xrootd/CN=Test User/CN=12345}"
DAYS="${5:-7}"

mkdir -p "$OUTPUT_DIR"

openssl genrsa -out "${OUTPUT_DIR}/userkey.pem" 2048
chmod 400 "${OUTPUT_DIR}/userkey.pem"

openssl req -new \
  -key "${OUTPUT_DIR}/userkey.pem" \
  -out /tmp/user.csr \
  -subj "$USER_SUBJECT"

cat > /tmp/ca-ext.cnf << 'EOF'
[v3_ca]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 -req \
  -in /tmp/user.csr \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -out "${OUTPUT_DIR}/usercert.pem" \
  -days "$DAYS" \
  -sha256 \
  -extfile /tmp/ca-ext.cnf \
  -extensions v3_ca

rm -f /tmp/user.csr /tmp/ca-ext.cnf
echo "User proxy certificate generated in $OUTPUT_DIR/"
