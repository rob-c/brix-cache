set -euo pipefail

OUTPUT_DIR="${1:-/etc/grid-security}"
CA_KEY="${2:-${OUTPUT_DIR}/certificates/ca-key.pem}"
CA_CERT="${3:-${OUTPUT_DIR}/certificates/ca.crt}"
SUBJECT="${4:-/DC=test/DC=xrootd/CN=localhost}"
DAYS="${5:-365}"

mkdir -p "$OUTPUT_DIR"

openssl genrsa -out "${OUTPUT_DIR}/hostkey.pem" 2048
chmod 400 "${OUTPUT_DIR}/hostkey.pem"

openssl req -new \
  -key "${OUTPUT_DIR}/hostkey.pem" \
  -out /tmp/host.csr \
  -subj "$SUBJECT"

openssl x509 -req \
  -in /tmp/host.csr \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -out "${OUTPUT_DIR}/hostcert.pem" \
  -days "$DAYS" \
  -sha256

rm -f /tmp/host.csr
echo "Server certificate generated in $OUTPUT_DIR/"
