set -euo pipefail

OUTPUT_DIR="${1:-/etc/grid-security/certificates}"
SUBJECT="${2:-/DC=test/DC=xrootd/CN=Test XRootD CA}"
DAYS="${3:-3650}"

mkdir -p "$OUTPUT_DIR"

openssl genrsa -out "${OUTPUT_DIR}/ca-key.pem" 4096
chmod 400 "${OUTPUT_DIR}/ca-key.pem"

openssl req -new -x509 \
  -key "${OUTPUT_DIR}/ca-key.pem" \
  -out "${OUTPUT_DIR}/ca.crt" \
  -days "$DAYS" \
  -sha256 \
  -subj "$SUBJECT" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "CA certificate generated in $OUTPUT_DIR/ca.crt"
