set -euo pipefail

OUTPUT_DIR="${1:-/etc/grid-security/crl}"
CA_KEY="${2:-${OUTPUT_DIR}/../certificates/ca-key.pem}"
CA_CERT="${3:-${OUTPUT_DIR}/../certificates/ca.crt}"
DAYS="${4:-30}"

mkdir -p "$OUTPUT_DIR"

touch "${OUTPUT_DIR}/index.txt"
echo "01" > "${OUTPUT_DIR}/crlnumber"

openssl ca -gencrl \
  -keyfile "$CA_KEY" \
  -cert "$CA_CERT" \
  -out "${OUTPUT_DIR}/ca.crl.pem" \
  -crldays "$DAYS"

case "${OUTPUT_DIR}/ca.crl.pem" in
  *.der)
    openssl crl -in "${OUTPUT_DIR}/ca.crl.pem" -outform PEM \
      -out "${OUTPUT_DIR}/ca.crl.pem" 2>/dev/null || true
    ;;
esac

cp "${OUTPUT_DIR}/ca.crl.pem" "${OUTPUT_DIR}/../certificates/ca.crl" 2>/dev/null || true

echo "CRL generated at ${OUTPUT_DIR}/ca.crl.pem"
