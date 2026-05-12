set -euo pipefail

VOMSDIR="${1:-/etc/grid-security/vomsdir}"
CA_CERT="${2:-${VOMSDIR}/../certificates/ca.crt}"
VO_NAME="${3:-atlas}"
ATTRIBUTE="${4:-/atlas/Role=production}"
VO_HOST="${5:-voms.atlas.cern.ch}"
VO_PORT="${6:-15000}"

mkdir -p "${VOMSDIR}/${VO_NAME}"

cat > "${VOMSDIR}/${VO_NAME}/voms.${VO_NAME}.cern.ch:${VO_PORT}.ini" << EOF
[voms]
vn = ${VO_NAME}
url = https://${VO_HOST}:${VO_PORT}/voms/${VO_NAME}
ca_cert = /etc/grid-security/certificates/ca.crt

[${ATTRIBUTE}]
role = production
wf_role = analysis
EOF

echo "VOMS attributes for $VO_NAME written to ${VOMSDIR}/${VO_NAME}/"
