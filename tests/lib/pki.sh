# tests/lib/pki.sh - Phase-38 extraction of manage_test_servers.sh.
# Sourced (not executed) by manage_test_servers.sh; uses its global
# config vars.  Do not run directly.

regenerate_pki() {
    local pki_dir="${1:-$PKI_DIR}"

    if [[ ! -d "$pki_dir" ]]; then
        echo "PKI directory does not exist, creating: $pki_dir"
        mkdir -p "$pki_dir"/{ca,server,user,voms,vomsdir}
    fi

    cd /home/rcurrie/HEP-x/nginx-xrootd || return 1

    python3 -c "
import os
import sys
sys.path.insert(0, 'tests')

os.environ['PKI_DIR'] = '$pki_dir'
from pki_helpers import blitz_test_pki
blitz_test_pki()
" 2>&1 || echo "WARNING: PKI regeneration failed, continuing anyway"

    python3 utils/make_proxy.py "$pki_dir" 2>&1 || true

    echo "PKI generated in $pki_dir"
}

substitute_config() {
    local src="$1"
    local dest="$2"
    
    # Provide sensible defaults which can be overridden by the environment
    : "${NGINX_ANON_PORT:=11094}"
    : "${NGINX_ANON_RESUME_OFF_PORT:=11118}"
    : "${NGINX_GSI_PORT:=11095}"
    : "${NGINX_GSI_TLS_PORT:=11096}"
    : "${NGINX_TOKEN_PORT:=11097}"
    : "${NGINX_METRICS_PORT:=9100}"
    : "${NGINX_WEBDAV_PORT:=8443}"
    : "${NGINX_WEBDAV_GSI_TLS_PORT:=8444}"
    : "${NGINX_HTTP_WEBDAV_PORT:=8080}"
    : "${NGINX_S3_PORT:=9001}"
    : "${TOKEN_DIR:=${TEST_ROOT}/tokens}"
    : "${CRL_PATH:=${PKI_DIR}/ca/test-user.crl.pem}"
    : "${CRL_RELOAD_INTERVAL:=5}"
    : "${HTTP_STUB_PORT:=11123}"
    : "${UPSTREAM_PORT:=12120}"
    : "${TOKEN_FILE:=${TEST_ROOT}/tokens/upstream.jwt}"
    : "${JWKS_FILE:=${TEST_ROOT}/tokens/jwks.json}"
    : "${REFRESH_INTERVAL_MS:=100}"
    : "${TOKEN_ISSUER:=https://test.example.com}"
    : "${TOKEN_AUDIENCE:=nginx-xrootd}"
    : "${WEBDAV_AUTH_CACHE_NGINX_PORT:=18445}"
    : "${WEBDAV_TPC_SOURCE_REQUIRED_PORT:=18450}"
    : "${WEBDAV_TPC_SOURCE_OPEN_PORT:=18451}"
    : "${WEBDAV_TPC_DEST_CAFILE_PORT:=18452}"
    : "${WEBDAV_TPC_DEST_CADIR_PORT:=18453}"
    : "${WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT:=18454}"
    : "${WEBDAV_TPC_DEST_DISABLED_PORT:=18455}"
    : "${WEBDAV_TPC_DEST_READONLY_PORT:=18456}"
    : "${MAP_A_HOST:=127.0.0.1}"
    : "${MAP_A_PORT:=${REF_PORT:-11098}}"
    : "${MAP_B_HOST:=127.0.0.1}"
    : "${MAP_B_PORT:=$(( ${REF_PORT:-11098} + 1 ))}"
    : "${AUTHDB_PATH:=${REF_DIR:-${TEST_ROOT}/ref}/authdb}"
    : "${SOURCE_REQUIRED_ROOT:=${DATA_DIR}/source_required}"
    : "${SOURCE_OPEN_ROOT:=${DATA_DIR}/source_open}"
    : "${DEST_CAFILE_ROOT:=${DATA_DIR}/dest_cafile}"
    : "${DEST_CADIR_ROOT:=${DATA_DIR}/dest_cadir}"
    : "${DEST_NO_SERVICE_CERT_ROOT:=${DATA_DIR}/dest_no_service_cert}"
    : "${DEST_DISABLED_ROOT:=${DATA_DIR}/dest_disabled}"
    : "${DEST_READONLY_ROOT:=${DATA_DIR}/dest_readonly}"
    : "${BIND_HOST:=127.0.0.1}"
    : "${BIND6_HOST:=[::1]}"   # IPv6 loopback for phase-36 IPv6 dedicated instances
    : "${CMS_PORT:=11161}"
    : "${CMS_PATHS:=/}"
    : "${CACHE_DIR:=${DATA_DIR}/cache}"
    : "${METRICS_PORT:=9100}"
    : "${META_CMS_PORT:=11186}"
    : "${SELF_REGISTER_PORT:=11189}"
    : "${KRB5_PRINCIPAL:=xrootd/localhost@NGINX.TEST}"
    : "${KRB5_KEYTAB:=${TEST_ROOT}/krb5/xrootd.keytab}"

    sed -e "s|{PORT}|$NGINX_PORT|g" \
        -e "s|{ANON_PORT}|${NGINX_ANON_PORT}|g" \
        -e "s|{ANON_RESUME_OFF_PORT}|${NGINX_ANON_RESUME_OFF_PORT}|g" \
        -e "s|{GSI_PORT}|${NGINX_GSI_PORT}|g" \
        -e "s|{GSI_TLS_PORT}|${NGINX_GSI_TLS_PORT}|g" \
        -e "s|{TOKEN_PORT}|${NGINX_TOKEN_PORT}|g" \
        -e "s|{METRICS_PORT}|${NGINX_METRICS_PORT}|g" \
-e "s|{WEBDAV_PORT}|${NGINX_WEBDAV_PORT}|g" \
        -e "s|{WEBDAV_GSI_TLS_PORT}|${NGINX_WEBDAV_GSI_TLS_PORT}|g" \
        -e "s|{HTTP_WEBDAV_PORT}|${NGINX_HTTP_WEBDAV_PORT}|g" \
        -e "s|{S3_PORT}|${NGINX_S3_PORT}|g" \
        -e "s|{TOKEN_DIR}|${TOKEN_DIR}|g" \
        -e "s|{UPSTREAM_PORT}|${UPSTREAM_PORT}|g" \
        -e "s|{TOKEN_FILE}|${TOKEN_FILE}|g" \
        -e "s|{JWKS_FILE}|${JWKS_FILE}|g" \
        -e "s|{REFRESH_INTERVAL_MS}|${REFRESH_INTERVAL_MS}|g" \
        -e "s|{TOKEN_ISSUER}|${TOKEN_ISSUER}|g" \
        -e "s|{TOKEN_AUDIENCE}|${TOKEN_AUDIENCE}|g" \
        -e "s|{LOG_DIR}|$LOG_DIR|g" \
        -e "s|{DATA_DIR}|$DATA_DIR|g" \
        -e "s|{TMP_DIR}|$TMP_DIR|g" \
        -e "s|{CA_CERT}|$PKI_DIR/ca/ca.pem|g" \
        -e "s|{CA_DIR}|$PKI_DIR/ca|g" \
        -e "s|{SERVER_CERT}|$PKI_DIR/server/hostcert.pem|g" \
        -e "s|{SERVER_KEY}|$PKI_DIR/server/hostkey.pem|g" \
        -e "s|{CA_PEM}|$PKI_DIR/ca/ca.pem|g" \
        -e "s|{CLIENT_CERT}|$PKI_DIR/user/usercert.pem|g" \
        -e "s|{CLIENT_KEY}|$PKI_DIR/user/userkey.pem|g" \
        -e "s|{CRL_PATH}|${CRL_PATH}|g" \
        -e "s|{VOMSDIR}|$PKI_DIR/vomsdir|g" \
        -e "s|{CRL_RELOAD_INTERVAL}|${CRL_RELOAD_INTERVAL}|g" \
        -e "s|{HTTP_STUB_PORT}|${HTTP_STUB_PORT}|g" \
        -e "s|{AUTH_PORT}|${WEBDAV_AUTH_CACHE_NGINX_PORT}|g" \
        -e "s|{SOURCE_REQUIRED_PORT}|${WEBDAV_TPC_SOURCE_REQUIRED_PORT}|g" \
        -e "s|{SOURCE_OPEN_PORT}|${WEBDAV_TPC_SOURCE_OPEN_PORT}|g" \
        -e "s|{DEST_CAFILE_PORT}|${WEBDAV_TPC_DEST_CAFILE_PORT}|g" \
        -e "s|{DEST_CADIR_PORT}|${WEBDAV_TPC_DEST_CADIR_PORT}|g" \
        -e "s|{DEST_NO_SERVICE_CERT_PORT}|${WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT}|g" \
        -e "s|{DEST_DISABLED_PORT}|${WEBDAV_TPC_DEST_DISABLED_PORT}|g" \
        -e "s|{DEST_READONLY_PORT}|${WEBDAV_TPC_DEST_READONLY_PORT}|g" \
        -e "s|{SOURCE_REQUIRED_ROOT}|${SOURCE_REQUIRED_ROOT}|g" \
        -e "s|{SOURCE_OPEN_ROOT}|${SOURCE_OPEN_ROOT}|g" \
        -e "s|{DEST_CAFILE_ROOT}|${DEST_CAFILE_ROOT}|g" \
        -e "s|{DEST_CADIR_ROOT}|${DEST_CADIR_ROOT}|g" \
        -e "s|{DEST_NO_SERVICE_CERT_ROOT}|${DEST_NO_SERVICE_CERT_ROOT}|g" \
        -e "s|{DEST_DISABLED_ROOT}|${DEST_DISABLED_ROOT}|g" \
        -e "s|{DEST_READONLY_ROOT}|${DEST_READONLY_ROOT}|g" \
        -e "s|{MAP_A_HOST}|${MAP_A_HOST}|g" \
        -e "s|{MAP_A_PORT}|${MAP_A_PORT}|g" \
        -e "s|{MAP_B_HOST}|${MAP_B_HOST}|g" \
        -e "s|{MAP_B_PORT}|${MAP_B_PORT}|g" \
        -e "s|{AUTHDB_PATH}|${AUTHDB_PATH}|g" \
        -e "s|{BIND_HOST}|${BIND_HOST}|g" \
        -e "s|{BIND6_HOST}|${BIND6_HOST}|g" \
        -e "s|{CMS_PORT}|${CMS_PORT}|g" \
        -e "s|{CMS_PATHS}|${CMS_PATHS}|g" \
        -e "s|{CACHE_DIR}|${CACHE_DIR}|g" \
        -e "s|{METRICS_PORT}|${METRICS_PORT}|g" \
        -e "s|{META_CMS_PORT}|${META_CMS_PORT}|g" \
        -e "s|{SELF_REGISTER_PORT}|${SELF_REGISTER_PORT}|g" \
        -e "s|{STAGE_CMD}|${STAGE_CMD:-/bin/true}|g" \
        -e "s|{KRB5_PRINCIPAL}|${KRB5_PRINCIPAL}|g" \
        -e "s|{KRB5_KEYTAB}|${KRB5_KEYTAB}|g" \
        "$src" > "$dest"
}
