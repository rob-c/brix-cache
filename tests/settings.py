"""Centralized test settings shared across test modules."""

import os

TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
PKI_DIR = os.path.join(TEST_ROOT, "pki")
DATA_ROOT = os.path.join(TEST_ROOT, "data")
TOKENS_DIR = os.path.join(TEST_ROOT, "tokens")
LOG_DIR = os.path.join(TEST_ROOT, "logs")
TMP_DIR = os.path.join(TEST_ROOT, "tmp")

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
XROOTD_BIN = os.environ.get("TEST_XROOTD_BIN", "xrootd")
XRDFS_BIN = os.environ.get("TEST_XRDFS_BIN", "xrdfs")
XRDCP_BIN = os.environ.get("TEST_XRDCP_BIN", "xrdcp")

NGINX_ANON_PORT = int(os.environ.get("TEST_NGINX_ANON_PORT", "11094"))
NGINX_GSI_PORT = int(os.environ.get("TEST_NGINX_GSI_PORT", "11095"))
NGINX_GSI_TLS_PORT = int(os.environ.get("TEST_NGINX_GSI_TLS_PORT", "11096"))
NGINX_TOKEN_PORT = int(os.environ.get("TEST_NGINX_TOKEN_PORT", "11097"))
REF_XROOTD_PORT = int(os.environ.get("TEST_REF_XROOTD_PORT", "11098"))
REF_XROOTD_GSI_PORT = int(os.environ.get("TEST_REF_XROOTD_GSI_PORT", "11099"))
REF_XROOTD_GSI_SHARED_PORT = int(
    os.environ.get("TEST_REF_XROOTD_GSI_SHARED_PORT", "11100")
)
NGINX_METRICS_PORT = int(os.environ.get("TEST_NGINX_METRICS_PORT", "9100"))
NGINX_WEBDAV_PORT = int(os.environ.get("TEST_NGINX_WEBDAV_PORT", "8443"))
NGINX_HTTP_WEBDAV_PORT = int(os.environ.get("TEST_NGINX_HTTP_WEBDAV_PORT", "8080"))
NGINX_S3_PORT = int(os.environ.get("TEST_NGINX_S3_PORT", "9001"))

MANAGER_PORT = int(os.environ.get("TEST_MANAGER_PORT", "11101"))
READONLY_PORT = int(os.environ.get("TEST_READONLY_PORT", "11102"))
VO_PORT = int(os.environ.get("TEST_VO_PORT", "11103"))

CRL_PORT = int(os.environ.get("TEST_CRL_PORT", "11104"))
WEBDAV_CRL_PORT = int(os.environ.get("TEST_WEBDAV_CRL_PORT", "11105"))
CRL_DIR_PORT = int(os.environ.get("TEST_CRL_DIR_PORT", "11106"))
WEBDAV_DIR_PORT = int(os.environ.get("TEST_WEBDAV_DIR_PORT", "11107"))
CRL_RELOAD_PORT = int(os.environ.get("TEST_CRL_RELOAD_PORT", "11108"))
CRL_RELOAD_HTTP_PORT = int(os.environ.get("TEST_CRL_RELOAD_HTTP_PORT", "11109"))

ROOT_TPC_NGINX_PORT = int(os.environ.get("TEST_ROOT_TPC_NGINX_PORT", "11110"))
ROOT_TPC_REF_PORT = int(os.environ.get("TEST_ROOT_TPC_REF_PORT", "11111"))
XRDHTTP_ROOT_PORT = int(os.environ.get("TEST_XRDHTTP_ROOT_PORT", "11112"))
XRDHTTP_HTTP_PORT = int(os.environ.get("TEST_XRDHTTP_HTTP_PORT", "11113"))
AUTHDB_PORT = int(os.environ.get("TEST_AUTHDB_PORT", "11114"))

WEBDAV_AUTH_CACHE_MANUAL_PORT = int(
    os.environ.get("TEST_WEBDAV_AUTH_CACHE_MANUAL_PORT", "18444")
)
WEBDAV_AUTH_CACHE_NGINX_PORT = int(
    os.environ.get("TEST_WEBDAV_AUTH_CACHE_NGINX_PORT", "18445")
)

WEBDAV_TPC_SOURCE_REQUIRED_PORT = int(
    os.environ.get("TEST_WEBDAV_TPC_SOURCE_REQUIRED_PORT", "18450")
)
WEBDAV_TPC_SOURCE_OPEN_PORT = int(
    os.environ.get("TEST_WEBDAV_TPC_SOURCE_OPEN_PORT", "18451")
)
WEBDAV_TPC_DEST_CAFILE_PORT = int(
    os.environ.get("TEST_WEBDAV_TPC_DEST_CAFILE_PORT", "18452")
)
WEBDAV_TPC_DEST_CADIR_PORT = int(
    os.environ.get("TEST_WEBDAV_TPC_DEST_CADIR_PORT", "18453")
)
WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT = int(
    os.environ.get("TEST_WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT", "18454")
)
WEBDAV_TPC_DEST_DISABLED_PORT = int(
    os.environ.get("TEST_WEBDAV_TPC_DEST_DISABLED_PORT", "18455")
)
WEBDAV_TPC_DEST_READONLY_PORT = int(
    os.environ.get("TEST_WEBDAV_TPC_DEST_READONLY_PORT", "18456")
)

UPSTREAM_REDIRECT_NGINX_PORT = int(
    os.environ.get("TEST_UPSTREAM_REDIRECT_NGINX_PORT", "11120")
)
UPSTREAM_WAIT_NGINX_PORT = int(
    os.environ.get("TEST_UPSTREAM_WAIT_NGINX_PORT", "11121")
)
UPSTREAM_WAITRESP_NGINX_PORT = int(
    os.environ.get("TEST_UPSTREAM_WAITRESP_NGINX_PORT", "11122")
)
UPSTREAM_ERROR_NGINX_PORT = int(
    os.environ.get("TEST_UPSTREAM_ERROR_NGINX_PORT", "11123")
)
UPSTREAM_REDIRECT_BACKEND_PORT = int(
    os.environ.get("TEST_UPSTREAM_REDIRECT_BACKEND_PORT", "12120")
)
UPSTREAM_WAIT_BACKEND_PORT = int(
    os.environ.get("TEST_UPSTREAM_WAIT_BACKEND_PORT", "12121")
)
UPSTREAM_WAITRESP_BACKEND_PORT = int(
    os.environ.get("TEST_UPSTREAM_WAITRESP_BACKEND_PORT", "12122")
)
UPSTREAM_ERROR_BACKEND_PORT = int(
    os.environ.get("TEST_UPSTREAM_ERROR_BACKEND_PORT", "12123")
)

CA_DIR = os.path.join(PKI_DIR, "ca")
CA_CERT = os.path.join(CA_DIR, "ca.pem")
CA_KEY = os.path.join(CA_DIR, "ca.key")

USER_CERT = os.path.join(PKI_DIR, "user", "usercert.pem")
USER_KEY = os.path.join(PKI_DIR, "user", "userkey.pem")
PROXY_STD = os.path.join(PKI_DIR, "user", "proxy_std.pem")
PROXY_CMS = os.path.join(PKI_DIR, "user", "proxy_cms.pem")
PROXY_ATLAS = os.path.join(PKI_DIR, "user", "proxy_atlas.pem")

SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")

VOMSDIR = os.path.join(PKI_DIR, "vomsdir")
VOMS_CERT = os.path.join(PKI_DIR, "voms", "vomscert.pem")
VOMS_KEY = os.path.join(PKI_DIR, "voms", "vomskey.pem")
