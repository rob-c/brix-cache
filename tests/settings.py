"""Centralized test settings shared across test modules."""

import os

TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/xrd-test")

# ---------------------------------------------------------------------------
# Remote server target
#
# Set TEST_SERVER_HOST to the hostname/IP of a pre-deployed server (e.g. a
# kubernetes pod).  When set, conftest.py skips all local server lifecycle
# management (no start/stop, no data-directory wipe) and all tests connect
# to that host instead of 127.0.0.1.
#
# Leave unset (the default) to run in self-contained local mode where
# conftest.py starts/stops nginx and xrootd on 127.0.0.1.
# ---------------------------------------------------------------------------
_server_host_env = os.environ.get("TEST_SERVER_HOST")
SERVER_HOST   = _server_host_env if _server_host_env else "localhost"
REMOTE_SERVER = _server_host_env is not None   # True → skip local lifecycle
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
NGINX_WEBDAV_GSI_TLS_PORT = int(
    os.environ.get("TEST_NGINX_WEBDAV_GSI_TLS_PORT", "8444")
)
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
XRDHTTP_LIB_HTTP = os.environ.get(
    "TEST_XRDHTTP_LIB_HTTP", "/usr/lib64/libXrdHttp-5.so"
)
XRDHTTP_LIB_TPC = os.environ.get(
    "TEST_XRDHTTP_LIB_TPC", "/usr/lib64/libXrdHttpTPC-5.so"
)
AUTHDB_PORT = int(os.environ.get("TEST_AUTHDB_PORT", "11114"))
NGINX_JWKS_REFRESH_PORT = int(
    os.environ.get("TEST_NGINX_JWKS_REFRESH_PORT", "11115")
)

# XrdHttp protocol ports — reference xrootd daemon with XrdHttp module enabled.
# These are used for davs:// conformance tests against the official server.
XRDHTTP_HTTPS_PORT = int(
    os.environ.get("TEST_XRDHTTP_HTTPS_PORT", "11113")
)

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

# Phase 2: token auth / gotoTLS upstream tests
UPSTREAM_AUTH_NGINX_PORT = int(
    os.environ.get("TEST_UPSTREAM_AUTH_NGINX_PORT", "11124")
)
UPSTREAM_AUTH_BACKEND_PORT = int(
    os.environ.get("TEST_UPSTREAM_AUTH_BACKEND_PORT", "12124")
)
UPSTREAM_AUTH_NOFILE_NGINX_PORT = int(
    os.environ.get("TEST_UPSTREAM_AUTH_NOFILE_NGINX_PORT", "11125")
)
UPSTREAM_AUTH_NOFILE_BACKEND_PORT = int(
    os.environ.get("TEST_UPSTREAM_AUTH_NOFILE_BACKEND_PORT", "12125")
)
UPSTREAM_GOTORLS_NOTLS_NGINX_PORT = int(
    os.environ.get("TEST_UPSTREAM_GOTORLS_NOTLS_NGINX_PORT", "11126")
)
UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT = int(
    os.environ.get("TEST_UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT", "12126")
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

# ---------------------------------------------------------------------------
# NGINX_WEBDAV_GSI_TLS_PORT is the HTTPS WebDAV server with GSI/x509 proxy cert
# auth + TLS on port 8444.
# ---------------------------------------------------------------------------

# TPC SSRF policy dedicated servers (ports 11180-11182)
TPC_SSRF_DEFAULT_PORT = int(os.environ.get("TEST_TPC_SSRF_DEFAULT_PORT", "11180"))
TPC_SSRF_ALLOW_LOCAL_PORT = int(os.environ.get("TEST_TPC_SSRF_ALLOW_LOCAL_PORT", "11181"))
TPC_SSRF_DENY_PRIVATE_PORT = int(os.environ.get("TEST_TPC_SSRF_DENY_PRIVATE_PORT", "11182"))

# S3 presigned URL dedicated servers (ports 11183-11184)
S3_PRESIGNED_PORT = int(os.environ.get("TEST_S3_PRESIGNED_PORT", "11183"))
S3_PRESIGNED_STS_PORT = int(os.environ.get("TEST_S3_PRESIGNED_STS_PORT", "11184"))

# Security level dedicated servers (ports 11191-11192)
SECURITY_LEVEL_STANDARD_PORT = int(os.environ.get("TEST_SECURITY_LEVEL_STANDARD_PORT", "11191"))
SECURITY_LEVEL_PEDANTIC_PORT = int(os.environ.get("TEST_SECURITY_LEVEL_PEDANTIC_PORT", "11192"))
