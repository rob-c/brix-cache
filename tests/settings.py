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

# CMS cluster: redirector + data server pair (ports 11160, 11162)
CLUSTER_REDIR_PORT = int(os.environ.get("TEST_CLUSTER_REDIR_PORT", "11160"))
CLUSTER_DS_PORT = int(os.environ.get("TEST_CLUSTER_DS_PORT", "11162"))
CLUSTER_DS_DATA_ROOT = os.path.join(TEST_ROOT, "data-cluster-ds")

# Chaos Mesh tier stack: Tier1 proxy → Tier2 cache → Tier3 storage (11163-11165)
# Plus a separate discovery cluster (11166, 11168) for delayed-CMS tests.
CHAOS_TIER3_PORT = int(os.environ.get("TEST_CHAOS_TIER3_PORT", "11163"))
CHAOS_TIER2_PORT = int(os.environ.get("TEST_CHAOS_TIER2_PORT", "11164"))
CHAOS_TIER1_PORT = int(os.environ.get("TEST_CHAOS_TIER1_PORT", "11165"))
CHAOS_DISCOVERY_REDIR_PORT = int(os.environ.get("TEST_CHAOS_DISCOVERY_REDIR_PORT", "11166"))
CHAOS_DISCOVERY_DS_PORT = int(os.environ.get("TEST_CHAOS_DISCOVERY_DS_PORT", "11168"))
CHAOS_TIER3_DATA_ROOT = os.path.join(TEST_ROOT, "data-chaos-tier3")
CHAOS_TIER2_CACHE_ROOT = os.path.join(TEST_ROOT, "data-chaos-tier2", "cache")

# HTTP read-through cache (port 18457)
NGINX_HTTP_CACHE_PORT = int(os.environ.get("TEST_NGINX_HTTP_CACHE_PORT", "18457"))

# WebDAV with VOMS extraction configured (port 18458)
NGINX_WEBDAV_VOMS_PORT = int(os.environ.get("TEST_NGINX_WEBDAV_VOMS_PORT", "18458"))

# CMS heartbeat test: dedicated nginx (12500) connecting to real CMS manager (12399/12400)
CMS_TEST_NGINX_PORT = int(os.environ.get("TEST_CMS_TEST_NGINX_PORT", "12500"))
CMS_TEST_CMS_PORT = int(os.environ.get("TEST_CMS_TEST_CMS_PORT", "12400"))
CMS_TEST_REDIR_PORT = int(os.environ.get("TEST_CMS_TEST_REDIR_PORT", "12399"))

# Proxy mode test pair (test_proxy_mode.py)
PROXY_NGINX_PORT = int(os.environ.get("TEST_PROXY_NGINX_PORT", "11193"))
PROXY_UPSTREAM_PORT = int(os.environ.get("TEST_PROXY_UPSTREAM_PORT", "12501"))

# Cluster topologies for test_manager_mode.py
CLUSTER_MP_REDIR_PORT = int(os.environ.get("TEST_CLUSTER_MP_REDIR_PORT", "11169"))
CLUSTER_MP_DS_PORT = int(os.environ.get("TEST_CLUSTER_MP_DS_PORT", "11170"))
CLUSTER_MS_REDIR_PORT = int(os.environ.get("TEST_CLUSTER_MS_REDIR_PORT", "11172"))
CLUSTER_MS_DS1_PORT = int(os.environ.get("TEST_CLUSTER_MS_DS1_PORT", "11173"))
CLUSTER_MS_DS2_PORT = int(os.environ.get("TEST_CLUSTER_MS_DS2_PORT", "11174"))
CLUSTER_MW_PORT = int(os.environ.get("TEST_CLUSTER_MW_PORT", "11176"))
CLUSTER_MW_REDIR_PORT = int(os.environ.get("TEST_CLUSTER_MW_REDIR_PORT", "11178"))
CLUSTER_3T_META_PORT = int(os.environ.get("TEST_CLUSTER_3T_META_PORT", "11185"))
CLUSTER_3T_SUB_PORT = int(os.environ.get("TEST_CLUSTER_3T_SUB_PORT", "11187"))
CLUSTER_3T_LEAF_PORT = int(os.environ.get("TEST_CLUSTER_3T_LEAF_PORT", "11190"))
CLUSTER_SELECT_PORT = int(os.environ.get("TEST_CLUSTER_SELECT_PORT", "11194"))
CLUSTER_SELECT_CMS_PORT = int(os.environ.get("TEST_CLUSTER_SELECT_CMS_PORT", "12601"))
CLUSTER_SLOTS_REDIR_PORT = int(os.environ.get("TEST_CLUSTER_SLOTS_REDIR_PORT", "11195"))
CLUSTER_SLOTS_METRICS_PORT = int(os.environ.get("TEST_CLUSTER_SLOTS_METRICS_PORT", "11196"))
CLUSTER_SLOTS_DS1_PORT = int(os.environ.get("TEST_CLUSTER_SLOTS_DS1_PORT", "12602"))
CLUSTER_SLOTS_DS2_PORT = int(os.environ.get("TEST_CLUSTER_SLOTS_DS2_PORT", "12603"))
CLUSTER_SLOTS_DS3_PORT = int(os.environ.get("TEST_CLUSTER_SLOTS_DS3_PORT", "12604"))
CLUSTER_SLOTS_DS4_PORT = int(os.environ.get("TEST_CLUSTER_SLOTS_DS4_PORT", "12605"))
CLUSTER_TRY_PORT = int(os.environ.get("TEST_CLUSTER_TRY_PORT", "11197"))
CLUSTER_TRY_CMS_PORT = int(os.environ.get("TEST_CLUSTER_TRY_CMS_PORT", "12606"))
CLUSTER_ESC_SUB_PORT = int(os.environ.get("TEST_CLUSTER_ESC_SUB_PORT", "11198"))
CLUSTER_ESC_LEAF_PORT = int(os.environ.get("TEST_CLUSTER_ESC_LEAF_PORT", "11199"))
CLUSTER_ESC_CMS_PORT = int(os.environ.get("TEST_CLUSTER_ESC_CMS_PORT", "12607"))

# Proxy interoperability matrix (Section 3A) + credential bridge (Section 4C)
PROXY_BRIDGE_XROOTD_PORT = int(os.environ.get("TEST_PROXY_BRIDGE_XROOTD_PORT", "11214"))
PROXY_PURE_NGINX_PROXY_PORT = int(os.environ.get("TEST_PROXY_PURE_NGINX_PROXY_PORT", "11213"))
CREDENTIAL_BRIDGE_PORT = int(os.environ.get("TEST_CREDENTIAL_BRIDGE_PORT", "11215"))

# Internal CMS ports used within each cluster topology
CLUSTER_CMS_PORT = int(os.environ.get("TEST_CLUSTER_CMS_PORT", "11161"))
CLUSTER_MW_CMS_PORT = int(os.environ.get("TEST_CLUSTER_MW_CMS_PORT", "11177"))
CLUSTER_3T_META_CMS_PORT = int(os.environ.get("TEST_CLUSTER_3T_META_CMS_PORT", "11186"))
CLUSTER_3T_SUB_CMS_PORT = int(os.environ.get("TEST_CLUSTER_3T_SUB_CMS_PORT", "11188"))
CLUSTER_3T_SELF_PORT = int(os.environ.get("TEST_CLUSTER_3T_SELF_PORT", "11189"))
CLUSTER_MS_CMS_PORT = int(os.environ.get("TEST_CLUSTER_MS_CMS_PORT", "11175"))
CLUSTER_MP_CMS_PORT = int(os.environ.get("TEST_CLUSTER_MP_CMS_PORT", "11171"))
CLUSTER_SLOTS_CMS_PORT = int(os.environ.get("TEST_CLUSTER_SLOTS_CMS_PORT", "12608"))

# Fixed redirect ports advertised by Python mock CMS in select/try responses
CLUSTER_SELECT_REDIRECT_PORT = int(os.environ.get("TEST_CLUSTER_SELECT_REDIRECT_PORT", "29000"))
CLUSTER_TRY_FIRST_PORT = int(os.environ.get("TEST_CLUSTER_TRY_FIRST_PORT", "29001"))
CLUSTER_TRY_SECOND_PORT = int(os.environ.get("TEST_CLUSTER_TRY_SECOND_PORT", "29002"))

# Phantom DS ports for kYR_gone tests — registered with CMS mock but no service listens
CLUSTER_GONE_DS_PORT   = int(os.environ.get("TEST_CLUSTER_GONE_DS_PORT",   "29010"))
CLUSTER_GONE_DS_PORT_A = int(os.environ.get("TEST_CLUSTER_GONE_DS_PORT_A", "29011"))
CLUSTER_GONE_DS_PORT_B = int(os.environ.get("TEST_CLUSTER_GONE_DS_PORT_B", "29012"))

# Proxy backend-unavailable test (points at a guaranteed-dead upstream port)
PROXY_DEAD_NGINX_PORT = int(os.environ.get("TEST_PROXY_DEAD_NGINX_PORT", "11203"))
PROXY_DEAD_UPSTREAM_PORT = int(os.environ.get("TEST_PROXY_DEAD_UPSTREAM_PORT", "19999"))

# kXR_prepare staging command test servers
PREPARE_CMD_PORT = int(os.environ.get("TEST_PREPARE_CMD_PORT", "11204"))
PREPARE_NOCMD_PORT = int(os.environ.get("TEST_PREPARE_NOCMD_PORT", "11205"))

# Phase 2 capability-flag servers (test_protocol_flags.py)
META_ONLY_PORT     = int(os.environ.get("TEST_META_ONLY_PORT",     "11206"))
SUPERVISOR_PORT    = int(os.environ.get("TEST_SUPERVISOR_PORT",    "11207"))
VIRTUAL_REDIR_PORT = int(os.environ.get("TEST_VIRTUAL_REDIR_PORT", "11208"))
COLLAPSE_REDIR_PORT = int(os.environ.get("TEST_COLLAPSE_REDIR_PORT", "11209"))

# Cache/write-through test servers (test_cache_write_through.py)
CACHE_ONLY_PORT = int(os.environ.get("TEST_CACHE_ONLY_PORT", "11200"))
WT_SYNC_PORT = int(os.environ.get("TEST_WT_SYNC_PORT", "11201"))
WT_ASYNC_PORT = int(os.environ.get("TEST_WT_ASYNC_PORT", "11202"))

# Multi-server cluster data roots
CLUSTER_MS_DS1_DATA_ROOT = os.path.join(TEST_ROOT, "data-cluster-ms-ds1")
CLUSTER_MS_DS2_DATA_ROOT = os.path.join(TEST_ROOT, "data-cluster-ms-ds2")

# Slots cluster data roots
CLUSTER_SLOTS_DS1_DATA_ROOT = os.path.join(TEST_ROOT, "data-cluster-slots-ds1")
CLUSTER_SLOTS_DS2_DATA_ROOT = os.path.join(TEST_ROOT, "data-cluster-slots-ds2")
CLUSTER_SLOTS_DS3_DATA_ROOT = os.path.join(TEST_ROOT, "data-cluster-slots-ds3")
CLUSTER_SLOTS_DS4_DATA_ROOT = os.path.join(TEST_ROOT, "data-cluster-slots-ds4")

# Three-tier leaf data root
CLUSTER_3T_LEAF_DATA_ROOT = os.path.join(TEST_ROOT, "data-cluster-3t-leaf")

# Escalation leaf data root
CLUSTER_ESC_LEAF_DATA_ROOT = os.path.join(TEST_ROOT, "data-cluster-esc-leaf")

# Mock-only backend ports for test_a_upstream_redirect.py
#
# No real xrootd server ever runs on these ports.  Each test in
# test_a_upstream_redirect.py binds a Python MockUpstream to one of these
# ports, exercises the nginx instance that points at it, then the mock exits.
# SO_REUSEADDR lets the next test reclaim the same port.
MOCK_REDIRECT_NGINX_PORT = int(os.environ.get("TEST_MOCK_REDIRECT_NGINX_PORT", "11130"))
MOCK_REDIRECT_BACKEND_PORT = int(os.environ.get("TEST_MOCK_REDIRECT_BACKEND_PORT", "13120"))
MOCK_WAIT_NGINX_PORT = int(os.environ.get("TEST_MOCK_WAIT_NGINX_PORT", "11131"))
MOCK_WAIT_BACKEND_PORT = int(os.environ.get("TEST_MOCK_WAIT_BACKEND_PORT", "13121"))
MOCK_WAITRESP_NGINX_PORT = int(os.environ.get("TEST_MOCK_WAITRESP_NGINX_PORT", "11132"))
MOCK_WAITRESP_BACKEND_PORT = int(os.environ.get("TEST_MOCK_WAITRESP_BACKEND_PORT", "13122"))
MOCK_ERROR_NGINX_PORT = int(os.environ.get("TEST_MOCK_ERROR_NGINX_PORT", "11133"))
MOCK_ERROR_BACKEND_PORT = int(os.environ.get("TEST_MOCK_ERROR_BACKEND_PORT", "13123"))
MOCK_AUTH_NGINX_PORT = int(os.environ.get("TEST_MOCK_AUTH_NGINX_PORT", "11134"))
MOCK_AUTH_BACKEND_PORT = int(os.environ.get("TEST_MOCK_AUTH_BACKEND_PORT", "13124"))
MOCK_AUTH_NOFILE_NGINX_PORT = int(os.environ.get("TEST_MOCK_AUTH_NOFILE_NGINX_PORT", "11135"))
MOCK_AUTH_NOFILE_BACKEND_PORT = int(os.environ.get("TEST_MOCK_AUTH_NOFILE_BACKEND_PORT", "13125"))
MOCK_GOTORLS_NGINX_PORT = int(os.environ.get("TEST_MOCK_GOTORLS_NGINX_PORT", "11136"))
MOCK_GOTORLS_BACKEND_PORT = int(os.environ.get("TEST_MOCK_GOTORLS_BACKEND_PORT", "13126"))

# Real-upstream-redirect: nginx at 11137 proxies to cluster-redir (11160) to
# test kXR_redirect forwarding without a Python mock backend.
REAL_REDIRECT_NGINX_PORT = int(os.environ.get("TEST_REAL_REDIRECT_NGINX_PORT", "11137"))

# Proxy upstream data root
PROXY_DATA_ROOT = os.path.join(TEST_ROOT, "data-proxy-upstream")

# Authdb dedicated instance data root
AUTHDB_DIR = os.path.join(TEST_ROOT, "data-authdb")
READONLY_DATA_ROOT = os.path.join(TEST_ROOT, "data-readonly")
