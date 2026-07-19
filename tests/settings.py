"""Centralized test settings shared across test modules."""

import os
import socket

TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
REGISTRY_ROOT = os.environ.get(
    "TEST_REGISTRY_ROOT", os.path.join(TEST_ROOT, "registry")
)
REGISTRY_MANIFEST = os.environ.get(
    "TEST_REGISTRY_MANIFEST", os.path.join(REGISTRY_ROOT, "manifest.json")
)
REGISTRY_ENABLED = os.environ.get("TEST_SERVER_REGISTRY", "1") != "0"
REGISTRY_START = os.environ.get("TEST_REGISTRY_START", "1") != "0"
REGISTRY_KEEP_LOGS = os.environ.get("TEST_REGISTRY_KEEP_LOGS", "0") == "1"
REGISTRY_STRICT_TEMPLATES = os.environ.get("TEST_REGISTRY_STRICT_TEMPLATES", "1") != "0"
REGISTRY_PORT_BASE = os.environ.get("TEST_REGISTRY_PORT_BASE")


# ---------------------------------------------------------------------------
# Free-port allocation for SELF-CONTAINED fixtures.
#
# A test that starts its OWN nginx/brix must NOT bind a fixed port: it would
# collide with the managed fleet (whose ports below are already bound) or with
# another self-contained test running in the same session. Such fixtures should
# bind ports from free_port()/free_ports() instead of a literal. The fleet ports
# further down stay fixed — tests CONNECT to those, they do not re-bind them.
# ---------------------------------------------------------------------------
def free_port(host="127.0.0.1"):
    """Return one OS-assigned free TCP port (bind :0, read it, release)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, 0))
        return s.getsockname()[1]
    finally:
        s.close()


def free_ports(n, host="127.0.0.1"):
    """Return n DISTINCT free TCP ports. All sockets are held open during
    allocation so the OS hands out different ports (multi-server fixtures)."""
    socks = []
    try:
        for _ in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def reserve_ports(names, host="127.0.0.1"):
    """Return a stable name->port map while holding sockets during allocation."""
    ports = free_ports(len(names), host=host)
    return dict(zip(names, ports))

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

# ---------------------------------------------------------------------------
# Host parameterization — split clients (tests) and servers onto different
# nodes (e.g. a k8s cluster). Defaults stay on loopback so a local run is
# byte-identical to before; set the env vars to point elsewhere.
#
#   HOST       — IPv4 address a CLIENT uses to reach a server it (or the
#                fixture) started/targets.            env: TEST_HOST
#   BIND_HOST  — IPv4 address a SELF-STARTED server LISTENs on (defaults to
#                HOST; set to 0.0.0.0 to expose it).  env: TEST_BIND_HOST
#   HOST6 / BIND_HOST6 — IPv6 equivalents for the dedicated [::1] tier.
#                                          env: TEST_HOST6 / TEST_BIND_HOST6
#
# url_host() brackets a bare IPv6 literal for a URL/authority (host:port).
# ---------------------------------------------------------------------------
HOST       = os.environ.get("TEST_HOST", "127.0.0.1")
BIND_HOST  = os.environ.get("TEST_BIND_HOST") or HOST
HOST6      = os.environ.get("TEST_HOST6", "::1")
BIND_HOST6 = os.environ.get("TEST_BIND_HOST6") or HOST6


def url_host(h):
    """Bracket a bare IPv6 literal for use in a URL authority (host:port)."""
    return "[%s]" % h if (":" in h and not h.startswith("[")) else h


PKI_DIR = os.path.join(TEST_ROOT, "pki")
DATA_ROOT = os.path.join(TEST_ROOT, "data")
TOKENS_DIR = os.path.join(TEST_ROOT, "tokens")
# The fleet logs the tests scrape (access/error/brix_access) are the main nginx's.
# Under the registry launcher every instance writes to its own prefix
# (REGISTRY_ROOT/<name>/logs), so the main instance's logs live there — not the
# bash-era flat TEST_ROOT/logs.  Point log-reading tests at the real location.
LOG_DIR = os.path.join(REGISTRY_ROOT, "main", "logs")

# Fleet dedicated instances migrated off per-test self-start (started once by
# start_all_dedicated; tests attach to these fixed ports and only seed data).
COMPRESS_WEBDAV_PORT = int(os.environ.get("TEST_COMPRESS_WEBDAV_PORT", "12960"))
COMPRESS_S3_PORT = int(os.environ.get("TEST_COMPRESS_S3_PORT", "12961"))
COMPRESS_DATA_ROOT = os.path.join(TEST_ROOT, "data-compress")
INTEROP_OUR_PORT = int(os.environ.get("TEST_INTEROP_OUR_PORT", "21200"))
INTEROP_OFF_PORT = int(os.environ.get("TEST_INTEROP_OFF_PORT", "21201"))
TMP_DIR = os.path.join(TEST_ROOT, "tmp")
# Scratch working directory the whole test session chdir()s into, so any
# cwd-relative artifact a spawned process makes (e.g. an xrootd `-n` instance
# dir) lands inside the temp tree and never in the repo.
CWD_DIR = os.path.join(TEST_ROOT, "cwd")

# Confine ALL scratch under TEST_ROOT instead of bare /tmp.  settings is imported
# (via conftest) before any test module loads, so pointing Python's tempdir and
# the inherited $TMPDIR here makes every tempfile.mkdtemp/mkstemp/TemporaryDirectory
# and every TMPDIR-honoring subprocess land under the one test tree the session
# wipes and recreates.  Test modules also root their explicit scratch paths at
# os.environ["TMPDIR"], which this guarantees is set.  The directory itself is
# (re)created by conftest at session start; setting tempfile.tempdir before it
# exists is fine — mkdtemp only needs it to exist when called, at test runtime.
import tempfile as _tempfile
os.environ["TMPDIR"] = TMP_DIR
_tempfile.tempdir = TMP_DIR

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
BRIX_BIN = os.environ.get("TEST_BRIX_BIN", "xrootd")
XRDFS_BIN = os.environ.get("TEST_XRDFS_BIN", "xrdfs")
XRDCP_BIN = os.environ.get("TEST_XRDCP_BIN", "xrdcp")

NGINX_ANON_PORT = int(os.environ.get("TEST_NGINX_ANON_PORT", "11094"))
# Same shared anon data root, but with brix_upload_resume OFF (stock
# direct-to-disk write posture).  Conformance suites that inspect on-disk state
# out-of-band (pgwrite accept-then-correct, fsync durability) target this port;
# the resume-ON behaviour is covered on NGINX_ANON_PORT.
NGINX_ANON_RESUME_OFF_PORT = int(
    os.environ.get("TEST_NGINX_ANON_RESUME_OFF_PORT", "11118")
)
NGINX_GSI_PORT = int(os.environ.get("TEST_NGINX_GSI_PORT", "11095"))
NGINX_GSI_TLS_PORT = int(os.environ.get("TEST_NGINX_GSI_TLS_PORT", "11096"))
NGINX_TOKEN_PORT = int(os.environ.get("TEST_NGINX_TOKEN_PORT", "11097"))
# Strict zero-skew token port — dedicated nginx instance with brix_token_clock_skew 0,
# proving that the configurable skew correctly enforces exact expiry (no grace window).
NGINX_TOKEN_STRICT_PORT = int(os.environ.get("TEST_NGINX_TOKEN_STRICT_PORT", "11119"))

# Kerberos 5 (krb5) auth tier — a DEDICATED nginx instance (not part of the
# shared instance) so an invalid keytab/principal or a krb5-less binary can only
# break this tier, never the anon/gsi/token blocks.  Provisioned + gated by
# tests/kdc_helpers.py (skips cleanly when the MIT KDC tooling or a krb5-linked
# nginx binary is absent).  The KDC listens on KRB5_KDC_PORT; everything lives
# under TEST_ROOT/krb5; the served data root is data-krb5 (the start_dedicated
# convention).  See the [[krb5-testing-deps]] notes for the install/setup story.
NGINX_KRB5_PORT = int(os.environ.get("TEST_NGINX_KRB5_PORT", "11116"))
KRB5_KDC_PORT = int(os.environ.get("TEST_KRB5_KDC_PORT", "11117"))
KRB5_REALM = os.environ.get("TEST_KRB5_REALM", "NGINX.TEST")
KRB5_DIR = os.path.join(TEST_ROOT, "krb5")
KRB5_CONF = os.path.join(KRB5_DIR, "krb5.conf")
KRB5_KEYTAB = os.path.join(KRB5_DIR, "xrootd.keytab")
KRB5_CCACHE = os.path.join(KRB5_DIR, "ccache")
KRB5_SERVICE_PRINCIPAL = os.environ.get(
    "TEST_KRB5_PRINCIPAL", "xrootd/localhost@" + KRB5_REALM
)
KRB5_CLIENT_PRINCIPAL = "alice@" + KRB5_REALM
KRB5_CLIENT_KEYTAB = os.path.join(KRB5_DIR, "client.keytab")
KRB5_DATA_ROOT = os.path.join(TEST_ROOT, "data-krb5")

REF_BRIX_PORT = int(os.environ.get("TEST_REF_BRIX_PORT", "11098"))
REF_BRIX_GSI_PORT = int(os.environ.get("TEST_REF_BRIX_GSI_PORT", "11099"))
REF_BRIX_GSI_SHARED_PORT = int(
    os.environ.get("TEST_REF_BRIX_GSI_SHARED_PORT", "11100")
)
NGINX_METRICS_PORT = int(os.environ.get("TEST_NGINX_METRICS_PORT", "9100"))
NGINX_WEBDAV_PORT = int(os.environ.get("TEST_NGINX_WEBDAV_PORT", "8443"))
NGINX_WEBDAV_GSI_TLS_PORT = int(
    os.environ.get("TEST_NGINX_WEBDAV_GSI_TLS_PORT", "8444")
)
NGINX_HTTP_WEBDAV_PORT = int(os.environ.get("TEST_NGINX_HTTP_WEBDAV_PORT", "8080"))
NGINX_S3_PORT = int(os.environ.get("TEST_NGINX_S3_PORT", "9001"))
# Enforcing WLCG bearer-token S3 port — brix_s3_token on, rejects requests that
# carry neither a valid Bearer JWT nor SigV4 credentials (INVARIANT §6).
NGINX_S3_TOKEN_PORT = int(os.environ.get("TEST_NGINX_S3_TOKEN_PORT", "9002"))
S3_BUCKET = os.environ.get("TEST_S3_BUCKET", "testbucket")

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

# XrdHttp davs:// endpoint.  The reference xrootd daemon opens a *single* TLS
# listener via `xrd.protocol XrdHttp:{HTTP_PORT}` (see configs/xrootd_xrdhttp.conf
# and the fleet spec in fleet_specs.py), so https:// and davs:// are the same
# port as XRDHTTP_HTTP_PORT — they are one server, not two.  Derive the default
# from XRDHTTP_HTTP_PORT rather than hard-coding a second "11113" literal: two
# independent literals silently drift the moment someone exports only
# TEST_XRDHTTP_HTTP_PORT, pointing test_xrdhttp_auth's davs URL at a dead port
# while nothing listens there.  Kept as a named alias for davs call-site clarity.
XRDHTTP_HTTPS_PORT = int(
    os.environ.get("TEST_XRDHTTP_HTTPS_PORT", str(XRDHTTP_HTTP_PORT))
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
PROXY_BRIDGE_BRIX_PORT = int(os.environ.get("TEST_PROXY_BRIDGE_BRIX_PORT", "11214"))
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

# Fixed redirect ports advertised by cms_parent_stubs.py in select/try responses
CLUSTER_SELECT_REDIRECT_PORT = int(os.environ.get("TEST_CLUSTER_SELECT_REDIRECT_PORT", "29000"))
CLUSTER_TRY_FIRST_PORT = int(os.environ.get("TEST_CLUSTER_TRY_FIRST_PORT", "29001"))
CLUSTER_TRY_SECOND_PORT = int(os.environ.get("TEST_CLUSTER_TRY_SECOND_PORT", "29002"))

# Phantom DS ports for kYR_gone tests — registered via CMS protocol but no service listens
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

# Stub-backed upstream nginx instances (test_a_upstream_redirect.py).
# Each nginx proxies to one port of upstream_protocol_stubs.py, which emits
# protocol sequences (kXR_wait, kXR_waitresp, kXR_authmore, kXR_gotoTLS) that
# a real xrootd server never produces.
STUB_REDIRECT_NGINX_PORT = int(os.environ.get("TEST_STUB_REDIRECT_NGINX_PORT", "11130"))
STUB_REDIRECT_BACKEND_PORT = int(os.environ.get("TEST_STUB_REDIRECT_BACKEND_PORT", "13120"))
STUB_WAIT_NGINX_PORT = int(os.environ.get("TEST_STUB_WAIT_NGINX_PORT", "11131"))
STUB_WAIT_BACKEND_PORT = int(os.environ.get("TEST_STUB_WAIT_BACKEND_PORT", "13121"))
STUB_WAITRESP_NGINX_PORT = int(os.environ.get("TEST_STUB_WAITRESP_NGINX_PORT", "11132"))
STUB_WAITRESP_BACKEND_PORT = int(os.environ.get("TEST_STUB_WAITRESP_BACKEND_PORT", "13122"))
STUB_ERROR_NGINX_PORT = int(os.environ.get("TEST_STUB_ERROR_NGINX_PORT", "11133"))
STUB_ERROR_BACKEND_PORT = int(os.environ.get("TEST_STUB_ERROR_BACKEND_PORT", "13123"))
STUB_AUTH_NGINX_PORT = int(os.environ.get("TEST_STUB_AUTH_NGINX_PORT", "11134"))
STUB_AUTH_BACKEND_PORT = int(os.environ.get("TEST_STUB_AUTH_BACKEND_PORT", "13124"))
STUB_AUTH_NOFILE_NGINX_PORT = int(os.environ.get("TEST_STUB_AUTH_NOFILE_NGINX_PORT", "11135"))
STUB_AUTH_NOFILE_BACKEND_PORT = int(os.environ.get("TEST_STUB_AUTH_NOFILE_BACKEND_PORT", "13125"))
STUB_GOTORLS_NGINX_PORT = int(os.environ.get("TEST_STUB_GOTORLS_NGINX_PORT", "11136"))
STUB_GOTORLS_BACKEND_PORT = int(os.environ.get("TEST_STUB_GOTORLS_BACKEND_PORT", "13126"))

# Real-upstream-redirect: nginx at 11137 proxies to cluster-redir (11160) to
# test kXR_redirect forwarding against a real xrootd redirector.
REAL_REDIRECT_NGINX_PORT = int(os.environ.get("TEST_REAL_REDIRECT_NGINX_PORT", "11137"))

# Proxy upstream data root
PROXY_DATA_ROOT = os.path.join(TEST_ROOT, "data-proxy-upstream")

# Authdb dedicated instance data root
AUTHDB_DIR = os.path.join(TEST_ROOT, "data-authdb")
READONLY_DATA_ROOT = os.path.join(TEST_ROOT, "data-readonly")

# HA failover cluster (HAProxy + two nginx instances)
HA_HAPROXY_PORT = int(os.environ.get("TEST_HA_HAPROXY_PORT", "11210"))
HA_NGINX1_PORT = int(os.environ.get("TEST_HA_NGINX1_PORT", "11211"))
HA_NGINX2_PORT = int(os.environ.get("TEST_HA_NGINX2_PORT", "11212"))

# ---------------------------------------------------------------------------
# Migration: pre-started dedicated instances
# Tests that used to spawn their own nginx now connect to a dedicated instance
# launched once by manage_test_servers.sh start-all (via start_dedicated_nginx).
# Each serves ${TEST_ROOT}/data-<name>; the test skips cleanly if it is not up.
# ---------------------------------------------------------------------------
OPEN_FLAGS_LIFECYCLE_NGINX_PORT = int(
    os.environ.get("TEST_OPEN_FLAGS_LIFECYCLE_NGINX_PORT", "12980")
)
OPEN_FLAGS_LIFECYCLE_DATA_ROOT = os.path.join(TEST_ROOT, "data-open-flags-lifecycle")

# Writable WebDAV HTTP — DELETE/lock security suite
WEBDAV_DELLOCK_PORT = int(os.environ.get("TEST_WDAV_DELLOCK_PORT", "13210"))
WEBDAV_DELLOCK_DATA_ROOT = os.path.join(TEST_ROOT, "data-webdav-dellock")

# Writable WebDAV HTTP — LOCK/UNLOCK ownership (xattr-backed locks)
WEBDAV_UNLOCK_OWNERSHIP_PORT = int(
    os.environ.get("TEST_WEBDAV_UNLOCK_OWNERSHIP_PORT", "22014")
)
WEBDAV_UNLOCK_OWNERSHIP_DATA_ROOT = os.path.join(
    TEST_ROOT, "data-webdav-unlock-ownership"
)

# Writable S3 — multipart upload-part-copy traversal suite
S3_MPU_PORT = int(os.environ.get("TEST_S3_MPU_PORT", "22017"))
S3_MPU_DATA_ROOT = os.path.join(TEST_ROOT, "data-s3-mpu")

# Read-only WebDAV + read-only S3 (two server blocks, one dedicated instance)
READONLY_HTTP_DAV_PORT = int(os.environ.get("TEST_READONLY_HTTP_DAV_PORT", "11216"))
READONLY_HTTP_S3_PORT = int(os.environ.get("TEST_READONLY_HTTP_S3_PORT", "11217"))
READONLY_HTTP_DATA_ROOT = os.path.join(TEST_ROOT, "data-readonly-http")

# Cleartext HTTP WebDAV with a tight per-IP rate-limit rule — XrdHttp
# wait/retry + RFC-3230 digest + RFC-7233 range conformance suite.
XRDHTTP_DIGEST_PORT = int(os.environ.get("TEST_XRDHTTP_DIGEST_PORT", "12988"))
XRDHTTP_DIGEST_DATA_ROOT = os.path.join(TEST_ROOT, "data-xrdhttp-digest")

# ---------------------------------------------------------------------------
# Phase 36: IPv6 dedicated instances (all listen on [::1]).
# See docs/refactor/phase-36-ipv6-completion.md §7. Tests gate on the
# requires_ipv6_loopback fixture (conftest.py) and skip if the instance is down.
# ---------------------------------------------------------------------------
IPV6_STREAM_PORT = int(os.environ.get("TEST_IPV6_STREAM_PORT", "11240"))
IPV6_STREAM_DATA_ROOT = os.path.join(TEST_ROOT, "data-ipv6-stream")
# manager-mode redirector + CMS + dashboard/admin/metrics, all on [::1]
IPV6_MGR_PORT = int(os.environ.get("TEST_IPV6_MGR_PORT", "11241"))       # stream manager
IPV6_MGR_CMS_PORT = int(os.environ.get("TEST_IPV6_MGR_CMS_PORT", "11242"))
IPV6_MGR_HTTP_PORT = int(os.environ.get("TEST_IPV6_MGR_HTTP_PORT", "11247"))  # dashboard/admin/metrics
IPV6_MGR_DATA_ROOT = os.path.join(TEST_ROOT, "data-ipv6-mgr")
IPV6_WEBDAV_PORT = int(os.environ.get("TEST_IPV6_WEBDAV_PORT", "11243"))
IPV6_WEBDAV_DATA_ROOT = os.path.join(TEST_ROOT, "data-ipv6-webdav")
IPV6_S3_PORT = int(os.environ.get("TEST_IPV6_S3_PORT", "11244"))
IPV6_S3_DATA_ROOT = os.path.join(TEST_ROOT, "data-ipv6-s3")
IPV6_UPSTREAM_PORT = int(os.environ.get("TEST_IPV6_UPSTREAM_PORT", "11245"))  # webdav backend origin
IPV6_UPSTREAM_DATA_ROOT = os.path.join(TEST_ROOT, "data-ipv6-upstream")
IPV6_PROXY_PORT = int(os.environ.get("TEST_IPV6_PROXY_PORT", "11246"))        # webdav proxy -> [::1] upstream
IPV6_PROXY_DATA_ROOT = os.path.join(TEST_ROOT, "data-ipv6-proxy")

# ---------------------------------------------------------------------------
# WLCG token conformance: multi-key, multi-issuer registry, enforcing WebDAV
# ---------------------------------------------------------------------------
NGINX_TOKEN_MULTIKEY_PORT = int(os.environ.get("TEST_NGINX_TOKEN_MULTIKEY_PORT", "11250"))
NGINX_TOKEN_REGISTRY_PORT = int(os.environ.get("TEST_NGINX_TOKEN_REGISTRY_PORT", "11251"))
NGINX_WEBDAV_TOKEN_PORT   = int(os.environ.get("TEST_NGINX_WEBDAV_TOKEN_PORT",   "8446"))
