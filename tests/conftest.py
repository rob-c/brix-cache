"""Shared fixtures for nginx-xrootd test suite.

LOCAL mode (default — TEST_SERVER_HOST not set):
    conftest.py regenerates PKI, seeds test data, and starts/stops servers
    automatically.  All connections go to 127.0.0.1.

REMOTE mode (TEST_SERVER_HOST=<host>):
    conftest.py skips all local server lifecycle.  The server must already
    be running (e.g. a kubernetes pod).  Connections go to TEST_SERVER_HOST.
    Tests marked @pytest.mark.requires_local_server are skipped because they
    write directly to the server's data directory.
"""

import os
import shutil
import random
import socket
import tempfile

import pytest
from settings import (
    CA_CERT,
    CA_DIR,
    HOST,
    BIND_HOST6,
    CWD_DIR,
    DATA_ROOT,
    LOG_DIR,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    NGINX_METRICS_PORT,
    NGINX_JWKS_REFRESH_PORT,
    NGINX_KRB5_PORT,
    NGINX_TOKEN_PORT,
    KRB5_CCACHE,
    NGINX_WEBDAV_PORT,
    NGINX_WEBDAV_GSI_TLS_PORT,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_S3_PORT,
    PROXY_STD,
    PKI_DIR,
    READONLY_PORT,
    REF_XROOTD_GSI_PORT,
    REF_XROOTD_GSI_SHARED_PORT,
    REF_XROOTD_PORT,
    REMOTE_SERVER,
    SERVER_HOST,
    TEST_ROOT,
    TOKENS_DIR,
    TMP_DIR,
    UPSTREAM_AUTH_BACKEND_PORT,
    UPSTREAM_AUTH_NGINX_PORT,
    UPSTREAM_AUTH_NOFILE_BACKEND_PORT,
    UPSTREAM_AUTH_NOFILE_NGINX_PORT,
    UPSTREAM_ERROR_BACKEND_PORT,
    UPSTREAM_ERROR_NGINX_PORT,
    UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT,
    UPSTREAM_GOTORLS_NOTLS_NGINX_PORT,
    UPSTREAM_REDIRECT_BACKEND_PORT,
    UPSTREAM_REDIRECT_NGINX_PORT,
    UPSTREAM_WAIT_BACKEND_PORT,
    UPSTREAM_WAIT_NGINX_PORT,
    UPSTREAM_WAITRESP_BACKEND_PORT,
    UPSTREAM_WAITRESP_NGINX_PORT,
    VO_PORT,
    WEBDAV_AUTH_CACHE_MANUAL_PORT,
    WEBDAV_AUTH_CACHE_NGINX_PORT,
    WEBDAV_TPC_DEST_CADIR_PORT,
    WEBDAV_TPC_DEST_CAFILE_PORT,
    WEBDAV_TPC_DEST_DISABLED_PORT,
    WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT,
    WEBDAV_TPC_DEST_READONLY_PORT,
    WEBDAV_TPC_SOURCE_OPEN_PORT,
    WEBDAV_TPC_SOURCE_REQUIRED_PORT,
)

# Repo cwd captured at import (pytest's rootdir).  The session chdir()s into
# CWD_DIR for the run and restores this at teardown before wiping the tree.
_ORIG_CWD = os.getcwd()
# Guards the destructive full-tree wipe so it runs at most once per process
# (defensive — _setup_session is normally called only from pytest_sessionstart).
_test_tree_wiped = False


def _chdir_scratch():
    """Run the session from a scratch CWD inside the temp tree (mandatory in
    local mode) so no cwd-relative artifact can ever land in the repo."""
    os.makedirs(CWD_DIR, exist_ok=True)
    os.chdir(CWD_DIR)


def _check_server_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    """Return True if the server is accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# IPv6 test support (phase-36).  Tests targeting the [::1] dedicated instances
# gate on this fixture so the whole IPv6 suite is a clean no-op on hosts without
# usable IPv6 loopback (IPv6-disabled kernels, some containers/CI).
# ---------------------------------------------------------------------------
def _ipv6_loopback_available() -> bool:
    """True if this host can bind the IPv6 loopback ::1."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            s.bind((BIND_HOST6, 0))
            return True
        finally:
            s.close()
    except OSError:
        return False


_HAVE_IPV6_LOOPBACK = _ipv6_loopback_available()


@pytest.fixture(scope="session")
def requires_ipv6_loopback():
    """Skip the test cleanly when the host has no usable IPv6 loopback ::1."""
    if not _HAVE_IPV6_LOOPBACK:
        pytest.skip("IPv6 loopback ::1 not available on this host")


@pytest.fixture(scope="session")
def requires_krb5():
    """Skip krb5 tests unless the krb5 tier is actually up on this host.

    The tier self-disables when the MIT KDC tooling (krb5-server) is missing or
    the nginx binary was built without Kerberos, so probe for the live result
    rather than for the tooling: the dedicated nginx port must accept AND a
    client credential cache must have been minted by ``kdc_helpers.up``.  This is
    re-checked each session (not cached at import) because the tier is started by
    ``manage_test_servers.sh start-all`` after this module is imported.
    """
    if REMOTE_SERVER:
        pytest.skip("krb5 tier is local-only (KDC + keytab live on the test host)")
    if not _check_server_reachable(SERVER_HOST, NGINX_KRB5_PORT):
        pytest.skip(
            f"krb5 nginx tier not up on {SERVER_HOST}:{NGINX_KRB5_PORT} "
            "(needs krb5-server installed + an nginx binary built with krb5)"
        )
    if not os.path.exists(KRB5_CCACHE):
        pytest.skip(f"no krb5 client credential cache at {KRB5_CCACHE}")


def _selected_tests_do_not_need_server(config) -> bool:
    """Return True when the requested pytest target is static-only."""
    raw_args = getattr(config, "args", ()) or ()
    no_server_files = {
        "test_cross_protocol_shared_helpers.py",
        "test_ipv6_fallback.py",
        "test_loss_sweep_gsi.py",
        "test_tools_resilience.py",
        "test_net_resilience.py",
        "test_official_xrootd_resilience.py",
        "test_phase0_guardrails.py",
        "test_phase1_commodity_libraries.py",
        "test_plan6_guardrails.py",
        "test_tpc_token_mode.py",
    }
    saw_test_path = False

    for arg in raw_args:
        if arg.startswith("-"):
            continue

        path = arg.split("::", 1)[0]
        if not path.endswith(".py"):
            return False

        saw_test_path = True
        if os.path.basename(path) not in no_server_files:
            return False

    return saw_test_path


def _setup_session():
    """Shared session setup logic.

    In REMOTE mode: verify the server is reachable; skip all local lifecycle.
    In LOCAL mode: wipe data dirs, regenerate PKI, start servers.
    """
    import subprocess

    if REMOTE_SERVER:
        # Verify connectivity before the test suite begins.
        if not _check_server_reachable(SERVER_HOST, NGINX_ANON_PORT):
            raise pytest.UsageError(
                f"Remote server at {SERVER_HOST}:{NGINX_ANON_PORT} is not reachable. "
                "Check TEST_SERVER_HOST and that the server is running."
            )
        # PKI dirs still needed locally for cert-based tests (they read certs,
        # but do NOT regenerate them — operator must pre-provision).
        os.makedirs(LOG_DIR, exist_ok=True)
        os.makedirs(TMP_DIR, exist_ok=True)
        os.environ.setdefault("X509_CERT_DIR", CA_DIR)
        os.environ.setdefault("X509_USER_PROXY", PROXY_STD)
        return

    # ---- LOCAL mode ----

    # MANDATED CLEAN SLATE: destroy the entire temp tree so every run regenerates
    # all artifacts (data, PKI, tokens, server configs) from scratch — no stale
    # files are ever carried between runs.  Then chdir into a scratch dir inside
    # the (recreated) tree so the whole session — including every server the
    # harness spawns below — runs with a CWD under /tmp, never the repo.
    global _test_tree_wiped
    if not _test_tree_wiped:
        shutil.rmtree(TEST_ROOT, ignore_errors=True)
        _test_tree_wiped = True
    os.makedirs(TEST_ROOT, exist_ok=True)
    _chdir_scratch()

    # Clear data and pki folders before each test session
    if os.path.exists(DATA_ROOT):
        shutil.rmtree(DATA_ROOT)
    os.makedirs(DATA_ROOT, exist_ok=True)

    if os.path.exists(PKI_DIR):
        shutil.rmtree(PKI_DIR)
    os.makedirs(PKI_DIR, exist_ok=True)

    # Create subdirectories for PKI
    for subdir in ["ca", "server", "user", "voms", "vomsdir"]:
        os.makedirs(os.path.join(PKI_DIR, subdir), exist_ok=True)

    # Create logs and tmp directories
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(TMP_DIR, exist_ok=True)

    # Create data-gsi-bridge directory for cross-server GSI tests (test_gsi_bridge.py)
    gsi_bridge_data = os.path.join(TEST_ROOT, "data-gsi-bridge")
    if os.path.exists(gsi_bridge_data):
        shutil.rmtree(gsi_bridge_data)
    os.makedirs(gsi_bridge_data, exist_ok=True)

    # Create required test files in data directory
    with open(os.path.join(DATA_ROOT, "test.txt"), "wb") as f:
        f.write(b"hello from nginx-xrootd\n")

    # Generate random.bin (5MB of random data)
    with open(os.path.join(DATA_ROOT, "random.bin"), "wb") as f:
        f.write(bytes(random.getrandbits(8) for _ in range(5242880)))

    # Generate large200.bin (200 MiB) — MD5 exposed via env var for tests that need it.
    LARGE_FILE_SIZE = 200 * 1024 * 1024
    LARGE_FILE_PATH = os.path.join(DATA_ROOT, "large200.bin")
    import hashlib as _hashlib
    h = _hashlib.md5()
    seed_val = int(os.environ.get("LARGE_FILE_SEED", "42"))
    rng = random.Random(seed_val)
    if (not os.path.exists(LARGE_FILE_PATH)
            or os.path.getsize(LARGE_FILE_PATH) != LARGE_FILE_SIZE):
        with open(LARGE_FILE_PATH, "wb") as f:
            # Write in 16 MiB chunks to limit memory pressure
            chunk_size = 16 * 1024 * 1024
            remaining = LARGE_FILE_SIZE
            while remaining > 0:
                n = min(chunk_size, remaining)
                chunk = bytes(rng.getrandbits(8) for _ in range(n))
                f.write(chunk)
                h.update(chunk)
                remaining -= n
        os.environ["LARGE_FILE_MD5"] = h.hexdigest()
    else:
        # File exists from prior run — recompute MD5 to stay consistent.
        with open(LARGE_FILE_PATH, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        os.environ["LARGE_FILE_MD5"] = h.hexdigest()

    os.environ["X509_CERT_DIR"] = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_STD

    subprocess.run(
        [
            os.path.join(os.path.dirname(__file__), "manage_test_servers.sh"),
            "start-all",
        ],
        check=True,
        capture_output=True,
    )


def pytest_sessionstart(session):
    skip = (os.environ.get("TEST_SKIP_SERVER_SETUP") == "1"
            or _selected_tests_do_not_need_server(session.config))
    # xdist workers inherit the environment from the controller which has already
    # called start-all (and wiped the tree).  Running it again from every worker
    # in parallel would race — but each worker still chdir()s into the shared
    # scratch CWD so its own spawns can't pollute the repo either.
    if hasattr(session.config, "workerinput"):
        if not REMOTE_SERVER and not skip:
            _chdir_scratch()
        return
    if skip:
        return
    _setup_session()


def pytest_configure(config):
    """Register custom markers and confine all scratch under TEST_ROOT.

    Many tests (and the servers/clients they spawn) create scratch via
    ``tempfile.mkdtemp/mkstemp/TemporaryDirectory`` or a ``TMPDIR``-honoring
    subprocess.  Left at the default they litter bare ``/tmp`` (e.g.
    ``/tmp/xrd-jwks-test-*``).  Point Python's tempdir AND the inherited
    ``$TMPDIR`` at ``TEST_ROOT/tmp`` so every such artifact lands under the one
    test tree that the session wipes and recreates — nothing leaks into /tmp.
    Runs on the controller and on every xdist worker, before any test executes.
    """
    os.makedirs(TMP_DIR, exist_ok=True)
    os.environ["TMPDIR"] = TMP_DIR
    tempfile.tempdir = TMP_DIR

    config.addinivalue_line(
        "markers",
        "requires_local_server: test writes directly to the server filesystem "
        "and cannot run against a remote server (skipped when TEST_SERVER_HOST is set)",
    )


def pytest_collection_modifyitems(config, items):
    """Skip requires_local_server tests in remote mode; order CMS tests last."""
    cms_items = []
    other_items = []

    for item in items:
        name = os.path.basename(str(item.fspath))

        if item.get_closest_marker("requires_local_server") and REMOTE_SERVER:
            item.add_marker(
                pytest.mark.skip(
                    reason=f"requires_local_server: test writes to server filesystem "
                    f"(remote: {SERVER_HOST})"
                )
            )

        # Honor the `serial` marker under pytest-xdist: assign every serial test
        # to one xdist group so they land on a single worker and never run
        # concurrently with each other.  Effective only with `--dist loadgroup`
        # (the project's canonical parallel invocation); a harmless no-op under the
        # default `--dist load` or serial runs.  Stateful suites (e.g. the chaos
        # meshes) mark themselves `serial` precisely because parallel co-execution
        # corrupts their shared mesh/port state.
        if item.get_closest_marker("serial"):
            item.add_marker(pytest.mark.xdist_group("serial"))

        if name == "test_cms.py":
            cms_items.append(item)
        else:
            other_items.append(item)

    if cms_items:
        items[:] = other_items + cms_items


def pytest_sessionfinish(session, exitstatus):
    """Stop local servers when the session ends (no-op in remote mode or xdist workers)."""
    import subprocess

    # xdist workers must not call stop-all: the controller owns server lifecycle.
    # A worker finishing early would kill servers other workers still need.
    if hasattr(session.config, "workerinput"):
        return

    if (REMOTE_SERVER
            or os.environ.get("TEST_SKIP_SERVER_SETUP") == "1"
            or _selected_tests_do_not_need_server(session.config)):
        return

    try:
        subprocess.run(
            [
                os.path.join(os.path.dirname(__file__), "manage_test_servers.sh"),
                "stop-all",
            ],
            capture_output=True,
            timeout=30,
        )
    except Exception:
        pass  # best-effort cleanup

    # MANDATED CLEANUP: leave nothing behind.  Restore the original CWD first
    # (we are currently inside CWD_DIR, which is about to be deleted), then
    # destroy the whole temp tree so the next run starts from a clean slate and
    # regenerates every file.  Only reached on the controller in local mode
    # (remote/skip/no-server returned above).
    try:
        os.chdir(_ORIG_CWD)
    except OSError:
        pass
    shutil.rmtree(TEST_ROOT, ignore_errors=True)


@pytest.fixture(scope="session")
def _test_session_setup():
    """Session-scoped fixture that ensures servers are running.

    In remote mode: verifies connectivity; does not start/stop any process.
    In local mode: starts servers and tears them down when the session ends.
    """
    _setup_session()
    yield
    if REMOTE_SERVER:
        return
    import subprocess

    try:
        subprocess.run(
            [
                os.path.join(os.path.dirname(__file__), "manage_test_servers.sh"),
                "stop-all",
            ],
            capture_output=True,
            timeout=30,
        )
    except Exception:
        pass


@pytest.fixture(scope="session")
def test_env():
    h = SERVER_HOST
    ports = {
        "anon_port": NGINX_ANON_PORT,
        "gsi_port": NGINX_GSI_PORT,
        "gsi_tls_port": NGINX_GSI_TLS_PORT,
        "token_port": NGINX_TOKEN_PORT,
        "krb5_port": NGINX_KRB5_PORT,
        "metrics_port": NGINX_METRICS_PORT,
        "webdav_port": NGINX_WEBDAV_PORT,
        "webdav_gsi_tls_port": NGINX_WEBDAV_GSI_TLS_PORT,
        "http_webdav_port": NGINX_HTTP_WEBDAV_PORT,
        "s3_port": NGINX_S3_PORT,
        "jwks_refresh_port": NGINX_JWKS_REFRESH_PORT,
        "readonly_port": READONLY_PORT,
        "vo_port": VO_PORT,
        "webdav_auth_cache_manual_port": WEBDAV_AUTH_CACHE_MANUAL_PORT,
        "webdav_auth_cache_nginx_port": WEBDAV_AUTH_CACHE_NGINX_PORT,
        "webdav_tpc_source_required_port": WEBDAV_TPC_SOURCE_REQUIRED_PORT,
        "webdav_tpc_source_open_port": WEBDAV_TPC_SOURCE_OPEN_PORT,
        "webdav_tpc_dest_cafile_port": WEBDAV_TPC_DEST_CAFILE_PORT,
        "webdav_tpc_dest_cadir_port": WEBDAV_TPC_DEST_CADIR_PORT,
        "webdav_tpc_dest_no_service_cert_port": WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT,
        "webdav_tpc_dest_disabled_port": WEBDAV_TPC_DEST_DISABLED_PORT,
        "webdav_tpc_dest_readonly_port": WEBDAV_TPC_DEST_READONLY_PORT,
        "upstream_redirect_nginx_port": UPSTREAM_REDIRECT_NGINX_PORT,
        "upstream_wait_nginx_port": UPSTREAM_WAIT_NGINX_PORT,
        "upstream_waitresp_nginx_port": UPSTREAM_WAITRESP_NGINX_PORT,
        "upstream_error_nginx_port": UPSTREAM_ERROR_NGINX_PORT,
        "upstream_auth_nginx_port": UPSTREAM_AUTH_NGINX_PORT,
        "upstream_auth_nofile_nginx_port": UPSTREAM_AUTH_NOFILE_NGINX_PORT,
        "upstream_gotorls_notls_nginx_port": UPSTREAM_GOTORLS_NOTLS_NGINX_PORT,
        "upstream_redirect_backend_port": UPSTREAM_REDIRECT_BACKEND_PORT,
        "upstream_wait_backend_port": UPSTREAM_WAIT_BACKEND_PORT,
        "upstream_waitresp_backend_port": UPSTREAM_WAITRESP_BACKEND_PORT,
        "upstream_error_backend_port": UPSTREAM_ERROR_BACKEND_PORT,
        "upstream_auth_backend_port": UPSTREAM_AUTH_BACKEND_PORT,
        "upstream_auth_nofile_backend_port": UPSTREAM_AUTH_NOFILE_BACKEND_PORT,
        "upstream_gotorls_notls_backend_port": UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT,
    }

    return {
        **ports,
        "server_host": h,
        "anon_url": f"root://{h}:{ports['anon_port']}",
        "gsi_url": f"root://{h}:{ports['gsi_port']}",
        "gsi_tls_url": f"roots://{h}:{ports['gsi_tls_port']}",
        "token_url": f"root://{h}:{ports['token_port']}",
        "krb5_url": f"root://{h}:{ports['krb5_port']}",
        "metrics_url": f"http://{h}:{ports['metrics_port']}/metrics",
        "webdav_url": f"https://{h}:{ports['webdav_port']}",
        "webdav_gsi_tls_url": f"https://{h}:{ports['webdav_gsi_tls_port']}",
        "http_webdav_url": f"http://{h}:{ports['http_webdav_port']}",
        "s3_url": f"http://{h}:{ports['s3_port']}",
        "data_dir": DATA_ROOT,
        "ca_dir": CA_DIR,
        "ca_pem": CA_CERT,
        "proxy_pem": PROXY_STD,
        "token_dir": TOKENS_DIR,
        "log_dir": LOG_DIR,
    }


@pytest.fixture(scope="session")
def ref_xrootd(test_env):
    return {
        "url": f"root://{HOST}:{REF_XROOTD_PORT}",
        "port": REF_XROOTD_PORT,
        "data_dir": test_env["data_dir"],
    }


@pytest.fixture(scope="session")
def ref_xrootd_gsi(test_env):
    return {
        "url": f"root://{HOST}:{REF_XROOTD_GSI_PORT}",
        "port": REF_XROOTD_GSI_PORT,
        "data_dir": os.path.join(TEST_ROOT, "data-gsi-bridge"),
    }


@pytest.fixture(scope="session")
def ref_xrootd_gsi_shared(test_env):
    return {
        "url": f"root://{HOST}:{REF_XROOTD_GSI_SHARED_PORT}",
        "port": REF_XROOTD_GSI_SHARED_PORT,
        "data_dir": test_env["data_dir"],
    }
