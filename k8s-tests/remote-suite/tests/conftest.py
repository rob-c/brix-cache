# brix-remote-adapted
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
    REF_BRIX_GSI_PORT,
    REF_BRIX_GSI_SHARED_PORT,
    REF_BRIX_PORT,
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
# getcwd() raises FileNotFoundError if the process's cwd was removed out from
# under it (e.g. an xdist worker whose scratch cwd a concurrent session wiped,
# or a re-import of this module from a transient cwd).  Fall back to the repo
# root (this file lives in <repo>/tests/) so import never fails — a robust
# restore target regardless.  Without this, a racy getcwd() aborts collection on
# some xdist workers, tripping pytest's "different tests collected" guard.
try:
    _ORIG_CWD = os.getcwd()
except OSError:
    _ORIG_CWD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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


# Tri-state memo for "is a fleet already running that we should attach to rather
# than manage?"  None = not yet decided; resolved once per process on first query.
_external_fleet = None


def _external_fleet_attached() -> bool:
    """True when a local fleet is already listening and pytest should ATTACH to
    it without taking lifecycle ownership -- no tree wipe, no start-all/stop-all,
    no rmtree.

    This closes a footgun in the dev-iteration workflow: an operator keeps a
    fleet up out of band (``tests/manage_test_servers.sh start-all``) and runs a
    single test file for a quick check.  Without this guard the session teardown
    would ``stop-all`` + ``rmtree(TEST_ROOT)`` and orphan every still-running
    server's export-root fd, so the next manual ``xrdcp``/TPC hangs -- looking
    exactly like a server bug when it is pure test-harness teardown.  CI is
    unaffected: there no fleet is listening at session start, so pytest owns the
    lifecycle (wipe / start-all / stop-all / rmtree) exactly as before.

    Never engages in REMOTE mode (the server is managed elsewhere) and is
    overridden by ``TEST_OWN_FLEET=1`` for the operator who genuinely wants a
    clean wipe+restart on top of a running fleet.  Probed once and memoized so we
    neither re-probe nor re-print the notice on the teardown call."""
    global _external_fleet
    if _external_fleet is not None:
        return _external_fleet
    if REMOTE_SERVER or os.environ.get("TEST_OWN_FLEET") == "1":
        _external_fleet = False
        return _external_fleet
    _external_fleet = _check_server_reachable(HOST, NGINX_ANON_PORT, timeout=1.0)
    if _external_fleet:
        print(
            f"\n[conftest] A fleet is already listening on {HOST}:{NGINX_ANON_PORT}; "
            "attaching WITHOUT lifecycle management (no wipe / start-all / stop-all "
            "/ rmtree) so a stray test run cannot tear down a fleet it did not "
            "start.  Set TEST_OWN_FLEET=1 to force a clean wipe+restart.",
            flush=True,
        )
    return _external_fleet


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
        "test_aio_waitresp.py",
        "test_cross_protocol_shared_helpers.py",
        "test_ipv6_fallback.py",
        "test_loss_sweep_gsi.py",
        "test_tools_resilience.py",
        "test_net_resilience.py",
        "test_official_brix_resilience.py",
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


def _should_skip_local_lifecycle(config) -> bool:
    """Whether pytest should NOT manage (wipe / start-all / stop-all / rmtree)
    the local fleet this session: explicitly told to skip, the selected tests
    need no server, or a fleet is already running and we have not been told to
    take ownership.  Shared by session setup and teardown so both sides agree on
    who owns the lifecycle -- the asymmetry that previously let setup attach to a
    running fleet while teardown still tore it down."""
    return (
        os.environ.get("TEST_SKIP_SERVER_SETUP") == "1"
        or _selected_tests_do_not_need_server(config)
        or _external_fleet_attached()
    )


def _setup_session():
    """Shared session setup logic.

    In REMOTE mode: verify the server is reachable; skip all local lifecycle.
    In LOCAL mode: wipe data dirs, regenerate PKI, start servers.
    """
    if REMOTE_SERVER:
        _setup_remote_session()
        return
    if _external_fleet_attached():
        return
    _prepare_local_tree()
    _seed_local_data()
    _write_large_file()
    os.environ["X509_CERT_DIR"] = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_STD
    _start_local_fleet()


def _setup_remote_session():
    if not _check_server_reachable(SERVER_HOST, NGINX_ANON_PORT):
        raise pytest.UsageError(
            f"Remote server at {SERVER_HOST}:{NGINX_ANON_PORT} is not reachable. "
            "Check TEST_SERVER_HOST and that the server is running."
        )
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(TMP_DIR, exist_ok=True)
    os.environ.setdefault("X509_CERT_DIR", CA_DIR)
    os.environ.setdefault("X509_USER_PROXY", PROXY_STD)


def _prepare_local_tree():
    global _test_tree_wiped
    if not _test_tree_wiped:
        shutil.rmtree(TEST_ROOT, ignore_errors=True)
        _test_tree_wiped = True
    os.makedirs(TEST_ROOT, exist_ok=True)
    _chdir_scratch()
    _recreate_directory(DATA_ROOT)
    _recreate_directory(PKI_DIR)
    for subdir in ["ca", "server", "user", "voms", "vomsdir"]:
        os.makedirs(os.path.join(PKI_DIR, subdir), exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(TMP_DIR, exist_ok=True)
    gsi_bridge_data = os.path.join(TEST_ROOT, "data-gsi-bridge")
    _recreate_directory(gsi_bridge_data)


def _recreate_directory(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)


def _seed_local_data():
    with open(os.path.join(DATA_ROOT, "test.txt"), "wb") as f:
        f.write(b"hello from nginx-xrootd\n")
    with open(os.path.join(DATA_ROOT, "random.bin"), "wb") as f:
        f.write(random.randbytes(5242880))


def _write_large_file():
    size = 200 * 1024 * 1024
    path = os.path.join(DATA_ROOT, "large200.bin")
    import hashlib as _hashlib
    h = _hashlib.md5()
    seed_val = int(os.environ.get("LARGE_FILE_SEED", "42"))
    rng = random.Random(seed_val)
    if not os.path.exists(path) or os.path.getsize(path) != size:
        _create_large_file(path, size, rng, h)
    else:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    os.environ["LARGE_FILE_MD5"] = h.hexdigest()


def _create_large_file(path, size, rng, digest):
    with open(path, "wb") as handle:
        remaining = size
        while remaining > 0:
            length = min(16 * 1024 * 1024, remaining)
            chunk = rng.randbytes(length)
            handle.write(chunk)
            digest.update(chunk)
            remaining -= length


def _start_local_fleet():
    import subprocess
    subprocess.run(
        [
            os.path.join(os.path.dirname(__file__), "manage_test_servers.sh"),
            "start-all",
        ],
        check=True,
        capture_output=True,
    )


def pytest_sessionstart(session):
    # xdist workers inherit the environment from the controller which has already
    # called start-all (and wiped the tree).  Running it again from every worker
    # in parallel would race — but each worker still chdir()s into the shared
    # scratch CWD so its own spawns can't pollute the repo either.  That chdir is
    # gated on whether the session does local server work at all — NOT on
    # _external_fleet_attached(): in an xdist run the controller has already
    # started the fleet, so a worker probing the port would always see it
    # "running" and wrongly skip the chdir.  Lifecycle ownership (the destructive
    # wipe/start/stop) is a separate, controller-only concern.
    no_local_work = (os.environ.get("TEST_SKIP_SERVER_SETUP") == "1"
                     or _selected_tests_do_not_need_server(session.config))
    if hasattr(session.config, "workerinput"):
        if not REMOTE_SERVER and not no_local_work:
            _chdir_scratch()
        return
    if _should_skip_local_lifecycle(session.config):
        return
    _setup_session()

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "conftest_part2.py")
