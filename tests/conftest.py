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
import subprocess
import sys


# Make the packaged harness importable without an installed BriXTest project: the
# canonical dev invocation is `PYTHONPATH=tests pytest ...`, which puts only
# tests/ on sys.path.  Prepending the repo's brixtest/src keeps ONE source of
# truth even when CI has `pip install -e brixtest/` (same tree either way).
_BRIXTEST_SRC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "brixtest", "src")
if os.path.isdir(_BRIXTEST_SRC) and _BRIXTEST_SRC not in sys.path:
    sys.path.insert(0, _BRIXTEST_SRC)

# Fleet sentinel — forensic half (TS-2: moved to brix_suite.harness.kill_tracer).
# Importing it wraps os.kill / os.killpg / subprocess.Popen exactly where the
# inline install used to happen; being import-cached, a second execution of this
# source (the by-path pinning loader) can no longer stack a second wrapper.
from brix_suite.harness.kill_tracer import (  # noqa: F401  (re-exported)
    _CURRENT_NODEID,
    _FLEET_SENTINEL_ON,
)
import tempfile
import time
from pathlib import Path

import pytest
import fleet_declares
from server_launcher import LifecycleHarness, RegistryLauncher
from server_registry import fleet_ready_for_test_root, manifest_owns_test_root
from server_registry import (
    dependency_closure,
    get_server,
    read_manifest,
    registered_specs,
)
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
    FLEET_READY,
    REGISTRY_MANIFEST,
    REGISTRY_ROOT,
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

# load_test.py matches pytest's default `*_test.py` collection pattern but is a
# CLI driver, not a test module — and as a §10.2 self-replacement shim its
# module object's __file__ points at brix_suite/perf/load_test.py, which pytest
# rejects as an import file mismatch.  Nothing to collect there; skip it.
collect_ignore = ["load_test.py"]

# TS-2 re-exports: the sentinel arbiter (formerly conftest_part4.py) and the
# session/service fixtures (formerly the tail of conftest_part5.py) now live in
# brix_suite.harness.  Binding their names HERE keeps three consumers working
# unchanged: pytest collects the hooks/fixtures from this conftest namespace,
# the exec-composed lifecycle shards (parts 2/3/5) resolve them as bare-name
# globals, and the by-path pinning suite monkeypatches them on its private
# duplicate of this module.
from brix_suite.harness.sentinel import (  # noqa: F401  (re-exported)
    _SENTINEL_ABORT_MARKER,
    _capture_fleet_baseline,
    _check_server_reachable,
    _clear_fleet_sentinel_marker,
    _require_fleet_startup_stability,
    _sentinel,
    _sentinel_watchdog,
    _start_sentinel_watchdog,
    _stop_sentinel_watchdog,
    _verify_fleet_conservation,
    pytest_runtest_setup,
    pytest_runtest_teardown,
)
from brix_suite.harness.fixtures import (  # noqa: F401  (re-exported)
    command_runner,
    lifecycle,
    matrix_node,
    pytest_generate_tests,
    ref_brix_gsi,
    ref_brix_gsi_shared,
    ref_xrootd,
    registry,
    registry_server,
    test_env,
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
_pytest_config = None


def _chdir_scratch():
    """Run the session from a scratch CWD inside the temp tree (mandatory in
    local mode) so no cwd-relative artifact can ever land in the repo."""
    os.makedirs(CWD_DIR, exist_ok=True)
    os.chdir(CWD_DIR)


def _ensure_client_x509_env():
    """Point GSI clients at the shared CA dir + proxy.

    Normally set inside _setup_session(), but that is skipped in attach mode
    (external fleet already up) and in xdist worker processes.  GSI subprocess
    clients — notably test_concurrent's spawn ProcessPoolExecutor workers, which
    inherit this env — then find no X509_USER_PROXY and fail every GSI open with
    "No protocols left to try".  setdefault so a test that forges its own proxy
    still wins; skipped for a remote fleet, which manages its own credentials."""
    if REMOTE_SERVER:
        return
    os.environ.setdefault("X509_CERT_DIR", CA_DIR)
    os.environ.setdefault("X509_USER_PROXY", PROXY_STD)
    # Publish LARGE_FILE_MD5 from the sidecar the controller wrote when seeding
    # the shared export (attach mode) — so xdist workers get it without
    # re-hashing 200 MiB.  No-op when own-fleet setup already set it.
    if "LARGE_FILE_MD5" not in os.environ:
        side = os.path.join(DATA_ROOT, ".large200.md5")
        try:
            with open(side) as f:
                os.environ["LARGE_FILE_MD5"] = f.read().strip()
        except OSError:
            pass


def _seed_text_file():
    path = os.path.join(DATA_ROOT, "test.txt")
    if not os.path.exists(path):
        with open(path, "wb") as handle:
            handle.write(b"hello from nginx-xrootd\n")


def _seed_random_file():
    path = os.path.join(DATA_ROOT, "random.bin")
    if not os.path.exists(path) or os.path.getsize(path) != 5242880:
        with open(path, "wb") as handle:
            handle.write(random.randbytes(5242880))


def _write_large_file(path, size):
    import hashlib as _hashlib

    digest = _hashlib.md5()
    rng = random.Random(int(os.environ.get("LARGE_FILE_SEED", "42")))
    with open(path, "wb") as handle:
        remaining = size
        while remaining > 0:
            count = min(16 * 1024 * 1024, remaining)
            chunk = rng.randbytes(count)
            handle.write(chunk)
            digest.update(chunk)
            remaining -= count
    return digest.hexdigest()


def _hash_large_file(path):
    import hashlib as _hashlib

    digest = _hashlib.md5()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _large_file_digest(path, sidecar, size):
    if not os.path.exists(path) or os.path.getsize(path) != size:
        return _write_large_file(path, size)
    if os.path.exists(sidecar):
        with open(sidecar) as handle:
            return handle.read().strip()
    return _hash_large_file(path)


def _publish_large_digest(sidecar, digest):
    os.environ["LARGE_FILE_MD5"] = digest
    try:
        with open(sidecar, "w") as handle:
            handle.write(digest)
    except OSError:
        pass


def _seed_canonical_data():
    """Idempotently place the canonical seed files in the shared export."""
    os.makedirs(DATA_ROOT, exist_ok=True)
    _seed_text_file()
    _seed_random_file()
    size = 200 * 1024 * 1024
    path = os.path.join(DATA_ROOT, "large200.bin")
    sidecar = os.path.join(DATA_ROOT, ".large200.md5")
    _publish_large_digest(sidecar, _large_file_digest(path, sidecar, size))


# Tri-state memo for "is a fleet already running that we should attach to rather
# than manage?"  None = not yet decided; resolved once per process on first query.
_external_fleet = None
_foreign_fleet_collision = False


def _clean_session_owned_state() -> None:
    """Remove stale suite state while preserving pytest's active temp tree."""
    for child in (LOG_DIR, REGISTRY_ROOT, os.path.join(TEST_ROOT, "artifacts")):
        shutil.rmtree(child, ignore_errors=True)


def _reap_lost_fleet_before_clean() -> None:
    """Stop stale catalogue members before their pidfiles/configs are removed."""
    try:
        _stop_owned_fleet(None)
    except Exception as exc:  # teardown is best-effort; exact-root reap still ran
        sys.stderr.write(f"\n[conftest] stale-fleet preflight warning: {exc}\n")


def _reset_session_tree_once() -> None:
    """Reap old processes before removing the on-disk ownership evidence."""
    global _test_tree_wiped
    if _test_tree_wiped:
        return
    _reap_lost_fleet_before_clean()
    _clean_session_owned_state()
    _test_tree_wiped = True


def _report_existing_fleet(reachable, owned, attached):
    global _foreign_fleet_collision
    if attached:
        print(
            f"\n[conftest] A fleet is already listening on {HOST}:{NGINX_ANON_PORT}; "
            "attaching WITHOUT lifecycle management (no wipe / start-all / stop-all "
            "/ rmtree) so a stray test run cannot tear down a fleet it did not "
            "start.  Set TEST_OWN_FLEET=1 to force a clean wipe+restart.",
            flush=True)
        return
    if reachable and owned:
        print(
            f"\n[conftest] Found stale/incomplete servers owned by "
            f"TEST_ROOT={TEST_ROOT}; startup will reap them before cleaning "
            "the old registry and launching the new fleet.", flush=True)
        return
    if reachable:
        _foreign_fleet_collision = True
        print(
            f"\n[conftest] Port {HOST}:{NGINX_ANON_PORT} is occupied, but "
            f"{REGISTRY_MANIFEST} plus its completion marker do not identify a "
            f"fully started fleet for TEST_ROOT={TEST_ROOT}. Treating this as a "
            "port collision or partial prior start; this session will not attach "
            "to or clean up the listener.", flush=True)


def _external_fleet_attached() -> bool:
    """True when a local fleet is already listening and pytest should ATTACH to
    it without taking lifecycle ownership -- no tree wipe, no start-all/stop-all,
    no rmtree.

    This closes a footgun in the dev-iteration workflow: an operator keeps a
    fleet up out of band (``python3 -m cmdscripts.manage_test_servers start-all``) and runs a
    single test file for a quick check.  Without this guard the session teardown
    would ``stop-all`` + ``rmtree(TEST_ROOT)`` and orphan every still-running
    server's export-root fd, so the next manual ``xrdcp``/TPC hangs -- looking
    exactly like a server bug when it is pure test-harness teardown.  CI is
    unaffected: there no fleet is listening at session start, so pytest owns the
    lifecycle (wipe / start-all / stop-all / rmtree) exactly as before.

    Never engages in REMOTE mode (the server is managed elsewhere) and is
    overridden by ``TEST_OWN_FLEET=1`` for the operator who genuinely wants a
    clean wipe+restart on top of a running fleet.  Attach is the default so a
    NESTED pytest (spawned by a test) never wipes the shared fleet its parent
    owns.  Probed once and memoized so we neither re-probe nor re-print the
    notice on the teardown call."""
    global _external_fleet, _foreign_fleet_collision
    if _external_fleet is not None:
        return _external_fleet
    if REMOTE_SERVER or os.environ.get("TEST_OWN_FLEET") == "1":
        _external_fleet = False
        return _external_fleet
    reachable = _check_server_reachable(HOST, NGINX_ANON_PORT, timeout=1.0)
    owned = manifest_owns_test_root()
    ready = fleet_ready_for_test_root()
    master_alive = _fleet_main_master_alive()
    _external_fleet = reachable and owned and ready and master_alive
    _report_existing_fleet(reachable, owned, _external_fleet)
    return _external_fleet


def _fleet_main_master_alive() -> bool:
    """Require a live main master before treating a listener as attachable."""
    pidfile = Path(REGISTRY_ROOT) / "main" / "logs" / "nginx.pid"
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False
    return True


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
            from ephemeral_port import free_port
            s.bind((BIND_HOST6, free_port(BIND_HOST6)))
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
        pytest.skip("IPv6 loopback ::1 not available on this host")  # net-literal-allow: IPv6 loopback skip-message prose


@pytest.fixture(scope="session")
def requires_krb5():
    """Skip krb5 tests unless the krb5 tier is actually up on this host.

    The tier self-disables when the MIT KDC tooling (krb5-server) is missing or
    the nginx binary was built without Kerberos, so probe for the live result
    rather than for the tooling: the dedicated nginx port must accept AND a
    client credential cache must have been minted by ``kdc_helpers.up``.  This is
    re-checked each session (not cached at import) because the tier is started by
    the registry launcher (``krb5-kdc`` external spec) after this module is imported.
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


def _should_skip_local_lifecycle(config) -> bool:
    """Whether pytest should NOT manage (wipe / start-all / stop-all / rmtree)
    the local fleet this session: explicitly told to skip, or a fleet is already
    running and we have not been told to take ownership.  Shared by session
    setup and teardown so both sides agree on who owns the lifecycle -- the
    asymmetry that previously let setup attach to a running fleet while teardown
    still tore it down.  (A run whose collected tests need no server still owns
    the lifecycle, but its post-collection boot set is empty -- zero servers
    start -- so there is nothing to special-case here; see _specs_to_boot.)"""
    attached = _external_fleet_attached()
    if _foreign_fleet_collision:
        # Message text single-sourced in brixtest.config.lanes (TS-3):
        # byte-identical to the historical inline string, quoted in ops docs.
        from brixtest.config.lanes import refuse_foreign_lane
        raise pytest.UsageError(
            refuse_foreign_lane(TEST_ROOT, HOST, NGINX_ANON_PORT))
    return os.environ.get("TEST_SKIP_SERVER_SETUP") == "1" or attached

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "conftest_part2.py", "conftest_part3.py",
                    "conftest_part5.py")
