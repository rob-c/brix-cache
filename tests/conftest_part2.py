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


def _setup_session(*, chdir: bool = True):
    """Shared session setup logic.

    In REMOTE mode: verify the server is reachable; skip all local lifecycle.
    In LOCAL mode: wipe data dirs, regenerate PKI, seed data, prep session
    artifacts.  The fleet itself starts AFTER collection
    (pytest_collection_finish), when the declared-server subset is known —
    except under xdist, where the controller never collects and boots the full
    fleet from pytest_sessionstart instead.
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

    # A fleet started out of band owns its own lifecycle: never wipe the tree or
    # start-all on top of it.  pytest_sessionstart already pre-checks and skips
    # this call in that case; this self-guard makes the destructive setup safe for
    # any other caller too (defense-in-depth) so the attach guarantee cannot be
    # silently bypassed.
    if _external_fleet_attached():
        return

    # ---- LOCAL mode ----

    # MANDATED CLEAN SLATE: clean suite-owned state without removing TEST_ROOT or
    # TMP_DIR themselves.  pytest/xdist creates its basetemp below TMP_DIR before
    # all sessionstart hooks have completed; removing the parent here invalidates
    # popen-gw*/tmp_path paths that live workers already hold.  The data and PKI
    # trees are rebuilt explicitly below, while registry/log/artifact state is
    # safe to discard.  TMP_DIR is deliberately preserved for pytest ownership.
    _reset_session_tree_once()
    os.makedirs(TEST_ROOT, exist_ok=True)
    if chdir:
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
    os.makedirs(os.path.join(TEST_ROOT, "artifacts"), exist_ok=True)

    # Create data-gsi-bridge directory for cross-server GSI tests (test_gsi_bridge.py)
    gsi_bridge_data = os.path.join(TEST_ROOT, "data-gsi-bridge")
    if os.path.exists(gsi_bridge_data):
        shutil.rmtree(gsi_bridge_data)
    os.makedirs(gsi_bridge_data, exist_ok=True)

    # Create required test files in data directory
    with open(os.path.join(DATA_ROOT, "test.txt"), "wb") as f:
        f.write(b"hello from nginx-xrootd\n")

    # Generate random.bin (5MB of random data). randbytes() fills the buffer in
    # one C call — the byte-at-a-time getrandbits() generator it replaces took
    # ~0.2s here and ~11s for the 200 MiB file below, on every (wiped) session.
    with open(os.path.join(DATA_ROOT, "random.bin"), "wb") as f:
        f.write(random.randbytes(5242880))

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
                chunk = rng.randbytes(n)   # vectorized; ~15x faster than per-byte
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

    # Generate every pre-instance session artifact (PKI + proxies, token signing
    # keys + issued JWTs, JWKS, CRL drops, authdb, stage hook) — the fleet-wide
    # setup the retired bash bridge performed at the top of start-all.
    import fleet_prep  # noqa: PLC0415 — pure-Python session artifact generator
    fleet_prep.prepare()

    # Freeze the ONE session-shared nginx binary now — after the tree wipe and
    # before any server starts — so every fleet spawn and every xdist worker
    # execs the same immutable copy (never a per-process private one, never the
    # relinkable live objs/nginx).  Later callers reuse this copy.
    from cmdscripts.live_common import freeze_nginx  # noqa: PLC0415
    from settings import NGINX_BIN  # noqa: PLC0415
    freeze_nginx(NGINX_BIN)


def _reap_leaked_test_servers():
    """Kill every fleet process owned by this exact TEST_ROOT.

    Pidfile-based ``stop-all`` only knows the servers it launched; a fleet
    process orphaned by a ``kill -9``'d prior run keeps holding its fixed port,
    which makes the next ``start-all`` bind fail.  This is the cmdline-scoped
    reap the brutal-teardown utility uses, done in-process so it never touches the
    freshly-generated data/PKI (a full brutal_teardown would wipe them).

    TEST_ROOT is the ownership boundary.  Historical shared markers such as
    ``/tmp/xrd`` and ``/tmp/hsproto`` are deliberately forbidden here: they can
    occur in a healthy parallel lane's argv and caused collision recovery in one
    lane to SIGKILL another lane's live fleet.

    Ownership + the daemon set live in ``fleet_orphans`` so the SAME detector
    backs the reaper, the post-teardown leak alarm (conftest_part4), and its
    unit test.  Two leaks the old inline scan missed and this closes: ``cmsd``
    (never in the exe list) and nginx WORKERS (own argv carries no path — matched
    via the master's argv), which a bare SIGKILL of the master would strand.
    """
    from fleet_orphans import kill_orphans  # noqa: PLC0415

    kill_orphans(TEST_ROOT)


def _register_fleet() -> None:
    """Populate the server registry with the full pure-Python fleet catalogue.

    Idempotent (``register_full_fleet`` skips already-registered names), so the
    collection-time and start-time call sites can both invoke it safely.
    """
    import fleet_specs  # noqa: PLC0415 — declarative fleet catalogue
    fleet_specs.register_full_fleet()


def _start_all_resilient(specs=None):
    """Start the fleet, self-healing the one recoverable start-all failure.

    A leaked fixed-port server from an interrupted (``kill -9``'d) prior run
    makes ``start-all`` fail to bind.  The old call used ``check=True`` +
    ``capture_output=True``, so that transient condition aborted the WHOLE
    session with a bare ``CalledProcessError`` (pytest INTERNALERROR, zero tests
    run) AND swallowed the stderr that names the stuck port — the exact failure
    the brutal-teardown utility warns about.  Now: on failure the captured output is
    always surfaced, leaked test servers are reaped, and start-all is retried
    once.  A genuinely-unstartable fleet still raises, but with the diagnostic
    visible instead of hidden.
    """
    import sys
    import time

    # Idempotency guard: a HEALTHY fleet is already up for this TEST_ROOT (an
    # operator pre-started it, or the previous operator_runtime lane left it
    # running).  Re-running start-all would try to bind ports the live fleet
    # already holds, fail rc=1, then reap (stop-all) + restart the WHOLE fleet —
    # a multi-second window during which every test hitting a shared port fails
    # with ConnectionRefused (the fleet-availability cascade).  Reuse the running
    # fleet instead: the marker proves this root completed a start-all and the
    # main endpoint answering proves it is actually live.
    if (fleet_ready_for_test_root()
            and _check_server_reachable(HOST, NGINX_ANON_PORT, timeout=2.0)):
        return

    for attempt in (1, 2):
        launcher = RegistryLauncher(os.path.dirname(__file__))
        try:
            _register_fleet()
            launcher.start_registered(specs)
            marker = Path(FLEET_READY)
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(TEST_ROOT + "\n", encoding="utf-8")
            return
        except BaseException as exc:
            # pytest does not guarantee sessionfinish when session startup or an
            # xdist collection hook is interrupted. Roll back everything this
            # attempt may have started before propagating Ctrl-C/SystemExit.
            if not isinstance(exc, Exception):
                try:
                    launcher.stop_registered(specs)
                finally:
                    _reap_leaked_test_servers()
                raise
            message = str(exc)
            class _Result:
                returncode = 1
                stdout = ""
                stderr = message
            r = _Result()
        sys.stderr.write(
            f"\n[conftest] start-all failed (attempt {attempt}/2, rc={r.returncode}).\n"
            f"--- start-all stdout (tail) ---\n{(r.stdout or '')[-4000:]}\n"
            f"--- start-all stderr (tail) ---\n{(r.stderr or '')[-4000:]}\n"
        )
        if attempt == 1:
            sys.stderr.write(
                "[conftest] reaping leaked fixed-port test servers and retrying "
                "start-all once…\n"
            )
            RegistryLauncher(os.path.dirname(__file__)).stop_registered(specs)
            _reap_leaked_test_servers()
            time.sleep(2)
    raise pytest.UsageError(
        "start-all failed twice (see the surfaced stdout/stderr above — typically "
        "a leaked server from an interrupted run still holding a fixed port). The "
        "session cannot proceed without the fleet; run 'PYTHONPATH=tests "
        "python3 -m cmdscripts.operator_build brutal_teardown' and retry."
    )


def _stop_owned_fleet(specs=None) -> None:
    """Stop this lane even when the xdist controller registry is empty.

    Collection and subset selection happen in xdist workers.  The controller
    owns session teardown but never collects, so it may have no in-memory specs
    at all.  Rebuild the declarative catalogue before the stateless pidfile/CLI
    stop.  Finally reap only processes whose argv proves ownership by this exact
    TEST_ROOT; this covers a crashed or half-started role without touching a
    parallel lane.
    """
    try:
        _register_fleet()
        RegistryLauncher(os.path.dirname(__file__)).stop_registered(specs)
    finally:
        _reap_leaked_test_servers()


def _xdist_requested(config) -> bool:
    """True when this run was invoked with pytest-xdist parallelism (-n).

    Under xdist the controller never collects — the workers do — so the
    post-collection subset-boot hook (pytest_collection_finish) cannot see the
    item list there.  The controller boots the full fleet up front instead;
    parallel runs are the full-suite lane, where the subset is ~everything
    anyway."""
    return bool(getattr(config.option, "numprocesses", None))


def _validate_requested_paths(config) -> None:
    """Reject nonexistent explicit test paths before starting the xdist fleet.

    Relative arguments resolve against the *invocation* directory, exactly as
    pytest itself resolves them — not against rootdir.  The repo-root habit
    (``pytest tests/foo.py``) makes the two look interchangeable, but a lane
    that runs from ``tests/`` (``tools/ci/asan.py`` drives
    ``pytest test_sanitizer_smoke.py`` with ``cwd=tests``) passes a name that
    exists only under the invocation dir; resolving against rootdir rejected a
    file pytest would have collected fine, aborting the lane with UsageError.
    Rootdir stays as a fallback for pytest builds without
    ``invocation_params``.
    """
    invocation = getattr(getattr(config, "invocation_params", None), "dir", None)
    root = Path(str(invocation if invocation is not None else config.rootpath))
    missing = []
    for argument in config.args:
        path_text = str(argument).split("::", 1)[0]
        path = Path(path_text)
        candidate = path if path.is_absolute() else root / path
        if not candidate.exists():
            missing.append(path_text)
    if missing:
        raise pytest.UsageError(
            "test path(s) do not exist; refusing to start managed servers: "
            + ", ".join(missing)
        )


def pytest_sessionstart(session):
    # A collection-only session runs no test and needs no fleet.  Skip the
    # sentinel watchdog, the stale-fleet reap sweep, the destructive tree wipe
    # and the PKI/data regeneration outright — pytest_collection_finish and
    # pytest_sessionfinish carry the same gate — so `pytest --collect-only`
    # neither pays the ~30s lifecycle cost nor touches a live fleet's tree.
    if getattr(session.config.option, "collectonly", False):
        return
    # xdist workers inherit the environment from the controller which has already
    # called start-all (and wiped the tree).  Running it again from every worker
    # in parallel would race — but each worker still chdir()s into the shared
    # scratch CWD so its own spawns can't pollute the repo either.  That chdir is
    # gated on whether the session does local server work at all — NOT on
    # _external_fleet_attached(): in an xdist run the controller has already
    # started the fleet, so a worker probing the port would always see it
    # "running" and wrongly skip the chdir.  Lifecycle ownership (the destructive
    # wipe/start/stop) is a separate, controller-only concern.
    no_local_work = os.environ.get("TEST_SKIP_SERVER_SETUP") == "1"
    if hasattr(session.config, "workerinput"):
        if not REMOTE_SERVER and not no_local_work:
            _ensure_client_x509_env()
            # The controller prepares the tree. The exact selected dependency
            # union is known only after worker collection, so gw0 starts it from
            # pytest_collection_finish and peer workers wait there. Do not chdir
            # before collection: xdist workers must still resolve relative args.
        return
    _validate_requested_paths(session.config)
    if _should_skip_local_lifecycle(session.config):
        # Attach mode (an external fleet is already up) skips _setup_session(),
        # which is where X509_CERT_DIR / X509_USER_PROXY normally get set.  Without
        # them, GSI clients — especially test_concurrent's spawn ProcessPoolExecutor
        # workers, which inherit this env — find no proxy and fail every GSI open
        # with "No protocols left to try".  This is the exact race behind the
        # lane-2 retry-ladder GSI failures: the --lf rerun attaches to the prior
        # attempt's not-yet-stopped fleet.  Set the client env even when attaching.
        _ensure_client_x509_env()
        # Attach mode also skips _setup_session's seeding of the shared export, so
        # the fleet's main DATA_ROOT lacks the canonical test.txt / random.bin /
        # large200.bin.  Seed them here (controller only, before workers dispatch)
        # so read/GSI/large-file tests find their fixtures.  Not for a remote
        # fleet, whose data lives on the server.
        if _external_fleet_attached() and not REMOTE_SERVER:
            _seed_canonical_data()
            # Snapshot the already-running (attached) fleet as the health
            # baseline so the pre-teardown conservation check can prove no
            # shared server was lost during the session.
            _capture_fleet_baseline()
            # Start monitoring only after the attach decision and any inherited
            # baseline have settled.  Starting it before that window lets a stale
            # prior-run baseline look like a test-induced fleet collapse.
            _start_sentinel_watchdog(session)
        return
    _setup_session(chdir=not _xdist_requested(session.config))
    # The session setup has now cleared stale registry state.  The watchdog can
    # safely wait for the fresh post-collection baseline without mistaking the
    # intentional pre-launch gap for a crashed fleet.
    _start_sentinel_watchdog(session)
