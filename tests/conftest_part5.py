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
import subprocess
import sys
import time
from pathlib import Path

import pytest

from server_launcher import LifecycleHarness, RegistryLauncher
from server_registry import fleet_ready_for_test_root, get_server, read_manifest
from settings import (
    CA_CERT,
    CA_DIR,
    HOST,
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
    NGINX_WEBDAV_PORT,
    NGINX_WEBDAV_GSI_TLS_PORT,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_S3_PORT,
    PROXY_STD,
    READONLY_PORT,
    REF_BRIX_GSI_PORT,
    REF_BRIX_GSI_SHARED_PORT,
    REF_BRIX_PORT,
    REGISTRY_ROOT,
    REMOTE_SERVER,
    SERVER_HOST,
    TEST_ROOT,
    TOKENS_DIR,
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


# ---------------------------------------------------------------------------
# Session hooks and the session-scoped fixtures.
#
# Physical continuation of conftest_part4.py (loaded from conftest.py, executed
# into ITS namespace), split off purely to keep both files inside the file-size
# tiers.  Everything above -- the fleet-health baseline, the sentinel watchdog
# and the module state the hooks below drive -- is already bound here; the
# imports above are repeated for readability, not because the shard could stand
# alone.  pytest finds the hooks and fixtures by name in the conftest namespace,
# so which shard physically defines one is invisible to collection.
# ---------------------------------------------------------------------------

@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    if not _FLEET_SENTINEL_ON:
        return
    _CURRENT_NODEID[0] = item.nodeid        # so the kill tracer can attribute
    if _sentinel_watchdog["session"] is None:
        _sentinel_watchdog["session"] = item.session
    # A peer worker (or the watchdog) already found the fleet damaged — stop.
    if not _sentinel["fired"] and _SENTINEL_ABORT_MARKER.exists():
        _sentinel["fired"] = True
        try:
            item.session.shouldstop = "fleet sentinel: peer worker aborted (fleet damaged)"
        except Exception:
            pass


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item, nextitem):
    # The watchdog (controller/serial) owns the active fleet probing; a worker
    # only needs to notice its cross-process abort marker and stop promptly, so
    # no downstream test runs against an already-damaged fleet.  No per-test
    # network scan here — 20 workers each probing the fleet would be a storm.
    if not _FLEET_SENTINEL_ON or _sentinel["fired"]:
        return
    if _SENTINEL_ABORT_MARKER.exists():
        _sentinel["fired"] = True
        try:
            item.session.shouldstop = "fleet sentinel: fleet damaged (watchdog/peer)"
        except Exception:
            pass


def pytest_collection_finish(session):
    """Start the session fleet once collection has settled.

    Runs after every ``pytest_collection_modifyitems`` (including the mark
    plugin's ``-m``/``-k`` deselection), so ``session.items`` is the final test
    set and the declared-union subset is exact.  Controller-only and only when
    this session owns the local lifecycle; xdist runs never reach the start
    here — their controller boots the full fleet from ``pytest_sessionstart``
    because it does not collect.  ``--collect-only`` starts nothing."""
    config = session.config
    if hasattr(config, "workerinput"):
        if (getattr(config.option, "collectonly", False)
                or REMOTE_SERVER
                or os.environ.get("TEST_SKIP_SERVER_SETUP") == "1"
                or not session.items):
            return
        _chdir_scratch()
        specs = _specs_to_boot(session.items)
        worker_id = config.workerinput.get("workerid")
        error_path = Path(REGISTRY_ROOT) / ".xdist-fleet-error"
        if worker_id == "gw0":
            error_path.unlink(missing_ok=True)
            try:
                _start_all_resilient(specs)
            except Exception as exc:
                error_path.parent.mkdir(parents=True, exist_ok=True)
                error_path.write_text(str(exc), encoding="utf-8")
                raise
            _capture_fleet_baseline()   # snapshot the freshly-launched fleet
        else:
            deadline = time.time() + 180
            while time.time() < deadline:
                if fleet_ready_for_test_root():
                    break
                if error_path.exists():
                    raise pytest.UsageError(
                        "xdist fleet coordinator failed: "
                        + error_path.read_text(encoding="utf-8"))
                time.sleep(0.1)
            else:
                raise pytest.UsageError(
                    "timed out waiting for xdist worker gw0 to start the "
                    "collected subset fleet")
        read_manifest()
        return
    if _xdist_requested(config):
        return
    if getattr(config.option, "collectonly", False):
        return
    if REMOTE_SERVER or _should_skip_local_lifecycle(config):
        return
    if not session.items:
        return
    specs = _specs_to_boot(session.items)
    config._nginx_xrootd_selected_registry_specs = specs
    _start_all_resilient(specs)
    _capture_fleet_baseline()           # snapshot the freshly-launched fleet


def pytest_sessionfinish(session, exitstatus):
    """Stop local servers when the session ends (no-op in remote mode or xdist workers)."""
    import subprocess

    # xdist workers must not call stop-all: the controller owns server lifecycle.
    # A worker finishing early would kill servers other workers still need.
    if hasattr(session.config, "workerinput"):
        return

    # Fleet health conservation guard — runs BEFORE any teardown, whether this
    # session owns the fleet or merely attached to a harness-managed one.  A
    # server missing at session end means a test stopped/crashed it; fail loudly
    # so the run is red and the culprit fleet server is named.
    ok, message = _verify_fleet_conservation()
    if not ok:
        sys.stderr.write(message)
        session.exitstatus = 1
        try:
            session.config._fleet_health_failure = message
        except Exception:
            pass

    if REMOTE_SERVER or _should_skip_local_lifecycle(session.config):
        return

    try:
        specs = getattr(session.config, "_nginx_xrootd_selected_registry_specs", None)
        _stop_owned_fleet(specs)
    except Exception:
        pass  # best-effort cleanup

    # POST-TEARDOWN ORPHAN ALARM: teardown just ran (_stop_owned_fleet ->
    # kill_orphans).  If ANY fleet process owned by this TEST_ROOT is STILL alive
    # now, teardown FAILED to reap it — the exact condition that leaks fixed
    # ports and strands cmsd/nginx-worker orphans across runs.  Scream: red
    # banner to stderr, name every survivor, fail the session, and surface it in
    # the terminal summary so it cannot be lost in the scrollback.
    try:
        from fleet_orphans import find_orphans  # noqa: PLC0415

        survivors = find_orphans(TEST_ROOT)
        if survivors:
            listing = "\n".join(
                "    pid %d: %s" % (pid, cmd) for pid, cmd in survivors
            )
            banner = (
                "\n"
                "################################################################\n"
                "##  FLEET TEARDOWN FAILED -- %3d ORPHAN(S) SURVIVED THE REAP  ##\n"
                "################################################################\n"
                "TEST_ROOT: %s\n"
                "These processes were NOT reaped by teardown and are leaking\n"
                "their fixed ports into the next run:\n"
                "%s\n"
                "################################################################\n"
                % (len(survivors), os.path.realpath(str(TEST_ROOT)), listing)
            )
            sys.stderr.write(banner)
            sys.stderr.flush()
            session.exitstatus = 1
            try:
                prior = getattr(session.config, "_fleet_health_failure", "") or ""
                session.config._fleet_health_failure = prior + banner
            except Exception:
                pass
    except Exception:
        pass  # detection must never itself break teardown

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


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Surface a fleet-health conservation failure in the run's summary so it is
    not lost among test results — it explains an otherwise-mysterious cascade."""
    message = getattr(config, "_fleet_health_failure", None)
    if message:
        terminalreporter.write_line(message, red=True, bold=True)


@pytest.fixture(scope="session")
def registry():
    return RegistryLauncher(os.path.dirname(__file__))


@pytest.fixture
def registry_server():
    def _lookup(name):
        return get_server(name)

    return _lookup


@pytest.fixture
def lifecycle():
    """Per-test registry lifecycle harness for throwaway nginx instances.

    Tests whose subject is lifecycle behavior (reload/reopen/restart/crash)
    drive their own short-lived instances through this instead of hand-rolled
    subprocess calls; teardown stops and unregisters everything it created.
    """
    harness = LifecycleHarness()
    try:
        yield harness
    finally:
        harness.close()


@pytest.fixture
def command_runner(registry):
    return registry.run_cmd


# --------------------------------------------------------------------------- #
# The (protocol × auth × tls × backend) parametrization layer.                  #
# --------------------------------------------------------------------------- #
def pytest_generate_tests(metafunc):
    """Expand `@pytest.mark.matrix(...)` into one case per coverage cell.

    Before this hook the suite had no generative parametrization at all: every
    cell of the matrix was a hand-written module with its own template, which is
    why the matrix was sparse and re-sparsified with each new backend
    (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md item 19).
    Unreachable combinations are parametrized too and skip with the product
    reason from `matrix_layer.supported()`, so "empty" and "impossible" stay
    distinguishable in the report.
    """
    if "matrix_node" not in metafunc.fixturenames:
        return
    mark = metafunc.definition.get_closest_marker("matrix")
    if mark is None:
        raise pytest.UsageError(
            f"{metafunc.definition.nodeid}: requests the `matrix_node` fixture "
            "but carries no @pytest.mark.matrix(...) to expand")
    import matrix_layer
    cells, ids = matrix_layer.expand(**mark.kwargs)
    metafunc.parametrize("matrix_node", cells, ids=ids, indirect=True)


@pytest.fixture(scope="module")
def matrix_node(request, tmp_path_factory):
    """Stand up the parametrized cell; one instance per cell, not per test."""
    import matrix_layer
    from server_launcher import LifecycleHarness

    cell = request.param
    token = None
    if cell.auth == "token":
        from utils.make_token import TokenIssuer
        ti = TokenIssuer(matrix_layer.TOKEN_DIR)
        if not os.path.exists(ti.key_path):
            ti.init_keys()
        token = ti.generate(scope="storage.read:/ storage.modify:/")
    harness = LifecycleHarness()
    try:
        yield matrix_layer.make_node(
            cell, tmp=tmp_path_factory.mktemp(f"matrix-{cell.id}"),
            lifecycle=harness, token=token)
    finally:
        harness.close()


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
        "url": f"root://{HOST}:{REF_BRIX_PORT}",
        "port": REF_BRIX_PORT,
        "data_dir": test_env["data_dir"],
    }


@pytest.fixture(scope="session")
def ref_brix_gsi(test_env):
    return {
        "url": f"root://{HOST}:{REF_BRIX_GSI_PORT}",
        "port": REF_BRIX_GSI_PORT,
        "data_dir": os.path.join(TEST_ROOT, "data-gsi-bridge"),
    }


@pytest.fixture(scope="session")
def ref_brix_gsi_shared(test_env):
    return {
        "url": f"root://{HOST}:{REF_BRIX_GSI_SHARED_PORT}",
        "port": REF_BRIX_GSI_SHARED_PORT,
        "data_dir": test_env["data_dir"],
    }
