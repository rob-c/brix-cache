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
# Session lifecycle hooks (loaded from conftest.py, executed into ITS
# namespace).  The sentinel state and helpers these hooks drive
# (_stop_sentinel_watchdog, _verify_fleet_conservation, _capture_fleet_baseline,
# ...) live in brix_suite.harness.sentinel since TS-2 and are bound into the
# conftest namespace by its re-export imports; the boot/gate machinery
# (_specs_to_boot, _start_all_resilient, ...) is bound by the part2/part3
# shards.  pytest finds hooks by name in the conftest namespace, so which shard
# or module physically defines one is invisible to collection.
# ---------------------------------------------------------------------------

# The controller receives each worker's collection report before xdist adds that
# report to its scheduler.  Keeping this state here lets the last report start
# the whole fleet in the small, deliberate gap before any item can be assigned.
_xdist_collected_nodes: set[str] = set()
_xdist_fleet_started = False


def _xdist_worker_count(config) -> int:
    """Return the explicitly requested xdist worker count, if available."""
    workers = getattr(config.option, "numprocesses", None)
    try:
        return int(workers)
    except (TypeError, ValueError):
        return 0


def _xdist_fleet_wait_seconds() -> int:
    """Bound how long workers wait while the controller boots every server."""
    try:
        return max(1, int(os.environ.get("TEST_FLEET_START_TIMEOUT", "900")))
    except ValueError:
        return 900


@pytest.hookimpl(tryfirst=True)
def pytest_xdist_node_collection_finished(node, ids):
    """Boot the shared fleet after every xdist worker has collected.

    ``WorkerInteractor`` sends its collection event before it runs ordinary
    ``pytest_collection_finish`` hooks.  Starting from such a worker races the
    scheduler: the controller can assign tests while the chosen worker is still
    launching servers.  This controller hook runs before xdist adds the final
    collection to its scheduler, which gives us a real collection barrier.
    """
    del ids
    global _xdist_fleet_started
    config = node.config
    if (_xdist_fleet_started
            or getattr(config.option, "collectonly", False)
            or REMOTE_SERVER
            or os.environ.get("TEST_SKIP_SERVER_SETUP") == "1"):
        return
    _xdist_collected_nodes.add(node.gateway.id)
    worker_count = _xdist_worker_count(config)
    if worker_count and len(_xdist_collected_nodes) < worker_count:
        return
    if not worker_count:
        raise pytest.UsageError(
            "xdist fleet startup needs an explicit -n worker count so it can "
            "wait for collection from every worker"
        )

    error_path = Path(REGISTRY_ROOT) / ".xdist-fleet-error"
    stable_path = Path(REGISTRY_ROOT) / ".xdist-fleet-stable"
    error_path.unlink(missing_ok=True)
    stable_path.unlink(missing_ok=True)
    try:
        specs = _specs_to_boot(())
        _start_all_resilient(specs)
        _require_fleet_startup_stability()
        _capture_fleet_baseline()
    except Exception as exc:
        error_path.parent.mkdir(parents=True, exist_ok=True)
        error_path.write_text(str(exc), encoding="utf-8")
        raise
    node.config._nginx_xrootd_selected_registry_specs = specs
    stable_path.parent.mkdir(parents=True, exist_ok=True)
    stable_path.write_text("stable\n", encoding="utf-8")
    _xdist_fleet_started = True


def pytest_collection_finish(session):
    """Start the complete session fleet once collection has settled.

    Runs after every ``pytest_collection_modifyitems`` (including the mark
    plugin's ``-m``/``-k`` deselection), so no test can begin before the full
    fixed-port catalogue is running.  Controller-only and only when this
    session owns the local lifecycle.  ``--collect-only`` starts nothing."""
    config = session.config
    if hasattr(config, "workerinput"):
        if (getattr(config.option, "collectonly", False)
                or REMOTE_SERVER
                or os.environ.get("TEST_SKIP_SERVER_SETUP") == "1"
                or not session.items):
            return
        _chdir_scratch()
        error_path = Path(REGISTRY_ROOT) / ".xdist-fleet-error"
        stable_path = Path(REGISTRY_ROOT) / ".xdist-fleet-stable"
        deadline = time.time() + _xdist_fleet_wait_seconds()
        while time.time() < deadline:
            if stable_path.exists():
                break
            if error_path.exists():
                raise pytest.UsageError(
                    "xdist fleet coordinator failed: "
                    + error_path.read_text(encoding="utf-8"))
            time.sleep(0.1)
        else:
            raise pytest.UsageError(
                "timed out waiting for the xdist controller to start the "
                "complete test fleet")
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
    _require_fleet_startup_stability()
    _capture_fleet_baseline()           # snapshot the freshly-launched fleet


def pytest_sessionfinish(session, exitstatus):
    """Stop local servers when the session ends (no-op in remote mode or xdist workers)."""
    import subprocess

    # xdist workers must not call stop-all: the controller owns server lifecycle.
    # A worker finishing early would kill servers other workers still need.
    if hasattr(session.config, "workerinput"):
        return

    # Collection-only sessions started nothing (pytest_sessionstart and
    # pytest_collection_finish carry the same gate): no fleet to conserve, no
    # stop sweep to run, no scratch tree to destroy.
    if getattr(session.config.option, "collectonly", False):
        return

    # The watchdog protects the fleet while tests execute.  Session teardown is
    # the one deliberate full-fleet stop, after which its probes must be silent.
    _stop_sentinel_watchdog()

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
