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
import csv
import json
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
    if _skip_xdist_fleet_start(config):
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
    specs, stable_path = _start_xdist_fleet()
    node.config._nginx_xrootd_selected_registry_specs = specs
    stable_path.parent.mkdir(parents=True, exist_ok=True)
    stable_path.write_text("stable\n", encoding="utf-8")
    _xdist_fleet_started = True


def _skip_xdist_fleet_start(config) -> bool:
    """Return whether this controller must leave the shared fleet untouched."""
    return any((
        _xdist_fleet_started,
        getattr(config.option, "collectonly", False),
        REMOTE_SERVER,
        os.environ.get("TEST_SKIP_SERVER_SETUP") == "1",
    ))


def _start_xdist_fleet():
    """Start the shared fleet and return its specs and stability marker."""
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
    return specs, stable_path


def pytest_collection_finish(session):
    """Start the complete session fleet once collection has settled.

    Runs after every ``pytest_collection_modifyitems`` (including the mark
    plugin's ``-m``/``-k`` deselection), so no test can begin before the full
    fixed-port catalogue is running.  Controller-only and only when this
    session owns the local lifecycle.  ``--collect-only`` starts nothing."""
    config = session.config
    if hasattr(config, "workerinput"):
        _finish_worker_collection(session)
        return
    if _skip_controller_collection(session):
        return
    specs = _specs_to_boot(session.items)
    config._nginx_xrootd_selected_registry_specs = specs
    _start_all_resilient(specs)
    _require_fleet_startup_stability()
    _capture_fleet_baseline()           # snapshot the freshly-launched fleet


def _finish_worker_collection(session) -> None:
    """Join a worker to the fleet after the controller's collection barrier."""
    if any((
        getattr(session.config.option, "collectonly", False),
        REMOTE_SERVER,
        os.environ.get("TEST_SKIP_SERVER_SETUP") == "1",
        not session.items,
    )):
        return
    _chdir_scratch()
    _wait_for_xdist_fleet()
    read_manifest()


def _wait_for_xdist_fleet() -> None:
    """Wait for the controller's stable marker or propagate its failure."""
    error_path = Path(REGISTRY_ROOT) / ".xdist-fleet-error"
    stable_path = Path(REGISTRY_ROOT) / ".xdist-fleet-stable"
    deadline = time.time() + _xdist_fleet_wait_seconds()
    while time.time() < deadline:
        if stable_path.exists():
            return
        if error_path.exists():
            message = error_path.read_text(encoding="utf-8")
            raise pytest.UsageError(f"xdist fleet coordinator failed: {message}")
        time.sleep(0.1)
    raise pytest.UsageError(
        "timed out waiting for the xdist controller to start the complete test fleet"
    )


def _skip_controller_collection(session) -> bool:
    """Return whether controller collection should avoid fleet startup."""
    config = session.config
    return any((
        _xdist_requested(config),
        getattr(config.option, "collectonly", False),
        REMOTE_SERVER,
        _should_skip_local_lifecycle(config),
        not session.items,
    ))


def pytest_sessionfinish(session, exitstatus):
    """Stop local servers when the session ends (no-op in remote mode or xdist workers)."""
    del exitstatus
    if _skip_session_finish(session):
        return
    _stop_sentinel_watchdog()
    _record_fleet_conservation(session)
    if REMOTE_SERVER or _should_skip_local_lifecycle(session.config):
        return
    _stop_session_fleet(session)
    _record_orphans(session)
    _remove_test_root()


def _skip_session_finish(session) -> bool:
    """Return whether this process has no session fleet to finish."""
    return any((
        hasattr(session.config, "workerinput"),
        getattr(session.config.option, "collectonly", False),
    ))


def _record_fleet_conservation(session) -> None:
    """Make a fleet-health failure visible to pytest and its summary."""
    ok, message = _verify_fleet_conservation()
    if ok:
        return
    sys.stderr.write(message)
    session.exitstatus = 1
    try:
        session.config._fleet_health_failure = message
    except Exception:
        pass


def _stop_session_fleet(session) -> None:
    """Best-effort stop of the fleet selected by this session."""
    try:
        specs = getattr(session.config, "_nginx_xrootd_selected_registry_specs", None)
        _stop_owned_fleet(specs)
    except Exception:
        pass  # best-effort cleanup


def _record_orphans(session) -> None:
    """Detect and report processes that survived the fleet stop sweep."""
    try:
        from fleet_orphans import find_orphans  # noqa: PLC0415
        survivors = find_orphans(TEST_ROOT)
    except Exception:
        pass  # detection must never itself break teardown
    else:
        if survivors:
            _report_orphans(session, survivors)


def _report_orphans(session, survivors) -> None:
    """Write the post-teardown orphan alarm and fail the session."""
    listing = "\n".join("    pid %d: %s" % entry for entry in survivors)
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


def _remove_test_root() -> None:
    """Restore the original directory and remove the session scratch tree."""
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
