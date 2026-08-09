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

import concurrent.futures as _cf
import os
import shutil
import random
import signal
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


# ---------------------------------------------------------------------------
# Fleet health conservation guard.
#
# The central test management launches a fixed catalogue of fleet servers.  A
# well-behaved test session must LEAVE THAT FLEET INTACT: every server that was
# listening when the session began must still be listening when it ends (before
# the harness tears it down), and the number of occupied fleet ports must be
# conserved.  A server that is gone at session end was either stopped by a
# misbehaving test (a test-isolation bug — a shared server treated as private)
# or crashed (a server bug).  Either way it is the direct cause of the
# ConnectionRefused cascades seen when the rest of the suite keeps hitting a
# port that is no longer answering, so we surface it loudly and fail the run.
# ---------------------------------------------------------------------------
import json as _json

_FLEET_BASELINE_PATH = Path(REGISTRY_ROOT) / ".fleet-health-baseline.json"
_fleet_baseline_captured = False   # per-process guard: capture once per session


def _fleet_manifest_endpoints():
    """[(name, host, port), ...] for every port a launched fleet server listens
    on (primary + any extra_ports), read from the session manifest."""
    out = []
    try:
        servers = read_manifest().get("servers", {})
    except Exception:
        return out
    for name, rec in (servers.items() if isinstance(servers, dict) else []):
        ep = rec.get("endpoint", {}) if isinstance(rec, dict) else {}
        host = ep.get("host") or HOST
        port = ep.get("port")
        if port:
            out.append((name, host, int(port)))
        for _label, xport in (ep.get("extra_ports") or {}).items():
            try:
                out.append((name, host, int(xport)))
            except (TypeError, ValueError):
                continue
    return out


def _fleet_reachable_labels(endpoints):
    """Set of "name:port" labels for endpoints currently accepting TCP."""
    return {
        f"{name}:{port}"
        for (name, host, port) in endpoints
        if _check_server_reachable(host, port, timeout=1.0)
    }


def _capture_fleet_baseline():
    """Snapshot the launched-and-listening fleet as this session's health
    baseline.

    Captured once per session, at session start (before any test runs), so the
    baseline reflects the fleet THIS session inherited — the conservation check
    then measures only the damage THIS session did, never damage a prior lane
    left behind.  Overwrites any earlier session's snapshot.  A remote fleet is
    managed elsewhere, so it is never guarded here."""
    global _fleet_baseline_captured
    if REMOTE_SERVER or _fleet_baseline_captured:
        return
    endpoints = _fleet_manifest_endpoints()
    if not endpoints:
        return
    live = _fleet_reachable_labels(endpoints)
    if not live:
        return                       # fleet not up yet — a later hook captures it
    try:
        _FLEET_BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _FLEET_BASELINE_PATH.write_text(
            _json.dumps({"count": len(live), "servers": sorted(live)}),
            encoding="utf-8")
        _fleet_baseline_captured = True
        # A freshly launched-and-listening fleet is ground truth that nothing is
        # damaged yet: drop any sentinel abort marker a PRIOR run/lane left on
        # disk so this healthy session is not aborted at its first test, and
        # reset the in-process sentinel so a reused interpreter starts clean.
        _clear_fleet_sentinel_marker()
    except OSError:
        pass


def _verify_fleet_conservation():
    """After all tests, before teardown: every server listening at the baseline
    must STILL be listening, and the occupied-port count must be conserved.
    Returns (ok: bool, message: str)."""
    # Only judge conservation when THIS session captured the baseline (i.e. it
    # actually started/attached the fleet).  A subset run with no fleet
    # (TEST_SKIP_SERVER_SETUP=1, or a plain `pytest <file>` that skips lifecycle)
    # must not fail on a stale baseline a previous run left on disk.
    if REMOTE_SERVER or not _fleet_baseline_captured or not _FLEET_BASELINE_PATH.exists():
        return True, ""
    try:
        base = _json.loads(_FLEET_BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True, ""
    base_servers = set(base.get("servers", []))
    if not base_servers:
        return True, ""
    live = _fleet_reachable_labels(_fleet_manifest_endpoints())
    now_count = len(live & base_servers)
    base_count = int(base.get("count", len(base_servers)))
    down = sorted(base_servers - live)
    if not down and now_count == base_count:
        return True, ""
    bar = "=" * 78
    body = "".join(f"    - {label}\n" for label in down)
    message = (
        f"\n{bar}\n"
        "FLEET HEALTH CHECK FAILED — server conservation (pre-teardown)\n"
        f"  occupied fleet ports before = {base_count}, after = {now_count}\n"
        f"  {len(down)} server(s) launched by the central test management are NOT\n"
        f"  listening at session end:\n{body}"
        "  A shared fleet server went down during the session and did not come\n"
        "  back.  Either a test STOPPED or CRASHED it (a test-isolation bug: a\n"
        "  shared server was treated as private) or the server itself crashed and\n"
        "  needs attention.  This is a direct cause of ConnectionRefused cascades\n"
        "  in the rest of the suite.\n"
        f"{bar}\n"
    )
    return False, message


# ---------------------------------------------------------------------------
# Fleet sentinel — arbiter half (fail-fast on a test that kills a shared server).
#
# The forensic half (conftest.py) logs every fatal signal to a registry nginx
# master.  This half decides whether the fleet was actually DAMAGED and aborts.
# Per test (throttled) it checks each baseline server via its CURRENT pidfile
# pid — restart-aware: a test that stops-and-restarts its own subject server is
# fine, because the pidfile then holds a live pid again.  A server only counts
# as damaged once it has stayed dead for BRIX_FLEET_SENTINEL_GRACE seconds
# (tracked across the natural per-test cadence, no sleeps), so transient restart
# windows never trip it.  The first confirmed death aborts the whole run with a
# banner naming the culprit test and pointing at $TEST_ROOT/kill-diag.log for
# the exact killer traceback — turning a fleet-wide ConnectionRefused cascade
# into one attributable, must-fix bug.  Disable with BRIX_FLEET_SENTINEL=0.
# ---------------------------------------------------------------------------
import threading as _threading

_SENTINEL_GRACE = float(os.environ.get("BRIX_FLEET_SENTINEL_GRACE", "8"))
# The sentinel exists to catch a CATASTROPHIC collapse — a test that tears down
# the whole shared fleet (a mass stop-all / port-band reap) and strands the rest
# of the suite in ConnectionRefused.  It must NOT fire on legitimate partial
# churn: mesh/chaos/reload tests routinely stop-and-restart a handful of shared
# nodes, and a slow restart can leave several transiently unreachable.  So the
# trip threshold is a MAJORITY of the baseline (default 50%), floored at an
# absolute so a tiny fleet still needs several down.  Down-for-grace AND
# majority-of-fleet together mean "the fleet collapsed", not "a test is busy".
_SENTINEL_MIN_DOWN = int(os.environ.get("BRIX_FLEET_SENTINEL_MIN_DOWN", "8"))
_SENTINEL_DOWN_FRACTION = float(os.environ.get("BRIX_FLEET_SENTINEL_FRACTION", "0.5"))
_SENTINEL_POLL = float(os.environ.get("BRIX_FLEET_SENTINEL_POLL", "2.0"))
# The mid-run watchdog DETECTS + LOGS a suspected collapse by default but does
# NOT halt the suite: its reachability probe false-positives under launch-load
# (an ephemeral-port storm from many interop pairs coming up at once exhausts
# outbound ports for the probe's own sockets, so live servers read as dead).
# The pre-teardown conservation check is the authoritative session-end verdict.
# Opt into hard mid-run abort with BRIX_FLEET_SENTINEL_ABORT=1.
_SENTINEL_HARD_ABORT = os.environ.get("BRIX_FLEET_SENTINEL_ABORT", "0") == "1"
_SENTINEL_ABORT_MARKER = Path(REGISTRY_ROOT) / ".fleet-sentinel-abort"
_sentinel = {"protected": None, "down_since": {}, "last": 0.0, "fired": False}
_sentinel_lock = _threading.Lock()
_sentinel_watchdog = {"thread": None, "session": None}


def _clear_fleet_sentinel_marker():
    """Drop a stale abort marker and reset in-process sentinel state.

    Called when a fresh healthy fleet baseline is captured, so a new run (or the
    next suite lane) never inherits a previous run's abort."""
    _sentinel.update({"protected": None, "down_since": {}, "last": 0.0,
                      "fired": False})
    try:
        _SENTINEL_ABORT_MARKER.unlink()
    except OSError:
        pass


def _sentinel_protected_names():
    """Server names that were listening at the session baseline.

    Cached once read, but ONLY on a successful non-empty read: in xdist the
    controller writes the baseline while workers are already running, so an
    early miss must NOT be cached as "nothing to protect" (that would disable
    the sentinel on this worker for the whole run) — it retries next scan.
    """
    if _sentinel["protected"]:
        return _sentinel["protected"]
    names = set()
    try:
        base = _json.loads(_FLEET_BASELINE_PATH.read_text(encoding="utf-8"))
        names = {label.rsplit(":", 1)[0] for label in base.get("servers", [])}
    except (OSError, ValueError):
        return set()
    if names:
        _sentinel["protected"] = names
    return names


def _sentinel_probe(endpoints, timeout):
    """Set of names among ``endpoints`` accepting TCP within ``timeout``."""
    got = set()
    with _cf.ThreadPoolExecutor(max_workers=64) as pool:
        futs = {pool.submit(_check_server_reachable, host, port, timeout): name
                for (name, host, port) in endpoints}
        for fut in _cf.as_completed(futs):
            try:
                if fut.result():
                    got.add(futs[fut])
            except Exception:
                pass
    return got


def _sentinel_reachable_names():
    """Names of baseline servers currently accepting TCP on any manifest port.

    Reachability — not pidfile liveness — is the source of truth: it is exactly
    how the baseline is captured and how a downstream test experiences a dead
    server (ConnectionRefused), and it is immune to the stale-nginx.pid problem
    (several fleet servers record a pid that no longer matches their live master
    yet keep serving).

    Two-stage so a launch-load SPIKE (many interop pairs coming up at once now
    that the port fix lets them run instead of skip) can't be misread as a
    collapse: a fast parallel probe, then RE-CONFIRM only the misses with a
    generous timeout.  A truly dead server misses both; a live-but-slow one
    (accept queue backed up under load) answers the retry and is counted up."""
    endpoints = _fleet_manifest_endpoints()
    if not endpoints:
        return None                          # manifest unreadable — cannot judge
    up = _sentinel_probe(endpoints, 0.6)
    misses = [(n, h, p) for (n, h, p) in endpoints if n not in up]
    if misses:
        up |= _sentinel_probe(misses, 3.0)   # slow-under-load ≠ dead
    return up


def _sentinel_detect(throttle):
    """Return the list of baseline servers unreachable past the grace window.

    Updates the shared down-since state under the lock so the per-test hook and
    the watchdog thread can both call it safely.  ``throttle`` bounds the scan
    rate on the hot per-test path; the watchdog passes 0 (it self-paces)."""
    if _sentinel["fired"] or REMOTE_SERVER:
        return []
    now = time.monotonic()
    with _sentinel_lock:
        if throttle and now - _sentinel["last"] < throttle:
            return []
        _sentinel["last"] = now
        protected = _sentinel_protected_names()
    if not protected:
        return []
    reachable = _sentinel_reachable_names()   # network probe — outside the lock
    if reachable is None:
        return []
    raw_down = protected - reachable
    with _sentinel_lock:
        now = time.monotonic()
        for name in list(_sentinel["down_since"]):
            if name not in raw_down:          # recovered (e.g. finished restarting)
                _sentinel["down_since"].pop(name, None)
        for name in raw_down:
            _sentinel["down_since"].setdefault(name, now)
        return sorted(n for n, t in _sentinel["down_since"].items()
                      if now - t >= _SENTINEL_GRACE)


def _sentinel_fire(nodeid, confirmed, via):
    """Announce the collapse once, mark the run for abort, wake the process."""
    with _sentinel_lock:
        if _sentinel["fired"]:
            return
        _sentinel["fired"] = True
    bar = "=" * 78
    shown = confirmed[:12]
    body = "".join(f"    - {n}\n" for n in shown)
    if len(confirmed) > len(shown):
        body += f"    - … and {len(confirmed) - len(shown)} more\n"
    verb = ("STOPPED or CRASHED shared fleet servers — aborting the run"
            if _SENTINEL_HARD_ABORT
            else "may have STOPPED or CRASHED shared fleet servers (warn-only)")
    message = (
        f"\n{bar}\n"
        f"FLEET SENTINEL: a test {verb}.\n"
        f"  detected by: {via}   around test: {nodeid}\n"
        f"  {len(confirmed)} shared server(s) unreachable for >= "
        f"{_SENTINEL_GRACE:.0f}s and not restarted:\n"
        f"{body}"
        "  If real, a test killed a shared server the suite depends on and\n"
        "  downstream tests fail with ConnectionRefused.  The culprit's traceback\n"
        "  + timestamp (os.kill AND subprocess stop-all / nginx -s quit) is in\n"
        f"  {os.path.join(str(TEST_ROOT), 'kill-diag.log')}.  NOTE: mid-run\n"
        "  reachability can false-positive under launch-load (ephemeral-port\n"
        "  pressure breaks the probe); the pre-teardown conservation check is the\n"
        "  authoritative session-end verdict.  Set BRIX_FLEET_SENTINEL_ABORT=1 to\n"
        "  make this halt the run instead of warn.\n"
        f"{bar}\n"
    )
    sys.stderr.write(message)
    session = _sentinel_watchdog.get("session")
    try:
        if session is not None:
            session.config._fleet_sentinel_failure = message
    except Exception:
        pass
    if not _SENTINEL_HARD_ABORT:
        return                              # warn-only: detect + log, never halt
    try:
        if session is not None:
            session.shouldstop = "fleet sentinel: shared servers were killed"
    except Exception:
        pass
    try:                                    # cross-process signal to peer workers
        _SENTINEL_ABORT_MARKER.parent.mkdir(parents=True, exist_ok=True)
        _SENTINEL_ABORT_MARKER.write_text(message, encoding="utf-8")
    except OSError:
        pass
    # Break the main thread out of any blocking dead-socket wait so the abort is
    # honoured even when every worker is hung: pytest treats SIGINT as a graceful
    # stop.  Harmless on the controller loop too.
    try:
        os.kill(os.getpid(), signal.SIGINT)
    except OSError:
        pass


def _sentinel_threshold(protected_count):
    """Number of down-past-grace servers that constitutes a fleet collapse:
    a majority of the baseline, floored at the absolute minimum."""
    return max(_SENTINEL_MIN_DOWN, int(_SENTINEL_DOWN_FRACTION * protected_count))


def _sentinel_watchdog_loop():
    """Poll the fleet independent of test cadence; fire on a confirmed collapse.

    Runs on the controller / serial process (never a hung worker), so a fleet
    that dies mid-lane is caught even if every test worker is blocked on a dead
    socket and no teardown hook is running."""
    while not _sentinel["fired"]:
        try:
            confirmed = _sentinel_detect(throttle=0)
            need = _sentinel_threshold(len(_sentinel.get("protected") or ()))
            if confirmed and len(confirmed) >= need:
                _sentinel_fire("<none — between tests>", confirmed, "watchdog")
                return
        except Exception:
            pass
        time.sleep(_SENTINEL_POLL)


def _start_sentinel_watchdog(session):
    """Start the fleet watchdog once, on the controller/serial process only."""
    if (not _FLEET_SENTINEL_ON or REMOTE_SERVER
            or _sentinel_watchdog["thread"] is not None
            or os.environ.get("PYTEST_XDIST_WORKER") is not None):
        return
    _sentinel_watchdog["session"] = session
    t = _threading.Thread(target=_sentinel_watchdog_loop,
                          name="brix-fleet-sentinel", daemon=True)
    _sentinel_watchdog["thread"] = t
    t.start()


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
