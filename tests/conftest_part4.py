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
