"""Fleet health conservation, watchdog, and cross-process abort handling.

``tests.conftest`` re-exports this module's hooks.  Signal forensics live in
:mod:`brix_suite.harness.kill_tracer`.
"""

import concurrent.futures as _cf
import json as _json
import os
import signal
import socket
import sys
import threading as _threading
import time
from pathlib import Path

import pytest
from server_registry import read_manifest
from settings import HOST, REGISTRY_ROOT, REMOTE_SERVER, TEST_ROOT

from brix_suite.harness.kill_tracer import _CURRENT_NODEID, _FLEET_SENTINEL_ON

def _check_server_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    """Return True if the server is accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# The session must leave every inherited fleet listener intact until teardown.

_FLEET_BASELINE_PATH = Path(REGISTRY_ROOT) / ".fleet-health-baseline.json"
_fleet_baseline_captured = False   # per-process guard: capture once per session


def _fleet_stability_seconds() -> float:
    """Return the required post-launch health window, bounded to 3--5 seconds."""
    raw = os.environ.get("TEST_FLEET_STABILITY_SECS", "5")
    try:
        seconds = float(raw)
    except ValueError as exc:
        raise pytest.UsageError(
            "TEST_FLEET_STABILITY_SECS must be a number from 3 through 5"
        ) from exc
    if not 3.0 <= seconds <= 5.0:
        raise pytest.UsageError(
            "TEST_FLEET_STABILITY_SECS must be a number from 3 through 5"
        )
    return seconds


def _fleet_primary_endpoints():
    """Return one TCP readiness endpoint for each registered listener process."""
    out = []
    try:
        servers = read_manifest().get("servers", {})
    except Exception:
        return out
    for name, rec in (servers.items() if isinstance(servers, dict) else []):
        ep = rec.get("endpoint", {}) if isinstance(rec, dict) else {}
        port = ep.get("port")
        if port:
            out.append((name, ep.get("host") or HOST, int(port)))
    return out


def _require_fleet_startup_stability() -> None:
    """Require every primary fleet listener to stay reachable before dispatch."""
    endpoints = _fleet_primary_endpoints()
    if not endpoints:
        raise pytest.UsageError(
            "full-fleet startup produced no registered TCP endpoints"
        )
    seconds = _fleet_stability_seconds()
    deadline = time.monotonic() + seconds
    expected = {f"{name}:{port}" for name, _host, port in endpoints}
    while True:
        live = _fleet_reachable_labels(endpoints)
        missing = sorted(expected - live)
        if missing:
            raise pytest.UsageError(
                "full-fleet startup is unstable; listener(s) went down before "
                "test dispatch: " + ", ".join(missing)
            )
        if time.monotonic() >= deadline:
            print(
                f"[conftest] complete fleet stayed healthy for {seconds:g}s; "
                "dispatching tests.",
                flush=True,
            )
            return
        time.sleep(0.2)


def _fleet_manifest_endpoints():
    """[(name, host, port), ...] for every port a launched fleet server listens
    on (primary + any extra_ports), read from the session manifest."""
    try:
        servers = read_manifest().get("servers", {})
    except Exception:
        return []
    if not isinstance(servers, dict):
        return []
    out = []
    for name, record in servers.items():
        out.extend(_record_endpoints(name, record))
    return out


def _endpoint(name, host, port):
    if not port:
        return None
    try:
        return name, host, int(port)
    except (TypeError, ValueError):
        return None


def _record_endpoints(name, record):
    if not isinstance(record, dict):
        return []
    endpoint = record.get("endpoint", {})
    host = endpoint.get("host") or HOST
    ports = [endpoint.get("port")]
    extra_ports = endpoint.get("extra_ports") or {}
    ports.extend(extra_ports.values())
    rows = [_endpoint(name, host, port) for port in ports]
    return list(filter(None, rows))


def _fleet_reachable_labels(endpoints):
    """Set of "name:port" labels for endpoints currently accepting TCP."""
    return {
        f"{name}:{port}"
        for (name, host, port) in endpoints
        if _check_server_reachable(host, port, timeout=1.0)
    }


def _capture_fleet_baseline():
    """Snapshot this session's reachable local fleet before tests run."""
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
        _clear_fleet_sentinel_marker()
    except OSError:
        pass


def _load_fleet_baseline():
    if not _fleet_baseline_captured or not _FLEET_BASELINE_PATH.exists():
        return None
    try:
        return _json.loads(_FLEET_BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _conservation_message(base_count, now_count, down):
    bar = "=" * 78
    body = "".join(f"    - {label}\n" for label in down)
    return (
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


def _verify_fleet_conservation():
    """Check that every baseline listener remains reachable before teardown."""
    if REMOTE_SERVER:
        return True, ""
    base = _load_fleet_baseline()
    if base is None:
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
    return False, _conservation_message(base_count, now_count, down)


# The arbiter confirms prolonged fleet collapse; kill_tracer records its cause.

_SENTINEL_GRACE = float(os.environ.get("BRIX_FLEET_SENTINEL_GRACE", "8"))
# Require both prolonged failure and a fleet-wide threshold to avoid churn noise.
_SENTINEL_MIN_DOWN = int(os.environ.get("BRIX_FLEET_SENTINEL_MIN_DOWN", "8"))
_SENTINEL_DOWN_FRACTION = float(os.environ.get("BRIX_FLEET_SENTINEL_FRACTION", "0.5"))
_SENTINEL_POLL = float(os.environ.get("BRIX_FLEET_SENTINEL_POLL", "2.0"))
# Mid-run detection warns by default; session-end conservation is authoritative.
_SENTINEL_HARD_ABORT = os.environ.get("BRIX_FLEET_SENTINEL_ABORT", "0") == "1"
_SENTINEL_ABORT_MARKER = Path(REGISTRY_ROOT) / ".fleet-sentinel-abort"
_sentinel = {"protected": None, "down_since": {}, "last": 0.0,
             "fired": False, "stopping": False}
_sentinel_lock = _threading.Lock()
_sentinel_watchdog = {"thread": None, "session": None}


def _clear_fleet_sentinel_marker():
    """Drop a stale abort marker and reset in-process sentinel state.

    Called when a fresh healthy fleet baseline is captured, so a new run (or the
    next suite lane) never inherits a previous run's abort."""
    _sentinel.update({"protected": None, "down_since": {}, "last": 0.0,
                      "fired": False, "stopping": False})
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
    """Probe manifest endpoints quickly, then reconfirm misses slowly."""
    endpoints = _fleet_manifest_endpoints()
    if not endpoints:
        return None                          # manifest unreadable — cannot judge
    up = _sentinel_probe(endpoints, 0.6)
    misses = [(n, h, p) for (n, h, p) in endpoints if n not in up]
    if misses:
        up |= _sentinel_probe(misses, 3.0)   # slow-under-load ≠ dead
    return up


def _scan_blocked():
    return _sentinel["fired"] or _sentinel["stopping"] or REMOTE_SERVER


def _begin_sentinel_scan(throttle, now):
    with _sentinel_lock:
        if throttle and now - _sentinel["last"] < throttle:
            return None
        _sentinel["last"] = now
        return _sentinel_protected_names()


def _record_unreachable(raw_down, now):
    for name in list(_sentinel["down_since"]):
        if name not in raw_down:
            _sentinel["down_since"].pop(name, None)
    for name in raw_down:
        _sentinel["down_since"].setdefault(name, now)


def _confirmed_unreachable(now):
    return sorted(
        name for name, since in _sentinel["down_since"].items()
        if now - since >= _SENTINEL_GRACE
    )


def _sentinel_detect(throttle):
    """Return the list of baseline servers unreachable past the grace window.

    Updates the shared down-since state under the lock so the per-test hook and
    the watchdog thread can both call it safely.  ``throttle`` bounds the scan
    rate on the hot per-test path; the watchdog passes 0 (it self-paces)."""
    if _scan_blocked():
        return []
    now = time.monotonic()
    protected = _begin_sentinel_scan(throttle, now)
    if not protected:
        return []
    reachable = _sentinel_reachable_names()   # network probe — outside the lock
    if reachable is None:
        return []
    raw_down = protected - reachable
    with _sentinel_lock:
        if _sentinel["stopping"]:
            return []
        now = time.monotonic()
        _record_unreachable(raw_down, now)
        return _confirmed_unreachable(now)


def _sentinel_message(nodeid, confirmed, via):
    bar = "=" * 78
    shown = confirmed[:12]
    body = "".join(f"    - {name}\n" for name in shown)
    if len(confirmed) > len(shown):
        body += f"    - … and {len(confirmed) - len(shown)} more\n"
    verb = ("STOPPED or CRASHED shared fleet servers — aborting the run"
            if _SENTINEL_HARD_ABORT
            else "may have STOPPED or CRASHED shared fleet servers (warn-only)")
    return (
        f"\n{bar}\nFLEET SENTINEL: a test {verb}.\n"
        f"  detected by: {via}   around test: {nodeid}\n"
        f"  {len(confirmed)} shared server(s) unreachable for >= "
        f"{_SENTINEL_GRACE:.0f}s and not restarted:\n{body}"
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


def _record_sentinel_failure(session, message):
    if session is None:
        return
    try:
        session.config._fleet_sentinel_failure = message
    except Exception:
        pass


def _request_sentinel_stop(session):
    if session is None:
        return
    try:
        session.shouldstop = "fleet sentinel: shared servers were killed"
    except Exception:
        pass


def _write_sentinel_marker(message):
    try:
        _SENTINEL_ABORT_MARKER.parent.mkdir(parents=True, exist_ok=True)
        _SENTINEL_ABORT_MARKER.write_text(message, encoding="utf-8")
    except OSError:
        pass


def _interrupt_main_thread():
    try:
        os.kill(os.getpid(), signal.SIGINT)
    except OSError:
        pass


def _sentinel_fire(nodeid, confirmed, via):
    """Announce the collapse once, mark the run for abort, wake the process."""
    with _sentinel_lock:
        if _sentinel["fired"] or _sentinel["stopping"]:
            return
        _sentinel["fired"] = True
    message = _sentinel_message(nodeid, confirmed, via)
    sys.stderr.write(message)
    session = _sentinel_watchdog.get("session")
    _record_sentinel_failure(session, message)
    if not _SENTINEL_HARD_ABORT:
        return                              # warn-only: detect + log, never halt
    _request_sentinel_stop(session)
    _write_sentinel_marker(message)
    _interrupt_main_thread()


def _sentinel_threshold(protected_count):
    """Number of down-past-grace servers that constitutes a fleet collapse:
    a majority of the baseline, floored at the absolute minimum."""
    return max(_SENTINEL_MIN_DOWN, int(_SENTINEL_DOWN_FRACTION * protected_count))


def _sentinel_watchdog_loop():
    """Poll the fleet independent of test cadence; fire on a confirmed collapse.

    Runs on the controller / serial process (never a hung worker), so a fleet
    that dies mid-lane is caught even if every test worker is blocked on a dead
    socket and no teardown hook is running."""
    while not _sentinel["fired"] and not _sentinel["stopping"]:
        try:
            confirmed = _sentinel_detect(throttle=0)
            if _sentinel["stopping"]:
                return
            need = _sentinel_threshold(len(_sentinel.get("protected") or ()))
            if confirmed and len(confirmed) >= need:
                _sentinel_fire("<none — between tests>", confirmed, "watchdog")
                return
        except Exception:
            pass
        time.sleep(_SENTINEL_POLL)


def _stop_sentinel_watchdog() -> None:
    """Tell the watcher that the controller is about to stop its own fleet.

    Conservation is checked immediately before this is called.  Without this
    boundary the daemon can observe the intentional stop sweep, wait through
    its grace period, and print a misleading "test killed the fleet" warning.
    """
    with _sentinel_lock:
        _sentinel["stopping"] = True


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


# ---------------------------------------------------------------------------
# Per-test sentinel hooks (moved with the arbiter from conftest_part5.py).
# tests/conftest.py re-exports these; pytest registers them from the conftest
# namespace, so this module itself is never a plugin and they fire exactly once.
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
