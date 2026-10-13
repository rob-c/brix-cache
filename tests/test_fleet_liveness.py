"""Crash-loop guard: every fleet server must stay alive across a 20s window.

A misconfigured nginx or xrootd instance often *binds its port* long enough to
pass a one-shot readiness probe, then dies and is respawned — a crash-loop.  The
fleet start-all reports it as "listening" and every downstream test then flakes
against a target that is only intermittently up.

This test catches that class directly.  It snapshots the live listener PID of
every registry server that is currently up, waits ``SETTLE`` seconds (the
"20s of startup" observation window), and then asserts, for every one of those
servers, that:

* it is **still listening** — a server that vanished inside a quiet window
  crashed and has not (yet) come back; and
* **every** process holding its listen port has been alive **> MIN_AGE** — a
  listener younger than 100 ms was respawned mid-window, the signature of a
  process that keeps dying and restarting; and
* at least one of its original listener PIDs survives — a quiet window that
  nonetheless rotated *every* PID is a crash-loop the age floor can miss when
  respawns outrun ``MIN_AGE``.

A healthy server started at session boot reads an age of tens of seconds here,
so the 100 ms floor has an enormous margin and never false-fails on a stable
fleet.  The end check is swept a few times over a couple of seconds so a
flapping server is caught even if its respawn does not line up with a single
sample.

Marked ``serial``: it must be the only thing touching the fleet for its window,
otherwise a chaos/e2e test that deliberately kills a server (e.g. the
``chaos-*`` discovery nodes) would read as a crash-loop here.
"""

from __future__ import annotations

import time

import pytest

import fleet_specs
from lib_py.util import (
    _darwin_netstat_row,
    _elapsed_time_seconds,
    listening_port_pids,
    pids_on_port,
    process_age,
)
from server_registry import endpoint_for, registered_specs

pytestmark = [pytest.mark.serial, pytest.mark.slow, pytest.mark.timeout(120)]

# Observation window — the "20s of startup" a crash-loop needs to manifest.
SETTLE = 20.0
# A listener younger than this was respawned mid-window: crash-loop signature.
MIN_AGE = 0.1
# End-of-window re-samples: widen the catch window for a slow flapper so we do
# not depend on a single sample landing in its brief post-respawn interval.
END_SAMPLES = 4
END_SAMPLE_GAP = 0.5


def _young_listeners(listeners):
    return {pid: age for pid, age in listeners.items()
            if age is None or age < MIN_AGE}


def _classify(name, start_pids, listeners):
    """Return a crash-loop reason for one server sample, or ``None`` if healthy.

    ``start_pids`` is the set of listener PIDs seen at the window's start;
    ``listeners`` maps each PID holding the port *now* to its age (``None`` if
    the PID vanished between the port read and the age read).  Pure so the
    signatures below can be pinned without a 20s live window.
    """
    if not listeners:
        return "stopped listening within the window (crashed)"
    young = _young_listeners(listeners)
    if young:
        detail = ", ".join(
            f"pid {pid} age {'gone' if age is None else f'{age:.3f}s'}"
            for pid, age in young.items()
        )
        return f"listener respawned < {MIN_AGE}s ago ({detail})"
    if start_pids and not (set(listeners) & start_pids):
        return (f"every listener PID replaced during the window "
                f"(was {sorted(start_pids)}, now {sorted(listeners)})")
    return None


def _port_pids(port: int, snapshot=None) -> set[int]:
    """Listener PIDs from a fleet-wide snapshot, with a portable fallback."""
    if snapshot is not None:
        return set(snapshot.get(port, ()))
    return set(pids_on_port(port))


def _listeners_with_age(port: int, snapshot=None) -> dict[int, float | None]:
    """Map each PID holding ``port`` to its process age in seconds."""
    return {pid: process_age(pid) for pid in _port_pids(port, snapshot)}


def _live_fleet_ports() -> list[tuple[str, int]]:
    """(name, port) for every registry server currently listening."""
    fleet_specs.register_full_fleet()  # idempotent
    snapshot = listening_port_pids()
    live = []
    for spec in registered_specs():
        port = endpoint_for(spec).port
        if port and _port_pids(int(port), snapshot):
            live.append((spec.name, int(port)))
    return live


def _sample_failures(servers, start, failures):
    snapshot = listening_port_pids()
    for name, port in servers:
        if name in failures:
            continue
        reason = _classify(name, start[name], _listeners_with_age(port, snapshot))
        if reason:
            failures[name] = reason


def _require_live_servers():
    servers = _live_fleet_ports()
    if not servers:
        pytest.skip("no fleet servers listening — start-all not run for this session")
    return servers


def _observe_failures(servers, start):
    failures: dict[str, str] = {}
    for _ in range(END_SAMPLES):
        _sample_failures(servers, start, failures)
        if len(failures) == len(servers):
            return failures
        time.sleep(END_SAMPLE_GAP)
    return failures


def _assert_no_failures(failures):
    detail = "\n".join(
        f"  - {name}: {why}" for name, why in sorted(failures.items())
    )
    assert not failures, (
        f"crash-looping fleet server(s) after {SETTLE:.0f}s:\n{detail}"
    )


def test_no_server_is_crash_looping():
    servers = _require_live_servers()

    # Snapshot the listener PIDs up front so a server that flaps *during* the
    # window is caught by the PID moving out from under it, not just by age.
    snapshot = listening_port_pids()
    start = {name: _port_pids(port, snapshot) for name, port in servers}

    time.sleep(SETTLE)

    # Sweep the end check so a flapper whose respawn misses one sample is still
    # caught by another.
    _assert_no_failures(_observe_failures(servers, start))


# --- hermetic coverage of the detector itself (no live fleet, no 20s sleep) ---

def test_classify_passes_a_stable_aged_listener():
    # A single worker up for ~20s, same PID as at window start: healthy.
    assert _classify("ok", {4242}, {4242: 20.3}) is None


def test_classify_flags_a_vanished_server():
    # Bound its port at start, holds nothing now: crashed inside the window.
    reason = _classify("dead", {4242}, {})
    assert reason and "crashed" in reason


def test_classify_flags_a_freshly_respawned_listener():
    # Listener younger than MIN_AGE: it was restarted mid-window.
    reason = _classify("loop", {4242}, {5555: 0.02})
    assert reason and "respawned" in reason


def test_classify_flags_full_pid_rotation_even_when_aged():
    # Every start PID replaced, yet each replacement already older than MIN_AGE:
    # the age floor alone would miss it; PID-set disjointness catches it.
    reason = _classify("churn", {100, 101}, {200: 5.0, 201: 5.0})
    assert reason and "replaced" in reason


@pytest.mark.parametrize(("value", "expected"), [
    ("00:09", 9.0),
    ("05:04:03", 18_243.0),
    ("2-05:04:03", 191_043.0),
])
def test_elapsed_time_parser_accepts_ps_shapes(value, expected):
    assert _elapsed_time_seconds(value) == expected


@pytest.mark.parametrize("value", ["", "garbage", "1:60", "1:2:60", "1:2:3:4"])
def test_elapsed_time_parser_rejects_malformed_shapes(value):
    assert _elapsed_time_seconds(value) is None


def test_darwin_netstat_parser_accepts_process_name_with_spaces():
    line = ("tcp4 0 0 127.0.0.1.10005 *.* LISTEN 0 0 131072 131072 "  # net-literal-allow: synthetic Darwin netstat row
            "Code Helper (Plugin):4242 00100 00000006 trailing")
    assert _darwin_netstat_row(line, "LISTEN") == (
        "127.0.0.1.10005", "*.*", 4242,  # net-literal-allow: expected parsed fixture address
    )


def test_darwin_netstat_parser_rejects_other_state():
    line = ("tcp4 0 0 127.0.0.1.10005 *.* ESTABLISHED 0 0 131072 131072 "  # net-literal-allow: synthetic Darwin netstat row
            "nginx:4242 00102 00000008 trailing")
    assert _darwin_netstat_row(line, "LISTEN") is None


def test_darwin_netstat_parser_rejects_missing_owner():
    line = "tcp4 0 0 127.0.0.1.10005 *.* LISTEN 0 0 131072 131072 -"  # net-literal-allow: synthetic Darwin netstat row
    assert _darwin_netstat_row(line, "LISTEN") is None
