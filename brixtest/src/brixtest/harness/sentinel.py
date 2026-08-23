"""Monitor fleet liveness during a test session.

The sentinel polls declared ports and current pidfiles, so supervised restarts
do not appear as stale-process failures. A session failure requires both the
configured minimum count and fraction of instances to remain down for the
stability window. Diagnostics identify the affected servers and active test.
"""

from __future__ import annotations

import dataclasses
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from brixtest.config.lanes import Lane
from brixtest.errors import ConservationError, FleetDiedError
from brixtest.events import emit
from brixtest.fleet.registry import InstanceSpec, Registry, endpoint_for
from brixtest.util.net import listening_ports

__all__ = ["FleetSentinel", "StabilityPolicy"]


@dataclasses.dataclass(frozen=True)
class StabilityPolicy:
    poll_interval: float = 2.0     # seconds between sweeps
    startup_grace: float = 8.0     # no verdicts this soon after start()
    fraction: float = 0.5          # this share of the fleet down, and
    min_down: int = 8              # at least this many down, together
    hard_abort: bool = False       # raise in-line vs. record-and-report
    stability_window: float = 5.0  # continuous downtime before counting


def _pid_alive(pidfile: Optional[Path]) -> bool:
    if pidfile is None:
        return False
    try:
        pid = int(pidfile.read_text().strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class FleetSentinel:
    def __init__(
        self,
        registry: Registry,
        lane: Lane,
        policy: Optional[StabilityPolicy] = None,
    ) -> None:
        self.registry = registry
        self.lane = lane
        self.policy = policy or StabilityPolicy()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._down_since: Dict[str, float] = {}
        self._verdict: Optional[FleetDiedError] = None
        self._current_test = ""
        self._baseline: Set[int] = set()
        self._watched: List[InstanceSpec] = []

    def note_test(self, test_id: str) -> None:
        with self._lock:
            self._current_test = test_id

    @property
    def verdict(self) -> Optional[FleetDiedError]:
        with self._lock:
            return self._verdict

    def start(self, watch: Optional[Set[str]] = None) -> None:
        """``watch`` restricts liveness to the named instances — the
        harness passes the *booted* set, because under selective boot a
        catalogued-but-unstarted server is not a corpse.  None (the CLI's
        start-everything path) watches the whole catalogue."""
        specs = self.registry.all_specs()
        if watch is not None:
            specs = [s for s in specs if s.name in watch]
        self._watched = [s for s in specs if s.primary_port is not None]
        self._baseline = listening_ports(self.lane.port_range())
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="brixtest-sentinel", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.policy.poll_interval * 2)
            self._thread = None

    def _sweep(self, now: float) -> List[str]:
        """Returns the names continuously down past the stability window."""
        answering = listening_ports(
            {s.primary_port for s in self._watched if s.primary_port}
        )
        confirmed: List[str] = []
        for spec in self._watched:
            if self._is_up(spec, answering):
                self._down_since.pop(spec.name, None)
                continue
            if self._continuously_down(spec.name, now):
                confirmed.append(spec.name)
        return confirmed

    def _is_up(self, spec: InstanceSpec, answering: Set[int]) -> bool:
        if spec.primary_port in answering:
            return True
        endpoint = endpoint_for(spec, self.lane)
        return _pid_alive(endpoint.pidfile)

    def _continuously_down(self, name: str, now: float) -> bool:
        first_seen = self._down_since.setdefault(name, now)
        return now - first_seen >= self.policy.stability_window

    def _run(self) -> None:
        started = time.monotonic()
        while not self._stop.wait(self.policy.poll_interval):
            now = time.monotonic()
            if now - started < self.policy.startup_grace:
                continue
            dead = self._sweep(now)
            threshold = max(self.policy.min_down, self.policy.fraction * len(self._watched))
            if dead and len(dead) >= threshold:
                self._declare_died(dead)
                return

    def _declare_died(self, dead: List[str]) -> None:
        with self._lock:
            culprit = self._current_test
        diag = self._write_diagnosis(dead, culprit)
        error = FleetDiedError(sorted(dead), culprit, str(diag))
        with self._lock:
            self._verdict = error
        emit("fleet.died", dead=len(dead), culprit=culprit)
        if self.policy.hard_abort:
            raise error

    def _write_diagnosis(self, dead: List[str], culprit: str) -> Path:
        diag = self.lane.log_dir / "fleet-died.json"
        payload = {
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dead": sorted(dead),
            "running_test": culprit,
            "watched": len(self._watched),
        }
        try:
            diag.parent.mkdir(parents=True, exist_ok=True)
            diag.write_text(json.dumps(payload, indent=2) + "\n")
        except OSError:
            pass
        return diag

    def conservation_check(self) -> None:
        """The session must not leak or lose lane listeners: the port set
        at stop must equal the baseline captured at start."""
        current = listening_ports(self.lane.port_range())
        appeared = sorted(current - self._baseline)
        vanished = sorted(self._baseline - current)
        if appeared or vanished:
            delta: List[Tuple[str, int]] = [("appeared", p) for p in appeared]
            delta += [("vanished", p) for p in vanished]
            raise ConservationError(delta)
