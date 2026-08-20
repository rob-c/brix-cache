"""The resource watch (feature F25): every server pid sampled for the
whole run, with explicit crash / memory-leak / CPU-spike verdicts.

The sentinel (F6) answers "is the fleet still *there*"; this module
answers "is the fleet still *healthy*".  A sampling thread walks the
pids a provider callback reports — static fleet pidfiles plus any
dynamically requested servers — and reads ``/proc/<pid>/stat``
(utime+stime ticks → CPU%) and ``/proc/<pid>/status`` (VmRSS).  Every
sample is attributed to the test running at that moment and batched
into the run store, so the portal can draw per-instance timelines and
the benchmark can name which test made which server hot.

Verdicts:

* **crash** — a pid the provider still claims has vanished from
  ``/proc``.  Reported the moment it is seen, once per instance.
* **cpu-spike** — CPU% at or above ``cpu_spike_pct`` for
  ``cpu_spike_samples`` consecutive samples.  Once per (instance, test).
* **leak** — decided at ``stop()`` over the whole series: least-squares
  RSS slope ≥ ``leak_slope_kb_per_min`` AND total growth ≥
  ``leak_min_growth_kb``.  Both bounds must trip so a short noisy
  series or a one-off allocation cannot fake a leak.

All timing is monotonic (WSL2 backwards-clock lesson); sample ``ts`` is
monotonic time re-anchored to the epoch once at start.
"""

from __future__ import annotations

import dataclasses
import os
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Tuple

from brixtest.results.model import Finding, Sample
from brixtest.results.store import ResultStore

__all__ = ["ResourcePolicy", "ResourceWatch"]

PidProvider = Callable[[], Mapping[str, int]]


@dataclasses.dataclass(frozen=True)
class ResourcePolicy:
    sample_interval: float = 1.0
    cpu_spike_pct: float = 90.0
    cpu_spike_samples: int = 5
    leak_slope_kb_per_min: float = 512.0
    leak_min_growth_kb: int = 8192
    min_leak_samples: int = 10      # below this the series proves nothing


def _read_proc(pid: int) -> Optional[Tuple[int, int]]:
    """(cpu_ticks, rss_kb) for a live pid, None for a vanished one."""
    try:
        stat = Path("/proc/%d/stat" % pid).read_text()
        status = Path("/proc/%d/status" % pid).read_text()
    except OSError:
        return None
    # comm may contain spaces/parens; the parseable tail starts after ')'.
    fields = stat.rpartition(")")[2].split()
    ticks = int(fields[11]) + int(fields[12])  # utime + stime
    rss_kb = 0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            rss_kb = int(line.split()[1])
            break
    return ticks, rss_kb


def _slope_kb_per_min(series: List[Tuple[float, int]]) -> float:
    """Least-squares slope of (ts, rss_kb), in kB per minute."""
    n = len(series)
    mean_t = sum(t for t, _ in series) / n
    mean_r = sum(r for _, r in series) / n
    denom = sum((t - mean_t) ** 2 for t, _ in series)
    if denom == 0:
        return 0.0
    num = sum((t - mean_t) * (r - mean_r) for t, r in series)
    return (num / denom) * 60.0


class ResourceWatch:
    def __init__(
        self,
        provider: PidProvider,
        store: ResultStore,
        run_id: str,
        policy: Optional[ResourcePolicy] = None,
    ) -> None:
        self.provider = provider
        self.store = store
        self.run_id = run_id
        self.policy = policy or ResourcePolicy()
        self.current_test = ""
        self._epoch_anchor = time.time() - time.monotonic()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_ticks: Dict[str, Tuple[int, int, float]] = {}  # name → (pid, ticks, mono)
        self._series: Dict[str, List[Tuple[float, int]]] = {}     # name → [(mono, rss_kb)]
        self._spike_streak: Dict[str, int] = {}
        self._reported: set = set()                               # (kind, instance[, test])
        self.findings: List[Finding] = []

    # -- lifecycle -------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="brixtest-resources", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.policy.sample_interval * 3 + 2)
            self._thread = None
        self._verdict_leaks()

    def note_test(self, nodeid: str) -> None:
        self.current_test = nodeid

    # -- the sampling loop -----------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._sweep()
            self._stop.wait(self.policy.sample_interval)

    def _sweep(self) -> None:
        now = time.monotonic()
        during = self.current_test
        batch: List[Sample] = []
        for name, pid in sorted(self.provider().items()):
            reading = _read_proc(pid)
            if reading is None:
                self._crash(name, pid, during)
                continue
            ticks, rss_kb = reading
            cpu_pct = self._cpu_pct(name, pid, ticks, now)
            self._series.setdefault(name, []).append((now, rss_kb))
            self._spike(name, cpu_pct, during)
            batch.append(Sample(
                instance=name, ts=self._epoch_anchor + now, pid=pid,
                rss_kb=rss_kb, cpu_pct=round(cpu_pct, 2), during_test=during,
            ))
        self.store.add_samples(self.run_id, batch)

    def _cpu_pct(self, name: str, pid: int, ticks: int, now: float) -> float:
        prev = self._last_ticks.get(name)
        self._last_ticks[name] = (pid, ticks, now)
        if prev is None or prev[0] != pid or now <= prev[2]:
            return 0.0  # first sight of this pid; no interval to rate over
        hz = float(os.sysconf("SC_CLK_TCK"))
        return (ticks - prev[1]) / hz / (now - prev[2]) * 100.0

    # -- detectors -------------------------------------------------------

    def _emit(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.store.add_finding(self.run_id, finding)

    def _crash(self, name: str, pid: int, during: str) -> None:
        key = ("crash", name)
        if key in self._reported:
            return
        # A deliberate release between the provider snapshot and the
        # /proc read looks identical to a crash; re-ask the provider,
        # and only a pid it STILL claims counts as one.
        if self.provider().get(name) != pid:
            return
        self._reported.add(key)
        self._emit(Finding(
            kind="crash", instance=name,
            detail="pid %d vanished from /proc while still registered" % pid,
            during_test=during, at=_utc_now(),
        ))

    def _spike(self, name: str, cpu_pct: float, during: str) -> None:
        if cpu_pct >= self.policy.cpu_spike_pct:
            self._spike_streak[name] = self._spike_streak.get(name, 0) + 1
        else:
            self._spike_streak[name] = 0
            return
        if self._spike_streak[name] != self.policy.cpu_spike_samples:
            return  # report exactly once, when the streak first qualifies
        key = ("cpu-spike", name, during)
        if key in self._reported:
            return
        self._reported.add(key)
        self._emit(Finding(
            kind="cpu-spike", instance=name,
            detail="CPU ≥ %.0f%% for %d consecutive samples (last %.1f%%)"
                   % (self.policy.cpu_spike_pct,
                      self.policy.cpu_spike_samples, cpu_pct),
            during_test=during, at=_utc_now(),
        ))

    def _verdict_leaks(self) -> None:
        for name, series in sorted(self._series.items()):
            if len(series) < self.policy.min_leak_samples:
                continue
            growth = series[-1][1] - series[0][1]
            slope = _slope_kb_per_min(series)
            if (slope >= self.policy.leak_slope_kb_per_min
                    and growth >= self.policy.leak_min_growth_kb):
                self._emit(Finding(
                    kind="leak", instance=name,
                    detail="RSS grew %d kB over %.0f s (slope %.0f kB/min, "
                           "thresholds %d kB / %.0f kB/min)"
                           % (growth, series[-1][0] - series[0][0], slope,
                              self.policy.leak_min_growth_kb,
                              self.policy.leak_slope_kb_per_min),
                    during_test="", at=_utc_now(),
                ))

    # -- benchmark -------------------------------------------------------

    def summary(self) -> Dict[str, Dict[str, float]]:
        """Per-instance benchmark: samples, max_rss_kb, rss_growth_kb."""
        out: Dict[str, Dict[str, float]] = {}
        for name, series in sorted(self._series.items()):
            out[name] = {
                "samples": float(len(series)),
                "max_rss_kb": float(max(r for _, r in series)),
                "rss_growth_kb": float(series[-1][1] - series[0][1]),
            }
        return out


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
