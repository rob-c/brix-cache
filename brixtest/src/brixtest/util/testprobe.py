"""Capture per-test CPU time, RSS change, and peak RSS."""

from __future__ import annotations

import contextlib
import resource
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__all__ = ["PROBE_KEYS", "TestResourceProbe", "read_probe_properties"]

PROBE_KEYS = ("brixtest_cpu_s", "brixtest_rss_delta_kb", "brixtest_maxrss_kb")


def _cpu_seconds() -> float:
    own = resource.getrusage(resource.RUSAGE_SELF)
    kids = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + kids.ru_utime + kids.ru_stime


def _vmrss_kb() -> int:
    try:
        text = Path("/proc/self/status").read_text()
    except OSError:
        return 0
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


class TestResourceProbe:
    """``begin()`` at test setup, ``end()`` after teardown; one test at
    a time per process, which is exactly how pytest runs them."""

    def __init__(self) -> None:
        self._cpu0: Optional[float] = None
        self._rss0 = 0

    def begin(self) -> None:
        self._cpu0 = _cpu_seconds()
        self._rss0 = _vmrss_kb()

    def end(self) -> List[Tuple[str, float]]:
        """The user_properties pairs for this test, or [] when begin()
        never ran (a crashed setup phase, an unprobed process)."""
        if self._cpu0 is None:
            return []
        cpu = max(0.0, _cpu_seconds() - self._cpu0)
        rss_delta = _vmrss_kb() - self._rss0
        maxrss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # kB on Linux
        self._cpu0 = None
        return [
            ("brixtest_cpu_s", round(cpu, 4)),
            ("brixtest_rss_delta_kb", float(rss_delta)),
            ("brixtest_maxrss_kb", float(maxrss_kb)),
        ]


def read_probe_properties(user_properties) -> Dict[str, float]:
    """The controller-side inverse: this probe's keys picked out of a
    report's ``user_properties`` (tuples serially, lists over xdist)."""
    out: Dict[str, float] = {}
    for pair in user_properties or ():
        try:
            key, value = pair[0], pair[1]
        except (TypeError, IndexError, KeyError):
            continue
        if key in PROBE_KEYS:
            with contextlib.suppress(TypeError, ValueError):
                out[key] = float(value)
    return out
