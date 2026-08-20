"""The result data model (feature F21).

One test invocation produces one ``TestRecord`` — the complete,
self-describing account of what ran: outcome per phase, durations,
where its full captured output lives on disk, which servers it
touched (declared static + dynamically requested), which artifacts it
resolved, and its configuration (params, markers).  The record is the
unit the store catalogues (F22) and the portal renders (F23); it is
deliberately flat and JSON-faithful so exporting a run to OpenSearch
is a serialization, not a translation.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Dict, List

__all__ = ["PhaseResult", "TestRecord", "RunInfo", "Sample", "Finding", "OUTCOMES"]

OUTCOMES = ("passed", "failed", "skipped", "error", "xfailed", "xpassed")


@dataclasses.dataclass
class PhaseResult:
    """One pytest phase (setup | call | teardown)."""

    phase: str
    outcome: str            # passed | failed | skipped
    seconds: float
    stdout_chars: int = 0   # sizes here; the bytes live in the output dir
    stderr_chars: int = 0


@dataclasses.dataclass
class TestRecord:
    run_id: str
    nodeid: str
    outcome: str = "error"          # the folded verdict across phases
    started_at: str = ""
    wall_seconds: float = 0.0
    cpu_seconds: float = 0.0        # the test's own CPU: self + reaped children
    rss_delta_kb: int = 0           # test-process RSS delta across the test
    maxrss_kb: int = 0              # test-process high-water RSS at test end
    phases: List[PhaseResult] = dataclasses.field(default_factory=list)
    output_dir: str = ""            # stdout/stderr/log slices, in full
    workspace: str = ""
    servers: List[str] = dataclasses.field(default_factory=list)
    dynamic_servers: List[str] = dataclasses.field(default_factory=list)
    artifacts: List[str] = dataclasses.field(default_factory=list)
    markers: List[str] = dataclasses.field(default_factory=list)
    params: Dict[str, str] = dataclasses.field(default_factory=dict)
    failure: str = ""               # the FULL longrepr, never truncated

    def phase_seconds(self, phase: str) -> float:
        for entry in self.phases:
            if entry.phase == phase:
                return entry.seconds
        return 0.0

    def fold_outcome(self) -> str:
        """pytest's folding rules: setup/teardown failure = error; a
        skip anywhere = skipped unless something failed."""
        by_phase = {p.phase: p.outcome for p in self.phases}
        if by_phase.get("call") == "failed":
            return "failed"
        if "failed" in (by_phase.get("setup"), by_phase.get("teardown")):
            return "error"
        if "skipped" in by_phase.values():
            return "skipped"
        return "passed" if by_phase else "error"

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), indent=2, sort_keys=True)


@dataclasses.dataclass
class RunInfo:
    run_id: str
    started_at: str
    lane_root: str
    port_base: int
    hostname: str
    finished_at: str = ""
    wall_seconds: float = 0.0
    counts: Dict[str, int] = dataclasses.field(default_factory=dict)
    meta: Dict[str, str] = dataclasses.field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), indent=2, sort_keys=True)


@dataclasses.dataclass(frozen=True)
class Sample:
    """One resource observation of one instance (F25)."""

    instance: str
    ts: float               # monotonic-anchored epoch seconds
    pid: int
    rss_kb: int
    cpu_pct: float
    during_test: str


@dataclasses.dataclass(frozen=True)
class Finding:
    """A resource verdict: crash | leak | cpu-spike (F25)."""

    kind: str
    instance: str
    detail: str
    during_test: str
    at: str
