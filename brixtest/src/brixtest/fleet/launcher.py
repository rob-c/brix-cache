"""The start/stop engine (feature F3).

``FleetPlan`` levels the registry's dependency graph; the launcher
starts each level in parallel (bounded pool, default
``min(16, 2 × cpu)`` workers — the grown suite's measured sweet spot)
and proves readiness per instance before the next level begins.

Start is **idempotent**: an instance already answering is reported
``already-running`` and left alone.  A failed *critical* instance
aborts the remaining levels (their specs are reported ``skipped``);
a failed non-critical one is recorded and the level continues.

Stop is a **proof**, not a hope: after every stop completes, one
listener sweep over the declared ports must come back empty, or
``QuiescenceError`` names each survivor as (instance, port, pid).
"""

from __future__ import annotations

import dataclasses
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Sequence, Set, Tuple

from brixtest.config.lanes import Lane
from brixtest.errors import BrixTestError, QuiescenceError, SpecError
from brixtest.events import emit
from brixtest.fleet.registry import InstanceSpec, Registry
from brixtest.util.net import port_holders

__all__ = ["FleetPlan", "SpecOutcome", "StartReport", "FleetLauncher", "default_workers"]


def default_workers() -> int:
    return min(16, 2 * (os.cpu_count() or 1))


@dataclasses.dataclass(frozen=True)
class FleetPlan:
    """Specs arranged into dependency levels; level N starts only after
    every instance in levels < N proved ready."""

    levels: Tuple[Tuple[InstanceSpec, ...], ...]

    @staticmethod
    def build(specs: Sequence[InstanceSpec]) -> "FleetPlan":
        by_name = {spec.name: spec for spec in specs}
        placed: Set[str] = set()
        levels: List[Tuple[InstanceSpec, ...]] = []
        remaining = dict(by_name)
        while remaining:
            level = tuple(
                spec for spec in remaining.values()
                # deps outside the selection are assumed already satisfied
                if all(dep in placed or dep not in by_name for dep in spec.depends_on)
            )
            if not level:
                cycle = ", ".join(sorted(remaining))
                raise SpecError("depends_on", cycle, "dependency cycle — no startable order")
            for spec in level:
                placed.add(spec.name)
                del remaining[spec.name]
            levels.append(tuple(sorted(level, key=lambda s: s.name)))
        return FleetPlan(tuple(levels))

    def flat(self) -> Tuple[InstanceSpec, ...]:
        return tuple(spec for level in self.levels for spec in level)

    def describe(self) -> str:
        lines = []
        for depth, level in enumerate(self.levels):
            lines.append("level %d: %s" % (depth, ", ".join(s.name for s in level)))
        return "\n".join(lines)


@dataclasses.dataclass(frozen=True)
class SpecOutcome:
    name: str
    status: str          # started | already-running | failed | skipped
    elapsed: float = 0.0
    error: str = ""


@dataclasses.dataclass(frozen=True)
class StartReport:
    outcomes: Tuple[SpecOutcome, ...]

    @property
    def ok(self) -> bool:
        return all(o.status in ("started", "already-running") for o in self.outcomes)

    def by_status(self, status: str) -> Tuple[SpecOutcome, ...]:
        return tuple(o for o in self.outcomes if o.status == status)

    def summary(self) -> str:
        counts: Dict[str, int] = {}
        for outcome in self.outcomes:
            counts[outcome.status] = counts.get(outcome.status, 0) + 1
        parts = ["%d %s" % (counts[k], k) for k in sorted(counts)]
        return ", ".join(parts) if parts else "nothing to do"


class FleetLauncher:
    """Orchestrates one backend against one registry inside one lane."""

    def __init__(
        self,
        registry: Registry,
        backend,  # deploy.DeployBackend
        lane: Lane,
        *,
        workers: Optional[int] = None,
    ) -> None:
        if not registry.frozen:
            raise SpecError(
                "registry", "<unfrozen>",
                "freeze() the registry before launching — late registrations "
                "would silently miss the fleet plan",
            )
        self.registry = registry
        self.backend = backend
        self.lane = lane
        self.workers = workers or default_workers()

    # -- start -----------------------------------------------------------

    def _start_one(self, spec: InstanceSpec) -> SpecOutcome:
        started = time.monotonic()
        try:
            if self.backend.is_ready(spec):
                emit("instance.already_running", spec=spec.name)
                return SpecOutcome(spec.name, "already-running")
            self.backend.start(spec)
            elapsed = time.monotonic() - started
            emit("instance.started", spec=spec.name, elapsed=round(elapsed, 3))
            return SpecOutcome(spec.name, "started", elapsed)
        except BrixTestError as exc:
            elapsed = time.monotonic() - started
            emit("instance.failed", spec=spec.name, error=type(exc).__name__)
            return SpecOutcome(spec.name, "failed", elapsed, str(exc))

    def start_registered(self, specs: Optional[Sequence[str]] = None) -> StartReport:
        """Start the named specs (default: every registered one), levelled."""
        if specs is None:
            selection = self.registry.all_specs()
        else:
            selection = [self.registry.get_spec(name) for name in specs]
        plan = FleetPlan.build(selection)
        emit("fleet.start.begin", count=len(selection), levels=len(plan.levels))
        outcomes: List[SpecOutcome] = []
        abort = False
        for level in plan.levels:
            if abort:
                outcomes.extend(
                    SpecOutcome(spec.name, "skipped", error="critical instance failed earlier")
                    for spec in level
                )
                continue
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                level_outcomes = list(pool.map(self._start_one, level))
            outcomes.extend(level_outcomes)
            if any(
                o.status == "failed" and self.registry.get_spec(o.name).critical
                for o in level_outcomes
            ):
                abort = True
        report = StartReport(tuple(outcomes))
        emit("fleet.start.done", summary=report.summary())
        return report

    # -- stop ------------------------------------------------------------

    def stop(self, specs: Optional[Sequence[str]] = None) -> None:
        """Stop the named specs (default: all), then prove quiescence."""
        if specs is None:
            selection = self.registry.all_specs()
        else:
            selection = [self.registry.get_spec(name) for name in specs]
        # reverse dependency order: dependents down before their deps
        plan = FleetPlan.build(selection)
        for level in reversed(plan.levels):
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                list(pool.map(lambda spec: self.backend.stop(spec.name), level))
        self._prove_quiescence(selection)
        emit("fleet.stop.done", count=len(selection))

    def _prove_quiescence(self, selection: Sequence[InstanceSpec]) -> None:
        """One sweep: every declared port of every stopped spec is silent."""
        port_owner: Dict[int, str] = {}
        for spec in selection:
            for port in spec.ports.values():
                port_owner[port] = spec.name
        if not port_owner:
            return
        survivors: List[Tuple[str, int, int]] = []
        for port, pids in port_holders(port_owner).items():
            for pid in sorted(pids) or [-1]:
                survivors.append((port_owner[port], port, pid))
        if survivors:
            emit("fleet.stop.survivors", count=len(survivors))
            raise QuiescenceError(survivors)
