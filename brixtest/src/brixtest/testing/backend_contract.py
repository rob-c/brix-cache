"""Behavioral conformance checks for deployment backends.

``check_backend_contract(backend, spec, lane)`` exercises a backend
against one disposable spec and returns violations. Implementing the ``DeployBackend``
protocol's signatures is necessary but proves nothing about semantics.

Obligations checked:

1. ``prepare`` is callable twice (idempotent) and leaves the lane's
   directory skeleton in place;
2. ``endpoint`` answers for a registered name whether or not the
   instance runs, and its workdir is inside the lane;
3. ``is_ready`` on a never-started instance is False, and never raises;
4. ``logs`` returns a lane-contained path;
5. ``process_snapshot`` returns a mapping and never raises;
6. ``stop`` on a never-started instance is a harmless no-op;
7. after ``start`` (only when the caller opts in with a startable
   spec), ``is_ready`` flips True and ``stop`` silences the port.
"""

from __future__ import annotations

from typing import List

from brixtest.config.lanes import Lane
from brixtest.fleet.registry import InstanceSpec
from brixtest.util.net import tcp_answering

__all__ = ["check_backend_contract"]


def _obligation(violations, number, action) -> object:
    try:
        return action()
    except Exception as exc:
        violations.append("%d: %s" % (number, exc))
        return None


def _prepare(backend, lane: Lane, violations: List[str]) -> None:
    def action():
        backend.prepare(lane, None)
        backend.prepare(lane, None)
    _obligation(violations, 1, action)
    if not lane.log_dir.is_dir() or not lane.instances_dir.is_dir():
        violations.append("1: prepare left no lane skeleton")


def _endpoint(backend, spec: InstanceSpec, lane: Lane, violations: List[str]):
    endpoint = _obligation(
        violations, 2,
        lambda: backend.endpoint(spec.name),
    )
    if endpoint is not None and not lane.contains_path(endpoint.workdir):
        violations.append("2: endpoint workdir %s escapes the lane" % endpoint.workdir)
    return endpoint


def _passive_obligations(backend, spec: InstanceSpec, lane: Lane, violations: List[str]) -> None:
    ready = _obligation(violations, 3, lambda: backend.is_ready(spec))
    if ready:
        violations.append("3: is_ready True before any start")
    log_path = _obligation(violations, 4, lambda: backend.logs(spec.name))
    if log_path is not None and not lane.contains_path(log_path):
        violations.append("4: log path %s escapes the lane" % log_path)
    snapshot = _obligation(violations, 5, backend.process_snapshot)
    if snapshot is not None:
        _obligation(violations, 5, lambda: dict(snapshot))
    _obligation(violations, 6, lambda: backend.stop(spec.name))


def _start_stop(backend, spec: InstanceSpec, violations: List[str]) -> None:
    try:
        backend.start(spec)
        if not backend.is_ready(spec):
            violations.append("7: is_ready False right after a successful start")
        backend.stop(spec.name)
        if spec.primary_port is not None and tcp_answering(spec.host, spec.primary_port):
            violations.append("7: port %d still answers after stop" % spec.primary_port)
    except Exception as exc:
        violations.append("7: start/stop cycle failed (%s)" % exc)


def check_backend_contract(
    backend,
    spec: InstanceSpec,
    lane: Lane,
    *,
    start_stop: bool = False,
) -> List[str]:
    """Returns violation strings; empty list = pass.  ``start_stop=True``
    additionally runs obligation 7, which really spawns the instance —
    only pass a spec whose command is safe and fast."""
    violations: List[str] = []

    _prepare(backend, lane, violations)
    _endpoint(backend, spec, lane, violations)
    _passive_obligations(backend, spec, lane, violations)
    if start_stop:
        _start_stop(backend, spec, violations)

    return violations
