"""The backend contract kit: §8.1's seven methods as obligations.

``check_backend_contract(backend, spec, lane)`` exercises a backend
against one disposable spec and returns violations.  It is deliberately
behavioural, not structural — implementing the ``DeployBackend``
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

    try:
        backend.prepare(lane, None)
        backend.prepare(lane, None)
    except Exception as exc:
        violations.append("1: prepare is not idempotent (%s)" % exc)
    if not lane.log_dir.is_dir() or not lane.instances_dir.is_dir():
        violations.append("1: prepare left no lane skeleton")

    try:
        endpoint = backend.endpoint(spec.name)
        if not lane.contains_path(endpoint.workdir):
            violations.append("2: endpoint workdir %s escapes the lane" % endpoint.workdir)
    except Exception as exc:
        violations.append("2: endpoint() failed for a registered name (%s)" % exc)
        endpoint = None

    try:
        if backend.is_ready(spec):
            violations.append("3: is_ready True before any start")
    except Exception as exc:
        violations.append("3: is_ready raised (%s)" % exc)

    try:
        log_path = backend.logs(spec.name)
        if not lane.contains_path(log_path):
            violations.append("4: log path %s escapes the lane" % log_path)
    except Exception as exc:
        violations.append("4: logs() raised (%s)" % exc)

    try:
        snapshot = backend.process_snapshot()
        dict(snapshot)
    except Exception as exc:
        violations.append("5: process_snapshot raised (%s)" % exc)

    try:
        backend.stop(spec.name)
    except Exception as exc:
        violations.append("6: stop on a never-started instance raised (%s)" % exc)

    if start_stop:
        try:
            backend.start(spec)
            if not backend.is_ready(spec):
                violations.append("7: is_ready False right after a successful start")
            backend.stop(spec.name)
            port = spec.primary_port
            if port is not None and tcp_answering(spec.host, port):
                violations.append("7: port %d still answers after stop" % port)
        except Exception as exc:
            violations.append("7: start/stop cycle failed (%s)" % exc)

    return violations
