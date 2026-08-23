"""Protocol separating fleet declarations from deployment backends.

``DeployBackend`` is the boundary between *what the fleet is* (specs,
kinds, probes — the fleet layer) and *where it runs*.  ``LocalBackend``
supports unprivileged processes on the local host.

Backend rules:

1. nothing above the backend touches processes, sockets, or ``/proc``;
2. backends never interpret spec semantics — kinds do;
3. every backend method is lane-scoped;
4. readiness is probed through the fleet layer's probes, not invented
   per backend;
5. stop must be provable (the launcher's quiescence sweep);
6. logs are files with paths, wherever the instance runs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Optional, Protocol, runtime_checkable

from brixtest.config.lanes import Lane
from brixtest.fleet.prep import ArtifactSet
from brixtest.fleet.registry import InstanceSpec, ServerEndpoint

__all__ = ["DeployBackend"]


@runtime_checkable
class DeployBackend(Protocol):
    """Operations required from each deployment backend."""

    def prepare(self, lane: Lane, artifacts: Optional[ArtifactSet]) -> None:
        """Make the lane's directory skeleton and adopt the artifact tree."""
        ...

    def start(self, spec: InstanceSpec) -> ServerEndpoint:
        """Spawn one instance and prove it ready; raise StartError or
        ReadinessTimeout otherwise.  Idempotence lives in the launcher."""
        ...

    def stop(self, name: str) -> None:
        """Stop one instance per its kind's stop strategy.  Best-effort;
        the launcher's quiescence sweep is the proof."""
        ...

    def endpoint(self, name: str) -> ServerEndpoint:
        """Where the named instance lives (running or not)."""
        ...

    def is_ready(self, spec: InstanceSpec) -> bool:
        """Non-blocking: does the instance answer right now?"""
        ...

    def logs(self, name: str) -> Path:
        """Path to the instance's log file."""
        ...

    def process_snapshot(self) -> Mapping[int, object]:
        """Declared port → observed holder pids, one sweep."""
        ...
