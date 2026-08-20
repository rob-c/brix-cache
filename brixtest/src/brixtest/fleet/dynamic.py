"""Dynamic per-test servers (feature F24).

A test that needs a server with *its own* config no longer builds one
by hand: it asks the fleet — ``fleet.request_server(kind="nginx",
config_template=..., config_values=...)`` — and gets back a
``ServerEndpoint`` on a freshly allocated port.  The framework does
the launching, the readiness proof, the watching (the resource watch
samples dynamic pids exactly like static ones), and the teardown.

Design boundaries, deliberately:

* The dynamic fleet owns a **separate, never-frozen** ``Registry`` and
  its own ``LocalBackend`` over the same lane.  The session registry
  stays frozen and the launcher's frozen-registry invariant stays
  intact; the two catalogues never mix.
* Ports come from a **dedicated block** at the top of the lane —
  ``[port_base + offset, port_base + span)`` — so a dynamic server can
  never collide with a declared static port.  Allocation skips ports
  something is already listening on; exhaustion is a typed error, not
  a bind failure.
* Names are generated (``dyn-<test-stem>-<n>``), counter-unique, and
  **never reused** within a session — the same rule workspaces follow —
  so a log line or a sample row always names one launch, ever.
* Test-scoped release is a quiescence *proof*: after stopping, the
  released ports must be silent, and a survivor is named with its pid.
"""

from __future__ import annotations

import re
import socket
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from brixtest.config.lanes import Lane
from brixtest.errors import PortExhaustedError, QuiescenceError, SpecError, StartError
from brixtest.deploy.local import LocalBackend
from brixtest.events import emit
from brixtest.fleet.registry import InstanceSpec, Registry, ServerEndpoint
from brixtest.util.net import listening_ports, pids_on_port

__all__ = ["DynamicFleet", "DEFAULT_DYNAMIC_OFFSET"]

DEFAULT_DYNAMIC_OFFSET = 700
_SCOPES = ("test", "session")
_STEM_RE = re.compile(r"[^a-z0-9_-]+")
_START_ATTEMPTS = 3


def _bindable(port: int, host: str = "127.0.0.1") -> bool:
    """Can we bind this port right now — the allocator's ground truth.
    A LISTEN scan misses outbound sockets whose *source* port landed in
    the lane (lane ranges sit inside the host's ephemeral range, and
    nothing reserves them); attempting the bind sees every conflicting
    socket state exactly as the launched server will, with the same
    SO_REUSEADDR semantics (pure TIME_WAIT passes, live sockets fail)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _stem(nodeid: str) -> str:
    """`tests/test_tpc.py::test_pull[gsi]` → `test_pull-gsi`, spec-legal."""
    tail = nodeid.rsplit("::", 1)[-1] if nodeid else "session"
    cleaned = _STEM_RE.sub("-", tail.lower()).strip("-") or "test"
    return cleaned[:24]


class DynamicFleet:
    def __init__(
        self,
        lane: Lane,
        *,
        port_offset: int = DEFAULT_DYNAMIC_OFFSET,
        extra_values: Optional[Mapping[str, object]] = None,
        strict_templates: bool = False,
    ) -> None:
        if not (0 < port_offset < lane.port_span):
            raise SpecError(
                "port_offset", port_offset,
                "must fall inside the lane's span (1-%d)" % (lane.port_span - 1),
            )
        self.lane = lane
        self.block_start = lane.port_base + port_offset
        self.block_end = lane.port_base + lane.port_span  # exclusive
        self.registry = Registry()          # never frozen, by design
        self.backend = LocalBackend(
            self.registry, lane,
            extra_values=extra_values, strict_templates=strict_templates,
        )
        self._cursor = self.block_start
        self._allocated: Dict[int, str] = {}        # port → instance name
        self._live: Dict[str, str] = {}             # name → scope
        self._current_test = ""
        self._counter = 0

    # -- addressing ------------------------------------------------------

    def note_test(self, nodeid: str) -> None:
        self._current_test = nodeid

    def names(self, scope: Optional[str] = None) -> List[str]:
        return sorted(
            name for name, s in self._live.items()
            if scope is None or s == scope
        )

    def endpoint(self, name: str) -> ServerEndpoint:
        return self.registry.endpoint_for(name, self.lane)

    def process_pids(self) -> Dict[str, int]:
        """Live dynamic pids, for the resource watch's provider."""
        procs = self.backend.process_pids()
        return {name: pid for name, pid in procs.items() if name in self._live}

    # -- ports -----------------------------------------------------------

    def _next_port(self) -> int:
        busy = listening_ports(range(self.block_start, self.block_end))
        span = self.block_end - self.block_start
        for _ in range(span):
            candidate = self._cursor
            self._cursor += 1
            if self._cursor >= self.block_end:
                self._cursor = self.block_start
            if candidate in self._allocated or candidate in busy:
                continue
            if not _bindable(candidate):
                continue    # held by a non-LISTEN socket the scan can't see
            return candidate
        raise PortExhaustedError(
            self.block_start, self.block_end - 1, len(self._allocated)
        )

    # -- request / release -----------------------------------------------

    def request(
        self,
        kind: str,
        *,
        config_template: Optional[str] = None,
        config_values: Optional[Mapping[str, object]] = None,
        command: Optional[Sequence[str]] = None,
        env: Optional[Mapping[str, str]] = None,
        readiness: str = "",
        readiness_timeout: float = 10.0,
        port_roles: Sequence[str] = ("primary",),
        scope: str = "test",
    ) -> ServerEndpoint:
        if scope not in _SCOPES:
            raise SpecError("scope", scope, "must be one of %s" % (_SCOPES,))
        last_error: Optional[StartError] = None
        for _ in range(_START_ATTEMPTS):
            self._counter += 1
            name = "dyn-%s-%d" % (_stem(self._current_test), self._counter)
            ports = {role: self._next_port() for role in port_roles}
            spec = InstanceSpec(
                name=name,
                kind=kind,
                ports=ports,
                config_template=config_template,
                config_values=config_values or {},
                command=command,
                env=env or {},
                readiness=readiness,
                readiness_timeout=readiness_timeout,
            )
            self.registry.register(spec)
            for port in ports.values():
                self._allocated[port] = name
            try:
                endpoint = self.backend.start(spec)
            except StartError as exc:
                self._forget(name)      # failed launch releases its ports
                stolen = [p for p in ports.values() if not _bindable(p)]
                if not stolen:
                    raise               # the command failed; the port is fine
                # an outbound socket landed on our port between allocation
                # and the child's bind — provably not the command's fault:
                # renumber and relaunch (names are never reused, so the
                # failed launch keeps its own identity in logs and events)
                emit("dynamic.port_stolen", name=name, ports=stolen)
                last_error = exc
                continue
            except Exception:
                self._forget(name)
                raise
            self._live[name] = scope
            return endpoint
        raise last_error

    def _forget(self, name: str) -> None:
        self._live.pop(name, None)
        for port in [p for p, holder in self._allocated.items() if holder == name]:
            del self._allocated[port]

    def _release(self, names: Sequence[str]) -> None:
        released_ports: List[Tuple[str, int]] = []
        for name in names:
            spec = self.registry.get_spec(name)
            released_ports.extend((name, port) for port in spec.ports.values())
            self.backend.stop(name)
            self._forget(name)
        survivors = [
            (name, port, min(pids_on_port(port) or {0}))
            for name, port in released_ports
            if listening_ports([port])
        ]
        if survivors:
            raise QuiescenceError(survivors)

    def release_test_scope(self) -> None:
        self._release(self.names("test"))

    def release_all(self) -> None:
        self._release(self.names())
