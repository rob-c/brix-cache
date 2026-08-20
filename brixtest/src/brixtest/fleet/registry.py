"""The instance registry (feature F1).

An ``InstanceSpec`` is a validated description of one server or
long-lived process; a ``Registry`` is the checked catalogue of them.
Validation happens at **registration**, not at start: a bad spec fails
the moment it is declared, with the field and the rule named, instead
of as a dead process twenty seconds into a session.

``kind`` is required.  The grown catalogue defaulted it to ``nginx``
because 109 of its 126 entries were nginx; a generic core has no
business having a favourite server.
"""

from __future__ import annotations

import dataclasses
import re
import threading
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from brixtest.config.lanes import Lane
from brixtest.errors import RegistrationError, SpecError
from brixtest.fleet.kinds import get_kind
from brixtest.util.immutable import freeze_mapping

__all__ = ["InstanceSpec", "Registry", "ServerEndpoint", "endpoint_for"]

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]*$")
PRIMARY = "primary"


def _freeze_mapping(value: Optional[Mapping]) -> Mapping:
    return freeze_mapping(value or {})


@dataclasses.dataclass(frozen=True)
class InstanceSpec:
    """One declared instance.  Frozen; construct a new one to vary a field."""

    name: str
    kind: str
    ports: Mapping[str, int] = dataclasses.field(default_factory=dict)
    config_template: Optional[str] = None
    config_values: Mapping[str, object] = dataclasses.field(default_factory=dict)
    command: Optional[Sequence[str]] = None
    env: Mapping[str, str] = dataclasses.field(default_factory=dict)
    depends_on: Tuple[str, ...] = ()
    readiness: str = ""             # "": use the kind's default_probe
    readiness_timeout: float = 10.0
    probe: Optional[object] = None
    critical: bool = False
    tags: Tuple[str, ...] = ()
    stop_timeout: float = 8.0
    workdir: Optional[str] = None   # subdir under the lane's instances dir
    host: str = "127.0.0.1"
    shutdown_signal: str = "TERM"
    shutdown_command: Sequence[str] = ()
    expected_exit: bool = False
    background: bool = True
    log_max_bytes: int = 64 << 20

    def __post_init__(self) -> None:
        if not self.name or not _NAME_RE.match(self.name):
            raise SpecError(
                "name", self.name,
                "must be lowercase [a-z0-9_-], starting alphanumeric",
            )
        if not self.kind:
            raise SpecError("kind", self.kind, "is required — the core has no default kind")
        for role, port in dict(self.ports).items():
            if not isinstance(port, int) or not (0 < port < 65536):
                raise SpecError("ports[%s]" % role, port, "must be a TCP port (1-65535)")
        if self.name in self.depends_on:
            raise SpecError("depends_on", self.name, "an instance cannot depend on itself")
        if self.readiness_timeout <= 0:
            raise SpecError("readiness_timeout", self.readiness_timeout, "must be > 0")
        if self.stop_timeout <= 0:
            raise SpecError("stop_timeout", self.stop_timeout, "must be > 0")
        if self.shutdown_signal not in ("TERM", "INT", "QUIT", "KILL", "NONE"):
            raise SpecError(
                "shutdown_signal", self.shutdown_signal,
                "must be TERM, INT, QUIT, KILL, or NONE",
            )
        if not isinstance(self.expected_exit, bool) or not isinstance(self.background, bool):
            raise SpecError("lifecycle", self, "expected_exit and background must be boolean")
        if (
            isinstance(self.log_max_bytes, bool)
            or not isinstance(self.log_max_bytes, int)
            or self.log_max_bytes < 1
        ):
            raise SpecError("log_max_bytes", self.log_max_bytes, "must be an integer >= 1")
        # normalise the mutable-ish fields so hashing and equality behave
        object.__setattr__(self, "ports", _freeze_mapping(self.ports))
        object.__setattr__(self, "config_values", _freeze_mapping(self.config_values))
        object.__setattr__(self, "env", _freeze_mapping(self.env))
        object.__setattr__(self, "depends_on", tuple(self.depends_on))
        object.__setattr__(self, "tags", tuple(self.tags))
        if self.command is not None:
            object.__setattr__(self, "command", tuple(self.command))
        object.__setattr__(self, "shutdown_command", tuple(self.shutdown_command))

    @property
    def primary_port(self) -> Optional[int]:
        return self.ports.get(PRIMARY)

    def replace(self, **changes: object) -> "InstanceSpec":
        return dataclasses.replace(self, **changes)

    def to_dict(self) -> Dict[str, object]:
        """A JSON-safe mapping that round-trips through ``from_dict``."""
        out = dataclasses.asdict(self)
        out["ports"] = dict(self.ports)
        out["config_values"] = dict(self.config_values)
        out["env"] = dict(self.env)
        out["depends_on"] = list(self.depends_on)
        out["tags"] = list(self.tags)
        out["command"] = list(self.command) if self.command is not None else None
        out["shutdown_command"] = list(self.shutdown_command)
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "InstanceSpec":
        """The inverse of ``to_dict`` — same validation as the constructor,
        with unknown keys named instead of a bare TypeError."""
        known = {field.name for field in dataclasses.fields(cls)}
        unknown = sorted(set(data) - known)
        if unknown:
            raise SpecError(
                "spec dict", ", ".join(unknown),
                "unknown field(s) — known: %s" % ", ".join(sorted(known)),
            )
        return cls(**dict(data))


@dataclasses.dataclass(frozen=True)
class ServerEndpoint:
    """Where a (possibly running) instance lives — spec × kind × lane."""

    name: str
    kind: str
    host: str
    ports: Mapping[str, int]
    workdir: Path
    log_path: Path
    pidfile: Optional[Path]

    @property
    def primary_port(self) -> Optional[int]:
        return self.ports.get(PRIMARY)

    def address(self, role: str = PRIMARY) -> Tuple[str, int]:
        try:
            return (self.host, self.ports[role])
        except KeyError:
            raise SpecError("port role", role, "%r declares no such port" % self.name) from None

    def url(self, scheme: str = "http", *, role: str = PRIMARY, path: str = "/") -> str:
        """The one way to spell a service URL — tests stop assembling
        f-strings out of port constants."""
        host, port = self.address(role)
        if not path.startswith("/"):
            path = "/" + path
        return "%s://%s:%d%s" % (scheme, host, port, path)


def endpoint_for(spec: InstanceSpec, lane: Lane) -> ServerEndpoint:
    profile = get_kind(spec.kind)
    workdir = lane.instances_dir / (spec.workdir or spec.name)
    pidfile = workdir / profile.pidfile if profile.pidfile else None
    return ServerEndpoint(
        name=spec.name,
        kind=spec.kind,
        host=spec.host,
        ports=dict(spec.ports),
        workdir=workdir,
        log_path=lane.log_dir / ("%s.log" % spec.name),
        pidfile=pidfile,
    )


class Registry:
    """The checked catalogue.  ``freeze()`` after declaration; the launcher
    and gate both refuse an unfrozen registry so late registrations cannot
    silently miss the session's fleet plan."""

    def __init__(self) -> None:
        self._specs: Dict[str, InstanceSpec] = {}
        self._frozen = False
        self._lock = threading.Lock()

    def register(self, spec: InstanceSpec) -> InstanceSpec:
        with self._lock:
            if self._frozen:
                raise RegistrationError(spec.name, "<frozen registry>", "registry")
            existing = self._specs.get(spec.name)
            if existing is not None:
                raise RegistrationError(spec.name, existing.name, "instance")
            self._specs[spec.name] = spec
        return spec

    def freeze(self) -> None:
        with self._lock:
            # dependency edges must resolve inside the catalogue
            for spec in self._specs.values():
                for dep in spec.depends_on:
                    if dep not in self._specs:
                        raise SpecError(
                            "depends_on", dep,
                            "%r depends on an instance that is not registered" % spec.name,
                        )
            self._frozen = True

    @property
    def frozen(self) -> bool:
        return self._frozen

    def get_spec(self, name: str) -> InstanceSpec:
        try:
            return self._specs[name]
        except KeyError:
            raise SpecError(
                "instance name", name,
                "not registered — known: %s" % ", ".join(sorted(self._specs)),
            ) from None

    def all_specs(self) -> List[InstanceSpec]:
        return [self._specs[name] for name in sorted(self._specs)]

    def __contains__(self, name: str) -> bool:
        return name in self._specs

    def __len__(self) -> int:
        return len(self._specs)

    def endpoint_for(self, name: str, lane: Lane) -> ServerEndpoint:
        return endpoint_for(self.get_spec(name), lane)

    def declared_ports(self) -> Dict[int, str]:
        """port → instance name, across every spec and role."""
        out: Dict[int, str] = {}
        for spec in self.all_specs():
            for port in spec.ports.values():
                out.setdefault(port, spec.name)
        return out

    def validate(self, lane: Lane) -> List[str]:
        """Warn-only strict validation (F1): findings a spec constructor
        cannot see because they need the lane or the kind table.  Ships
        as warnings; the harness's ``spec_validation="refuse"`` promotes
        them to a hard error once a catalogue has proven warn-clean."""
        from brixtest.fleet.probes import probe_from_alias  # cycle-free at call time
        findings: List[str] = []
        for spec in self.all_specs():
            for role, port in sorted(spec.ports.items()):
                if not lane.owns_port(port):
                    findings.append(
                        "%s: ports[%s]=%d is outside the lane's range %d-%d"
                        % (spec.name, role, port, lane.port_base,
                           lane.port_base + lane.port_span - 1)
                    )
            try:
                get_kind(spec.kind)
            except Exception:
                findings.append(
                    "%s: kind %r is not registered" % (spec.name, spec.kind)
                )
            if spec.config_template is not None and not Path(spec.config_template).is_file():
                findings.append(
                    "%s: config_template %s does not exist"
                    % (spec.name, spec.config_template)
                )
            if spec.readiness:
                try:
                    probe_from_alias(spec.readiness)
                except Exception:
                    findings.append(
                        "%s: readiness alias %r does not resolve"
                        % (spec.name, spec.readiness)
                    )
        for port, first, second in self.port_conflicts():
            findings.append(
                "port %d is claimed by both %r and %r" % (port, first, second)
            )
        return findings

    def port_conflicts(self) -> List[Tuple[int, str, str]]:
        """(port, first holder, second holder) for every double-claimed port."""
        seen: Dict[int, str] = {}
        conflicts: List[Tuple[int, str, str]] = []
        for spec in self.all_specs():
            for port in spec.ports.values():
                if port in seen and seen[port] != spec.name:
                    conflicts.append((port, seen[port], spec.name))
                else:
                    seen[port] = spec.name
        return conflicts
