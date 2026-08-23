"""Validated registry of server and long-lived process specifications.

An ``InstanceSpec`` is a validated description of one server or
long-lived process; a ``Registry`` is the checked catalogue of them.
Validation happens at **registration**, not at start: a bad spec fails
the moment it is declared, with the field and the rule named, instead
of as a dead process twenty seconds into a session.

``kind`` is required; the generic core does not assume a server type.
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


def _instance_identity(spec: "InstanceSpec") -> None:
    _validate_instance_name(spec.name)
    _validate_instance_kind(spec.kind)
    for role, port in dict(spec.ports).items():
        _validate_instance_port(role, port)
    if not isinstance(spec.hosts, Mapping):
        raise SpecError("hosts", spec.hosts, "must map endpoint roles to host names")
    for role, host in spec.hosts.items():
        _validate_instance_host(role, host)
    if spec.name in spec.depends_on:
        raise SpecError("depends_on", spec.name, "an instance cannot depend on itself")


def _validate_instance_name(name: object) -> None:
    if not isinstance(name, str) or not name or not _NAME_RE.match(name):
        raise SpecError("name", name, "must be lowercase [a-z0-9_-], starting alphanumeric")


def _validate_instance_kind(kind: object) -> None:
    if not kind:
        raise SpecError("kind", kind, "is required — the core has no default kind")


def _validate_instance_port(role: str, port: object) -> None:
    if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
        raise SpecError("ports[%s]" % role, port, "must be a TCP port (1-65535)")


def _validate_instance_host(role: object, host: object) -> None:
    if not isinstance(role, str) or not role:
        raise SpecError("hosts role", role, "must be non-empty text")
    if not isinstance(host, str) or not host or "\x00" in host:
        raise SpecError("hosts[%s]" % role, host, "must be non-empty NUL-free text")


def _lane_port_findings(spec: "InstanceSpec", lane: Lane) -> List[str]:
    findings = []
    for role, port in sorted(spec.ports.items()):
        if not lane.owns_port(port):
            findings.append(
                "%s: ports[%s]=%d is outside the lane's range %d-%d"
                % (spec.name, role, port, lane.port_base, lane.port_base + lane.port_span - 1)
            )
    return findings


def _kind_findings(spec: "InstanceSpec") -> List[str]:
    try:
        get_kind(spec.kind)
    except Exception:
        return ["%s: kind %r is not registered" % (spec.name, spec.kind)]
    return []


def _config_findings(spec: "InstanceSpec") -> List[str]:
    if spec.config_template is None or Path(spec.config_template).is_file():
        return []
    return [
        "%s: config_template %s does not exist" % (spec.name, spec.config_template)
    ]


def _readiness_findings(spec: "InstanceSpec") -> List[str]:
    if not spec.readiness:
        return []
    from brixtest.fleet.probes import probe_from_alias

    try:
        probe_from_alias(spec.readiness)
    except Exception:
        return [
            "%s: readiness alias %r does not resolve" % (spec.name, spec.readiness)
        ]
    return []


def _spec_findings(spec: "InstanceSpec", lane: Lane) -> List[str]:
    return [
        *_lane_port_findings(spec, lane),
        *_kind_findings(spec),
        *_config_findings(spec),
        *_readiness_findings(spec),
    ]


def _instance_lifecycle(spec: "InstanceSpec") -> None:
    if spec.readiness_timeout <= 0:
        raise SpecError("readiness_timeout", spec.readiness_timeout, "must be > 0")
    if spec.stop_timeout <= 0:
        raise SpecError("stop_timeout", spec.stop_timeout, "must be > 0")
    if spec.shutdown_signal not in ("TERM", "INT", "QUIT", "KILL", "NONE"):
        raise SpecError("shutdown_signal", spec.shutdown_signal, "must be TERM, INT, QUIT, KILL, or NONE")
    if not isinstance(spec.expected_exit, bool) or not isinstance(spec.background, bool):
        raise SpecError("lifecycle", spec, "expected_exit and background must be boolean")
    if isinstance(spec.log_max_bytes, bool) or not isinstance(spec.log_max_bytes, int) \
            or spec.log_max_bytes < 1:
        raise SpecError("log_max_bytes", spec.log_max_bytes, "must be an integer >= 1")


def _freeze_instance(spec: "InstanceSpec") -> None:
    for field in ("ports", "config_values", "env", "hosts"):
        object.__setattr__(spec, field, _freeze_mapping(getattr(spec, field)))
    for field in ("depends_on", "tags", "shutdown_command"):
        object.__setattr__(spec, field, tuple(getattr(spec, field)))
    if spec.command is not None:
        object.__setattr__(spec, "command", tuple(spec.command))


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
    hosts: Mapping[str, str] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        _instance_identity(self)
        _instance_lifecycle(self)
        _freeze_instance(self)

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
    """Location derived from an instance specification, kind, and lane."""

    name: str
    kind: str
    host: str
    ports: Mapping[str, int]
    workdir: Path
    log_path: Path
    pidfile: Optional[Path]
    hosts: Mapping[str, str] = dataclasses.field(default_factory=dict)

    @property
    def primary_port(self) -> Optional[int]:
        return self.ports.get(PRIMARY)

    def address(self, role: str = PRIMARY) -> Tuple[str, int]:
        try:
            return (self.hosts.get(role, self.host), self.ports[role])
        except KeyError:
            raise SpecError("port role", role, "%r declares no such port" % self.name) from None

    def url(self, scheme: str = "http", *, role: str = PRIMARY, path: str = "/") -> str:
        """The one way to spell a service URL — tests stop assembling
        f-strings out of port constants."""
        host, port = self.address(role)
        if not path.startswith("/"):
            path = "/" + path
        rendered_host = "[%s]" % host if ":" in host and not host.startswith("[") else host
        return "%s://%s:%d%s" % (scheme, rendered_host, port, path)


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
        hosts=dict(spec.hosts),
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
        """Return findings that require the lane or registered kind table.

        The harness can report these as warnings or promote them to errors.
        """
        findings = []
        for spec in self.all_specs():
            findings.extend(_spec_findings(spec, lane))
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
