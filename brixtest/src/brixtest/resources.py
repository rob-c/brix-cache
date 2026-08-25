"""Immutable resource declarations shared by servers, clients, and backends."""

from __future__ import annotations

import dataclasses
import math
import re
from pathlib import Path
from typing import Mapping, Optional, Sequence, Union

from brixtest._resource_validation import (
    argv as _argv,
    command_policy as _command_policy,
    endpoint_contract,
    probe_contract,
    relative as _relative,
)
from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping

_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_PROBE_KINDS = ("tcp", "http", "https", "exec", "log", "none")
_REFERENCE_KINDS = (
    "artifact", "binary", "config", "credential", "mount", "parameter",
    "environment", "identity", "resource", "run", "server", "task", "volume",
    "workspace",
)
_REFERENCE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REFERENCE_ATTRIBUTES = {
    "artifact": ("path", "directory"), "binary": ("path", "directory"),
    "config": ("path",), "credential": ("path", "directory"), "mount": ("path",),
    "parameter": ("value",), "run": ("root",), "workspace": ("path",),
    "server": ("config", "host", "log", "port", "url"),
    "environment": ("context", "name", "namespace"),
    "identity": ("name", "service_account"),
    "resource": ("output",), "task": ("output",),
    "volume": ("claim", "path"),
}
_REFERENCE_KEYS = {
    ("artifact", "path"): "artifact_{name}",
    ("artifact", "directory"): "artifact_{name}_dir",
    ("binary", "path"): "binary_{name}",
    ("binary", "directory"): "binary_{name}_dir",
    ("config", "path"): "config_{name}",
    ("credential", "path"): "credential_{name}",
    ("credential", "directory"): "credential_{name}_dir",
    ("mount", "path"): "mount_{name}",
    ("parameter", "value"): "param_{name}",
    ("environment", "context"): "environment_{name}_context",
    ("environment", "name"): "environment_{name}_name",
    ("environment", "namespace"): "environment_{name}_namespace",
    ("identity", "name"): "identity_{name}_name",
    ("identity", "service_account"): "identity_{name}_service_account",
    ("volume", "claim"): "volume_{name}_claim",
    ("volume", "path"): "volume_{name}_path",
}


def _name(value: object, field: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise SpecError(field, value, "must match [a-z][a-z0-9_-]*")
    return value


def _positive(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value <= 0
    ):
        raise SpecError(field, value, "must be a finite number > 0")
    return float(value)


def _strings(value: Mapping[str, object], field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str)
        and isinstance(item, (str, Reference))
        and "\x00" not in key + str(item)
        for key, item in value.items()
    ):
        raise SpecError(
            field, value,
            "must map NUL-free text names to text values or typed references",
        )
    return freeze_mapping(value)


def _validate_reference_name(kind: str, name: object) -> None:
    if kind in ("config", "mount", "parameter"):
        if not isinstance(name, str):
            raise SpecError("reference.name", name, "must be a runtime placeholder identifier")
        if _REFERENCE_NAME.fullmatch(name) is None:
            raise SpecError("reference.name", name, "must be a runtime placeholder identifier")
        return
    if kind in ("run", "workspace"):
        if name:
            raise SpecError("reference.name", name, "must be empty for run/workspace")
        return
    _name(name, "reference.name")


def _validate_reference_role(kind: str, attribute: str, role: object) -> None:
    if not role:
        if kind in ("resource", "task") and attribute == "output":
            raise SpecError(
                "reference.role", role,
                "must name a task or resource output",
            )
        return
    _name(role, "reference.role")
    valid = kind == "server" and attribute in ("host", "port", "url")
    valid = valid or (kind in ("resource", "task") and attribute == "output")
    if not valid:
        raise SpecError(
            "reference.role", role,
            "is valid for server host/port/url or task/resource output references",
        )


@dataclasses.dataclass(frozen=True)
class Reference:
    """Typed, collection-safe reference to one materialized resource value."""

    kind: str
    name: str = ""
    attribute: str = "path"
    role: str = ""

    def __post_init__(self) -> None:
        if self.kind not in _REFERENCE_KINDS:
            raise SpecError("reference.kind", self.kind, "has an unknown resource kind")
        _validate_reference_name(self.kind, self.name)
        if not isinstance(self.attribute, str):
            raise SpecError("reference.attribute", self.attribute, "must be non-empty text")
        if not self.attribute:
            raise SpecError("reference.attribute", self.attribute, "must be non-empty text")
        allowed = _REFERENCE_ATTRIBUTES[self.kind]
        if self.attribute not in allowed:
            raise SpecError(
                "reference.attribute", self.attribute,
                "known for %s: %s" % (self.kind, ", ".join(allowed)),
            )
        _validate_reference_role(self.kind, self.attribute, self.role)

    @property
    def key(self) -> str:
        """Return the stable runtime value key used by renderers and manifests."""
        fixed = {"run": "run_root", "workspace": "workspace"}.get(self.kind)
        if fixed:
            return fixed
        template = _REFERENCE_KEYS.get((self.kind, self.attribute))
        if template:
            return template.format(name=self.name)
        if self.kind == "server":
            return _server_reference_key(self)
        if self.kind in ("resource", "task") and self.attribute == "output":
            return "%s_%s_%s" % (self.kind, self.name, self.role)
        raise SpecError("reference", self, "cannot be converted to a runtime key")

    def __str__(self) -> str:
        return "{%s}" % self.key


def _server_reference_key(reference: Reference) -> str:
    role = reference.role
    if reference.attribute == "port":
        role = role or "primary"
    if role and reference.attribute in ("host", "port", "url"):
        return "server_%s_%s_%s" % (reference.name, role, reference.attribute)
    return "server_%s_%s" % (reference.name, reference.attribute)


def ref(
    kind: str, name: str = "", *, attribute: str = "path", role: str = "",
) -> Reference:
    """Create a typed runtime reference; convenience factories cover common kinds."""
    return Reference(kind, name, attribute, role)


def artifact_ref(value: object, *, directory: bool = False) -> Reference:
    """Reference a materialized artifact path or its containing directory."""
    return Reference("artifact", getattr(value, "name", value), "directory" if directory else "path")


def binary_ref(value: object, *, directory: bool = False) -> Reference:
    """Reference a captured binary path or its containing directory."""
    return Reference("binary", getattr(value, "name", value), "directory" if directory else "path")


def config_ref(value: object) -> Reference:
    """Reference a config by its confined destination filename."""
    raw = getattr(value, "destination", value)
    name = re.sub(r"[^A-Za-z0-9_]", "_", str(raw)).strip("_")
    return Reference("config", name)


def credential_ref(value: object, *, directory: bool = False) -> Reference:
    """Reference a materialized credential path or its containing directory."""
    return Reference(
        "credential", getattr(value, "name", value),
        "directory" if directory else "path",
    )


def param(name: str) -> Reference:
    """Reference one ``pytest.mark.parametrize`` value from a declaration.

    The value is resolved separately for every collected pytest item, so the
    declaration remains immutable and safe to import in the controller.
    """
    return Reference("parameter", name, "value")


def server_ref(
    value: object, *, attribute: str = "url", role: str = "",
) -> Reference:
    """Reference a server host, URL, port, config, or log without magic text."""
    return Reference("server", getattr(value, "name", value), attribute, role)


def workspace_ref() -> Reference:
    """Reference the confined writable workspace for the current case."""
    return Reference("workspace", attribute="path")


def run_root_ref() -> Reference:
    """Reference the unique provenance root retained for the current case."""
    return Reference("run", attribute="root")


def _command_text(input_value: object, encoding: object) -> None:
    if input_value is not None and not isinstance(input_value, (str, bytes)):
        raise SpecError("command.input", input_value, "must be text, bytes, or None")
    if not isinstance(encoding, str) or not encoding:
        raise SpecError("command.encoding", encoding, "must be non-empty text")


@dataclasses.dataclass(frozen=True)
class Command:
    """Reusable shell-free invocation defaults for a server or client tool."""

    argv: Sequence[object]
    env: Mapping[str, object] = dataclasses.field(default_factory=dict)
    cwd: str = ""
    input: Optional[Union[str, bytes]] = None
    encoding: str = "utf-8"
    timeout: float = 30.0
    expected_exit_codes: Sequence[int] = (0,)
    output_limit: int = 1 << 20
    mode: str = "capture"
    retries: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv", _argv(self.argv, "command.argv"))
        object.__setattr__(self, "env", _strings(self.env, "command.env"))
        object.__setattr__(self, "cwd", _relative(self.cwd, "command.cwd"))
        _command_text(self.input, self.encoding)
        object.__setattr__(self, "timeout", _positive(self.timeout, "command.timeout"))
        exits = tuple(self.expected_exit_codes)
        if not exits or not all(isinstance(value, int) and not isinstance(value, bool) for value in exits):
            raise SpecError("command.expected_exit_codes", exits, "must contain integer statuses")
        object.__setattr__(self, "expected_exit_codes", exits)
        _command_policy(self.output_limit, self.mode, self.retries)


def command(
    *argv: object,
    env: Optional[Mapping[str, object]] = None,
    cwd: str = "",
    input: Optional[Union[str, bytes]] = None,
    encoding: str = "utf-8",
    timeout: float = 30.0,
    expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20,
    mode: str = "capture",
    retries: int = 0,
) -> Command:
    """Declare one reusable shell-free command and its execution policy."""
    selected = tuple(argv[0]) if len(argv) == 1 and isinstance(argv[0], (list, tuple)) else argv
    return Command(
        selected, env={} if env is None else env, cwd=cwd, input=input, encoding=encoding,
        timeout=timeout, expected_exit_codes=expected_exit_codes,
        output_limit=output_limit, mode=mode, retries=retries,
    )


@dataclasses.dataclass(frozen=True)
class Execution(Command):
    """Canonical shell-free execution declaration shared by every resource."""


def execution(
    *argv: object,
    env: Optional[Mapping[str, object]] = None,
    cwd: str = "",
    input: Optional[Union[str, bytes]] = None,
    encoding: str = "utf-8",
    timeout: float = 30.0,
    expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20,
    mode: str = "capture",
    retries: int = 0,
) -> Execution:
    """Canonical alias for a reusable, shell-free execution declaration."""
    selected = tuple(argv[0]) if len(argv) == 1 and isinstance(argv[0], (list, tuple)) else argv
    return Execution(
        selected, env={} if env is None else env, cwd=cwd, input=input,
        encoding=encoding, timeout=timeout,
        expected_exit_codes=expected_exit_codes, output_limit=output_limit,
        mode=mode, retries=retries,
    )


@dataclasses.dataclass(frozen=True)
class Endpoint:
    """Named network interface whose concrete address is assigned by a backend."""

    name: str = "primary"
    protocol: str = "tcp"
    port: Optional[int] = None
    scheme: str = ""
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)
    family: str = "any"
    exposure: str = "case"

    def __post_init__(self) -> None:
        _name(self.name, "endpoint.name")
        metadata = endpoint_contract(
            self.protocol, self.port, self.scheme, self.metadata,
        )
        if self.family not in ("any", "ipv4", "ipv6", "dual"):
            raise SpecError(
                "endpoint.family", self.family, "must be any, ipv4, ipv6, or dual",
            )
        if self.exposure not in ("case", "environment", "host", "external"):
            raise SpecError(
                "endpoint.exposure", self.exposure,
                "must be case, environment, host, or external",
            )
        object.__setattr__(self, "metadata", metadata)


def endpoint(
    name: str = "primary", *, protocol: str = "tcp", port: Optional[int] = None,
    scheme: str = "", metadata: Optional[Mapping[str, object]] = None,
    family: str = "any", exposure: str = "case",
) -> Endpoint:
    """Declare a named backend-assigned TCP or UDP endpoint."""
    return Endpoint(
        name, protocol, port, scheme, {} if metadata is None else metadata,
        family, exposure,
    )


def http_endpoint(
    name: str = "http", *, port: Optional[int] = None, tls: bool = False,
    metadata: Optional[Mapping[str, object]] = None, family: str = "any",
    exposure: str = "case",
) -> Endpoint:
    """Declare an HTTP or HTTPS endpoint with a backend-assigned port."""
    return Endpoint(
        name, "tcp", port, "https" if tls else "http",
        {} if metadata is None else metadata, family, exposure,
    )


@dataclasses.dataclass(frozen=True)
class Probe:
    """Portable startup or liveness probe interpreted by a backend driver."""

    kind: str = "tcp"
    endpoint: str = "primary"
    timeout: float = 10.0
    interval: float = 0.1
    path: str = "/"
    command: Sequence[object] = ()
    statuses: Sequence[int] = (200,)
    pattern: str = ""

    def __post_init__(self) -> None:
        if self.kind not in _PROBE_KINDS:
            _name(self.kind, "probe.kind")
        _name(self.endpoint, "probe.endpoint")
        object.__setattr__(self, "timeout", _positive(self.timeout, "probe.timeout"))
        object.__setattr__(self, "interval", _positive(self.interval, "probe.interval"))
        selected, statuses = probe_contract(
            self.kind, self.path, self.command, self.statuses, self.pattern,
        )
        object.__setattr__(self, "command", selected)
        object.__setattr__(self, "statuses", statuses)


def probe(
    kind: str = "tcp", *, endpoint: str = "primary", timeout: float = 10.0,
    interval: float = 0.1, path: str = "/", command: Sequence[object] = (),
    statuses: Sequence[int] = (200,), pattern: str = "",
) -> Probe:
    """Declare a backend-neutral startup or liveness probe."""
    return Probe(kind, endpoint, timeout, interval, path, command, statuses, pattern)


def http_probe(
    endpoint: str = "http", *, path: str = "/", tls: bool = False,
    statuses: Sequence[int] = (200,), timeout: float = 10.0, interval: float = 0.1,
) -> Probe:
    """Wait for a successful HTTP response on a named endpoint."""
    return Probe("https" if tls else "http", endpoint, timeout, interval, path, (), statuses)


def exec_probe(
    *argv: object, endpoint: str = "primary", timeout: float = 10.0,
    interval: float = 0.1,
) -> Probe:
    """Wait until a rendered shell-free command exits successfully."""
    return Probe("exec", endpoint, timeout, interval, "/", argv)


@dataclasses.dataclass(frozen=True)
class Mount:
    """Place a declared config, artifact, credential, or path into an environment."""

    source: object
    target: str
    read_only: bool = True
    kind: str = "auto"
    propagation: str = "none"

    def __post_init__(self) -> None:
        if self.source is None or isinstance(self.source, bytes):
            raise SpecError("mount.source", self.source, "must identify a resource or path")
        object.__setattr__(self, "target", _relative(self.target, "mount.target", allow_empty=False))
        if not isinstance(self.read_only, bool):
            raise SpecError("mount.read_only", self.read_only, "must be true or false")
        if self.kind not in (
            "auto", "config", "artifact", "credential", "path", "tmp", "volume",
        ):
            raise SpecError("mount.kind", self.kind, "has an unknown resource kind")
        if self.propagation not in ("none", "host-to-container", "bidirectional"):
            raise SpecError(
                "mount.propagation", self.propagation,
                "must be none, host-to-container, or bidirectional",
            )


def mount(
    source: object, target: Union[str, Path], *, read_only: bool = True,
    kind: str = "auto", propagation: str = "none",
) -> Mount:
    """Declare one confined resource mount for a server or client environment."""
    return Mount(source, str(target), read_only, kind, propagation)


@dataclasses.dataclass(frozen=True)
class Lifecycle:
    """Portable process startup and shutdown expectations."""

    background: bool = True
    shutdown_signal: str = "TERM"
    shutdown_command: Sequence[object] = ()
    stop_timeout: float = 8.0
    expected_exit: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.background, bool) or not isinstance(self.expected_exit, bool):
            raise SpecError("lifecycle", self, "boolean fields must be true or false")
        if self.shutdown_signal not in ("TERM", "INT", "QUIT", "KILL", "NONE"):
            raise SpecError("lifecycle.shutdown_signal", self.shutdown_signal, "has an unknown signal")
        object.__setattr__(
            self, "shutdown_command", _argv(self.shutdown_command, "lifecycle.shutdown_command", empty=True)
        )
        object.__setattr__(self, "stop_timeout", _positive(self.stop_timeout, "lifecycle.stop_timeout"))


@dataclasses.dataclass(frozen=True)
class ResourceLimits:
    """Optional CPU, memory, and process ceilings for a placed resource."""

    cpu: Optional[float] = None
    memory_bytes: Optional[int] = None
    pids: Optional[int] = None

    def __post_init__(self) -> None:
        if self.cpu is not None:
            object.__setattr__(self, "cpu", _positive(self.cpu, "resources.cpu"))
        for name in ("memory_bytes", "pids"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 1
            ):
                raise SpecError("resources.%s" % name, value, "must be an integer >= 1 or None")


from brixtest._resource_policies import LogPolicy as LogPolicy  # noqa: E402 - facade cycle
from brixtest._resource_policies import Placement as Placement  # noqa: E402 - facade cycle
