"""Composable declarations shared by servers, clients, tools, and backends.

The objects in this module describe intent only.  They are immutable, safe to
inspect during pytest collection, and deliberately contain no runtime handles.
Backends translate them into processes, containers, pods, and evidence records.
"""

from __future__ import annotations

import dataclasses
import math
import re
from pathlib import Path, PurePosixPath
from typing import Mapping, Optional, Sequence, Union

from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping

_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_PROTOCOLS = ("tcp", "udp")
_PROBE_KINDS = ("tcp", "http", "https", "exec", "log", "none")
_COMMAND_MODES = ("capture", "stream", "pty")
_REFERENCE_KINDS = (
    "artifact", "binary", "config", "credential", "mount", "parameter",
    "run", "server", "workspace",
)
_REFERENCE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


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


def _argv(value: Sequence[object], field: str, *, empty: bool = False) -> tuple[object, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError(field, value, "must be an argv sequence, not shell text")
    result = tuple(value)
    if not empty and not result:
        raise SpecError(field, value, "must contain at least one argv item")
    for part in result:
        if isinstance(part, bytes) or not str(part) or "\x00" in str(part):
            raise SpecError(field, value, "argv entries must be non-empty and NUL-free")
    return result


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


def _relative(value: str, field: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise SpecError(field, value, "must be NUL-free text")
    if not value and allow_empty:
        return value
    path = PurePosixPath(value)
    if path.is_absolute() or value in ("", ".") or ".." in path.parts:
        raise SpecError(field, value, "must be a confined relative path")
    return value


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
        if self.kind in ("config", "mount", "parameter"):
            if not isinstance(self.name, str) or _REFERENCE_NAME.fullmatch(self.name) is None:
                raise SpecError(
                    "reference.name", self.name,
                    "must be a runtime placeholder identifier",
                )
        elif self.kind not in ("run", "workspace"):
            _name(self.name, "reference.name")
        elif self.name:
            raise SpecError("reference.name", self.name, "must be empty for run/workspace")
        if not isinstance(self.attribute, str) or not self.attribute:
            raise SpecError("reference.attribute", self.attribute, "must be non-empty text")
        if self.role:
            _name(self.role, "reference.role")
        allowed = {
            "artifact": ("path", "directory"),
            "binary": ("path", "directory"),
            "config": ("path",),
            "credential": ("path", "directory"),
            "mount": ("path",),
            "parameter": ("value",),
            "run": ("root",),
            "server": ("config", "host", "log", "port", "url"),
            "workspace": ("path",),
        }[self.kind]
        if self.attribute not in allowed:
            raise SpecError(
                "reference.attribute", self.attribute,
                "known for %s: %s" % (self.kind, ", ".join(allowed)),
            )
        if self.role and not (self.kind == "server" and self.attribute in ("port", "url")):
            raise SpecError(
                "reference.role", self.role,
                "is valid only for server port/url references",
            )

    @property
    def key(self) -> str:
        """Return the stable runtime value key used by renderers and manifests."""
        if self.kind == "run":
            return "run_root"
        if self.kind == "workspace":
            return "workspace"
        suffix = {
            ("artifact", "path"): "artifact_%s" % self.name,
            ("artifact", "directory"): "artifact_%s_dir" % self.name,
            ("binary", "path"): "binary_%s" % self.name,
            ("binary", "directory"): "binary_%s_dir" % self.name,
            ("config", "path"): "config_%s" % self.name,
            ("credential", "path"): "credential_%s" % self.name,
            ("credential", "directory"): "credential_%s_dir" % self.name,
            ("mount", "path"): "mount_%s" % self.name,
            ("parameter", "value"): "param_%s" % self.name,
        }.get((self.kind, self.attribute))
        if suffix is not None:
            return suffix
        if self.kind == "server":
            if self.attribute == "port":
                return "server_%s_%s_port" % (self.name, self.role or "primary")
            if self.attribute == "url" and self.role:
                return "server_%s_%s_url" % (self.name, self.role)
            return "server_%s_%s" % (self.name, self.attribute)
        raise SpecError("reference", self, "cannot be converted to a runtime key")

    def __str__(self) -> str:
        return "{%s}" % self.key


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


@dataclasses.dataclass(frozen=True)
class Command:
    """Reusable shell-free invocation defaults for a server or client tool."""

    argv: Sequence[object]
    env: Mapping[str, object] = dataclasses.field(default_factory=dict)
    cwd: str = ""
    input: Optional[str] = None
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
        if self.input is not None and not isinstance(self.input, str):
            raise SpecError("command.input", self.input, "must be text or None")
        if not isinstance(self.encoding, str) or not self.encoding:
            raise SpecError("command.encoding", self.encoding, "must be non-empty text")
        object.__setattr__(self, "timeout", _positive(self.timeout, "command.timeout"))
        exits = tuple(self.expected_exit_codes)
        if not exits or not all(isinstance(value, int) and not isinstance(value, bool) for value in exits):
            raise SpecError("command.expected_exit_codes", exits, "must contain integer statuses")
        object.__setattr__(self, "expected_exit_codes", exits)
        if isinstance(self.output_limit, bool) or not isinstance(self.output_limit, int) or self.output_limit < 1:
            raise SpecError("command.output_limit", self.output_limit, "must be an integer >= 1")
        if self.mode not in _COMMAND_MODES:
            raise SpecError("command.mode", self.mode, "must be capture, stream, or pty")
        if isinstance(self.retries, bool) or not isinstance(self.retries, int) or self.retries < 0:
            raise SpecError("command.retries", self.retries, "must be an integer >= 0")


def command(
    *argv: object,
    env: Optional[Mapping[str, object]] = None,
    cwd: str = "",
    input: Optional[str] = None,
    encoding: str = "utf-8",
    timeout: float = 30.0,
    expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20,
    mode: str = "capture",
    retries: int = 0,
) -> Command:
    """Declare one reusable shell-free command and its execution policy."""
    if len(argv) == 1 and isinstance(argv[0], (list, tuple)):
        selected = tuple(argv[0])
    else:
        selected = argv
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
    input: Optional[str] = None,
    encoding: str = "utf-8",
    timeout: float = 30.0,
    expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20,
    mode: str = "capture",
    retries: int = 0,
) -> Execution:
    """Canonical alias for a reusable, shell-free execution declaration."""
    if len(argv) == 1 and isinstance(argv[0], (list, tuple)):
        selected = tuple(argv[0])
    else:
        selected = argv
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

    def __post_init__(self) -> None:
        _name(self.name, "endpoint.name")
        if self.protocol not in _PROTOCOLS:
            raise SpecError("endpoint.protocol", self.protocol, "must be tcp or udp")
        if self.port is not None and (
            isinstance(self.port, bool) or not isinstance(self.port, int) or not 0 < self.port < 65536
        ):
            raise SpecError("endpoint.port", self.port, "must be a port from 1 to 65535 or None")
        if not isinstance(self.scheme, str) or (
            self.scheme and _SCHEME.fullmatch(self.scheme) is None
        ):
            raise SpecError("endpoint.scheme", self.scheme, "must be a valid URI scheme")
        if not isinstance(self.metadata, Mapping):
            raise SpecError("endpoint.metadata", self.metadata, "must be a mapping")
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))


def endpoint(
    name: str = "primary", *, protocol: str = "tcp", port: Optional[int] = None,
    scheme: str = "", metadata: Optional[Mapping[str, object]] = None,
) -> Endpoint:
    """Declare a named backend-assigned TCP or UDP endpoint."""
    return Endpoint(name, protocol, port, scheme, {} if metadata is None else metadata)


def http_endpoint(
    name: str = "http", *, port: Optional[int] = None, tls: bool = False,
    metadata: Optional[Mapping[str, object]] = None,
) -> Endpoint:
    """Declare an HTTP or HTTPS endpoint with a backend-assigned port."""
    return Endpoint(
        name, "tcp", port, "https" if tls else "http",
        {} if metadata is None else metadata,
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
        if not isinstance(self.path, str) or not self.path.startswith("/"):
            raise SpecError("probe.path", self.path, "must start with /")
        selected = _argv(self.command, "probe.command", empty=True)
        if self.kind == "exec" and not selected:
            raise SpecError("probe.command", selected, "is required for an exec probe")
        object.__setattr__(self, "command", selected)
        statuses = tuple(self.statuses)
        if not statuses or not all(isinstance(value, int) and 100 <= value <= 599 for value in statuses):
            raise SpecError("probe.statuses", statuses, "must contain HTTP statuses from 100 to 599")
        object.__setattr__(self, "statuses", statuses)
        if not isinstance(self.pattern, str):
            raise SpecError("probe.pattern", self.pattern, "must be text")


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

    def __post_init__(self) -> None:
        if self.source is None or isinstance(self.source, bytes):
            raise SpecError("mount.source", self.source, "must identify a resource or path")
        object.__setattr__(self, "target", _relative(self.target, "mount.target", allow_empty=False))
        if not isinstance(self.read_only, bool):
            raise SpecError("mount.read_only", self.read_only, "must be true or false")
        if self.kind not in ("auto", "config", "artifact", "credential", "path", "tmp"):
            raise SpecError("mount.kind", self.kind, "has an unknown resource kind")


def mount(
    source: object, target: Union[str, Path], *, read_only: bool = True, kind: str = "auto",
) -> Mount:
    """Declare one confined resource mount for a server or client environment."""
    return Mount(source, str(target), read_only, kind)


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


@dataclasses.dataclass(frozen=True)
class Placement:
    """Backend-neutral resource placement and container policy."""

    backend: str = "inherit"
    image: Optional[str] = None
    namespace: str = ""
    labels: Mapping[str, str] = dataclasses.field(default_factory=dict)
    node_selector: Mapping[str, str] = dataclasses.field(default_factory=dict)
    security_context: Mapping[str, object] = dataclasses.field(default_factory=dict)
    resources: ResourceLimits = dataclasses.field(default_factory=ResourceLimits)
    options: Mapping[str, object] = dataclasses.field(default_factory=dict)
    allow_mutable_image: bool = False

    def __post_init__(self) -> None:
        _name(self.backend, "placement.backend")
        if self.image is not None and (not isinstance(self.image, str) or not self.image):
            raise SpecError("placement.image", self.image, "must be non-empty text or None")
        if not isinstance(self.namespace, str):
            raise SpecError("placement.namespace", self.namespace, "must be text")
        object.__setattr__(self, "labels", _strings(self.labels, "placement.labels"))
        object.__setattr__(self, "node_selector", _strings(self.node_selector, "placement.node_selector"))
        if not isinstance(self.security_context, Mapping):
            raise SpecError("placement.security_context", self.security_context, "must be a mapping")
        object.__setattr__(self, "security_context", freeze_mapping(self.security_context))
        if not isinstance(self.resources, ResourceLimits):
            raise SpecError("placement.resources", self.resources, "must be ResourceLimits")
        if not isinstance(self.options, Mapping) or not all(
            isinstance(name, str) and name for name in self.options
        ):
            raise SpecError(
                "placement.options", self.options,
                "must map non-empty option names to immutable values",
            )
        object.__setattr__(self, "options", freeze_mapping(self.options))
        if not isinstance(self.allow_mutable_image, bool):
            raise SpecError(
                "placement.allow_mutable_image", self.allow_mutable_image,
                "must be true or false",
            )


@dataclasses.dataclass(frozen=True)
class LogPolicy:
    """Capture, retention, redaction, and failure-tail policy for one resource."""

    capture: bool = True
    max_bytes: int = 64 << 20
    tail_lines: int = 40
    redact: Sequence[str] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.capture, bool):
            raise SpecError("logs.capture", self.capture, "must be true or false")
        if isinstance(self.max_bytes, bool) or not isinstance(self.max_bytes, int) or self.max_bytes < 1:
            raise SpecError("logs.max_bytes", self.max_bytes, "must be an integer >= 1")
        if isinstance(self.tail_lines, bool) or not isinstance(self.tail_lines, int) or self.tail_lines < 0:
            raise SpecError("logs.tail_lines", self.tail_lines, "must be an integer >= 0")
        patterns = tuple(self.redact)
        if not all(isinstance(value, str) and value for value in patterns):
            raise SpecError("logs.redact", patterns, "must contain non-empty text patterns")
        object.__setattr__(self, "redact", patterns)
