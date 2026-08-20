"""Python declarations for BriXTest server/client cases.

The declarations are inert, immutable data.  Importing a test module describes
what a case needs; only the helper-process runtime materializes files, captures
binaries, allocates ports, or starts servers.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import (
    TYPE_CHECKING, Callable, Mapping, Optional, Sequence, Tuple, TypeVar, Union, overload,
)

from brixtest.errors import SpecError
from brixtest.evidence.collectors import CollectorSpec, process_tree
from brixtest.isolation import Isolation
from brixtest.isolation import process as process_isolation
from brixtest.resources import (
    Command,
    Endpoint,
    Execution,
    Lifecycle,
    LogPolicy,
    Mount,
    Placement,
    Probe,
    Reference,
    artifact_ref,
    binary_ref,
    server_ref,
)
from brixtest.util.immutable import freeze_mapping

if TYPE_CHECKING:
    from brixtest.auth.models import AuthRecipe
    from brixtest.credentials import Credential
    from brixtest.network import HostMapping

__all__ = [
    "Artifact",
    "Binary",
    "CaseDefinition",
    "Client",
    "ConfigFile",
    "ConfigSet",
    "ConfigTemplate",
    "GB",
    "GiB",
    "KB",
    "KiB",
    "MB",
    "MiB",
    "Readiness",
    "Server",
    "Tool",
    "artifact",
    "binary",
    "case",
    "client",
    "configs",
    "get_case",
    "is_case",
    "load_template",
    "file_artifact",
    "noise",
    "immediate",
    "server",
    "server_config",
    "static_config",
    "tcp",
    "template_config",
    "text_artifact",
    "tool",
]

KiB = 1 << 10
MiB = 1 << 20
GiB = 1 << 30
KB = 1_000
MB = 1_000_000
GB = 1_000_000_000

_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_PLACEHOLDER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ARTIFACT_KINDS = frozenset({"noise", "file", "text"})
_BACKENDS = frozenset({"auto", "local", "kubernetes", "minikube"})
_Function = TypeVar("_Function", bound=Callable[..., object])


def _name(value: str, field: str) -> str:
    if not isinstance(value, str) or not _NAME.match(value):
        raise SpecError(
            field, value,
            "must start with a lowercase letter and contain [a-z0-9_-] only",
        )
    return value


def _argv(value: Sequence[object], field: str) -> Tuple[object, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        raise SpecError(field, value, "must be a non-empty argv sequence")
    for part in value:
        if not isinstance(part, (str, Binary, Reference)):
            raise SpecError(
                field, part,
                "argv entries must be strings, Binary declarations, or typed references",
            )
    return tuple(value)


def _string_mapping(value: Mapping[str, object], field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) and _ENV_NAME.fullmatch(key) is not None
        and isinstance(item, (str, Reference)) and "\0" not in str(item)
               for key, item in value.items()):
        raise SpecError(
            field, value,
            "must map portable environment names to NUL-free text or typed references",
        )
    return freeze_mapping(value)


@dataclasses.dataclass(frozen=True)
class ConfigFile:
    """Immutable server-config content or a lazily loaded on-disk source."""

    path: Optional[Union[str, Path]] = None
    template: bool = True
    destination: str = "server.conf"
    content: Optional[str] = None
    values: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if (self.path is None) == (self.content is None):
            raise SpecError(
                "server config", self.path,
                "needs exactly one of an on-disk path or text content",
            )
        if self.path is not None and not isinstance(self.path, (str, Path)):
            raise SpecError("config.path", self.path, "must be a string or path")
        if self.path is not None and not str(self.path):
            raise SpecError("config.path", self.path, "must not be empty")
        if self.content is not None and not isinstance(self.content, str):
            raise SpecError("config.content", self.content, "must be text")
        if not isinstance(self.destination, str):
            raise SpecError("config.destination", self.destination, "must be text")
        destination = Path(self.destination)
        if not self.destination or destination.is_absolute() or ".." in destination.parts:
            raise SpecError(
                "config.destination", self.destination,
                "must be a confined relative path",
            )
        if not all(isinstance(key, str) and _PLACEHOLDER_NAME.match(key)
                   for key in self.values):
            raise SpecError(
                "config.values", self.values,
                "keys must be valid {placeholder_name} identifiers",
            )
        if not all(isinstance(value, (str, int, float, bool, Path, Reference))
                   for value in self.values.values()):
            raise SpecError(
                "config.values", self.values,
                "values must be text, numbers, booleans, paths, or typed references",
            )
        object.__setattr__(self, "values", freeze_mapping(self.values))

    @property
    def filename(self) -> str:
        """The relative filename BriXTest will give the captured config."""
        return self.destination


@dataclasses.dataclass(frozen=True)
class ConfigTemplate:
    """A lazy on-disk template completed with declaration-time values."""

    path: Union[str, Path]

    def __post_init__(self) -> None:
        if not isinstance(self.path, (str, Path)) or not str(self.path):
            raise SpecError("config template", self.path, "path must not be empty")

    def fill(self, *, filename: str = "server.conf", **values: object) -> ConfigFile:
        """Bind author values while leaving runtime placeholders unresolved."""
        return ConfigFile(
            path=self.path, template=True, destination=filename, values=values,
        )


def load_template(path: Union[str, Path]) -> ConfigTemplate:
    """Declare a template without reading or executing anything at collection."""
    return ConfigTemplate(path)


def server_config(
    content: str, filename: str = "server.conf", *, template: bool = True,
) -> ConfigFile:
    """Pass complete text content and its desired filename to BriXTest."""
    return ConfigFile(
        path=None, content=content, template=template, destination=filename,
    )


def template_config(
    path: Union[str, Path], *, destination: str = "server.conf",
    values: Optional[Mapping[str, object]] = None,
) -> ConfigFile:
    """Declare an on-disk config template with optional author-owned values."""
    return ConfigFile(
        path=path, template=True, destination=destination, values=dict(values or {}),
    )


def static_config(
    path: Union[str, Path], *, destination: str = "server.conf"
) -> ConfigFile:
    """Declare an on-disk config that must be captured without rendering."""
    return ConfigFile(path=path, template=False, destination=destination)


@dataclasses.dataclass(frozen=True)
class ConfigSet:
    """An ordered set of captured server configs with one command-line primary."""

    files: Sequence[ConfigFile]
    primary: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.files, (str, bytes)) or not isinstance(self.files, Sequence):
            raise SpecError("configs.files", self.files, "must be a ConfigFile sequence")
        selected = tuple(self.files)
        if not selected or not all(isinstance(item, ConfigFile) for item in selected):
            raise SpecError("configs.files", selected, "must contain at least one ConfigFile")
        destinations = [item.destination for item in selected]
        if len(set(destinations)) != len(destinations):
            raise SpecError("configs.files", destinations, "destinations must be unique")
        primary = self.primary or selected[0].destination
        if primary not in destinations:
            raise SpecError("configs.primary", primary, "must name a declared destination")
        object.__setattr__(self, "files", selected)
        object.__setattr__(self, "primary", primary)

    @property
    def primary_file(self) -> ConfigFile:
        """Return the config used by the conventional ``{config}`` placeholder."""
        return self.get(self.primary)

    def get(self, destination: str) -> ConfigFile:
        """Resolve one config declaration by its captured destination path."""
        for item in self.files:
            if item.destination == destination:
                return item
        raise SpecError(
            "config destination", destination,
            "known: %s" % ", ".join(item.destination for item in self.files),
        )


def configs(*files: ConfigFile, primary: str = "") -> ConfigSet:
    """Group one or more server configs and optionally select the primary file."""
    return ConfigSet(files, primary)


@dataclasses.dataclass(frozen=True)
class Binary:
    """A local executable snapshot and its immutable Kubernetes equivalent."""

    name: str
    path: Optional[Union[str, Path]] = None
    libraries: Sequence[Union[str, Path]] = ()
    discover_libraries: bool = True
    image: Optional[str] = None
    image_path: Optional[str] = None

    def ref(self, *, directory: bool = False) -> Reference:
        """Reference this binary's immutable captured path at runtime."""
        return binary_ref(self, directory=directory)

    def __post_init__(self) -> None:
        _name(self.name, "binary.name")
        if self.path is not None and not isinstance(self.path, (str, Path)):
            raise SpecError("binary.path", self.path, "must be a string or path")
        if self.image is not None and not isinstance(self.image, str):
            raise SpecError("binary.image", self.image, "must be text")
        if self.image_path is not None and not isinstance(self.image_path, str):
            raise SpecError("binary.image_path", self.image_path, "must be text")
        if not isinstance(self.discover_libraries, bool):
            raise SpecError(
                "binary.discover_libraries", self.discover_libraries, "must be boolean",
            )
        if self.path is None and not (self.image and self.image_path):
            raise SpecError(
                "binary", self.name,
                "needs a local path or an image plus image_path",
            )
        if bool(self.image) != bool(self.image_path):
            raise SpecError(
                "binary.image", self.image,
                "image and image_path must be supplied together",
            )
        if isinstance(self.libraries, (str, bytes)) or not isinstance(self.libraries, Sequence):
            raise SpecError("binary.libraries", self.libraries, "must be a path sequence")
        if not all(isinstance(path, (str, Path)) for path in self.libraries):
            raise SpecError("binary.libraries", self.libraries, "must contain strings or paths")
        object.__setattr__(self, "libraries", tuple(self.libraries))


def binary(
    name: str,
    path: Optional[Union[str, Path]] = None,
    *,
    libraries: Sequence[Union[str, Path]] = (),
    discover_libraries: bool = True,
    image: Optional[str] = None,
    image_path: Optional[str] = None,
) -> Binary:
    """Declare an executable snapshot and optional Kubernetes image identity."""
    return Binary(
        name=name, path=path, libraries=libraries,
        discover_libraries=discover_libraries,
        image=image, image_path=image_path,
    )


@dataclasses.dataclass(frozen=True)
class Artifact:
    """A deterministic or copied input published by name into one run."""

    name: str
    kind: str
    size: int = 0
    seed: int = 0
    source: Optional[Union[str, Path]] = None
    text: str = ""
    filename: str = ""
    options: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def ref(self, *, directory: bool = False) -> Reference:
        """Reference this artifact's materialized path at runtime."""
        return artifact_ref(self, directory=directory)

    def __post_init__(self) -> None:
        _name(self.name, "artifact.name")
        _name(self.kind, "artifact.kind")
        if self.kind == "noise" and (
            isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0
        ):
            raise SpecError("artifact.size", self.size, "must be an integer >= 0")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise SpecError("artifact.seed", self.seed, "must be an integer")
        if self.kind == "file" and self.source is None:
            raise SpecError("artifact.source", self.source, "is required for file artifacts")
        if self.kind == "text" and not isinstance(self.text, str):
            raise SpecError("artifact.text", self.text, "must be a string")
        if not isinstance(self.options, Mapping) or not all(
            isinstance(key, str) and key for key in self.options
        ):
            raise SpecError("artifact.options", self.options, "must map non-empty text keys")
        if self.kind in _ARTIFACT_KINDS and self.options:
            raise SpecError(
                "artifact.options", self.options,
                "built-in artifacts use their named declaration fields",
            )
        object.__setattr__(self, "options", freeze_mapping(self.options))
        filename = self.filename or (
            Path(str(self.source)).name if self.kind == "file" else self.name + ".bin"
        )
        if not isinstance(filename, str) or not filename or Path(filename).name != filename:
            raise SpecError("artifact.filename", filename, "must be a non-empty basename")
        object.__setattr__(self, "filename", filename)


def artifact(
    name: str, kind: str, *, filename: str = "", **options: object,
) -> Artifact:
    """Declare an artifact materialized by a versioned provider extension."""
    if kind in _ARTIFACT_KINDS:
        raise SpecError(
            "artifact kind", kind,
            "use noise(), file_artifact(), or text_artifact() for built-in inputs",
        )
    return Artifact(
        name=name, kind=kind, filename=filename or name + ".bin", options=options,
    )


def noise(name: str, *, size: int, seed: int = 0, filename: str = "") -> Artifact:
    """Declare deterministic high-entropy bytes generated inside the run."""
    return Artifact(name=name, kind="noise", size=size, seed=seed, filename=filename)


def file_artifact(
    name: str, path: Union[str, Path], *, filename: str = ""
) -> Artifact:
    """Declare a file that BriXTest copies and hashes before test execution."""
    return Artifact(name=name, kind="file", source=path, filename=filename)


def text_artifact(name: str, text: str, *, filename: str = "") -> Artifact:
    """Declare a small UTF-8 text artifact materialized inside the run."""
    return Artifact(name=name, kind="text", text=text, filename=filename or name + ".txt")


@dataclasses.dataclass(frozen=True)
class Readiness:
    """A server startup probe using a named port or immediate readiness."""
    kind: str = "tcp"
    port: str = "primary"
    timeout: float = 10.0

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in ("tcp", "none"):
            raise SpecError("readiness.kind", self.kind, "must be tcp or none")
        if not isinstance(self.port, str) or not self.port:
            raise SpecError("readiness.port", self.port, "must be a non-empty port role")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or self.timeout <= 0
        ):
            raise SpecError("readiness.timeout", self.timeout, "must be > 0")


def tcp(port: str = "primary", *, timeout: float = 10.0) -> Readiness:
    """Wait until a named TCP port accepts connections."""
    return Readiness(kind="tcp", port=port, timeout=timeout)


def immediate() -> Readiness:
    """Treat a successfully spawned process as ready without probing it."""
    return Readiness(kind="none")


@dataclasses.dataclass(frozen=True)
class Server:
    """A test-declared server whose exact config is captured on disk."""

    name: str
    command: Sequence[object]
    config: Optional[ConfigFile] = None
    ports: Mapping[str, Optional[int]] = dataclasses.field(
        default_factory=lambda: {"primary": None}
    )
    env: Mapping[str, object] = dataclasses.field(default_factory=dict)
    readiness: Readiness = dataclasses.field(default_factory=Readiness)
    depends_on: Sequence[Union[str, "Server"]] = ()
    binaries: Sequence[Binary] = ()
    image: Optional[str] = None
    scope: str = "case"
    configs: Optional[ConfigSet] = None
    endpoints: Sequence[Endpoint] = ()
    probe: Optional[Probe] = None
    mounts: Sequence[Mount] = ()
    lifecycle: Lifecycle = dataclasses.field(default_factory=Lifecycle)
    placement: Placement = dataclasses.field(default_factory=Placement)
    logs: LogPolicy = dataclasses.field(default_factory=LogPolicy)
    cwd: str = ""
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    @property
    def host(self) -> Reference:
        """Reference this server's backend-selected host."""
        return server_ref(self, attribute="host")

    @property
    def config_path(self) -> Reference:
        """Reference this server's primary captured configuration path."""
        return server_ref(self, attribute="config")

    @property
    def log_path(self) -> Reference:
        """Reference this server's correlated log path."""
        return server_ref(self, attribute="log")

    def port(self, role: str = "primary") -> Reference:
        """Reference a named backend-selected server port."""
        return server_ref(self, attribute="port", role=role)

    def url(self, role: str = "") -> Reference:
        """Reference the primary or a named endpoint URL."""
        return server_ref(self, attribute="url", role=role)

    @property
    def execution(self) -> Execution:
        """Canonical execution view of this server's compatible process fields."""
        return Execution(self.command, env=self.env, cwd=self.cwd)

    def __post_init__(self) -> None:
        _name(self.name, "server.name")
        if not isinstance(self.metadata, Mapping):
            raise SpecError("server.metadata", self.metadata, "must be a mapping")
        selected_config = self.config
        if selected_config is None:
            selected_config = ConfigFile(
                content="", destination="%s.conf" % self.name, template=False,
            )
            selected_metadata = dict(self.metadata)
            selected_metadata.setdefault("brixtest.synthetic_config", True)
            object.__setattr__(self, "metadata", selected_metadata)
            object.__setattr__(self, "config", selected_config)
        if not isinstance(selected_config, ConfigFile):
            raise SpecError("server.config", selected_config, "must be a ConfigFile declaration")
        selected_configs = self.configs or ConfigSet(
            (selected_config,), selected_config.destination,
        )
        if not isinstance(selected_configs, ConfigSet):
            if isinstance(selected_configs, Sequence) and not isinstance(selected_configs, (str, bytes)):
                selected_configs = ConfigSet(tuple(selected_configs), selected_config.destination)
            else:
                raise SpecError("server.configs", selected_configs, "must be a ConfigSet")
        if selected_config not in selected_configs.files:
            selected_configs = ConfigSet(
                (selected_config, *selected_configs.files), selected_config.destination,
            )
        if selected_configs.primary_file != selected_config:
            object.__setattr__(self, "config", selected_configs.primary_file)
        object.__setattr__(self, "configs", selected_configs)
        if not isinstance(self.readiness, Readiness):
            raise SpecError("server.readiness", self.readiness, "must be a Readiness declaration")
        object.__setattr__(self, "command", _argv(self.command, "server.command"))
        if not isinstance(self.ports, Mapping):
            raise SpecError("server.ports", self.ports, "must map role names to ports")
        normalized_ports = {}
        for role, port in self.ports.items():
            _name(role, "server.port role")
            if port is not None and (
                isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536
            ):
                raise SpecError("server.ports[%s]" % role, port, "must be a TCP port or None")
            normalized_ports[role] = port
        if not normalized_ports:
            raise SpecError("server.ports", self.ports, "must declare at least one role")
        object.__setattr__(self, "ports", freeze_mapping(normalized_ports))
        object.__setattr__(self, "env", _string_mapping(self.env, "server.env"))
        if isinstance(self.depends_on, (str, bytes)) or not isinstance(self.depends_on, Sequence):
            raise SpecError("server.depends_on", self.depends_on, "must be a server sequence")
        if not all(isinstance(item, (str, Server)) for item in self.depends_on):
            raise SpecError(
                "server.depends_on", self.depends_on,
                "must contain server names or Server declarations",
            )
        object.__setattr__(self, "depends_on", tuple(
            item.name if isinstance(item, Server) else item for item in self.depends_on
        ))
        if not all(isinstance(item, Binary) for item in self.binaries):
            raise SpecError("server.binaries", self.binaries, "must contain Binary declarations")
        object.__setattr__(self, "binaries", tuple(self.binaries))
        if self.image is not None and not isinstance(self.image, str):
            raise SpecError("server.image", self.image, "must be text")
        if self.scope not in ("case", "function", "class", "module", "package", "session"):
            raise SpecError(
                "server.scope", self.scope,
                "must be case, function, class, module, package, or session",
            )
        endpoints = tuple(self.endpoints) or tuple(
            Endpoint(role, "tcp", port) for role, port in normalized_ports.items()
        )
        if not all(isinstance(item, Endpoint) for item in endpoints):
            raise SpecError("server.endpoints", endpoints, "must contain Endpoint declarations")
        endpoint_names = [item.name for item in endpoints]
        if len(set(endpoint_names)) != len(endpoint_names):
            raise SpecError("server.endpoints", endpoint_names, "names must be unique")
        for item in endpoints:
            if item.name not in normalized_ports:
                normalized_ports[item.name] = item.port
            elif item.port is not None and normalized_ports[item.name] not in (None, item.port):
                raise SpecError(
                    "server endpoint %s" % item.name, item.port,
                    "conflicts with the declared port",
                )
        object.__setattr__(self, "ports", freeze_mapping(normalized_ports))
        object.__setattr__(self, "endpoints", endpoints)
        selected_probe = self.probe or Probe(
            self.readiness.kind, self.readiness.port, self.readiness.timeout
        )
        if not isinstance(selected_probe, Probe):
            raise SpecError("server.probe", selected_probe, "must be a Probe declaration")
        object.__setattr__(self, "probe", selected_probe)
        if not all(isinstance(item, Mount) for item in self.mounts):
            raise SpecError("server.mounts", self.mounts, "must contain Mount declarations")
        object.__setattr__(self, "mounts", tuple(self.mounts))
        for name, expected in (
            ("lifecycle", Lifecycle), ("placement", Placement), ("logs", LogPolicy),
        ):
            if not isinstance(getattr(self, name), expected):
                raise SpecError("server.%s" % name, getattr(self, name), "has the wrong declaration type")
        if not self.lifecycle.background and self.scope not in ("case", "function"):
            raise SpecError(
                "server.lifecycle.background", self.scope,
                "foreground commands require case or function scope",
            )
        if not isinstance(self.cwd, str) or Path(self.cwd).is_absolute() or ".." in Path(self.cwd).parts:
            raise SpecError("server.cwd", self.cwd, "must be a confined relative path")
        if not isinstance(self.metadata, Mapping):
            raise SpecError("server.metadata", self.metadata, "must be a mapping")
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))


@overload
def server(
    name: str, *, execution: Execution,
    config: Optional[ConfigFile] = None,
    configs: Union[Sequence[ConfigFile], ConfigSet] = (),
    ports: Union[Sequence[str], Mapping[str, Optional[int]]] = ("primary",),
    env: Optional[Mapping[str, object]] = None,
    readiness: Optional[Readiness] = None,
    endpoints: Sequence[Endpoint] = (), probe: Optional[Probe] = None,
    depends_on: Sequence[Union[str, Server]] = (), binaries: Sequence[Binary] = (),
    image: Optional[str] = None, scope: str = "case", mounts: Sequence[Mount] = (),
    lifecycle: Optional[Lifecycle] = None, placement: Optional[Placement] = None,
    logs: Optional[LogPolicy] = None, cwd: str = "",
    metadata: Optional[Mapping[str, object]] = None,
) -> Server: ...


@overload
def server(
    name: str, *, binary: Binary, args: Sequence[object] = (),
    config: Optional[ConfigFile] = None,
    configs: Union[Sequence[ConfigFile], ConfigSet] = (),
    ports: Union[Sequence[str], Mapping[str, Optional[int]]] = ("primary",),
    env: Optional[Mapping[str, object]] = None,
    readiness: Optional[Readiness] = None,
    endpoints: Sequence[Endpoint] = (), probe: Optional[Probe] = None,
    depends_on: Sequence[Union[str, Server]] = (), binaries: Sequence[Binary] = (),
    image: Optional[str] = None, scope: str = "case", mounts: Sequence[Mount] = (),
    lifecycle: Optional[Lifecycle] = None, placement: Optional[Placement] = None,
    logs: Optional[LogPolicy] = None, cwd: str = "",
    metadata: Optional[Mapping[str, object]] = None,
) -> Server: ...


@overload
def server(
    name: str, *, command: Union[Sequence[object], Command],
    config: Optional[ConfigFile] = None,
    configs: Union[Sequence[ConfigFile], ConfigSet] = (),
    ports: Union[Sequence[str], Mapping[str, Optional[int]]] = ("primary",),
    env: Optional[Mapping[str, object]] = None,
    readiness: Optional[Readiness] = None,
    depends_on: Sequence[Union[str, Server]] = (), binaries: Sequence[Binary] = (),
    image: Optional[str] = None, scope: str = "case",
    endpoints: Sequence[Endpoint] = (), probe: Optional[Probe] = None,
    mounts: Sequence[Mount] = (), lifecycle: Optional[Lifecycle] = None,
    placement: Optional[Placement] = None, logs: Optional[LogPolicy] = None,
    cwd: str = "", metadata: Optional[Mapping[str, object]] = None,
) -> Server: ...


def server(
    name: str,
    *,
    command: Optional[Union[Sequence[object], Command]] = None,
    execution: Optional[Execution] = None,
    binary: Optional[Binary] = None,
    args: Sequence[object] = (),
    config: Optional[ConfigFile] = None,
    configs: Union[Sequence[ConfigFile], ConfigSet] = (),
    ports: Union[Sequence[str], Mapping[str, Optional[int]]] = ("primary",),
    env: Optional[Mapping[str, object]] = None,
    readiness: Optional[Readiness] = None,
    depends_on: Sequence[Union[str, Server]] = (),
    binaries: Sequence[Binary] = (),
    image: Optional[str] = None,
    scope: str = "case",
    endpoints: Sequence[Endpoint] = (),
    probe: Optional[Probe] = None,
    mounts: Sequence[Mount] = (),
    lifecycle: Optional[Lifecycle] = None,
    placement: Optional[Placement] = None,
    logs: Optional[LogPolicy] = None,
    cwd: str = "",
    metadata: Optional[Mapping[str, object]] = None,
) -> Server:
    """Declare one managed server using ``command`` or ``binary`` + ``args``."""
    if execution is not None:
        if command is not None:
            raise SpecError("server execution", name, "use execution or command, not both")
        if not isinstance(execution, Command):
            raise SpecError("server execution", execution, "must be an Execution declaration")
        command = execution
    command_defaults: Optional[Command] = command if isinstance(command, Command) else None
    if command_defaults is not None:
        unsupported = (
            command_defaults.input is not None
            or command_defaults.encoding != "utf-8"
            or command_defaults.timeout != 30.0
            or tuple(command_defaults.expected_exit_codes) != (0,)
            or command_defaults.output_limit != 1 << 20
            or command_defaults.mode != "capture"
            or command_defaults.retries != 0
        )
        if unsupported:
            raise SpecError(
                "server command policy", name,
                "server Command declarations support argv/env/cwd; use Probe, Lifecycle, and LogPolicy for server execution policy",
            )
        command = command_defaults.argv
        combined_env = dict(command_defaults.env)
        combined_env.update(_string_mapping(
            {} if env is None else env, "server.env"
        ))
        env = combined_env
        cwd = cwd or command_defaults.cwd
    if binary is not None:
        if command is not None:
            raise SpecError("server command", name, "use command or binary+args, not both")
        if not isinstance(binary, Binary):
            raise SpecError("server binary", binary, "must be a Binary declaration")
        if isinstance(args, (str, bytes)) or not isinstance(args, Sequence):
            raise SpecError("server args", args, "must be an argv sequence, not text")
        command = (binary, *tuple(args))
    elif args:
        raise SpecError("server args", args, "requires server(binary=...)")
    if command is None:
        raise SpecError("server command", command, "is required")
    if isinstance(configs, ConfigSet):
        selected_configs = configs
    else:
        selected_configs = ConfigSet(tuple(configs), config.destination if config else "") \
            if configs else None
    if config is None:
        if selected_configs is None:
            config = server_config("", "%s.conf" % name, template=False)
            selected_metadata = dict(metadata or {})
            selected_metadata.setdefault("brixtest.synthetic_config", True)
            metadata = selected_metadata
            selected_configs = ConfigSet((config,), config.destination)
        else:
            config = selected_configs.primary_file
    if selected_configs is None:
        selected_configs = ConfigSet((config,), config.destination)
    elif config not in selected_configs.files:
        selected_configs = ConfigSet((config, *selected_configs.files), config.destination)
    port_map: Mapping[str, Optional[int]]
    if endpoints and tuple(ports) == ("primary",) and not isinstance(ports, Mapping):
        port_map = {item.name: item.port for item in endpoints}
    elif isinstance(ports, Mapping):
        port_map = dict(ports)
    else:
        if isinstance(ports, (str, bytes)) or not isinstance(ports, Sequence):
            raise SpecError("server.ports", ports, "must be a role sequence, not text")
        port_map = {role: None for role in ports}
    return Server(
        name=name, command=command, config=config, ports=port_map,
        env=_string_mapping({} if env is None else env, "server.env"),
        readiness=Readiness() if readiness is None else readiness, depends_on=depends_on,
        binaries=binaries, image=image, scope=scope, configs=selected_configs,
        endpoints=endpoints, probe=probe, mounts=mounts,
        lifecycle=Lifecycle() if lifecycle is None else lifecycle,
        placement=Placement(image=image) if placement is None else placement,
        logs=LogPolicy() if logs is None else logs, cwd=cwd,
        metadata={} if metadata is None else metadata,
    )


@dataclasses.dataclass(frozen=True)
class Client:
    """A reusable, named, shell-free client command declaration."""
    name: str
    command: Sequence[object]
    env: Mapping[str, object] = dataclasses.field(default_factory=dict)
    timeout: float = 30.0
    binaries: Sequence[Binary] = ()
    cwd: str = ""
    input: Optional[str] = None
    expected_exit_codes: Sequence[int] = (0,)
    output_limit: int = 1 << 20
    mode: str = "capture"
    retries: int = 0
    encoding: str = "utf-8"
    mounts: Sequence[Mount] = ()
    logs: LogPolicy = dataclasses.field(default_factory=LogPolicy)
    placement: Placement = dataclasses.field(default_factory=Placement)
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    @property
    def execution(self) -> Execution:
        """Canonical reusable execution policy represented by this client."""
        return Execution(
            self.command, env=self.env, cwd=self.cwd, input=self.input,
            encoding=self.encoding, timeout=self.timeout,
            expected_exit_codes=self.expected_exit_codes,
            output_limit=self.output_limit, mode=self.mode, retries=self.retries,
        )

    @property
    def resource_kind(self) -> str:
        """Stable author-model discriminator used by tooling and diagnostics."""
        return "client"

    def __post_init__(self) -> None:
        _name(self.name, "client.name")
        object.__setattr__(self, "command", _argv(self.command, "client.command"))
        object.__setattr__(self, "env", _string_mapping(self.env, "client.env"))
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or self.timeout <= 0
        ):
            raise SpecError("client.timeout", self.timeout, "must be > 0")
        if not all(isinstance(item, Binary) for item in self.binaries):
            raise SpecError("client.binaries", self.binaries, "must contain Binary declarations")
        object.__setattr__(self, "binaries", tuple(self.binaries))
        if not isinstance(self.cwd, str) or Path(self.cwd).is_absolute() or ".." in Path(self.cwd).parts:
            raise SpecError("client.cwd", self.cwd, "must be a confined relative path")
        if self.input is not None and not isinstance(self.input, str):
            raise SpecError("client.input", self.input, "must be text or None")
        exits = tuple(self.expected_exit_codes)
        if not exits or not all(isinstance(value, int) and not isinstance(value, bool) for value in exits):
            raise SpecError("client.expected_exit_codes", exits, "must contain integer statuses")
        object.__setattr__(self, "expected_exit_codes", exits)
        if isinstance(self.output_limit, bool) or not isinstance(self.output_limit, int) or self.output_limit < 1:
            raise SpecError("client.output_limit", self.output_limit, "must be an integer >= 1")
        if self.mode not in ("capture", "stream", "pty"):
            raise SpecError("client.mode", self.mode, "must be capture, stream, or pty")
        if isinstance(self.retries, bool) or not isinstance(self.retries, int) or self.retries < 0:
            raise SpecError("client.retries", self.retries, "must be an integer >= 0")
        if not isinstance(self.encoding, str) or not self.encoding:
            raise SpecError("client.encoding", self.encoding, "must be non-empty text")
        if not all(isinstance(item, Mount) for item in self.mounts):
            raise SpecError("client.mounts", self.mounts, "must contain Mount declarations")
        object.__setattr__(self, "mounts", tuple(self.mounts))
        if not isinstance(self.logs, LogPolicy):
            raise SpecError("client.logs", self.logs, "must be a LogPolicy declaration")
        if not isinstance(self.placement, Placement):
            raise SpecError("client.placement", self.placement, "must be a Placement declaration")
        if not isinstance(self.metadata, Mapping):
            raise SpecError("client.metadata", self.metadata, "must be a mapping")
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))


@overload
def client(
    name: str, *, execution: Execution, env: Optional[Mapping[str, object]] = None,
    timeout: float = 30.0, binaries: Sequence[Binary] = (), cwd: str = "",
    input: Optional[str] = None, expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20, mode: str = "capture", retries: int = 0,
    encoding: str = "utf-8", mounts: Sequence[Mount] = (),
    logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Client: ...


@overload
def client(
    name: str, *, binary: Binary, args: Sequence[object] = (),
    env: Optional[Mapping[str, object]] = None, timeout: float = 30.0,
    binaries: Sequence[Binary] = (), cwd: str = "", input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,), output_limit: int = 1 << 20,
    mode: str = "capture", retries: int = 0, encoding: str = "utf-8",
    mounts: Sequence[Mount] = (), logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Client: ...


@overload
def client(
    name: str, *, command: Union[Sequence[object], Command],
    env: Optional[Mapping[str, object]] = None, timeout: float = 30.0,
    binaries: Sequence[Binary] = (), cwd: str = "", input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,), output_limit: int = 1 << 20,
    mode: str = "capture", retries: int = 0, encoding: str = "utf-8",
    mounts: Sequence[Mount] = (), logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Client: ...


def client(
    name: str,
    *,
    command: Optional[Union[Sequence[object], Command]] = None,
    execution: Optional[Execution] = None,
    binary: Optional[Binary] = None,
    args: Sequence[object] = (),
    env: Optional[Mapping[str, object]] = None,
    timeout: float = 30.0,
    binaries: Sequence[Binary] = (),
    cwd: str = "",
    input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20,
    mode: str = "capture",
    retries: int = 0,
    encoding: str = "utf-8",
    mounts: Sequence[Mount] = (),
    logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Client:
    """Declare a named client using either ``command`` or ``binary`` + ``args``."""
    if execution is not None:
        if command is not None:
            raise SpecError("client execution", name, "use execution or command, not both")
        if not isinstance(execution, Command):
            raise SpecError("client execution", execution, "must be an Execution declaration")
        command = execution
    command_defaults: Optional[Command] = command if isinstance(command, Command) else None
    if command_defaults is not None:
        command = command_defaults.argv
        combined_env = dict(command_defaults.env)
        combined_env.update(_string_mapping(
            {} if env is None else env, "client.env"
        ))
        env = combined_env
        cwd = cwd or command_defaults.cwd
        input = input if input is not None else command_defaults.input
        timeout = command_defaults.timeout if timeout == 30.0 else timeout
        expected_exit_codes = (
            command_defaults.expected_exit_codes
            if tuple(expected_exit_codes) == (0,) else expected_exit_codes
        )
        output_limit = command_defaults.output_limit if output_limit == 1 << 20 else output_limit
        mode = command_defaults.mode if mode == "capture" else mode
        retries = command_defaults.retries if retries == 0 else retries
        encoding = command_defaults.encoding if encoding == "utf-8" else encoding
    if binary is not None:
        if command is not None:
            raise SpecError("client command", name, "use command or binary+args, not both")
        if not isinstance(binary, Binary):
            raise SpecError("client binary", binary, "must be a Binary declaration")
        if isinstance(args, (str, bytes)) or not isinstance(args, Sequence):
            raise SpecError("client args", args, "must be an argv sequence, not text")
        command = (binary, *tuple(args))
    elif args:
        raise SpecError("client args", args, "requires client(binary=...)")
    if command is None:
        raise SpecError("client command", command, "is required")
    return Client(
        name=name, command=command,
        env=_string_mapping({} if env is None else env, "client.env"), timeout=timeout,
        binaries=binaries, cwd=cwd, input=input, expected_exit_codes=expected_exit_codes,
        output_limit=output_limit, mode=mode, retries=retries, encoding=encoding,
        mounts=mounts,
        logs=LogPolicy() if logs is None else logs,
        placement=Placement() if placement is None else placement,
        metadata={} if metadata is None else metadata,
    )


@dataclasses.dataclass(frozen=True)
class Tool(Client):
    """First-class named test tool; a semantic specialization of Client."""

    @property
    def resource_kind(self) -> str:
        """Identify this declaration as an invocable tool rather than an actor."""
        return "tool"


@overload
def tool(
    name: str, *, execution: Execution, env: Optional[Mapping[str, object]] = None,
    timeout: float = 30.0, binaries: Sequence[Binary] = (), cwd: str = "",
    input: Optional[str] = None, expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20, mode: str = "capture", retries: int = 0,
    encoding: str = "utf-8", mounts: Sequence[Mount] = (),
    logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Tool: ...


@overload
def tool(
    name: str, *, binary: Binary, args: Sequence[object] = (),
    env: Optional[Mapping[str, object]] = None, timeout: float = 30.0,
    binaries: Sequence[Binary] = (), cwd: str = "", input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,), output_limit: int = 1 << 20,
    mode: str = "capture", retries: int = 0, encoding: str = "utf-8",
    mounts: Sequence[Mount] = (), logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Tool: ...


@overload
def tool(
    name: str, *, command: Union[Sequence[object], Command],
    env: Optional[Mapping[str, object]] = None, timeout: float = 30.0,
    binaries: Sequence[Binary] = (), cwd: str = "", input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,), output_limit: int = 1 << 20,
    mode: str = "capture", retries: int = 0, encoding: str = "utf-8",
    mounts: Sequence[Mount] = (), logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Tool: ...


def tool(
    name: str,
    *,
    execution: Optional[Execution] = None,
    command: Optional[Union[Sequence[object], Command]] = None,
    binary: Optional[Binary] = None,
    args: Sequence[object] = (),
    env: Optional[Mapping[str, object]] = None,
    timeout: float = 30.0,
    binaries: Sequence[Binary] = (),
    cwd: str = "",
    input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20,
    mode: str = "capture",
    retries: int = 0,
    encoding: str = "utf-8",
    mounts: Sequence[Mount] = (),
    logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Tool:
    """Declare a named tool with the same execution guarantees as a client."""
    declared = client(
        name, execution=execution, command=command, binary=binary, args=args,
        env=env, timeout=timeout, binaries=binaries, cwd=cwd, input=input,
        expected_exit_codes=expected_exit_codes, output_limit=output_limit,
        mode=mode, retries=retries, encoding=encoding, mounts=mounts,
        logs=logs, placement=placement, metadata=metadata,
    )
    return Tool(**{
        field.name: getattr(declared, field.name) for field in dataclasses.fields(Client)
    })


@dataclasses.dataclass(frozen=True)
class CaseDefinition:
    """The immutable resource and execution contract attached by ``@case``."""
    servers: Tuple[Server, ...]
    clients: Tuple[Client, ...]
    artifacts: Tuple[Artifact, ...]
    binaries: Tuple[Binary, ...]
    credentials: Tuple[Credential, ...]
    auth: Tuple[AuthRecipe, ...]
    hosts: Tuple[HostMapping, ...]
    observe: Tuple[CollectorSpec, ...]
    trials: int
    warmup: int
    timeout: float
    backend: str
    isolation: Isolation
    keep: str
    source: Path
    parameters: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        for field in (
            "servers", "clients", "artifacts", "binaries", "credentials",
            "auth", "hosts", "observe",
        ):
            values = getattr(self, field)
            if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
                raise SpecError("case.%s" % field, values, "must be a declaration sequence")
            object.__setattr__(self, field, tuple(values))
        if not isinstance(self.source, (str, Path)) or not str(self.source):
            raise SpecError("case.source", self.source, "must be a source file path")
        object.__setattr__(self, "source", Path(self.source).resolve())
        if not isinstance(self.parameters, Mapping) or not all(
            isinstance(name, str) and _PLACEHOLDER_NAME.fullmatch(name)
            for name in self.parameters
        ):
            raise SpecError(
                "case.parameters", self.parameters,
                "must map valid pytest parameter names to values",
            )
        object.__setattr__(self, "parameters", freeze_mapping(self.parameters))
        _validate_case_values(
            servers=self.servers, clients=self.clients, artifacts=self.artifacts,
            binaries=self.binaries, credentials=self.credentials, auth=self.auth,
            hosts=self.hosts, observe=self.observe, trials=self.trials,
            warmup=self.warmup, timeout=self.timeout, backend=self.backend,
            isolation=self.isolation, keep=self.keep,
        )

    @property
    def resource_names(self) -> Mapping[str, Tuple[str, ...]]:
        """Names grouped by resource kind for discovery and tooling."""
        return {
            field: tuple(item.name for item in getattr(self, field))
            for field in (
                "servers", "clients", "artifacts", "binaries", "credentials",
                "auth", "hosts", "observe",
            )
        }

    @property
    def tools(self) -> Tuple[Tool, ...]:
        """Named tool declarations, excluding compatibility-only Client values."""
        return tuple(item for item in self.clients if isinstance(item, Tool))

    def as_dict(self) -> Mapping[str, object]:
        """Return a JSON-safe, secret-free summary of the case contract."""
        return {
            "resources": {
                name: list(values) for name, values in self.resource_names.items()
            },
            "trials": self.trials, "warmup": self.warmup,
            "timeout": float(self.timeout), "backend": self.backend,
            "isolation": self.isolation.kind, "keep": self.keep,
            "source": str(self.source),
            "parameters": {
                name: value if isinstance(value, (str, int, float, bool, type(None)))
                else repr(value)
                for name, value in self.parameters.items()
            },
        }


def _unique(items: Sequence[object], label: str) -> None:
    names = [getattr(item, "name") for item in items]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SpecError(label, ", ".join(duplicates), "names must be unique in a case")


def _validate_case_values(
    *, servers: Sequence[Server], clients: Sequence[Client],
    artifacts: Sequence[Artifact], binaries: Sequence[Binary],
    credentials: Sequence[Credential], auth: Sequence[AuthRecipe],
    hosts: Sequence[HostMapping], observe: Sequence[CollectorSpec],
    trials: int, warmup: int, timeout: float, backend: str,
    isolation: Optional[Isolation], keep: str,
) -> None:
    from brixtest.auth.models import AuthRecipe
    from brixtest.credentials import Credential
    from brixtest.network import HostMapping

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise SpecError("case.timeout", timeout, "must be > 0")
    if not isinstance(backend, str) or (
        backend not in _BACKENDS and _NAME.fullmatch(backend) is None
    ):
        raise SpecError(
            "case.backend", backend,
            "must be auto, local, kubernetes, minikube, or a registered backend name",
        )
    if isolation is not None and not isinstance(isolation, Isolation):
        raise SpecError("case.isolation", isolation, "must be an Isolation declaration")
    if not isinstance(keep, str) or keep not in ("never", "failed", "always"):
        raise SpecError("case.keep", keep, "must be never, failed, or always")
    if isinstance(trials, bool) or not isinstance(trials, int) or trials < 1:
        raise SpecError("case.trials", trials, "must be an integer >= 1")
    if isinstance(warmup, bool) or not isinstance(warmup, int) or warmup < 0:
        raise SpecError("case.warmup", warmup, "must be an integer >= 0")
    if trials + warmup > 1000:
        raise SpecError("case attempts", trials + warmup, "must not exceed 1000")

    groups = (
        (servers, Server, "case.servers"),
        (clients, Client, "case.clients"),
        (artifacts, Artifact, "case.artifacts"),
        (binaries, Binary, "case.binaries"),
        (credentials, Credential, "case.credentials"),
        (auth, AuthRecipe, "case.auth"),
        (hosts, HostMapping, "case.hosts"),
        (observe, CollectorSpec, "case.observe"),
    )
    for values, expected, field in groups:
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise SpecError(field, values, "must be a declaration sequence")
        if not all(isinstance(item, expected) for item in values):
            raise SpecError(field, values, "contains an invalid declaration")

    collector_names = [item.name for item in observe]
    duplicates = sorted({name for name in collector_names if collector_names.count(name) > 1})
    if duplicates:
        raise SpecError("case.observe", duplicates, "collector names must be unique")
    for values, field in (
        (servers, "case.servers"), (clients, "case.clients"),
        (artifacts, "case.artifacts"), (binaries, "case.binaries"),
        (credentials, "case.credentials"), (auth, "case.auth"),
        (hosts, "case.hosts"),
    ):
        _unique(values, field)

    artifact_names = {item.name for item in artifacts}
    for declared_credential in credentials:
        if (
            declared_credential.artifact is not None
            and declared_credential.artifact.name not in artifact_names
        ):
            raise SpecError(
                "credential %s artifact" % declared_credential.name,
                declared_credential.artifact.name,
                "must be declared by the same case",
            )

    hostnames = [hostname for item in hosts for hostname in item.hostnames]
    duplicates = sorted({name for name in hostnames if hostnames.count(name) > 1})
    if duplicates:
        raise SpecError("case.hosts", duplicates, "hostnames and aliases must be unique")
    reverse_addresses = [mapping.address for mapping in hosts if mapping.reverse]
    duplicates = sorted({
        address for address in reverse_addresses if reverse_addresses.count(address) > 1
    })
    if duplicates:
        raise SpecError("case.hosts", duplicates, "reverse-enabled addresses must be unique")

    server_names = {item.name for item in servers}
    server_scopes = {item.name: item.scope for item in servers}
    for declared_server in servers:
        if (
            declared_server.probe.kind != "none"
            and declared_server.probe.endpoint not in declared_server.ports
        ):
            raise SpecError(
                "server %s readiness.port" % declared_server.name,
                declared_server.probe.endpoint,
                "must name a declared endpoint",
            )
        dependencies = set(declared_server.depends_on)
        missing = sorted(dependencies - server_names)
        if missing:
            raise SpecError(
                "server %s depends_on" % declared_server.name, ", ".join(missing),
                "dependencies must be servers declared by the same case",
            )
        if declared_server.scope in ("class", "module", "package", "session"):
            shorter = sorted(
                name for name in dependencies
                if server_scopes[name] != declared_server.scope
            )
            if shorter:
                raise SpecError(
                    "server %s depends_on" % declared_server.name, ", ".join(shorter),
                    "a %s server can only depend on servers with the same scope"
                    % declared_server.scope,
                )


def _merge_resources(
    explicit: Sequence[object], inferred: Sequence[object], field: str,
) -> tuple[object, ...]:
    """Merge resource shorthand with explicit lists while rejecting disagreement."""
    result = list(explicit)
    by_name = {getattr(item, "name", None): item for item in result}
    for item in inferred:
        name = getattr(item, "name", None)
        previous = by_name.get(name)
        if previous is not None:
            if previous != item:
                raise SpecError(field, name, "same name has conflicting declarations")
            continue
        result.append(item)
        by_name[name] = item
    return tuple(result)


def _classify_resources(values: Sequence[object]) -> Mapping[str, tuple[object, ...]]:
    from brixtest.auth.models import AuthRecipe
    from brixtest.credentials import Credential
    from brixtest.network import HostMapping

    groups: dict[str, list[object]] = {
        "servers": [], "clients": [], "artifacts": [], "binaries": [],
        "credentials": [], "auth": [], "hosts": [], "observe": [],
    }
    types = (
        (Server, "servers"), (Client, "clients"), (Artifact, "artifacts"),
        (Binary, "binaries"), (Credential, "credentials"),
        (AuthRecipe, "auth"), (HostMapping, "hosts"),
        (CollectorSpec, "observe"),
    )
    for item in values:
        for expected, field in types:
            if isinstance(item, expected):
                groups[field].append(item)
                break
        else:
            raise SpecError(
                "case.resources", item,
                "must contain a server, tool/client, artifact, binary, credential, auth, host, or collector declaration",
            )
    return freeze_mapping({name: tuple(items) for name, items in groups.items()})


def _resource_dependencies(
    servers: Sequence[Server], clients: Sequence[Client],
) -> Mapping[str, tuple[object, ...]]:
    from brixtest.credentials import Credential

    binaries: list[Binary] = []
    artifacts: list[Artifact] = []
    credentials: list[Credential] = []
    for owner in (*servers, *clients):
        binaries.extend(owner.binaries)
        binaries.extend(part for part in owner.command if isinstance(part, Binary))
        for declared_mount in owner.mounts:
            if isinstance(declared_mount.source, Artifact):
                artifacts.append(declared_mount.source)
            elif isinstance(declared_mount.source, Credential):
                credentials.append(declared_mount.source)
    for declared_credential in tuple(credentials):
        if declared_credential.artifact is not None:
            artifacts.append(declared_credential.artifact)
    return freeze_mapping({
        "binaries": tuple(binaries), "artifacts": tuple(artifacts),
        "credentials": tuple(credentials),
    })


def case(
    *declared_resources: object,
    resources: Sequence[object] = (),
    servers: Sequence[Server] = (),
    clients: Sequence[Client] = (),
    artifacts: Sequence[Artifact] = (),
    binaries: Sequence[Binary] = (),
    credentials: Sequence[Credential] = (),
    auth: Sequence[AuthRecipe] = (),
    hosts: Sequence[HostMapping] = (),
    observe: Sequence[CollectorSpec] = (process_tree(),),
    trials: int = 1,
    warmup: int = 0,
    timeout: float = 120.0,
    backend: str = "auto",
    isolation: Optional[Isolation] = None,
    keep: str = "failed",
) -> Callable[[_Function], _Function]:
    """Decorate a pytest function; positional/``resources`` values are inferred."""
    if isinstance(resources, (str, bytes)) or not isinstance(resources, Sequence):
        raise SpecError("case.resources", resources, "must be a declaration sequence")
    inferred = _classify_resources((*declared_resources, *tuple(resources)))
    servers = _merge_resources(servers, inferred["servers"], "case.servers")
    clients = _merge_resources(clients, inferred["clients"], "case.clients")
    artifacts = _merge_resources(artifacts, inferred["artifacts"], "case.artifacts")
    binaries = _merge_resources(binaries, inferred["binaries"], "case.binaries")
    credentials = _merge_resources(
        credentials, inferred["credentials"], "case.credentials"
    )
    auth = _merge_resources(auth, inferred["auth"], "case.auth")
    hosts = _merge_resources(hosts, inferred["hosts"], "case.hosts")
    observe = _merge_resources(observe, inferred["observe"], "case.observe")
    dependencies = _resource_dependencies(servers, clients)
    binaries = _merge_resources(binaries, dependencies["binaries"], "case.binaries")
    artifacts = _merge_resources(artifacts, dependencies["artifacts"], "case.artifacts")
    credentials = _merge_resources(
        credentials, dependencies["credentials"], "case.credentials"
    )
    _validate_case_values(
        servers=servers, clients=clients, artifacts=artifacts, binaries=binaries,
        credentials=credentials, auth=auth, hosts=hosts, observe=observe,
        trials=trials, warmup=warmup, timeout=timeout, backend=backend,
        isolation=isolation, keep=keep,
    )

    def decorate(function: _Function) -> _Function:
        source = Path(function.__code__.co_filename).resolve()
        definition = CaseDefinition(
            servers=tuple(servers), clients=tuple(clients), artifacts=tuple(artifacts),
            binaries=tuple(binaries), credentials=tuple(credentials), auth=tuple(auth),
            hosts=tuple(hosts), observe=tuple(observe), trials=trials, warmup=warmup,
            timeout=timeout, backend=backend,
            isolation=isolation or process_isolation(), keep=keep, source=source,
        )
        setattr(function, "__brixtest_case__", definition)
        return function

    return decorate


def is_case(value: object) -> bool:
    """Return whether ``value`` is a function decorated with :func:`case`."""
    return isinstance(getattr(value, "__brixtest_case__", None), CaseDefinition)


def get_case(value: object) -> CaseDefinition:
    """Return a decorated function's case contract with a structured error."""
    definition = getattr(value, "__brixtest_case__", None)
    if not isinstance(definition, CaseDefinition):
        raise SpecError("case function", value, "must be decorated with @brixtest.case")
    return definition
