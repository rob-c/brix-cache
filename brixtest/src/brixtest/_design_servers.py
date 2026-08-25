"""Server declarations and their author-facing factory."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Mapping, Optional, Sequence, Union, overload

from brixtest._design_inputs import (
    Binary,
    ConfigFile,
    ConfigSet,
    Readiness,
    _argv,
    _name,
    _string_mapping,
)
from brixtest._design_server_factory import (
    _server_command,
    _server_configuration,
    _server_port_map,
)
from brixtest.errors import SpecError
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
    server_ref,
)
from brixtest.util.immutable import freeze_mapping


def _normalize_server_configs(declaration: "Server") -> None:
    selected = _server_primary_config(declaration)
    configs = _server_config_set(declaration.configs, selected)
    if selected not in configs.files:
        configs = ConfigSet((selected, *configs.files), selected.destination)
    object.__setattr__(declaration, "config", configs.primary_file)
    object.__setattr__(declaration, "configs", configs)


def _server_primary_config(declaration: "Server") -> ConfigFile:
    selected = declaration.config
    if selected is None:
        selected = ConfigFile(
            content="",
            destination="%s.conf" % declaration.name,
            template=False,
        )
        metadata = dict(declaration.metadata)
        metadata.setdefault("brixtest.synthetic_config", True)
        object.__setattr__(declaration, "metadata", metadata)
        object.__setattr__(declaration, "config", selected)
    if not isinstance(selected, ConfigFile):
        raise SpecError("server.config", selected, "must be a ConfigFile declaration")
    return selected


def _server_config_set(configs: object, selected: ConfigFile) -> ConfigSet:
    configs = configs or ConfigSet((selected,), selected.destination)
    if not isinstance(configs, ConfigSet):
        if isinstance(configs, Sequence) and not isinstance(configs, (str, bytes)):
            return ConfigSet(tuple(configs), selected.destination)
        raise SpecError("server.configs", configs, "must be a ConfigSet")
    return configs


def _normalize_server_ports(declaration: "Server") -> dict[str, Optional[int]]:
    if not isinstance(declaration.ports, Mapping):
        raise SpecError("server.ports", declaration.ports, "must map role names to ports")
    normalized = {}
    for role, port in declaration.ports.items():
        _name(role, "server.port role")
        invalid = port is not None and (
            isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536
        )
        if invalid:
            raise SpecError("server.ports[%s]" % role, port, "must be a TCP port or None")
        normalized[role] = port
    if not normalized:
        raise SpecError("server.ports", declaration.ports, "must declare at least one role")
    return normalized


def _normalize_server_dependencies(declaration: "Server") -> None:
    values = declaration.depends_on
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise SpecError("server.depends_on", values, "must be a server sequence")
    if not all(_valid_server_dependency(item) for item in values):
        raise SpecError(
            "server.depends_on", values,
            "must contain names or Server, Task, or Resource declarations",
        )
    object.__setattr__(
        declaration,
        "depends_on",
        tuple(item if isinstance(item, str) else item.name for item in values),
    )


def _valid_server_dependency(value: object) -> bool:
    return isinstance(value, (str, Server)) or getattr(
        value, "resource_kind", "",
    ) in {"server", "task", "resource"}


def _normalize_server_endpoints(
    declaration: "Server",
    ports: dict[str, Optional[int]],
) -> None:
    endpoints = _server_endpoints(declaration, ports)
    _validate_server_endpoints(endpoints)
    for item in endpoints:
        _merge_endpoint(ports, item)
    object.__setattr__(declaration, "ports", freeze_mapping(ports))
    object.__setattr__(declaration, "endpoints", endpoints)


def _server_endpoints(
    declaration: "Server", ports: Mapping[str, Optional[int]],
) -> tuple[Endpoint, ...]:
    if declaration.endpoints:
        return tuple(declaration.endpoints)
    return tuple(Endpoint(role, "tcp", port) for role, port in ports.items())


def _validate_server_endpoints(endpoints: Sequence[object]) -> None:
    if not all(isinstance(item, Endpoint) for item in endpoints):
        raise SpecError("server.endpoints", endpoints, "must contain Endpoint declarations")
    names = [item.name for item in endpoints]
    if len(set(names)) != len(names):
        raise SpecError("server.endpoints", names, "names must be unique")


def _merge_endpoint(ports: dict[str, Optional[int]], endpoint: Endpoint) -> None:
    if endpoint.name not in ports:
        ports[endpoint.name] = endpoint.port
        return
    if endpoint.port is not None and ports[endpoint.name] not in (None, endpoint.port):
        raise SpecError(
            "server endpoint %s" % endpoint.name,
            endpoint.port,
            "conflicts with the declared port",
        )


def _normalize_server_process(declaration: "Server") -> None:
    if not isinstance(declaration.readiness, Readiness):
        raise SpecError(
            "server.readiness", declaration.readiness, "must be a Readiness declaration"
        )
    if not all(isinstance(item, Binary) for item in declaration.binaries):
        raise SpecError("server.binaries", declaration.binaries, "must contain Binary declarations")
    if declaration.image is not None and not isinstance(declaration.image, str):
        raise SpecError("server.image", declaration.image, "must be text")
    if declaration.scope not in (
        "case", "function", "class", "module", "package", "session", "worker",
    ):
        raise SpecError(
            "server.scope",
            declaration.scope,
            "must be case, function, class, module, package, session, or worker",
        )
    object.__setattr__(declaration, "command", _argv(declaration.command, "server.command"))
    object.__setattr__(declaration, "env", _string_mapping(declaration.env, "server.env"))
    object.__setattr__(declaration, "binaries", tuple(declaration.binaries))


def _normalize_server_resources(declaration: "Server") -> None:
    probe = declaration.probe or Probe(
        declaration.readiness.kind, declaration.readiness.port, declaration.readiness.timeout
    )
    if not isinstance(probe, Probe):
        raise SpecError("server.probe", probe, "must be a Probe declaration")
    if not all(isinstance(item, Mount) for item in declaration.mounts):
        raise SpecError("server.mounts", declaration.mounts, "must contain Mount declarations")
    _validate_server_resource_types(declaration)
    _validate_server_working_directory(declaration)
    if not isinstance(declaration.metadata, Mapping):
        raise SpecError("server.metadata", declaration.metadata, "must be a mapping")
    object.__setattr__(declaration, "probe", probe)
    object.__setattr__(declaration, "mounts", tuple(declaration.mounts))
    object.__setattr__(declaration, "metadata", freeze_mapping(declaration.metadata))


def _validate_server_resource_types(declaration: "Server") -> None:
    for name, expected in (
        ("lifecycle", Lifecycle),
        ("placement", Placement),
        ("logs", LogPolicy),
    ):
        if not isinstance(getattr(declaration, name), expected):
            raise SpecError(
                "server.%s" % name, getattr(declaration, name), "has the wrong declaration type"
            )
    if not declaration.lifecycle.background and declaration.scope not in ("case", "function"):
        raise SpecError(
            "server.lifecycle.background",
            declaration.scope,
            "foreground commands require case or function scope",
        )


def _validate_server_working_directory(declaration: "Server") -> None:
    if not isinstance(declaration.cwd, str):
        raise SpecError("server.cwd", declaration.cwd, "must be a confined relative path")
    path = Path(declaration.cwd)
    if path.is_absolute() or ".." in path.parts:
        raise SpecError("server.cwd", declaration.cwd, "must be a confined relative path")


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
    replicas: int = 1

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
        _normalize_server_configs(self)
        _normalize_server_process(self)
        ports = _normalize_server_ports(self)
        _normalize_server_dependencies(self)
        _normalize_server_endpoints(self, ports)
        _normalize_server_resources(self)
        if (
            isinstance(self.replicas, bool) or not isinstance(self.replicas, int)
            or self.replicas < 1
        ):
            raise SpecError("server.replicas", self.replicas, "must be an integer >= 1")


@overload
def server(
    name: str,
    *,
    execution: Execution,
    config: Optional[ConfigFile] = None,
    configs: Union[Sequence[ConfigFile], ConfigSet] = (),
    ports: Union[Sequence[str], Mapping[str, Optional[int]]] = ("primary",),
    env: Optional[Mapping[str, object]] = None,
    readiness: Optional[Readiness] = None,
    endpoints: Sequence[Endpoint] = (),
    probe: Optional[Probe] = None,
    depends_on: Sequence[Union[str, Server]] = (),
    binaries: Sequence[Binary] = (),
    image: Optional[str] = None,
    scope: str = "case",
    mounts: Sequence[Mount] = (),
    lifecycle: Optional[Lifecycle] = None,
    placement: Optional[Placement] = None,
    logs: Optional[LogPolicy] = None,
    cwd: str = "",
    metadata: Optional[Mapping[str, object]] = None,
    replicas: int = 1,
) -> Server: ...


@overload
def server(
    name: str,
    *,
    binary: Binary,
    args: Sequence[object] = (),
    config: Optional[ConfigFile] = None,
    configs: Union[Sequence[ConfigFile], ConfigSet] = (),
    ports: Union[Sequence[str], Mapping[str, Optional[int]]] = ("primary",),
    env: Optional[Mapping[str, object]] = None,
    readiness: Optional[Readiness] = None,
    endpoints: Sequence[Endpoint] = (),
    probe: Optional[Probe] = None,
    depends_on: Sequence[Union[str, Server]] = (),
    binaries: Sequence[Binary] = (),
    image: Optional[str] = None,
    scope: str = "case",
    mounts: Sequence[Mount] = (),
    lifecycle: Optional[Lifecycle] = None,
    placement: Optional[Placement] = None,
    logs: Optional[LogPolicy] = None,
    cwd: str = "",
    metadata: Optional[Mapping[str, object]] = None,
    replicas: int = 1,
) -> Server: ...


@overload
def server(
    name: str,
    *,
    command: Union[Sequence[object], Command],
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
    replicas: int = 1,
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
    replicas: int = 1,
) -> Server:
    """Declare one managed server using ``command`` or ``binary`` + ``args``."""
    command, env, cwd = _server_command(
        name,
        command,
        execution,
        binary,
        args,
        env,
        cwd,
    )
    config, selected_configs, metadata = _server_configuration(
        name,
        config,
        configs,
        metadata,
    )
    port_map = _server_port_map(ports, endpoints)
    return Server(
        name=name,
        command=command,
        config=config,
        ports=port_map,
        env=_string_mapping(env, "server.env"),
        readiness=Readiness() if readiness is None else readiness,
        depends_on=depends_on,
        binaries=binaries,
        image=image,
        scope=scope,
        configs=selected_configs,
        endpoints=endpoints,
        probe=probe,
        mounts=mounts,
        lifecycle=Lifecycle() if lifecycle is None else lifecycle,
        placement=Placement(image=image) if placement is None else placement,
        logs=LogPolicy() if logs is None else logs,
        cwd=cwd,
        metadata=metadata,
        replicas=replicas,
    )
