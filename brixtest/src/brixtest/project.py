"""File-configured BriXTest projects and the single test-facing fixture.

``Project.load()`` turns ``configs/servers.json`` and
``configs/clients.json`` into the same registry, launcher, and client objects
used by the lower-level API.  ``activate_project()`` installs those objects in
pytest and exposes one ``brix`` fixture for new tests.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
import warnings
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence

import pytest

from brixtest.clients import ClientRegistry, ClientSpec, ConfiguredClient
from brixtest.config.lanes import Lane
from brixtest.config.settings import env_bool, env_int, env_str
from brixtest.errors import SpecError
from brixtest.fleet.declares import DeclarationMap
from brixtest.fleet.kinds import KindProfile, get_kind, known_kinds, register_kind
from brixtest.fleet.registry import InstanceSpec, Registry, ServerEndpoint
from brixtest.harness.plugin import BrixTestPlugin, FleetHandle, HarnessConfig, activate
from brixtest.services.logs import LogView
from brixtest.util.configtext import render_cfg_strict

__all__ = ["Brix", "Project", "ProjectActivation", "activate_project"]

_PROCESS_KIND = KindProfile(
    name="process",
    pidfile=None,
    stop="port-kill",
    command=None,
    ports_only_quiescence=True,
)
_SERVER_TOP_LEVEL = frozenset({"lane", "harness", "declarations", "servers"})
_CLIENT_TOP_LEVEL = frozenset({"clients"})
_LANE_FIELDS = frozenset({"root", "port_base", "port_span", "dynamic_port_offset"})
_HARNESS_FIELDS = frozenset({
    "gate_mode", "manage_fleet", "workers", "session_name",
    "capture_results", "watch_resources", "spec_validation",
    "strict_templates", "file_linear",
})
_DECLARATION_FIELDS = frozenset({"fixture_specs", "port_name_specs", "backbone"})
_CLIENT_FIELDS = frozenset({"command", "env", "cwd", "timeout"})
_SPEC_FIELDS = frozenset(field.name for field in dataclasses.fields(InstanceSpec))
_SERVER_FIELDS = (_SPEC_FIELDS - {"name", "ports"}) | {"ports", "port_offsets"}
_TOKEN_FIELDS = frozenset({"python", "project_root", "repo_root", "src_root"})


def _mapping(value: object, field: str) -> Dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SpecError(field, value, "must be a JSON object with string keys")
    return dict(value)


def _unknown_fields(data: Mapping[str, object], allowed: Sequence[str], field: str) -> None:
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise SpecError(
            field, ", ".join(unknown),
            "unknown field(s) — known: %s" % ", ".join(sorted(allowed)),
        )


def _read_json(path: Path, *, required: bool) -> Dict[str, object]:
    try:
        text = path.read_text()
    except FileNotFoundError:
        if not required:
            return {}
        raise SpecError("project config", str(path), "file does not exist") from None
    except OSError as exc:
        raise SpecError("project config", str(path), "cannot be read: %s" % exc) from exc
    try:
        raw = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise SpecError("project config", str(path), "invalid JSON: %s" % exc) from exc
    return _mapping(raw, "project config %s" % path.name)


def _project_path(root: Path, raw: object, field: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise SpecError(field, raw, "must be a non-empty project-relative path")
    candidate = Path(raw)
    resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise SpecError(
            field, raw, "must stay inside the BriXTest project root %s" % root
        ) from None
    return resolved


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError(field, value, "must be an integer")
    return value


def _server_ports(raw, name: str, lane: Lane) -> None:
    offsets = raw.pop("port_offsets", None)
    ports = raw.get("ports")
    if offsets is not None and ports is not None:
        raise SpecError("servers.%s ports" % name, raw, "use either ports or port_offsets, not both")
    if offsets is not None:
        values = _mapping(offsets, "servers.%s.port_offsets" % name)
        raw["ports"] = {
            role: lane.port_base + _integer(value, "servers.%s.port_offsets.%s" % (name, role))
            for role, value in values.items()
        }
    elif ports is not None:
        values = _mapping(ports, "servers.%s.ports" % name)
        raw["ports"] = {
            role: _integer(value, "servers.%s.ports.%s" % (name, role))
            for role, value in values.items()
        }
    raw.setdefault("ports", {})


def _server_execution(raw, name: str) -> None:
    raw.setdefault("kind", "process")
    command = raw.get("command")
    _validate_server_command(raw["kind"], name, command)
    environment = _mapping(raw.get("env", {}), "servers.%s.env" % name)
    _validate_server_environment(name, environment)
    raw["env"] = environment


def _validate_server_command(kind: str, name: str, command: object) -> None:
    if kind == "process" and not command:
        raise SpecError("servers.%s.command" % name, command, "is required for the generic process kind")
    if command is not None and (
        not isinstance(command, list) or not command
        or not all(isinstance(part, str) for part in command)
    ):
        raise SpecError(
            "servers.%s.command" % name, command,
            "must be a non-empty JSON array of string arguments",
        )


def _validate_server_environment(name: str, environment: Mapping[str, object]) -> None:
    if not all(isinstance(value, str) for value in environment.values()):
        raise SpecError("servers.%s.env" % name, environment, "must map names to string values")


def _server_configuration(raw, name: str, root: Path, tokens) -> None:
    template = raw.get("config_template")
    if template is not None:
        raw["config_template"] = str(_project_path(
            root, template, "servers.%s.config_template" % name,
        ))
    values = _mapping(raw.get("config_values", {}), "servers.%s.config_values" % name)
    collisions = sorted(_TOKEN_FIELDS & set(values))
    if collisions:
        raise SpecError(
            "servers.%s.config_values" % name, ", ".join(collisions),
            "cannot override reserved project template values",
        )
    values.update(tokens)
    raw["config_values"] = values


@dataclasses.dataclass(frozen=True)
class Project:
    """A loaded project: lane, server catalogue, clients, and harness policy."""

    root: Path
    lane: Lane
    servers: Sequence[InstanceSpec]
    clients: ClientRegistry
    declarations: DeclarationMap
    harness_values: Mapping[str, object]
    dynamic_port_offset: int

    @classmethod
    def load(
        cls,
        root: Path,
        *,
        env: Optional[Mapping[str, str]] = None,
    ) -> "Project":
        project_root = Path(root).resolve()
        server_data = _read_json(
            project_root / "configs" / "servers.json", required=True
        )
        client_data = _read_json(
            project_root / "configs" / "clients.json", required=False
        )
        _unknown_fields(server_data, _SERVER_TOP_LEVEL, "servers.json")
        _unknown_fields(client_data, _CLIENT_TOP_LEVEL, "clients.json")

        environ = os.environ if env is None else env
        repo_root = project_root.parent
        src_root = project_root / "src"
        tokens: Dict[str, object] = {
            "python": sys.executable,
            "project_root": project_root,
            "repo_root": repo_root,
            "src_root": src_root,
            "uid": os.getuid(),
        }
        lane_data = _mapping(server_data.get("lane", {}), "lane")
        _unknown_fields(lane_data, _LANE_FIELDS, "lane")
        default_root = render_cfg_strict(
            str(lane_data.get("root", "/tmp/brixtest-{uid}")),
            tokens,
            template="lane.root",
        )
        lane_root = Path(env_str("BRIXTEST_LANE_ROOT", default_root, env=environ))
        port_base = env_int(
            "BRIXTEST_PORT_BASE",
            _integer(lane_data.get("port_base", 39000), "lane.port_base"),
            env=environ,
        )
        port_span = env_int(
            "BRIXTEST_PORT_SPAN",
            _integer(lane_data.get("port_span", 1000), "lane.port_span"),
            env=environ,
        )
        if port_span < 2:
            raise SpecError("lane.port_span", port_span, "must be at least 2")
        lane = Lane(lane_root, port_base=port_base, port_span=port_span)
        default_dynamic = _integer(
            lane_data.get("dynamic_port_offset", min(700, port_span - 1)),
            "lane.dynamic_port_offset",
        )
        dynamic_offset = env_int(
            "BRIXTEST_DYNAMIC_PORT_OFFSET", default_dynamic, env=environ
        )
        if not 0 < dynamic_offset < port_span:
            raise SpecError(
                "lane.dynamic_port_offset", dynamic_offset,
                "must fall inside the lane span (1-%d)" % (port_span - 1),
            )

        tokens.update({"lane_root": lane.root, "port_base": lane.port_base})
        servers = cls._load_servers(project_root, server_data, lane, tokens)
        clients = cls._load_clients(client_data, tokens)
        declarations = cls._load_declarations(server_data)
        harness_values = cls._load_harness(server_data, environ)
        return cls(
            root=project_root,
            lane=lane,
            servers=tuple(servers),
            clients=clients,
            declarations=declarations,
            harness_values=harness_values,
            dynamic_port_offset=dynamic_offset,
        )

    @staticmethod
    def _load_servers(
        root: Path,
        data: Mapping[str, object],
        lane: Lane,
        tokens: Mapping[str, object],
    ) -> Sequence[InstanceSpec]:
        declared = _mapping(data.get("servers", {}), "servers")
        specs = []
        for name, value in declared.items():
            raw = _mapping(value, "servers.%s" % name)
            _unknown_fields(raw, _SERVER_FIELDS, "servers.%s" % name)
            _server_ports(raw, name, lane)
            _server_execution(raw, name)
            _server_configuration(raw, name, root, tokens)
            specs.append(InstanceSpec.from_dict({"name": name, **raw}))
        return specs

    @staticmethod
    def _load_clients(
        data: Mapping[str, object], values: Mapping[str, object]
    ) -> ClientRegistry:
        declared = _mapping(data.get("clients", {}), "clients")
        specs = []
        for name, value in declared.items():
            raw = _mapping(value, "clients.%s" % name)
            _unknown_fields(raw, _CLIENT_FIELDS, "clients.%s" % name)
            specs.append(ClientSpec(name=name, **raw))
        return ClientRegistry(specs, values=values)

    @staticmethod
    def _load_declarations(data: Mapping[str, object]) -> DeclarationMap:
        raw = _mapping(data.get("declarations", {}), "declarations")
        _unknown_fields(raw, _DECLARATION_FIELDS, "declarations")
        return DeclarationMap(**raw)

    @staticmethod
    def _load_harness(
        data: Mapping[str, object], env: Mapping[str, str]
    ) -> Dict[str, object]:
        raw = _mapping(data.get("harness", {}), "harness")
        _unknown_fields(raw, _HARNESS_FIELDS, "harness")
        booleans = (
            ("manage_fleet", "BRIXTEST_MANAGE_FLEET", True),
            ("capture_results", "BRIXTEST_CAPTURE_RESULTS", True),
            ("watch_resources", "BRIXTEST_WATCH_RESOURCES", True),
            ("strict_templates", "BRIXTEST_STRICT_TEMPLATES", False),
            ("file_linear", "BRIXTEST_FILE_LINEAR", True),
        )
        for field, env_name, default in booleans:
            configured = raw.get(field, default)
            if not isinstance(configured, bool):
                raise SpecError("harness.%s" % field, configured, "must be boolean")
            raw[field] = env_bool(env_name, configured, env=env)
        return raw

    def register_kinds(self) -> None:
        if _PROCESS_KIND.name not in known_kinds():
            register_kind(_PROCESS_KIND)
            return
        if get_kind(_PROCESS_KIND.name) != _PROCESS_KIND:
            raise SpecError(
                "kind", _PROCESS_KIND.name,
                "is already registered with a different profile",
            )

    def register_catalogue(self, registry: Registry) -> None:
        for spec in self.servers:
            registry.register(spec)

    def harness_config(self) -> HarnessConfig:
        return HarnessConfig(
            lane=self.lane,
            register_kinds=self.register_kinds,
            register_catalogue=self.register_catalogue,
            declaration_map=lambda: self.declarations,
            dynamic_port_offset=self.dynamic_port_offset,
            **dict(self.harness_values),
        )


@dataclasses.dataclass(frozen=True)
class Brix:
    """The uniform test surface exposed as the function-scoped ``brix`` fixture."""

    fleet: FleetHandle
    clients: ClientRegistry
    workspace: Path

    def server(self, name: str) -> ServerEndpoint:
        return self.fleet.endpoint(name)

    def client(self, name: str) -> ConfiguredClient:
        return self.clients.get(name)

    def url(
        self,
        name: str,
        scheme: str = "http",
        *,
        role: str = "primary",
        path: str = "/",
    ) -> str:
        return self.fleet.url(name, scheme, role=role, path=path)

    def log(self, name: str) -> LogView:
        return self.fleet.log_view(name)

    def artifact(self, name: str) -> Path:
        return self.fleet.artifacts.path(name)

    def request_server(self, **kwargs: object) -> ServerEndpoint:
        return self.fleet.request_server(**kwargs)


class _ProjectPlugin:
    def __init__(self, project: Project) -> None:
        self.project = project

    @pytest.fixture(name="brix")
    def brix_fixture(self, fleet: FleetHandle, workspace: Path) -> Brix:
        return Brix(fleet=fleet, clients=self.project.clients, workspace=workspace)


@dataclasses.dataclass(frozen=True)
class ProjectActivation:
    project: Project
    harness: BrixTestPlugin

    def stop(self) -> None:
        self.harness.launcher.stop()


def activate_project(pytest_config, root: Path) -> ProjectActivation:
    """Load a legacy ``root/configs`` project and activate its fixtures."""
    warnings.warn(
        "brixtest.project is the legacy catalogue API; new tests should use "
        "@brixtest.case with the run fixture",
        DeprecationWarning, stacklevel=2,
    )
    project = Project.load(root)
    harness = activate(pytest_config, project.harness_config())
    pytest_config.pluginmanager.register(
        _ProjectPlugin(project), name="brixtest-project"
    )
    return ProjectActivation(project=project, harness=harness)
