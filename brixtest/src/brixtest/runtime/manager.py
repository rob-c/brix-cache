"""Materialize and manage one Python-declared case inside its helper process."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import tempfile
import time
import uuid
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union

from brixtest.archive import archive_case_logs
from brixtest.clients.configured import ConfiguredClient
from brixtest.deploy.local import LocalBackend
from brixtest.design import Binary, CaseDefinition, Client, Server, Task
from brixtest.errors import CaseRunError, SpecError
from brixtest.evidence.runtime import EvidenceRuntime
from brixtest.fleet.kinds import KindProfile
from brixtest.fleet.registry import Registry
from brixtest.metrics import MetricRecorder
from brixtest.planning import compile_case, validate_capabilities
from brixtest.runtime.api import Run, Service
from brixtest.runtime.artifacts import ArtifactStore
from brixtest.runtime.backends import BackendContext, case_backend
from brixtest.runtime.binaries import BinaryStore
from brixtest.runtime.case_summary import finalize_evidence, write_case_summary
from brixtest.runtime.commands import CommandResult, CommandRunner
from brixtest.runtime.configs import ConfigStore
from brixtest.runtime.launchers import (
    ServerLaunchPlan,
)
from brixtest.runtime.managed import ManagedResourceRuntime
from brixtest.runtime.manager_local import CaseManagerLocalMixin
from brixtest.runtime.manager_clients import CaseManagerClientsMixin
from brixtest.runtime.manager_operations import CaseManagerOperationsMixin
from brixtest.runtime.resources import record_materialized_sizes
from brixtest.runtime.security import SecurityResources
from brixtest.runtime.topology import injected_services, owned_servers, service_records
from brixtest.util.configtext import render_cfg_strict

__all__ = ["CaseManager", "CommandResult", "Run", "Service"]

_KIND = KindProfile(
    name="brixtest-case-process", pidfile=None, stop="process-group",
    command=None, ports_only_quiescence=True,
)


def _run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return "%s-%d-%s" % (stamp, os.getpid(), uuid.uuid4().hex[:8])


def _run_root() -> Path:
    explicit = os.environ.get("BRIXTEST_CASE_RUN")
    if explicit:
        return Path(explicit).resolve()
    base = Path(os.environ.get(
        "BRIXTEST_RUNS", str(Path(tempfile.gettempdir()) / "brixtest-runs")
    )).resolve()
    return base / _run_id()


def _environment(name: str) -> Mapping[str, str]:
    try:
        value = json.loads(os.environ.get(name, "{}"))
    except (TypeError, ValueError):
        return {}
    return {
        str(key): str(item) for key, item in value.items()
    } if isinstance(value, dict) else {}


class _Ports:
    """Hold every selected port until its owning server is about to spawn."""

    def __init__(self) -> None:
        self._sockets: Dict[Tuple[str, str], socket.socket] = {}

    def reserve(
        self, server: str, role: str, requested: Optional[int], protocol: str = "tcp",
        family: str = "any",
    ) -> int:
        socket_family = socket.AF_INET6 if family in ("ipv6", "dual") else socket.AF_INET
        handle = socket.socket(
            socket_family,
            socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM,
        )
        handle.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if socket_family == socket.AF_INET6:
            handle.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, family != "dual")
        host = "::" if family == "dual" else ("::1" if family == "ipv6" else "127.0.0.1")
        try:
            handle.bind((host, requested or 0))
            if protocol == "tcp":
                handle.listen(1)
        except OSError as exc:
            handle.close()
            raise SpecError(
                "server %s ports[%s]" % (server, role), requested,
                "cannot reserve the port: %s" % exc,
            ) from exc
        port = int(handle.getsockname()[1])
        self._sockets[(server, role)] = handle
        return port

    def release_server(self, name: str) -> None:
        for key in [key for key in self._sockets if key[0] == name]:
            self._sockets.pop(key).close()

    def close(self) -> None:
        for handle in self._sockets.values():
            handle.close()
        self._sockets.clear()


class CaseManager(
    CaseManagerClientsMixin, CaseManagerLocalMixin, CaseManagerOperationsMixin,
):
    """Own all inputs and processes for exactly one test case."""

    def __init__(
        self, definition: CaseDefinition, nodeid: str, *, root: Optional[Path] = None
    ) -> None:
        self.definition = definition
        self.nodeid = nodeid
        self.root = Path(root).resolve() if root else _run_root()
        self.workspace = self.root / "workspace"
        self.source_root = definition.source.parent
        self.parameters = definition.parameters
        requested = os.environ.get("BRIXTEST_BACKEND", definition.backend)
        self.backend_name = "local" if requested == "auto" else requested
        self.kubernetes_context = ""
        self.binary_store = BinaryStore(self.root / "inputs" / "binaries", self.source_root)
        self.artifact_store = ArtifactStore(self.root / "inputs" / "artifacts", self.source_root)
        self.config_store = ConfigStore(self.root / "inputs" / "configs", self.source_root)
        self.security = SecurityResources(
            self.root / "inputs", self.source_root, self.artifact_store,
            definition.credentials, definition.auth, definition.hosts,
        )
        self.registry = Registry()
        self._ports = _Ports()
        self._backend: Optional[LocalBackend] = None
        self._case_backend = case_backend(self.backend_name)
        self._case_backend.validate(definition)
        self._resource_graph = compile_case(definition, self.backend_name)
        validate_capabilities(self._resource_graph.nodes)
        self._case_plan: Mapping[str, object] = {}
        self._started: list[str] = []
        self._services: Dict[str, Service] = {}
        self._server_launchers: Dict[str, object] = {}
        self._server_launch_plans: Dict[str, ServerLaunchPlan] = {}
        self._server_mounts: Dict[str, tuple[Path, ...]] = {}
        self._filesystems: Dict[str, object] = {}
        self._allocated_ports: Mapping[str, Mapping[str, int]] = {}
        self._services.update(injected_services(Service))
        self._clients: Dict[str, ConfiguredClient] = {}
        self._pytest_hook = None
        self._outcome = "running"
        self._started_at = time.time()
        self._started_cpu = time.process_time()
        self._metrics_finalized = False
        self.metrics = MetricRecorder()
        self.commands = CommandRunner(
            self.root / "runtime" / "command-logs", cwd=self.workspace,
            observer=self._observe_command,
        )
        session = Path(os.environ.get("BRIXTEST_METRICS_SESSION", str(self.root / "evidence")))
        self.evidence = EvidenceRuntime(
            root=self.root, session_dir=session, nodeid=nodeid,
            source_root=self.source_root, backend=self.backend_name,
            isolation=os.environ.get("BRIXTEST_ISOLATION_KIND", definition.isolation.kind),
            collectors=definition.observe,
        )
        self._managed = ManagedResourceRuntime(self)
        self.backend_context = BackendContext(self)
        self.metrics.tag("backend", self.backend_name)
        self.metrics.gauge("resources.servers", len(definition.servers), unit="count")
        self.metrics.gauge("resources.clients", len(definition.clients), unit="count")
        self.metrics.gauge("resources.artifacts", len(definition.artifacts), unit="count")
        self.metrics.gauge("resources.credentials", len(definition.credentials), unit="count")
        self.metrics.gauge("resources.auth_stacks", len(definition.auth), unit="count")
        self.metrics.gauge("resources.host_mappings", len(definition.hosts), unit="count")
        self.metrics.gauge("resources.tasks", len(definition.tasks), unit="count")
        self.metrics.gauge("resources.volumes", len(definition.volumes), unit="count")

    def start(self) -> Run:
        """Materialize resources, start the declared fleet, and return its facade."""
        self.root.mkdir(parents=True, exist_ok=False)
        self.workspace.mkdir()
        self.evidence.begin()
        self.metrics.set_sink(self.evidence.metric_event, replay=True)
        try:
            with self.metrics.timer("case.startup"):
                planned = self._case_backend.plan(self.backend_context)
                if not isinstance(planned, Mapping):
                    raise SpecError(
                        "case backend plan", type(planned).__name__,
                        "must be a mapping",
                    )
                self._case_plan = {
                    "backend": dict(planned),
                    "resource_graph": self._resource_graph.as_dict(),
                }
                self.evidence.attach_json(
                    "resource-plan.json", self._case_plan,
                    role="resource-plan", description="normalized immutable case plan",
                )
                self._case_backend.prepare(self.backend_context)
                value = self._case_backend.start(self.backend_context)
                if not isinstance(value, Run):
                    raise SpecError(
                        "case backend start", type(value).__name__,
                        "must return brixtest.Run",
                    )
            self.evidence.set_servers(service_records(self))
            record_materialized_sizes(self)
            self.evidence.start_collectors(self, self.metrics)
            self._write_summary()
            return value
        except Exception as exc:
            self._outcome = "setup-failed"
            self._ports.close()
            with contextlib.suppress(Exception):
                self._managed.run_phase("finalize")
            with contextlib.suppress(Exception):
                self._case_backend.stop(self.backend_context)
            with contextlib.suppress(Exception):
                self.security.close()
            self._finalize_metrics()
            finalize_evidence(self)
            self._write_summary(error=str(exc))
            session = os.environ.get("BRIXTEST_METRICS_SESSION")
            if session and os.environ.get("BRIXTEST_SHARED_POOL_OWNER") != "1":
                archive_case_logs(Path(session), self.nodeid, self.root)
            if isinstance(exc, (SpecError, CaseRunError)):
                raise
            raise CaseRunError(self.nodeid, "setup", str(exc)) from exc

    def _all_binaries(self) -> Tuple[Binary, ...]:
        found: Dict[str, Binary] = {}
        self._register_binary_groups(found, self._binary_groups())
        owners: Iterable[Union[Server, Client, Task]] = chain(
            owned_servers(self.definition), self.definition.clients,
            self.definition.tasks,
        )
        for owner in owners:
            self._register_binary_groups(found, (self._command_binaries(owner.command),))
        return tuple(found[name] for name in sorted(found))

    def _binary_groups(self) -> tuple[Iterable[Binary], ...]:
        server_groups = tuple(item.binaries for item in owned_servers(self.definition))
        client_groups = tuple(item.binaries for item in self.definition.clients)
        task_groups = tuple(item.binaries for item in self.definition.tasks)
        return (self.definition.binaries, *server_groups, *client_groups, *task_groups)

    @staticmethod
    def _command_binaries(command: Sequence[object]) -> tuple[Binary, ...]:
        return tuple(part for part in command if isinstance(part, Binary))

    @classmethod
    def _register_binary_groups(
        cls, found: Dict[str, Binary], groups: Iterable[Iterable[Binary]],
    ) -> None:
        for declarations in groups:
            for declaration in declarations:
                cls._register_binary(found, declaration)

    @staticmethod
    def _register_binary(found: Dict[str, Binary], declaration: Binary) -> None:
        previous = found.get(declaration.name)
        if previous is not None and previous != declaration:
            raise SpecError("binary", declaration.name, "declarations disagree")
        found[declaration.name] = declaration

    def _allocate_ports(self, servers: Sequence[Server]) -> Dict[str, Dict[str, int]]:
        allocated: Dict[str, Dict[str, int]] = {}
        for server in servers:
            protocols = {item.name: item.protocol for item in server.endpoints}
            families = {item.name: item.family for item in server.endpoints}
            roles = {
                role: self._ports.reserve(
                    server.name, role, requested, protocols.get(role, "tcp"),
                    families.get(role, "any"),
                )
                for role, requested in server.ports.items()
            }
            if "primary" not in roles:
                role = (
                    server.probe.endpoint if server.probe.kind != "none"
                    else next(iter(server.ports))
                )
                roles["primary"] = roles[role]
            allocated[server.name] = roles
        return allocated

    def _global_values(
        self, ports: Mapping[str, Mapping[str, int]], *,
        credential_base: Optional[Path] = None, auth_base: Optional[Path] = None,
    ) -> Dict[str, object]:
        selected_ports = ports or self._allocated_ports
        values: Dict[str, object] = {
            "run_root": self.root, "workspace": self.workspace,
            "artifacts": self.artifact_store.root,
        }
        self._parameter_values(values)
        self._captured_values(values)
        values.update(self.security.values(
            credential_base=credential_base, auth_base=auth_base,
        ))
        self._declared_server_values(values, selected_ports)
        self._service_values(values)
        return values

    def _parameter_values(self, values: Dict[str, object]) -> None:
        for name, value in self.parameters.items():
            values["param_%s" % name] = (
                value if isinstance(value, (str, int, float, bool, Path)) else str(value)
            )

    def _captured_values(self, values: Dict[str, object]) -> None:
        for name, captured_binary in self.binary_store._captured.items():
            values["binary_%s" % name] = captured_binary.path
            values["binary_%s_dir" % name] = captured_binary.path.parent
        for name, materialized_artifact in self.artifact_store._items.items():
            values["artifact_%s" % name] = materialized_artifact.path
            values["artifact_%s_dir" % name] = materialized_artifact.path.parent
        values.update(self._managed.values)
        for declaration in self.definition.environments:
            values["environment_%s_name" % declaration.name] = declaration.name
            values["environment_%s_context" % declaration.name] = declaration.context
            values["environment_%s_namespace" % declaration.name] = declaration.namespace
        for declaration in self.definition.identities:
            values["identity_%s_name" % declaration.name] = declaration.name
            values["identity_%s_service_account" % declaration.name] = (
                declaration.service_account
            )

    def _declared_server_values(
        self, values: Dict[str, object], ports: Mapping[str, Mapping[str, int]],
    ) -> None:
        for name, roles in ports.items():
            self._add_declared_server_values(values, name, roles)

    def _declared_server(self, name: str) -> Optional[Server]:
        return next((item for item in self.definition.servers if item.name == name), None)

    def _declared_server_schemes(self, name: str) -> Dict[str, str]:
        declaration = self._declared_server(name)
        return {
            item.name: item.scheme for item in getattr(declaration, "endpoints", ())
        }

    def _declared_server_hosts(self, name: str) -> Dict[str, str]:
        declaration = self._declared_server(name)
        if declaration is None:
            return {"primary": "127.0.0.1"}
        return _server_hosts(declaration, bind=False)

    def _add_declared_server_values(
        self, values: Dict[str, object], name: str, roles: Mapping[str, int],
    ) -> None:
        hosts = self._declared_server_hosts(name)
        values["server_%s_host" % name] = hosts["primary"]
        schemes = self._declared_server_schemes(name)
        for role, port in roles.items():
            host = hosts.get(role, hosts["primary"])
            values["server_%s_%s_host" % (name, role)] = host
            values["server_%s_%s_port" % (name, role)] = port
            scheme = schemes.get(role) or "http"
            values["server_%s_%s_url" % (name, role)] = (
                "%s://%s:%d" % (scheme, _url_host(host), port)
            )
        values["server_%s_url" % name] = "http://%s:%d" % (
            _url_host(hosts["primary"]), roles["primary"],
        )

    def _service_values(self, values: Dict[str, object]) -> None:
        for name, service in self._services.items():
            values["server_%s_host" % name] = service.host
            values["server_%s_url" % name] = service.url()
            values["server_%s_config" % name] = service.config
            values["server_%s_log" % name] = service.log
            for role, port in service.ports.items():
                values["server_%s_%s_host" % (name, role)] = service.address(role)[0]
                values["server_%s_%s_port" % (name, role)] = port
                values["server_%s_%s_url" % (name, role)] = service.url(role=role)

    def _render_part(self, part: object, values: Mapping[str, object], label: str) -> str:
        if isinstance(part, Binary):
            return str(self.binary_store.get(part.name).path)
        return render_cfg_strict(str(part), values, template=label)

    def _render_value(self, value: object, *, label: str = "runtime value") -> str:
        """Resolve a typed reference or compatibility placeholder at call time."""
        return self._render_part(value, self._global_values({}), label)

    def _write_summary(self, *, error: str = "") -> None:
        write_case_summary(self, error=error)


def _primary_role(declaration: Server) -> str:
    if "primary" in declaration.ports:
        return "primary"
    if declaration.probe.kind != "none":
        return declaration.probe.endpoint
    return next(iter(declaration.ports))


def _server_hosts(declaration: Server, *, bind: bool) -> Dict[str, str]:
    hosts = {}
    for endpoint in declaration.endpoints:
        if endpoint.family == "dual":
            hosts[endpoint.name] = "::" if bind else "::1"
        elif endpoint.family == "ipv6":
            hosts[endpoint.name] = "::1"
        else:
            hosts[endpoint.name] = "127.0.0.1"
    primary = _primary_role(declaration)
    hosts["primary"] = hosts.get(primary, hosts.get("primary", "127.0.0.1"))
    return hosts


def _url_host(value: str) -> str:
    return "[%s]" % value if ":" in value and not value.startswith("[") else value
