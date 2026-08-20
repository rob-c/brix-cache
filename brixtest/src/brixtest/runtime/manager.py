"""Materialize and manage one Python-declared case inside its helper process."""

from __future__ import annotations

import json
import os
import resource
import shutil
import socket
import tempfile
import time
import uuid
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union

from brixtest.archive import archive_case_logs
from brixtest.clients.configured import ClientSpec, ConfiguredClient, ConfiguredTool
from brixtest.config.lanes import Lane
from brixtest.deploy.local import LocalBackend
from brixtest.credentials import Credential
from brixtest.design import Artifact, Binary, CaseDefinition, Client, ConfigFile, Server, Tool
from brixtest.errors import CaseRunError, SpecError
from brixtest.evidence.runtime import EvidenceRuntime
from brixtest.fleet.kinds import KindProfile, get_kind, known_kinds, register_kind
from brixtest.fleet.launcher import FleetPlan
from brixtest.fleet.registry import InstanceSpec, Registry, ServerEndpoint
from brixtest.metrics import MetricRecorder
from brixtest.runtime.api import Run, Service
from brixtest.runtime.artifacts import ArtifactStore
from brixtest.runtime.backends import BackendContext, case_backend
from brixtest.runtime.binaries import BinaryStore
from brixtest.runtime.case_summary import finalize_evidence, write_case_summary
from brixtest.runtime.configs import ConfigStore
from brixtest.runtime.commands import CommandResult, CommandRunner
from brixtest.runtime.executors import ToolExecutionContext, tool_executor
from brixtest.runtime.launchers import (
    ServerLaunchContext, ServerLaunchPlan, ServerLaunchRequest, server_launcher,
)
from brixtest.runtime.security import SecurityResources
from brixtest.runtime.resources import record_materialized_sizes
from brixtest.runtime.topology import injected_services, instance_for, owned_servers, service_records
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
    ) -> int:
        handle = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM,
        )
        handle.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            handle.bind(("127.0.0.1", requested or 0))
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


class CaseManager:
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
        self._case_plan: Mapping[str, object] = {}
        self._started: list[str] = []
        self._services: Dict[str, Service] = {}
        self._server_launchers: Dict[str, object] = {}
        self._server_launch_plans: Dict[str, ServerLaunchPlan] = {}
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
        self.backend_context = BackendContext(self)
        self.metrics.tag("backend", self.backend_name)
        self.metrics.gauge("resources.servers", len(definition.servers), unit="count")
        self.metrics.gauge("resources.clients", len(definition.clients), unit="count")
        self.metrics.gauge("resources.artifacts", len(definition.artifacts), unit="count")
        self.metrics.gauge("resources.credentials", len(definition.credentials), unit="count")
        self.metrics.gauge("resources.auth_stacks", len(definition.auth), unit="count")
        self.metrics.gauge("resources.host_mappings", len(definition.hosts), unit="count")

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
                self._case_plan = planned
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
            try:
                self._case_backend.stop(self.backend_context)
            except Exception:
                pass
            try:
                self.security.close()
            except Exception:
                pass
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
        sources: list[Iterable[Binary]] = [self.definition.binaries]
        sources.extend(item.binaries for item in owned_servers(self.definition))
        sources.extend(item.binaries for item in self.definition.clients)
        for declarations in sources:
            for declaration in declarations:
                previous = found.get(declaration.name)
                if previous is not None and previous != declaration:
                    raise SpecError(
                        "binary", declaration.name,
                        "same name has different declarations in one case",
                    )
                found[declaration.name] = declaration
        owners: Iterable[Union[Server, Client]] = chain(
            owned_servers(self.definition), self.definition.clients
        )
        for owner in owners:
            for part in owner.command:
                if isinstance(part, Binary):
                    previous = found.get(part.name)
                    if previous is not None and previous != part:
                        raise SpecError("binary", part.name, "declarations disagree")
                    found[part.name] = part
        return tuple(found[name] for name in sorted(found))

    def _allocate_ports(self, servers: Sequence[Server]) -> Dict[str, Dict[str, int]]:
        allocated: Dict[str, Dict[str, int]] = {}
        for server in servers:
            protocols = {item.name: item.protocol for item in server.endpoints}
            roles = {
                role: self._ports.reserve(
                    server.name, role, requested, protocols.get(role, "tcp"),
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
        values: Dict[str, object] = {
            "run_root": self.root, "workspace": self.workspace,
            "artifacts": self.artifact_store.root,
        }
        for name, value in self.parameters.items():
            values["param_%s" % name] = (
                value if isinstance(value, (str, int, float, bool, Path)) else str(value)
            )
        for name, captured_binary in self.binary_store._captured.items():
            values["binary_%s" % name] = captured_binary.path
            values["binary_%s_dir" % name] = captured_binary.path.parent
        for name, materialized_artifact in self.artifact_store._items.items():
            values["artifact_%s" % name] = materialized_artifact.path
            values["artifact_%s_dir" % name] = materialized_artifact.path.parent
        values.update(self.security.values(
            credential_base=credential_base, auth_base=auth_base,
        ))
        for name, roles in ports.items():
            values["server_%s_host" % name] = "127.0.0.1"
            declared = next(
                (item for item in self.definition.servers if item.name == name), None
            )
            schemes = {
                item.name: item.scheme for item in getattr(declared, "endpoints", ())
            }
            for role, port in roles.items():
                values["server_%s_%s_port" % (name, role)] = port
                scheme = schemes.get(role) or "http"
                values["server_%s_%s_url" % (name, role)] = (
                    "%s://127.0.0.1:%d" % (scheme, port)
                )
            values["server_%s_url" % name] = "http://127.0.0.1:%d" % roles["primary"]
        for name, service in self._services.items():
            values["server_%s_host" % name] = service.host
            values["server_%s_url" % name] = service.url()
            values["server_%s_config" % name] = service.config
            values["server_%s_log" % name] = service.log
            for role, port in service.ports.items():
                values["server_%s_%s_port" % (name, role)] = port
                values["server_%s_%s_url" % (name, role)] = service.url(role=role)
        return values

    def _render_part(self, part: object, values: Mapping[str, object], label: str) -> str:
        if isinstance(part, Binary):
            return str(self.binary_store.get(part.name).path)
        return render_cfg_strict(str(part), values, template=label)

    def _render_value(self, value: object, *, label: str = "runtime value") -> str:
        """Resolve a typed reference or compatibility placeholder at call time."""
        return self._render_part(value, self._global_values({}), label)

    def _project_mounts(
        self, owner: str, mounts: Sequence[object], *,
        configs: Sequence[object] = (), config_server: str = "",
    ) -> Mapping[str, Path]:
        """Copy declared inputs into a confined, backend-neutral projection."""
        projected: Dict[str, Path] = {}
        config_paths = {
            declaration.destination: captured.rendered
            for declaration, captured in zip(
                configs, self.config_store.all(config_server)
            )
        } if configs else {}
        base = self.root / "runtime" / "mounts" / owner
        for index, declaration in enumerate(mounts):
            destination = base / declaration.target
            destination.parent.mkdir(parents=True, exist_ok=True)
            if declaration.kind == "tmp":
                destination.mkdir(parents=True, exist_ok=True)
            else:
                source = declaration.source
                if declaration.kind == "artifact" or isinstance(source, Artifact):
                    selected = self.artifact_store.get(
                        source.name if isinstance(source, Artifact) else str(source)
                    ).path
                elif declaration.kind == "credential" or isinstance(source, Credential):
                    selected = self.security.credential(
                        source.name if isinstance(source, Credential) else str(source)
                    ).path
                elif declaration.kind == "config" or isinstance(source, ConfigFile):
                    destination = (
                        source.destination if isinstance(source, ConfigFile) else str(source)
                    )
                    try:
                        selected = config_paths[destination]
                    except KeyError:
                        raise SpecError(
                            "mount.source", destination,
                            "config mounts must belong to the mounted server",
                        ) from None
                elif hasattr(source, "path"):
                    selected = Path(str(getattr(source, "path"))).resolve()
                else:
                    candidate = Path(str(source))
                    selected = (
                        candidate.resolve() if candidate.is_absolute()
                        else (self.source_root / candidate).resolve()
                    )
                if not selected.exists():
                    raise SpecError("mount.source", str(source), "does not exist")
                if selected.is_dir():
                    shutil.copytree(selected, destination, dirs_exist_ok=False)
                elif selected.is_file():
                    shutil.copy2(selected, destination)
                else:
                    raise SpecError("mount.source", str(source), "must be a file or directory")
            if declaration.read_only:
                paths = [destination]
                if destination.is_dir():
                    paths.extend(destination.rglob("*"))
                for path in paths:
                    try:
                        path.chmod(path.stat().st_mode & ~0o222)
                    except OSError:
                        pass
            suffix = ConfigStore.placeholder(declaration.target)
            projected["mount_%s" % suffix] = destination
            projected["mount_%d" % index] = destination
        return projected

    def _start_local(self) -> None:
        servers = owned_servers(self.definition)
        self.binary_store.capture_all(self._all_binaries())
        self.artifact_store.materialize_all(self.definition.artifacts)
        self.security.materialize()
        allocated = self._allocate_ports(servers)
        common = self._global_values(allocated)
        library_dirs = [
            str(item.library_dir) for item in self.binary_store._captured.values()
            if item.libraries
        ]
        binary_dirs = [
            str(item.path.parent) for item in self.binary_store._captured.values()
            if item.sha256
        ]
        server_names = {server.name for server in servers}
        for declaration in servers:
            roles = allocated[declaration.name]
            values = dict(common)
            values.update({"name": declaration.name, "host": "127.0.0.1"})
            for role, port in roles.items():
                values["port" if role == "primary" else "%s_port" % role] = port
            captured_files = self.config_store.capture_all(declaration, values)
            captured = self.config_store.get(declaration.name)
            values["config"] = captured.rendered
            for item in captured_files:
                key = "config_%s" % self.config_store.placeholder(item.filename)
                values[key] = item.rendered
            mounts = self._project_mounts(
                "server-%s" % declaration.name, declaration.mounts,
                configs=declaration.configs.files, config_server=declaration.name,
            )
            values.update(mounts)
            launcher_name = (
                "process" if declaration.placement.backend in ("inherit", "local")
                else declaration.placement.backend
            )
            launcher = server_launcher(launcher_name)
            launcher.validate(declaration)
            containerized = launcher_name in ("docker", "podman")
            command = tuple(
                str(part.image_path)
                if containerized and isinstance(part, Binary) and part.image_path
                else self._render_part(
                    part, values, "server %s command" % declaration.name,
                )
                for part in declaration.command
            )
            shutdown_command = tuple(
                self._render_part(
                    part, values, "server %s shutdown command" % declaration.name,
                )
                for part in declaration.lifecycle.shutdown_command
            )
            env = {
                key: render_cfg_strict(
                    str(value), values,
                    template="server %s env[%s]" % (declaration.name, key),
                )
                for key, value in declaration.env.items()
            }
            env.update(self.security.environment("server"))
            env.update({
                key.upper(): str(path) for key, path in mounts.items()
                if not key.rpartition("_")[2].isdigit()
            })
            env.update({
                key: render_cfg_strict(
                    value, values, template="suite server env[%s]" % key
                ) for key, value in _environment("BRIXTEST_SERVER_ENV_JSON").items()
            })
            if library_dirs:
                inherited = os.environ.get("LD_LIBRARY_PATH", "")
                env["LD_LIBRARY_PATH"] = ":".join(library_dirs + ([inherited] if inherited else []))
            if binary_dirs:
                inherited_path = env.get("PATH", os.environ.get("PATH", ""))
                env["PATH"] = os.pathsep.join(
                    binary_dirs + ([inherited_path] if inherited_path else [])
                )
            workdir = self.root / "runtime" / "instances" / declaration.name
            if declaration.cwd:
                workdir /= declaration.cwd
            launch_context = ServerLaunchContext(
                self.nodeid, self.root, self.workspace,
            )
            launch_plan = launcher.prepare(
                launch_context,
                ServerLaunchRequest(declaration, command, env, workdir),
            )
            self._server_launchers[declaration.name] = launcher
            self._server_launch_plans[declaration.name] = launch_plan
            self.registry.register(InstanceSpec(
                name=declaration.name, kind=_KIND.name, ports=roles,
                command=launch_plan.argv, env=launch_plan.env,
                depends_on=tuple(
                    item.name if isinstance(item, Server) else item
                    for item in declaration.depends_on
                    if (item.name if isinstance(item, Server) else item) in server_names
                ),
                readiness=declaration.readiness.kind,
                readiness_timeout=declaration.readiness.timeout,
                probe=declaration.probe,
                critical=True,
                stop_timeout=declaration.lifecycle.stop_timeout,
                shutdown_signal=declaration.lifecycle.shutdown_signal,
                shutdown_command=shutdown_command,
                expected_exit=declaration.lifecycle.expected_exit,
                background=declaration.lifecycle.background,
                log_max_bytes=declaration.logs.max_bytes,
                workdir=(
                    "%s/%s" % (declaration.name, declaration.cwd)
                    if declaration.cwd else declaration.name
                ),
            ))
        self.registry.freeze()
        if _KIND.name not in known_kinds():
            register_kind(_KIND)
        elif get_kind(_KIND.name) != _KIND:
            raise SpecError("kind", _KIND.name, "already registered with different behavior")

        all_ports = [port for spec in self.registry.all_specs() for port in spec.ports.values()]
        base = min(all_ports) if all_ports else 20000
        span = max(all_ports) - base + 1 if all_ports else 1
        lane = Lane(self.root / "runtime", port_base=base, port_span=span)
        self._backend = LocalBackend(self.registry, lane, strict_templates=True)
        self._backend.prepare(lane, None)
        plan = FleetPlan.build(self.registry.all_specs())
        for level in plan.levels:
            for spec in level:
                self._ports.release_server(spec.name)
                try:
                    with self.metrics.timer(
                        "server.startup", labels={"server": spec.name}
                    ):
                        self._backend.start(spec)
                except BaseException:
                    try:
                        self._backend.stop(spec.name)
                    except BaseException:
                        pass
                    launcher = self._server_launchers.get(spec.name)
                    launch_plan = self._server_launch_plans.get(spec.name)
                    if launcher is not None and launch_plan is not None:
                        launcher.cleanup(
                            ServerLaunchContext(
                                self.nodeid, self.root, self.workspace,
                            ),
                            launch_plan,
                        )
                    raise
                self._started.append(spec.name)
                endpoint = self._backend.endpoint(spec.name)
                original = next(item for item in servers if item.name == spec.name)
                self._services[spec.name] = self._service(endpoint, original)
        self._ports.close()
        self._prepare_clients(common, library_dirs, binary_dirs)

    def _service(self, endpoint: ServerEndpoint, declaration: Server) -> Service:
        ports = {role: endpoint.ports[role] for role in declaration.ports}
        ports.setdefault("primary", endpoint.ports["primary"])
        config = self.config_store.get(endpoint.name)
        captured_configs = {
            item.filename: item.rendered for item in self.config_store.all(endpoint.name)
        }
        schemes = {item.name: item.scheme for item in declaration.endpoints if item.scheme}
        protocols = {item.name: item.protocol for item in declaration.endpoints}
        launch_plan = self._server_launch_plans.get(declaration.name)
        metadata = dict(declaration.metadata)
        if launch_plan is not None:
            metadata["launcher"] = launch_plan.launcher
            metadata["launch"] = dict(launch_plan.metadata)
        service = Service(
            name=endpoint.name, host=endpoint.host,
            ports=ports,
            config=config.rendered,
            log=endpoint.log_path, workdir=endpoint.workdir,
            instance_id=instance_for(self.evidence.attempt_id, endpoint.name),
            scope=declaration.scope, started_at=time.time(),
            config_filename=config.filename,
            config_sha256=config.rendered_sha256,
            config_source_sha256=config.source_sha256,
            config_declared_sha256=config.declared_sha256,
            configs=captured_configs, schemes=schemes, protocols=protocols,
            metadata=metadata,
        )
        object.__setattr__(service, "_controller", self)
        return service

    def _prepare_clients(
        self, common: Mapping[str, object], libraries: Sequence[str],
        binary_dirs: Sequence[str] = (),
        *, remote_values: Optional[Mapping[str, object]] = None,
    ) -> None:
        values = dict(common)
        for name, service in self._services.items():
            values["server_%s_host" % name] = service.host
            values["server_%s_url" % name] = service.url()
            values["server_%s_config" % name] = service.config
            values["server_%s_log" % name] = service.log
            for role, port in service.ports.items():
                values["server_%s_%s_port" % (name, role)] = port
                values["server_%s_%s_url" % (name, role)] = service.url(role=role)
        for declaration in self.definition.clients:
            executor_name = (
                "local" if declaration.placement.backend == "inherit"
                else declaration.placement.backend
            )
            executor = tool_executor(executor_name)
            executor.validate(declaration)
            remote = executor_name == "kubernetes"
            containerized = executor_name in ("kubernetes", "docker", "podman")
            client_values = dict(remote_values if remote and remote_values is not None else values)
            kubernetes = getattr(self, "_kubernetes", None)
            executor_metadata = (
                kubernetes.client_metadata(declaration)
                if remote and kubernetes is not None else {}
            )
            mounts = (
                dict(executor_metadata.get("mount_values", {}))
                if remote else self._project_mounts(
                    "client-%s" % declaration.name, declaration.mounts,
                )
            )
            client_values.update(mounts)
            command = tuple(
                (
                    str(part.image_path)
                    if containerized and isinstance(part, Binary) and part.image_path
                    else str(self.binary_store.get(part.name).path)
                    if isinstance(part, Binary) else str(part)
                )
                for part in declaration.command
            )
            env = dict(declaration.env)
            env.update(
                self.security.environment(
                    "client", credential_base=Path("/brixtest/secure/credentials"),
                    auth_base=Path("/brixtest/secure/auth"),
                ) if remote else self.security.environment("client")
            )
            env.update({
                key.upper(): str(path) for key, path in mounts.items()
                if not key.rpartition("_")[2].isdigit()
            })
            env.update(_environment("BRIXTEST_CLIENT_ENV_JSON"))
            if remote:
                for secret_name in executor_metadata.get("secret_environment", {}):
                    env.pop(str(secret_name), None)
            if libraries and not remote:
                inherited = os.environ.get("LD_LIBRARY_PATH", "")
                env["LD_LIBRARY_PATH"] = ":".join(list(libraries) + ([inherited] if inherited else []))
            if binary_dirs and not remote:
                inherited_path = env.get("PATH", os.environ.get("PATH", ""))
                env["PATH"] = os.pathsep.join(
                    list(binary_dirs) + ([inherited_path] if inherited_path else [])
                )
            client_cwd = (
                Path("/brixtest/workspace") / declaration.cwd
                if remote and declaration.cwd else Path("/brixtest/workspace")
                if remote else self.workspace / declaration.cwd
                if declaration.cwd else self.workspace
            )
            if not remote:
                client_cwd.mkdir(parents=True, exist_ok=True)
            context = ToolExecutionContext(
                nodeid=self.nodeid, root=self.root, workspace=self.workspace,
                backend=self.backend_name,
                namespace=str(getattr(kubernetes, "namespace", "")),
                metadata={
                    "kubectl": str(getattr(kubernetes, "kubectl", "kubectl")),
                    "kubectl_context": str(getattr(kubernetes, "context", "")),
                },
            )
            configured_type = ConfiguredTool if isinstance(declaration, Tool) else ConfiguredClient
            self._clients[declaration.name] = configured_type(
                ClientSpec(
                    declaration.name, command, env=env,
                    cwd=str(client_cwd),
                    timeout=declaration.timeout, input=declaration.input,
                    expected_exit_codes=declaration.expected_exit_codes,
                    output_limit=min(declaration.output_limit, declaration.logs.max_bytes),
                    mode=declaration.mode,
                    retries=declaration.retries,
                    encoding=declaration.encoding,
                    log_redact=declaration.logs.redact,
                    placement=declaration.placement,
                    image=self._client_image(declaration),
                ),
                client_values,
                observer=self._observe_client,
                archive_dir=(
                    self.root / "runtime" / "client-logs" / declaration.name
                    if declaration.logs.capture else None
                ),
                executor=executor, execution_context=context,
                executor_metadata=executor_metadata,
                result_observer=self._observe_tool_result,
            )

    @staticmethod
    def _client_image(declaration: Client) -> str:
        if declaration.placement.image:
            return declaration.placement.image
        images = {
            item.image for item in chain(declaration.binaries, declaration.command)
            if isinstance(item, Binary) and item.image
        }
        return next(iter(images)) if len(images) == 1 else ""

    def _observe_client(
        self, name: str, elapsed: float, returncode: Optional[int], error: str
    ) -> None:
        labels = {"client": name}
        self.metrics.count("client.calls", labels=labels)
        self.metrics.observe("client.duration", elapsed, unit="s", labels=labels)
        if returncode is not None:
            self.metrics.gauge("client.returncode", returncode, labels=labels)
        if error:
            self.metrics.count(
                "client.errors", labels={"client": name, "error": error.lower()}
            )

    def _observe_tool_result(self, name: str, result: CommandResult) -> None:
        """Publish one completed tool invocation to trusted helper plugins."""
        if self._pytest_hook is None:
            return
        declaration = next(
            (item for item in self.definition.clients if item.name == name), name,
        )
        self._pytest_hook.pytest_brixtest_tool_result(
            run=Run(self), tool=declaration, result=result,
        )

    def _set_pytest_hook(self, hook: object) -> None:
        self._pytest_hook = hook

    def _observe_command(
        self, elapsed: float, returncode: Optional[int], error: str,
    ) -> None:
        self.metrics.count("command.calls")
        self.metrics.observe("command.duration", elapsed, unit="s")
        if returncode is not None:
            self.metrics.gauge("command.returncode", returncode)
        if error:
            self.metrics.count("command.errors", labels={"error": error.lower()})


    def _finalize_metrics(self) -> None:
        if self._metrics_finalized:
            return
        self._metrics_finalized = True
        self.metrics.gauge(
            "case.wall_time", time.time() - self._started_at, unit="s"
        )
        self.metrics.gauge(
            "process.cpu_time", time.process_time() - self._started_cpu, unit="s"
        )
        usage = resource.getrusage(resource.RUSAGE_SELF)
        self.metrics.gauge("process.max_rss", usage.ru_maxrss, unit="KiB")
        self.metrics.tag("outcome", self._outcome)

    def service(self, name: str) -> Service:
        """Resolve one running service by declaration name."""
        try:
            return self._services[name]
        except KeyError:
            raise SpecError("server", name, "known: %s" % ", ".join(sorted(self._services))) from None

    def _service_signal(self, name: str, signal_name: str) -> None:
        """Route an explicit signal through the owning backend."""
        if self._backend is not None:
            plan = self._server_launch_plans.get(name)
            if plan is not None and plan.launcher in ("docker", "podman"):
                self.commands.run(
                    plan.launcher, "kill", "--signal", signal_name,
                    str(plan.metadata.get("container_name", "")),
                    timeout=10.0,
                )
            else:
                self._backend.signal(name, signal_name)
            self.metrics.count(
                "server.signals", labels={"server": name, "signal": signal_name},
            )
            return
        kubernetes = getattr(self, "_kubernetes", None)
        if kubernetes is not None:
            kubernetes.signal(name, signal_name)
            self.metrics.count(
                "server.signals", labels={"server": name, "signal": signal_name},
            )
            return
        raise SpecError("server control", name, "backend does not expose signal control")

    def _service_wait(self, name: str, timeout: Optional[float]) -> Optional[int]:
        """Wait for a local supervised server without blocking indefinitely."""
        if timeout is not None and (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0
        ):
            raise SpecError("server wait timeout", timeout, "must be a number >= 0 or None")
        if self._backend is None:
            raise SpecError(
                "server wait", name,
                "process exit waiting is available for process, Docker, and Podman servers",
            )
        return self._backend.wait(name, timeout)

    def _service_restart(self, name: str) -> Service:
        """Restart one server through its original immutable launch plan."""
        if self._backend is not None:
            spec = self.registry.get_spec(name)
            declaration = next(
                item for item in owned_servers(self.definition) if item.name == name
            )
            self._backend.stop(name)
            launcher = self._server_launchers.get(name)
            plan = self._server_launch_plans.get(name)
            if launcher is not None and plan is not None:
                launcher.cleanup(
                    ServerLaunchContext(self.nodeid, self.root, self.workspace), plan,
                )
            with self.metrics.timer("server.restart", labels={"server": name}):
                endpoint = self._backend.start(spec)
            service = self._service(endpoint, declaration)
            self._services[name] = service
            return service
        kubernetes = getattr(self, "_kubernetes", None)
        if kubernetes is not None:
            with self.metrics.timer("server.restart", labels={"server": name}):
                kubernetes.restart(name)
            return self.service(name)
        raise SpecError("server restart", name, "backend does not expose restart control")

    def _service_command(
        self, name: str, argv: Sequence[object], *, timeout: float,
        check: bool,
    ) -> CommandResult:
        """Run one shell-free diagnostic command in the server environment."""
        service = self.service(name)
        if not argv:
            raise SpecError("server command", argv, "needs at least one argv item")
        plan = self._server_launch_plans.get(name)
        if plan is not None and plan.launcher in ("docker", "podman"):
            container_name = str(plan.metadata.get("container_name", ""))
            command = (plan.launcher, "exec", container_name, *argv)
            return self.commands.run(
                *command, timeout=timeout, check=check, cwd=self.workspace,
            )
        kubernetes = getattr(self, "_kubernetes", None)
        if kubernetes is not None:
            command = (*kubernetes.command_prefix(), "-n", kubernetes.namespace,
                       "exec", "deployment/%s" % name, "--", *argv)
            return self.commands.run(
                *command, timeout=timeout, check=check, cwd=self.workspace,
            )
        spec = self.registry.get_spec(name)
        return self.commands.run(
            *argv, timeout=timeout, check=check, cwd=service.workdir,
            env=dict(spec.env),
        )

    def client(self, name: str) -> ConfiguredClient:
        """Resolve one configured client by declaration name."""
        try:
            return self._clients[name]
        except KeyError:
            raise SpecError("client", name, "known: %s" % ", ".join(sorted(self._clients))) from None

    def set_outcome(self, outcome: str) -> None:
        """Record the test outcome that will be written during finalization."""
        self._outcome = outcome

    def close(self) -> None:
        """Stop resources, finalize evidence, and apply the retention policy."""
        errors = []
        self.evidence.close_collectors()
        try:
            self._case_backend.stop(self.backend_context)
        except Exception as exc:
            errors.append(str(exc))
        try:
            collected = self._case_backend.collect(self.backend_context)
            if not isinstance(collected, Mapping):
                raise SpecError(
                    "case backend collect", type(collected).__name__,
                    "must return a mapping",
                )
            if collected:
                self.evidence.attach_json(
                    "backend-result.json", collected, role="backend-result",
                    description="case backend collection result",
                )
        except Exception as exc:
            errors.append(str(exc))
        try:
            self.security.close()
        except Exception as exc:
            errors.append(str(exc))
        if errors:
            self._outcome = "teardown-failed"
        self._ports.close()
        self._finalize_metrics()
        evidence_error = finalize_evidence(self)
        if evidence_error:
            errors.append(evidence_error)
        error = "; ".join(errors)
        self._write_summary(error=error)
        session = os.environ.get("BRIXTEST_METRICS_SESSION")
        if session and os.environ.get("BRIXTEST_SHARED_POOL_OWNER") != "1":
            archive_case_logs(Path(session), self.nodeid, self.root)
        if self.definition.keep == "never" or (
            self.definition.keep == "failed" and self._outcome == "passed"
        ):
            shutil.rmtree(self.root, ignore_errors=True)
        if error:
            raise CaseRunError(self.nodeid, "teardown", error)

    def _stop_started(self) -> None:
        if self._backend is None:
            return
        errors = []
        for name in reversed(self._started):
            try:
                self._backend.stop(name)
            except Exception as exc:
                errors.append("%s: %s" % (name, exc))
            launcher = self._server_launchers.get(name)
            plan = self._server_launch_plans.get(name)
            if launcher is not None and plan is not None:
                try:
                    launcher.cleanup(
                        ServerLaunchContext(self.nodeid, self.root, self.workspace), plan,
                    )
                except Exception as exc:
                    errors.append("%s launcher: %s" % (name, exc))
            declaration = next(
                (item for item in self.definition.servers if item.name == name), None
            )
            if declaration is not None:
                self._apply_log_policy(self._backend.logs(name), declaration.logs)
        self._started.clear()
        if errors:
            raise RuntimeError("; ".join(errors))

    @staticmethod
    def _apply_log_policy(path: Path, policy: object) -> None:
        """Apply the resource's bounded/redacted archival policy in-place."""
        if not getattr(policy, "capture", True):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            return
        try:
            payload = path.read_bytes()
        except OSError:
            return
        text = payload.decode("utf-8", errors="replace")
        for secret in getattr(policy, "redact", ()):
            text = text.replace(secret, "[REDACTED]")
        payload = text.encode("utf-8")
        limit = int(getattr(policy, "max_bytes", len(payload) or 1))
        if len(payload) > limit:
            marker = b"[brixtest: earlier log bytes omitted]\n"
            tail = max(0, limit - len(marker))
            payload = marker[:limit] + (payload[-tail:] if tail else b"")
        path.write_bytes(payload)

    def _write_summary(self, *, error: str = "") -> None:
        write_case_summary(self, error=error)
