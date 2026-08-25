"""Local server materialization and launch behavior for CaseManager."""

from __future__ import annotations

import contextlib
import os
import shutil
import time
from pathlib import Path
from typing import Dict, Mapping, Sequence

from brixtest.config.lanes import Lane
from brixtest.credentials import Credential
from brixtest.deploy.local import LocalBackend
from brixtest.design import Artifact, Binary, ConfigFile, Server, Volume
from brixtest.errors import SpecError
from brixtest.fleet.kinds import get_kind, known_kinds, register_kind
from brixtest.fleet.launcher import FleetPlan
from brixtest.fleet.registry import InstanceSpec, ServerEndpoint
from brixtest.runtime.api import Service
from brixtest.runtime.configs import ConfigStore
from brixtest.runtime.input_pipeline import capture_deferred, capture_immediate
from brixtest.runtime.launchers import ServerLaunchContext, ServerLaunchRequest, server_launcher
from brixtest.runtime.replica import Replica
from brixtest.runtime.topology import instance_for, owned_servers
from brixtest.util.configtext import render_cfg_strict


def _local_mount_source(manager, declaration, configs: Mapping[str, Path]) -> Path:
    source = declaration.source
    if _is_artifact_mount(declaration.kind, source):
        return manager.artifact_store.get(
            source.name if isinstance(source, Artifact) else str(source)
        ).path
    if _is_credential_mount(declaration.kind, source):
        return manager.security.credential(
            source.name if isinstance(source, Credential) else str(source)
        ).path
    if _is_config_mount(declaration.kind, source):
        return _local_config_source(source, configs)
    if hasattr(source, "path"):
        return Path(str(source.path)).resolve()
    candidate = Path(str(source))
    return candidate.resolve() if candidate.is_absolute() else (
        manager.source_root / candidate
    ).resolve()


def _is_artifact_mount(kind: str, source: object) -> bool:
    return kind == "artifact" or isinstance(source, Artifact)


def _is_credential_mount(kind: str, source: object) -> bool:
    return kind == "credential" or isinstance(source, Credential)


def _is_config_mount(kind: str, source: object) -> bool:
    return kind == "config" or isinstance(source, ConfigFile)


def _local_config_source(source: object, configs: Mapping[str, Path]) -> Path:
    destination = source.destination if isinstance(source, ConfigFile) else str(source)
    try:
        return configs[destination]
    except KeyError:
        raise SpecError(
            "mount.source", destination, "config mounts must belong to the mounted server",
        ) from None


def _copy_local_mount(source: Path, destination: Path, declared: object) -> None:
    if not source.exists():
        raise SpecError("mount.source", str(declared), "does not exist")
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=False)
    elif source.is_file():
        shutil.copy2(source, destination)
    else:
        raise SpecError("mount.source", str(declared), "must be a file or directory")


def _make_read_only(destination: Path) -> None:
    paths = [destination]
    if destination.is_dir():
        paths.extend(destination.rglob("*"))
    for path in paths:
        with contextlib.suppress(OSError):
            path.chmod(path.stat().st_mode & ~0o222)


def _mount_read_only(declaration) -> bool:
    source = declaration.source
    return declaration.read_only or (
        isinstance(source, Volume) and source.access == "read-only-many"
    )


def _device_mount(declaration) -> bool:
    return isinstance(declaration.source, Volume) and declaration.source.kind == "device"


def _server_identity(definition, declaration):
    return next((
        identity for identity in definition.identities
        if identity.name == declaration.placement.identity
    ), None)


def _ordered_mount_paths(declaration, mounts: Mapping[str, Path]) -> tuple[Path, ...]:
    return tuple(
        mounts["mount_%d" % index] for index in range(len(declaration.mounts))
    )


def _project_mount_path(manager, base: Path, declaration, config_paths) -> Path:
    destination = base / declaration.target
    destination.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(declaration.source, Volume):
        source = manager._managed.volumes.get(declaration.source.name).path
        if _device_mount(declaration):
            return source
        if not _mount_read_only(declaration):
            return source
        _copy_local_mount(source, destination, declaration.source)
        return destination
    if declaration.kind == "tmp":
        destination.mkdir(parents=True, exist_ok=True)
        return destination
    source = _local_mount_source(manager, declaration, config_paths)
    _copy_local_mount(source, destination, declaration.source)
    return destination



class CaseManagerLocalMixin:
    def _project_mounts(
        self, owner: str, mounts: Sequence[object], *,
        configs: Sequence[object] = (), config_server: str = "",
    ) -> Mapping[str, Path]:
        """Copy declared inputs into a confined, backend-neutral projection."""
        projected: Dict[str, Path] = {}
        config_paths = {
            declaration.destination: captured.rendered
            for declaration, captured in zip(configs, self.config_store.all(config_server))
        } if configs else {}
        base = self.root / "runtime" / "mounts" / owner
        for index, declaration in enumerate(mounts):
            destination = _project_mount_path(self, base, declaration, config_paths)
            if _mount_read_only(declaration) and not _device_mount(declaration):
                _make_read_only(destination)
            suffix = ConfigStore.placeholder(declaration.target)
            projected["mount_%s" % suffix] = destination
            projected["mount_%d" % index] = destination
        return projected

    def _local_server_values(
        self, declaration: Server, roles: Mapping[str, int], common: Mapping[str, object],
    ) -> tuple[Dict[str, object], Mapping[str, Path]]:
        values = dict(common)
        from brixtest.runtime.manager import _server_hosts
        bind_hosts = _server_hosts(declaration, bind=True)
        values.update({"name": declaration.name, "host": bind_hosts["primary"]})
        for role, port in roles.items():
            values["port" if role == "primary" else "%s_port" % role] = port
            values["host" if role == "primary" else "%s_host" % role] = (
                bind_hosts.get(role, bind_hosts["primary"])
            )
        captured_files = self.config_store.capture_all(declaration, values)
        values["config"] = self.config_store.get(declaration.name).rendered
        for item in captured_files:
            values["config_%s" % self.config_store.placeholder(item.filename)] = item.rendered
        mounts = self._project_mounts(
            "server-%s" % declaration.name, declaration.mounts,
            configs=declaration.configs.files, config_server=declaration.name,
        )
        values.update(mounts)
        return values, mounts

    def _local_launch_plan(
        self, declaration: Server, values: Mapping[str, object],
        mounts: Mapping[str, Path], library_dirs: Sequence[str], binary_dirs: Sequence[str],
        group_anchor=None,
    ) -> tuple[object, object, tuple[str, ...]]:
        from brixtest.runtime.manager_local_registration import local_launch_plan
        return local_launch_plan(
            self, declaration, values, mounts, library_dirs, binary_dirs, group_anchor,
        )

    def _server_host_aliases(self):
        return tuple(
            item for item in self.definition.hosts
            if item.libc and "server" in item.targets
        )

    def _server_command_part(self, part, declaration, values, containerized: bool) -> str:
        if containerized and isinstance(part, Binary) and part.image_path:
            return str(part.image_path)
        return self._render_part(
            part, values, "server %s command" % declaration.name,
        )

    def _local_server_environment(self, declaration, values, mounts) -> Dict[str, str]:
        env = {
            key: render_cfg_strict(
                str(value), values, template="server %s env[%s]" % (declaration.name, key),
            )
            for key, value in declaration.env.items()
        }
        env.update(self.security.environment("server"))
        env.update({
            key.upper(): str(path) for key, path in mounts.items()
            if not key.rpartition("_")[2].isdigit()
        })
        from brixtest.runtime.manager import _environment
        env.update({
            key: render_cfg_strict(value, values, template="suite server env[%s]" % key)
            for key, value in _environment("BRIXTEST_SERVER_ENV_JSON").items()
        })
        return env

    @staticmethod
    def _local_server_search_paths(env, library_dirs, binary_dirs) -> None:
        if library_dirs:
            inherited = os.environ.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = ":".join(
                [*library_dirs, *([inherited] if inherited else [])]
            )
        if binary_dirs:
            inherited = env.get("PATH", os.environ.get("PATH", ""))
            env["PATH"] = os.pathsep.join([*binary_dirs, *([inherited] if inherited else [])])

    def _register_local_servers(
        self, servers: Sequence[Server], allocated: Mapping[str, Mapping[str, int]],
        common: Mapping[str, object], library_dirs: Sequence[str], binary_dirs: Sequence[str],
    ) -> None:
        from brixtest.runtime.manager_local_registration import register_local_servers
        register_local_servers(
            self, servers, allocated, common, library_dirs, binary_dirs,
        )

    def _prepare_local_backend(self) -> None:
        from brixtest.runtime.manager import _KIND
        self.registry.freeze()
        _ensure_server_kind(_KIND)
        all_ports = [port for spec in self.registry.all_specs() for port in spec.ports.values()]
        base, span = _lane_geometry(all_ports)
        lane = Lane(self.root / "runtime", port_base=base, port_span=span)
        self._backend = LocalBackend(self.registry, lane, strict_templates=True)
        self._backend.prepare(lane, None)

    def _launch_local_servers(self, servers: Sequence[Server]) -> None:
        by_name = {item.name: item for item in servers}
        for level in FleetPlan.build(self.registry.all_specs()).levels:
            self._launch_local_level(level, by_name)

    def _launch_local_level(self, level, by_name: Mapping[str, Server]) -> None:
        for spec in level:
            self._launch_local_spec(spec)
            self._started.append(spec.name)
            endpoint = self._backend.endpoint(spec.name)
            self._services[spec.name] = self._service(endpoint, by_name[spec.name])

    def _launch_local_spec(self, spec) -> None:
        self._ports.release_server(spec.name)
        try:
            with self.metrics.timer("server.startup", labels={"server": spec.name}):
                self._backend.start(spec)
        except BaseException:
            self._cleanup_failed_launch(spec.name)
            raise

    def _cleanup_failed_launch(self, name: str) -> None:
        with contextlib.suppress(BaseException):
            self._backend.stop(name)
        launcher = self._server_launchers.get(name)
        plan = self._server_launch_plans.get(name)
        if launcher is not None and plan is not None:
            launcher.cleanup(
                ServerLaunchContext(self.nodeid, self.root, self.workspace), plan,
            )

    def _start_local(self) -> None:
        servers = owned_servers(self.definition)
        capture_immediate(self)
        self.security.materialize()
        self._managed.materialize_volumes()
        self._providers.start_ready()
        allocated = self._allocate_ports(servers)
        self._allocated_ports = allocated
        self._managed.run_phase("prepare")
        self._managed.run_phase("init")
        self._providers.start_ready()
        self._providers.ensure_complete()
        capture_deferred(self)
        common = self._global_values(allocated)
        captured = tuple(self.binary_store._captured.values())
        library_dirs = [str(item.library_dir) for item in captured if item.libraries]
        binary_dirs = [str(item.path.parent) for item in captured if item.sha256]
        self._register_local_servers(
            servers, allocated, common, library_dirs, binary_dirs,
        )
        self._prepare_local_backend()
        self._launch_local_servers(servers)
        self._ports.close()
        self._prepare_clients(common, library_dirs, binary_dirs)

    def _service(self, endpoint: ServerEndpoint, declaration: Server) -> Service:
        from brixtest.runtime.manager import _server_hosts
        ports = _service_ports(endpoint, declaration)
        ports.setdefault("primary", endpoint.ports["primary"])
        config = self.config_store.get(endpoint.name)
        captured_configs = _captured_configs(self.config_store, endpoint.name)
        schemes = _endpoint_schemes(declaration)
        protocols = _endpoint_protocols(declaration)
        launch_plan = self._server_launch_plans.get(declaration.name)
        metadata = _service_metadata(
            declaration, launch_plan, self._server_mounts.get(declaration.name, ()),
        )
        instance_id = instance_for(self.evidence.attempt_id, endpoint.name)
        host = _server_hosts(declaration, bind=False)["primary"]
        service = Service(
            name=endpoint.name,
            host=host,
            ports=ports,
            config=config.rendered,
            log=endpoint.log_path, workdir=endpoint.workdir,
            instance_id=instance_id,
            scope=declaration.scope, started_at=time.time(),
            config_filename=config.filename,
            config_sha256=config.rendered_sha256,
            config_source_sha256=config.source_sha256,
            config_declared_sha256=config.declared_sha256,
            configs=captured_configs, schemes=schemes, protocols=protocols,
            hosts=_server_hosts(declaration, bind=False),
            metadata=metadata,
            replicas=(Replica(
                endpoint.name, host, ports, uid=instance_id,
                phase="running", ready=True,
                metadata={"launcher": metadata.get("launcher", "process")},
            ),),
        )
        object.__setattr__(service, "_controller", self)
        return service


def _launcher_name(declaration: Server) -> str:
    if declaration.placement.backend in ("inherit", "local"):
        return "process"
    return declaration.placement.backend


def _service_ports(endpoint: ServerEndpoint, declaration: Server) -> dict[str, int]:
    return {role: endpoint.ports[role] for role in declaration.ports}


def _captured_configs(store, name: str) -> dict[str, Path]:
    return {item.filename: item.rendered for item in store.all(name)}


def _endpoint_schemes(declaration: Server) -> dict[str, str]:
    return {item.name: item.scheme for item in declaration.endpoints if item.scheme}


def _endpoint_protocols(declaration: Server) -> dict[str, str]:
    return {item.name: item.protocol for item in declaration.endpoints}


def _server_workdir(root: Path, declaration: Server) -> Path:
    workdir = root / "runtime" / "instances" / declaration.name
    return workdir / declaration.cwd if declaration.cwd else workdir


def _local_dependencies(declaration: Server, names: set[str]) -> tuple[str, ...]:
    dependencies = []
    for item in declaration.depends_on:
        name = item.name if isinstance(item, Server) else item
        if name in names:
            dependencies.append(name)
    return tuple(dependencies)


def _instance_workdir(declaration: Server) -> str:
    if declaration.cwd:
        return "%s/%s" % (declaration.name, declaration.cwd)
    return declaration.name


def _ensure_server_kind(kind) -> None:
    if kind.name not in known_kinds():
        register_kind(kind)
        return
    if get_kind(kind.name) != kind:
        raise SpecError("kind", kind.name, "already registered with different behavior")


def _lane_geometry(ports: Sequence[int]) -> tuple[int, int]:
    if not ports:
        return 20000, 1
    base = min(ports)
    return base, max(ports) - base + 1


def _service_metadata(declaration: Server, launch_plan, mounts: Sequence[Path]) -> dict:
    metadata = dict(declaration.metadata)
    metadata["filesystem_roots"] = tuple(str(path) for path in mounts)
    if launch_plan is not None:
        metadata["launcher"] = launch_plan.launcher
        metadata["launch"] = dict(launch_plan.metadata)
        metadata["filesystem_transport"] = (
            "oci-shared-mount-v1"
            if launch_plan.launcher in ("docker", "podman") else "native-v1"
        )
    return metadata
