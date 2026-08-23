"""Server lifecycle operations for the Kubernetes case backend."""

from __future__ import annotations

import select
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict, Mapping, Sequence

from brixtest.design import Server
from brixtest.errors import CaseRunError, SpecError
from brixtest.fleet.launcher import FleetPlan
from brixtest.fleet.registry import InstanceSpec, ServerEndpoint
from brixtest.runtime.kubernetes_manifests import _resource_name
from brixtest.runtime.manager import Run, Service
from brixtest.runtime.resources import record_materialized_sizes
from brixtest.runtime.topology import instance_for, owned_servers


def _accepts_connection(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _config_paths(owner, server: Server) -> dict:
    return {
        item.filename: item.rendered for item in owner.config_store.all(server.name)
    }


def _endpoint_schemes(server: Server) -> dict[str, str]:
    return {item.name: item.scheme for item in server.endpoints if item.scheme}


def _endpoint_protocols(server: Server) -> dict[str, str]:
    return {item.name: item.protocol for item in server.endpoints}


class KubernetesLifecycleMixin:
    """Launch, expose, and tear down Kubernetes-backed servers."""

    def _launch_servers(
        self, servers: Sequence[Server], resources: Mapping[str, Sequence[dict]],
        specs: Sequence[InstanceSpec],
    ) -> None:
        by_name = {item.name: item for item in servers}
        for level in FleetPlan.build(specs).levels:
            for spec in level:
                self._launch_server(by_name[spec.name], resources[spec.name], spec)

    def _launch_server(
        self, declaration: Server, resources: Sequence[dict], spec: InstanceSpec,
    ) -> None:
        with self.owner.metrics.timer("server.startup", labels={"server": spec.name}):
            self._apply(resources)
            self._run(
                "-n", self.namespace, "rollout", "status",
                "deployment/%s" % _resource_name(spec.name),
                "--timeout=%ds" % int(declaration.probe.timeout),
                timeout=declaration.probe.timeout + 5.0,
            )

    def _wait_for_probe(
        self, server: Server, local_ports: Mapping[str, int],
    ) -> None:
        if server.probe.kind == "tcp":
            self._wait_ready(
                local_ports[server.probe.endpoint], server.probe.timeout, server.name,
            )
            return
        if server.probe.kind in ("none", "http", "https", "exec"):
            return
        from brixtest.fleet.probes import probe_from_declaration

        probe_from_declaration(server.probe).wait(
            self._server_endpoint(server, local_ports), server.probe.timeout,
        )

    def _server_endpoint(
        self, server: Server, local_ports: Mapping[str, int],
    ) -> ServerEndpoint:
        owner = self.owner
        return ServerEndpoint(
            server.name, "kubernetes", "127.0.0.1", local_ports,
            owner.root / "runtime" / "kubernetes" / server.name,
            owner.root / "runtime" / "logs" / (server.name + ".log"), None,
        )

    @staticmethod
    def _service_ports(server: Server, local_ports: Mapping[str, int]) -> Dict[str, int]:
        exposed = {role: local_ports[role] for role in server.ports}
        if server.probe.kind == "none":
            primary_role = next(iter(server.ports))
        else:
            primary_role = server.probe.endpoint
        exposed.setdefault("primary", local_ports[primary_role])
        return exposed

    def _service_from_server(
        self, server: Server, remote_ports: Mapping[str, int],
    ) -> Service:
        owner = self.owner
        local_ports = self._forward(server, remote_ports)
        self._wait_for_probe(server, local_ports)
        config = owner.config_store.get(server.name)
        service = Service(
            name=server.name,
            host="127.0.0.1",
            ports=self._service_ports(server, local_ports),
            config=config.rendered,
            log=owner.root / "runtime" / "logs" / (server.name + ".log"),
            workdir=owner.root / "runtime" / "kubernetes" / server.name,
            instance_id=instance_for(owner.evidence.attempt_id, server.name),
            scope=server.scope,
            started_at=time.time(),
            config_filename=config.filename,
            config_sha256=config.rendered_sha256,
            config_source_sha256=config.source_sha256,
            config_declared_sha256=config.declared_sha256,
            configs=_config_paths(owner, server),
            schemes=_endpoint_schemes(server),
            protocols=_endpoint_protocols(server),
            metadata={**dict(server.metadata), "launcher": "kubernetes"},
        )
        object.__setattr__(service, "_controller", owner)
        return service

    def _validate_backend(self, servers: Sequence[Server]) -> None:
        from brixtest.runtime import kubernetes as backend_module

        if backend_module.shutil.which(self.kubectl) is None:
            raise SpecError(
                "Kubernetes backend", self.kubectl, "kubectl is not installed or not on PATH",
            )
        names = [_resource_name(item.name) for item in servers]
        if len(names) != len(set(names)):
            raise SpecError(
                "Kubernetes server names", names,
                "names collide after Kubernetes DNS normalization",
            )

    def _prepare_case_assets(self) -> None:
        owner = self.owner
        owner.binary_store.capture_all(owner._all_binaries())
        owner.artifact_store.materialize_all(owner.definition.artifacts)
        owner.security.materialize()

    def _build_resources(
        self, servers: Sequence[Server], common: Mapping[str, object],
        ports: Mapping[str, Mapping[str, int]], secure_root: Path,
        secret_name: str, secure_items: Sequence[dict],
    ) -> tuple[dict[str, Sequence[dict]], list[InstanceSpec]]:
        resources = {}
        specs = []
        server_names = {server.name for server in servers}
        for server in servers:
            resources[server.name], spec = self._render_server_resource(
                server, common, ports, secure_root, secret_name, secure_items, server_names,
            )
            specs.append(spec)
        return resources, specs

    def _register_services(
        self, servers: Sequence[Server], ports: Mapping[str, Mapping[str, int]],
    ) -> None:
        for server in servers:
            self.owner._services[server.name] = self._service_from_server(
                server, ports[server.name],
            )

    def _prepare_kubernetes_clients(self) -> None:
        for client in self.owner.definition.clients:
            if client.placement.backend == "kubernetes":
                self._prepare_client_resources(client)

    def _prepare_clients(self, common: dict[str, object]) -> None:
        owner = self.owner
        local_values = owner._global_values({})
        common["workspace"] = Path("/brixtest/workspace")
        common["run_root"] = Path("/brixtest")
        owner._prepare_clients(local_values, (), remote_values=common)

    def start(self) -> Run:
        owner = self.owner
        servers = owned_servers(owner.definition)
        self._validate_backend(servers)
        self._prepare_case_assets()
        ports = self._internal_ports(servers)
        common, secure_root = self._case_values(servers, ports)
        secret_name, secure_items = self._create_case_secrets()
        resources, specs = self._build_resources(
            servers, common, ports, secure_root, secret_name, secure_items,
        )
        self._launch_servers(servers, resources, specs)
        self._register_services(servers, ports)
        self._prepare_kubernetes_clients()
        self._prepare_clients(common)
        record_materialized_sizes(owner)
        owner._write_summary()
        return Run(owner)

    @staticmethod
    def _free_port() -> int:
        handle = socket.socket()
        handle.bind(("127.0.0.1", 0))
        port = int(handle.getsockname()[1])
        handle.close()
        return port

    def _forward_process(
        self, server: Server, local: Mapping[str, int], remote: Mapping[str, int],
    ) -> subprocess.Popen:
        argv = list(self.command_prefix())
        argv.extend((
            "-n", self.namespace, "port-forward",
            "service/%s" % _resource_name(server.name),
        ))
        argv.extend("%d:%d" % (local[role], remote[role]) for role in server.ports)
        return subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        )

    @staticmethod
    def _forward_line(process: subprocess.Popen) -> str:
        assert process.stdout is not None
        ready, _, _ = select.select([process.stdout], [], [], 0.1)
        return process.stdout.readline() if ready else ""

    def _forward(
        self, server: Server, remote: Mapping[str, int],
    ) -> Dict[str, int]:
        local = {role: self._free_port() for role in server.ports}
        process = self._forward_process(server, local, remote)
        deadline = time.monotonic() + server.probe.timeout
        output = []
        while time.monotonic() < deadline and process.poll() is None:
            line = self._forward_line(process)
            output.append(line)
            if "Forwarding from" in line:
                self._forwards[server.name] = process
                return local
        process.terminate()
        process.wait(timeout=2.0)
        raise CaseRunError(
            self.owner.nodeid, "kubernetes port-forward",
            "server %s: %s" % (server.name, "".join(output).strip()),
        )

    def _wait_ready(self, port: int, timeout: float, server: str) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if _accepts_connection(port):
                return
            time.sleep(0.05)
        raise CaseRunError(
            self.owner.nodeid, "kubernetes readiness",
            "%s did not answer forwarded port %d within %.1fs" % (server, port, timeout),
        )

    def _collect_server_log(self, server: Server, log_dir: Path) -> str:
        try:
            result = self._run(
                "-n", self.namespace, "logs",
                "deployment/%s" % _resource_name(server.name), timeout=10.0,
            )
            path = log_dir / (server.name + ".log")
            path.write_text(result.stdout + result.stderr)
            self.owner._apply_log_policy(path, server.logs)
        except CaseRunError as exc:
            return str(exc)
        return ""

    @staticmethod
    def _stop_forward(process: subprocess.Popen) -> None:
        try:
            process.terminate()
            process.wait(timeout=2.0)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()

    def _close_forwards(self) -> None:
        for name, process in list(self._forwards.items()):
            self._stop_forward(process)
            self._forwards.pop(name, None)

    def _collect_server_logs(self, log_dir: Path) -> list[str]:
        errors = []
        for server in owned_servers(self.owner.definition):
            error = self._collect_server_log(server, log_dir)
            if error:
                errors.append(error)
        return errors

    def _delete_namespace(self) -> list[str]:
        try:
            self._run("delete", "namespace", self.namespace, "--wait=false", timeout=20.0)
        except CaseRunError as exc:
            return [str(exc)]
        finally:
            self._namespace_created = False
        return []

    def _close_namespace(self) -> list[str]:
        if not self._namespace_created:
            return []
        log_dir = self.owner.root / "runtime" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        errors = self._collect_server_logs(log_dir)
        errors.extend(self._delete_namespace())
        return errors

    def close(self) -> None:
        self._close_forwards()
        errors = self._close_namespace()
        if errors:
            raise CaseRunError(self.owner.nodeid, "kubernetes teardown", "; ".join(errors))
