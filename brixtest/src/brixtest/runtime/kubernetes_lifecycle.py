"""Server lifecycle operations for the Kubernetes case backend."""

from __future__ import annotations

import json
import select
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Mapping, Sequence

from brixtest.design import Server
from brixtest.errors import CaseRunError, SpecError
from brixtest.fleet.launcher import FleetPlan
from brixtest.fleet.registry import InstanceSpec, ServerEndpoint
from brixtest.runtime.kubernetes_images import prepare_server_images
from brixtest.runtime.kubernetes_auth import (
    close_kubernetes_auth_services, start_kubernetes_auth_services,
)
from brixtest.runtime.kubernetes_addressing import endpoint_families, endpoint_protocols
from brixtest.runtime.kubernetes_manifests import _resource_name
from brixtest.runtime.kubernetes_groups import (
    compile_grouped_resources, record_grouped_init_tasks,
)
from brixtest.runtime.kubernetes_observation import KubernetesObserver
from brixtest.runtime.kubernetes_replicas import replicas_from_pod_list
from brixtest.runtime.manager import Run, Service
from brixtest.runtime.replica import Replica
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
    return endpoint_protocols(server)


def _remote_filesystem_roots(server: Server) -> tuple[str, ...]:
    workspace = Path("/brixtest/workspace")
    workdir = workspace / server.cwd if server.cwd else workspace
    prefix = Path("/brixtest/groups") / _resource_name(server.name)
    config = prefix / "brixtest/config" if server.placement.group else Path("/brixtest/config")
    mounts = prefix / "brixtest/mounts" if server.placement.group else Path("/brixtest/mounts")
    return tuple(dict.fromkeys((
        str(workdir), str(workspace), str(config), "/brixtest/secure", str(mounts),
    )))


def _prepare_managed_resources(owner) -> None:
    owner._providers.start_ready()
    for phase in ("prepare", "init"):
        owner._managed.run_phase(phase)
        owner._providers.start_ready()
    owner._providers.ensure_complete()


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

    def read_log(self, name: str) -> str:
        """Return current server-container output from every matching replica."""
        target = self._server_target(name)
        result = self._run(
            "-n", target.namespace, "logs", "-l",
            self._workload_selector(name), "-c", self._container_name(name),
            "--prefix=true", "--tail=-1", timeout=15.0,
            context=target.context,
        )
        return result.stdout

    def _launch_server(
        self, declaration: Server, resources: Sequence[dict], spec: InstanceSpec,
    ) -> None:
        target = self._server_target(declaration.name)
        with self.owner.metrics.timer("server.startup", labels={"server": spec.name}):
            self._apply(resources, context=target.context)
            self._run(
                "-n", target.namespace, "rollout", "status",
                self._workload_resource(spec.name),
                "--timeout=%ds" % int(declaration.probe.timeout),
                timeout=declaration.probe.timeout + 5.0,
                context=target.context,
            )

    def _wait_for_probe(
        self, server: Server, local_ports: Mapping[str, int],
    ) -> None:
        if server.probe.kind == "tcp":
            self._wait_ready(
                local_ports[server.probe.endpoint], server.probe.timeout, server.name,
            )
            return
        if server.probe.kind in ("none", "exec"):
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
        replicas = self._server_replicas(server, remote_ports)
        target = self._server_target(server.name)
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
            metadata={
                **dict(server.metadata), "launcher": "kubernetes",
                "filesystem_transport": "kubernetes-sidecar-v1",
                "filesystem_roots": _remote_filesystem_roots(server),
                "kubernetes_namespace": target.namespace,
                "kubernetes_context": target.context,
                "environment": target.name,
            },
            replicas=replicas,
        )
        object.__setattr__(service, "_controller", owner)
        return service

    def _server_replicas(
        self, server: Server, remote_ports: Mapping[str, int],
    ) -> tuple[Replica, ...]:
        target = self._server_target(server.name)
        result = self._run(
            "-n", target.namespace, "get", "pods", "-l",
            self._workload_selector(server.name), "-o", "json",
            context=target.context,
        )
        try:
            payload = json.loads(result.stdout)
            replicas = replicas_from_pod_list(
                payload, self._service_ports(server, remote_ports),
                expected=server.replicas,
            )
        except (TypeError, ValueError, SpecError) as exc:
            raise CaseRunError(
                self.owner.nodeid, "Kubernetes replica discovery", str(exc),
            ) from exc
        for replica in replicas:
            self.owner.evidence.event("kubernetes-replica", replica.as_dict())
        return replicas

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

    def _prepare_case_assets(self, servers: Sequence[Server]) -> None:
        owner = self.owner
        owner.binary_store.capture_all(owner._all_binaries())
        self._generated_images, self._generated_binary_paths = prepare_server_images(
            self, servers,
        )
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
        return compile_grouped_resources(self, servers, resources, specs)

    def _register_services(
        self, servers: Sequence[Server], ports: Mapping[str, Mapping[str, int]],
    ) -> None:
        self._service_remote_ports = {name: dict(values) for name, values in ports.items()}
        for server in servers:
            self.owner._services[server.name] = self._service_from_server(
                server, ports[server.name],
            )

    def refreshed_replicas(self, name: str) -> tuple[Replica, ...]:
        """Read fresh Pod identities after a rollout or rescheduling event."""
        server = next(item for item in owned_servers(self.owner.definition) if item.name == name)
        return self._server_replicas(server, self._service_remote_ports[name])

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
        self._prepare_case_assets(servers)
        ports = self._internal_ports(servers)
        common, secure_root = self._case_values(servers, ports)
        secret_name, secure_items = self._create_case_secrets()
        start_kubernetes_auth_services(self)
        self._task_values = common
        self._task_secure_secret = self._client_secure_secret
        self._task_secure_items = self._client_secure_items
        _prepare_managed_resources(owner)
        resources, specs = self._build_resources(
            servers, common, ports, secure_root, secret_name, secure_items,
        )
        self._launch_servers(servers, resources, specs)
        record_grouped_init_tasks(self)
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
        roles: Sequence[str],
    ) -> subprocess.Popen:
        target = self._server_target(server.name)
        argv = list(self.command_prefix(target.context))
        argv.extend((
            "-n", target.namespace, "port-forward",
            "service/%s" % _resource_name(server.name),
        ))
        argv.extend("%d:%d" % (local[role], remote[role]) for role in roles)
        return subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        )

    @staticmethod
    def _forward_line(process: subprocess.Popen) -> str:
        assert process.stdout is not None
        ready, _, _ = select.select([process.stdout], [], [], 0.1)
        return process.stdout.readline() if ready else ""

    def _await_forward(self, process, marker: str, server: Server) -> str:
        deadline = time.monotonic() + server.probe.timeout
        output = []
        while time.monotonic() < deadline and process.poll() is None:
            line = self._forward_line(process)
            output.append(line)
            if marker in line:
                return line
        self._stop_forward(process)
        raise CaseRunError(
            self.owner.nodeid, "kubernetes gateway",
            "server %s: %s" % (server.name, "".join(output).strip()),
        )

    def _forward_tcp(self, server, remote, roles) -> Dict[str, int]:
        if not roles:
            return {}
        local = {role: self._free_port() for role in roles}
        process = self._forward_process(server, local, remote, roles)
        key = server.name + ":tcp"
        self._forward_logs[key] = self._await_forward(process, "Forwarding from", server)
        self._forwards[key] = process
        return local

    def _udp_forward_process(self, server, role: str, remote: int) -> subprocess.Popen:
        family = endpoint_families(server).get(role, "any")
        target = self._server_target(server.name)
        argv = [
            sys.executable, "-m", "brixtest.runtime.udp_gateway",
            "--kubectl", self.kubectl, "--namespace", target.namespace,
            "--target", _resource_name(server.name),
            "--target-host", "::1" if family in ("ipv6", "dual") else "127.0.0.1",
            "--target-port", str(remote), "--timeout", str(server.probe.timeout),
        ]
        if target.context:
            argv.extend(("--context", target.context))
        return subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        )

    def _forward_udp(self, server, remote, roles) -> Dict[str, int]:
        local = {}
        for role in roles:
            process = self._udp_forward_process(server, role, remote[role])
            line = self._await_forward(process, "BRIXTEST UDP READY", server)
            local[role] = int(line.rpartition(" ")[2])
            key = server.name + ":udp:" + role
            self._forward_logs[key] = line
            self._forwards[key] = process
        return local

    def _forward(
        self, server: Server, remote: Mapping[str, int],
    ) -> Dict[str, int]:
        protocols = endpoint_protocols(server)
        tcp = [role for role in server.ports if protocols.get(role, "tcp") == "tcp"]
        udp = [role for role in server.ports if protocols.get(role, "tcp") == "udp"]
        local = self._forward_tcp(server, remote, tcp)
        local.update(self._forward_udp(server, remote, udp))
        return local

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

    def _collect_server_log(self, server: Server, log_dir: Path) -> tuple[str, ...]:
        return KubernetesObserver(self).collect(server, log_dir)

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
            self._archive_forward_log(name, process)
            self._forwards.pop(name, None)

    def _archive_forward_log(self, name: str, process: subprocess.Popen) -> None:
        output = self._forward_logs.pop(name, "")
        if process.stdout is not None:
            output += process.stdout.read()
        root = self.owner.root / "runtime" / "logs" / "gateways"
        root.mkdir(parents=True, exist_ok=True)
        (root / (name.replace(":", "-") + ".log")).write_text(output)

    def _collect_server_logs(self, log_dir: Path) -> list[str]:
        errors = []
        for server in owned_servers(self.owner.definition):
            errors.extend(self._collect_server_log(server, log_dir))
        return errors

    def _delete_server_workloads(self) -> list[str]:
        grouped = {}
        for server in owned_servers(self.owner.definition):
            target = self._server_target(server.name)
            key = target.context, target.namespace
            grouped.setdefault(key, set()).add(self._workload_resource(server.name))
        errors = []
        for (context, namespace), resources in grouped.items():
            try:
                self._run(
                    "-n", namespace, "delete", *sorted(resources),
                    "--ignore-not-found=true", "--wait=true", timeout=30.0,
                    context=context,
                )
            except CaseRunError as exc:
                errors.append(str(exc))
        return errors

    def quiesce(self) -> None:
        """Stop owned workloads while retaining provider objects for teardown."""
        if self._quiesced or not self._namespace_created:
            return
        self._close_forwards()
        log_dir = self.owner.root / "runtime" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        errors = self._collect_server_logs(log_dir)
        errors.extend(self._delete_server_workloads())
        errors.extend(close_kubernetes_auth_services(self))
        self._quiesced = True
        if errors:
            raise CaseRunError(
                self.owner.nodeid, "Kubernetes workload teardown", "; ".join(errors),
            )

    def _delete_namespace(self) -> list[str]:
        return self._delete_environment_namespaces()

    def _close_namespace(self) -> list[str]:
        if not self._namespace_created:
            return []
        return self._delete_namespace()

    def close(self) -> None:
        errors = []
        try:
            self.quiesce()
        except CaseRunError as exc:
            errors.append(str(exc))
        errors.extend(self._close_namespace())
        if errors:
            raise CaseRunError(self.owner.nodeid, "kubernetes teardown", "; ".join(errors))
