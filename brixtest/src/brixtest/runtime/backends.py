"""One case-level backend contract shared by local and Kubernetes execution."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Mapping

from brixtest.errors import SpecError
from brixtest.extensions import get_extension, register_extension
from brixtest.minikube import _status_is_running
from brixtest.planning.capabilities import backend_capabilities
from brixtest.resources import Reference
from brixtest.runtime.executors import tool_executor
from brixtest.runtime.launchers import server_launcher
from brixtest.runtime.backend_validation import (
    validate_kubernetes_environments,
    validate_kubernetes_groups,
    validate_kubernetes_server_policy,
    validate_kubernetes_task_placement,
    validate_kubernetes_volumes,
    validate_local_server_groups,
    validate_local_volumes,
)

__all__ = ["BackendContext", "case_backend"]


class BackendContext:
    """Public, capability-focused facade supplied to case backend extensions."""

    def __init__(self, manager: object) -> None:
        self.__manager = manager

    @property
    def definition(self) -> object:
        """The immutable :class:`CaseDefinition` owned by this attempt."""
        return self.__manager.definition

    @property
    def nodeid(self) -> str:
        """The full pytest node id used for evidence correlation."""
        return self.__manager.nodeid

    @property
    def root(self) -> Path:
        """The unique retained root for this managed attempt."""
        return self.__manager.root

    @property
    def workspace(self) -> Path:
        """The confined writable workspace for servers and tools."""
        return self.__manager.workspace

    @property
    def backend(self) -> str:
        """The selected case-backend name."""
        return self.__manager.backend_name

    @property
    def metrics(self) -> object:
        """The case metric recorder."""
        return self.__manager.metrics

    @property
    def evidence(self) -> object:
        """The content-addressed evidence recorder."""
        return self.__manager.evidence

    @property
    def services(self) -> Mapping[str, object]:
        """A snapshot of services already published by the backend."""
        return dict(self.__manager._services)

    @property
    def run(self) -> object:
        """Build the normal backend-neutral fixture facade for this attempt."""
        from brixtest.runtime.api import Run

        return Run(self.__manager)

    def start_local(self) -> None:
        """Materialize and start the declared graph with the built-in local engine."""
        self.__manager._start_local()

    def stop_local(self) -> None:
        """Stop every server started by :meth:`start_local`."""
        self.__manager._stop_started()

    def start_kubernetes(self) -> object:
        """Materialize the graph in a unique Kubernetes namespace."""
        from brixtest.runtime.kubernetes import KubernetesCaseManager

        return KubernetesCaseManager.from_manager(self.__manager).start()

    def stop_kubernetes(self) -> None:
        """Collect logs and remove the owned Kubernetes namespace."""
        backend = getattr(self.__manager, "_kubernetes", None)
        if backend is not None:
            backend.close()

    def set_kubernetes_context(self, context: str) -> None:
        """Select one explicit kubeconfig context without mutating kubeconfig."""
        if not isinstance(context, str) or not context:
            raise SpecError("Kubernetes context", context, "must be non-empty text")
        self.__manager.kubernetes_context = context

    def publish_service(self, service: object) -> None:
        """Publish a backend-neutral Service for consumption through ``Run``."""
        from brixtest.runtime.api import Service

        if not isinstance(service, Service):
            raise SpecError("backend service", service, "must be brixtest.Service")
        self.__manager._services[service.name] = service


class LocalCaseBackend:
    """Run every case-owned server as a supervised local process."""

    name = "local"
    brixtest_api_version = 1
    brixtest_capabilities = tuple(sorted(backend_capabilities("local")))

    def validate(self, declaration: object) -> None:
        validate_local_volumes(getattr(declaration, "volumes", ()))
        servers = getattr(declaration, "servers", ())
        validate_local_server_groups(servers)
        self._validate_servers(servers)
        self._validate_clients(getattr(declaration, "clients", ()))
        groups = {
            server.placement.group for server in getattr(declaration, "servers", ())
            if server.placement.group
        }
        for task in getattr(declaration, "tasks", ()):
            self._validate_task(task, groups)

    @staticmethod
    def _validate_servers(servers) -> None:
        for server in servers:
            placement = server.placement
            selected = "process" if placement.backend in ("inherit", "local") else placement.backend
            server_launcher(selected).validate(server)

    @staticmethod
    def _validate_clients(clients) -> None:
        for client in clients:
            placement = client.placement
            selected = "local" if placement.backend == "inherit" else placement.backend
            tool_executor(selected).validate(client)

    @staticmethod
    def _validate_task(task, groups) -> None:
        placement = task.placement
        if placement.backend in ("docker", "podman"):
            tool_executor(placement.backend).validate(task)
            return
        if placement.backend not in ("inherit", "local", "process"):
            raise SpecError(
                "task %s placement.backend" % task.name, placement.backend,
                "local managed tasks require process, docker, or podman",
            )
        limits = placement.resources
        scheduled = (
            placement.image, placement.namespace, placement.labels,
            placement.node_selector, placement.security_context, placement.options,
            placement.allow_mutable_image,
            placement.environment,
            placement.network_policy != "declared",
            limits.cpu, limits.memory_bytes, limits.pids,
        )
        if any(scheduled):
            raise SpecError(
                "task %s placement" % task.name, placement,
                "local tasks cannot silently ignore image, environment, identity, scheduling, or resource policy",
            )
        if placement.group and (task.phase != "init" or placement.group not in groups):
            raise SpecError(
                "task %s placement.group" % task.name, placement.group,
                "local grouping is reserved for init tasks sharing a server group",
            )

    def plan(self, context: object) -> Mapping[str, object]:
        return {"backend": self.name}

    def prepare(self, context: object) -> None:
        return None

    def start(self, context: object):
        context.start_local()
        return context.run

    def stop(self, context: object) -> None:
        context.stop_local()

    def collect(self, context: object) -> Mapping[str, object]:
        return {"backend": self.name, "servers": tuple(sorted(context.services))}


class KubernetesCaseBackend:
    """Materialize the same resource graph as Kubernetes namespace resources."""

    name = "kubernetes"
    brixtest_api_version = 1
    brixtest_capabilities = tuple(sorted(backend_capabilities("kubernetes")))

    def validate(self, declaration: object) -> None:
        validate_kubernetes_environments(declaration, self.name)
        validate_kubernetes_groups(declaration)
        validate_kubernetes_volumes(
            getattr(declaration, "volumes", ()),
            getattr(declaration, "managed_resources", ()),
        )
        for server in getattr(declaration, "servers", ()):
            self._validate_server(server)
        for client in getattr(declaration, "clients", ()):
            self._validate_client(client, declaration)
        for task in getattr(declaration, "tasks", ()):
            self._validate_task(task, declaration)

    def _validate_server(self, server) -> None:
        if server.placement.backend not in ("inherit", "kubernetes", self.name):
            raise SpecError(
                "server %s placement.backend" % server.name, server.placement.backend,
                "the Kubernetes case backend accepts inherit or kubernetes",
            )
        if server.probe.kind == "log":
            raise SpecError(
                "server %s probe.kind" % server.name, "log",
                "Kubernetes logs are archived at teardown; use tcp, http, https, exec, or an extension probe",
            )
        validate_kubernetes_server_policy(server)

    @staticmethod
    def _validate_task(task, declaration) -> None:
        placement = task.placement
        if placement.backend not in ("inherit", "kubernetes"):
            raise SpecError(
                "task %s placement.backend" % task.name, placement.backend,
                "the Kubernetes backend accepts inherit or kubernetes tasks",
            )
        KubernetesCaseBackend._validate_task_resources(task)
        KubernetesCaseBackend._validate_task_limits(task)
        KubernetesCaseBackend._validate_task_references(task)
        _validate_remote_binary_references(task, declaration.binaries)
        validate_kubernetes_task_placement(task)

    @staticmethod
    def _validate_task_references(task) -> None:
        references = _direct_references(task)
        artifacts = sorted(item.name for item in references if item.kind == "artifact")
        if artifacts:
            raise SpecError(
                "task %s references" % task.name, artifacts,
                "Kubernetes task artifact inputs require a declared provider-backed mount",
            )

    @staticmethod
    def _validate_task_resources(task) -> None:
        if task.outputs or task.mounts:
            raise SpecError(
                "task %s resources" % task.name,
                {"outputs": dict(task.outputs), "mounts": tuple(task.mounts)},
                "Kubernetes task outputs and mounts require a provider-backed volume",
            )

    @staticmethod
    def _validate_task_limits(task) -> None:
        placement = task.placement
        if placement.resources.pids is not None:
            raise SpecError(
                "task %s placement.resources.pids" % task.name,
                placement.resources.pids,
                "Kubernetes has no portable per-container PID limit",
            )

    @staticmethod
    def _validate_client(client, declaration) -> None:
        placement = client.placement
        selected = _client_backend(placement.backend)
        tool_executor(selected).validate(client)
        if selected == "kubernetes":
            _validate_remote_binary_references(client, declaration.binaries)
        KubernetesCaseBackend._validate_client_namespace(
            client, selected, declaration.servers,
        )
        if selected == "kubernetes" and client.placement.network_policy != "declared":
            raise SpecError(
                "client %s placement.network_policy" % client.name,
                client.placement.network_policy,
                "Kubernetes tool policies require an executor extension",
            )

    @staticmethod
    def _validate_client_namespace(client, selected: str, servers) -> None:
        placement = client.placement
        if selected != "kubernetes" or not placement.namespace:
            return
        requested = _server_namespaces(servers)
        if requested and placement.namespace not in requested:
            raise SpecError(
                "client %s placement.namespace" % client.name, placement.namespace,
                "must match the case Kubernetes namespace prefix",
            )

    def plan(self, context: object) -> Mapping[str, object]:
        return {"backend": self.name}

    def prepare(self, context: object) -> None:
        return None

    def start(self, context: object):
        return context.start_kubernetes()

    def stop(self, context: object) -> None:
        context.stop_kubernetes()

    def collect(self, context: object) -> Mapping[str, object]:
        return {"backend": self.name, "servers": tuple(sorted(context.services))}


def _client_backend(value: str) -> str:
    return "local" if value == "inherit" else value


def _direct_references(declaration) -> tuple[Reference, ...]:
    return tuple(
        value for value in (*declaration.command, *declaration.env.values())
        if isinstance(value, Reference)
    )


def _validate_remote_binary_references(declaration, binaries) -> None:
    unavailable = _unavailable_remote_binaries(declaration, binaries)
    if unavailable:
        raise SpecError(
            "%s %s binary references" % (declaration.resource_kind, declaration.name),
            unavailable, "require image_path inside the selected Kubernetes image",
        )


def _unavailable_remote_binaries(declaration, binaries) -> list[str]:
    names = _remote_binary_reference_names(declaration)
    catalog = {item.name: item for item in binaries}
    return sorted(name for name in names if not catalog[name].image_path)


def _remote_binary_reference_names(declaration) -> set[str]:
    return {
        item.name for item in _direct_references(declaration)
        if item.kind == "binary"
    }


def _server_namespaces(servers) -> set[str]:
    return {
        server.placement.namespace
        for server in servers
        if server.placement.namespace
    }


def _minikube_tools() -> None:
    missing = [name for name in ("docker", "minikube", "kubectl") if shutil.which(name) is None]
    if missing:
        raise SpecError("Minikube backend", missing, "requires Docker, minikube, and kubectl on PATH")


def _minikube_profile(profile: str) -> Mapping[str, object]:
    try:
        result = subprocess.run(
            ["minikube", "profile", "list", "--output=json"],
            capture_output=True, text=True, timeout=10.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SpecError("Minikube backend", profile, "cannot inspect profiles: %s" % exc) from exc
    if result.returncode:
        raise SpecError("Minikube backend", profile, "cannot inspect profiles: %s" % result.stderr.strip())
    try:
        payload = json.loads(result.stdout or "{}")
    except ValueError as exc:
        raise SpecError("Minikube backend", profile, "profile list returned invalid JSON") from exc
    profiles = payload.get("valid", payload.get("Valid", ()))
    selected = next((row for row in profiles if row.get("Name") == profile), None)
    if selected is None:
        raise SpecError("Minikube backend", profile, "profile is not running; use `brixtest minikube start`")
    return selected


def _minikube_driver(selected: Mapping[str, object]) -> None:
    config = selected.get("Config", {})
    driver = config.get("Driver", selected.get("Driver", "")) if isinstance(config, Mapping) else ""
    if driver != "docker":
        raise SpecError(
            "Minikube backend driver", driver,
            "the first-class local target requires the Docker driver",
        )


def _minikube_status(profile: str) -> None:
    try:
        status = subprocess.run(
            ["minikube", "status", "--profile", profile, "--output=json"],
            capture_output=True, text=True, timeout=15.0, check=False,
        )
        payload = json.loads(status.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise SpecError("Minikube backend", profile, "cannot verify cluster readiness: %s" % exc) from exc
    if status.returncode or not _status_is_running(payload):
        raise SpecError("Minikube backend", profile, "profile is not ready; use `brixtest minikube start`")


class MinikubeCaseBackend(KubernetesCaseBackend):
    """Run the Kubernetes engine against a Docker-backed Minikube profile."""

    name = "minikube"
    brixtest_capabilities = tuple(sorted(backend_capabilities("minikube")))

    def plan(self, context: object) -> Mapping[str, object]:
        profile = os.environ.get("BRIXTEST_MINIKUBE_PROFILE", "brixtest")
        return {
            "backend": self.name, "profile": profile,
            "driver": "docker", "context": profile,
        }

    def prepare(self, context: object) -> None:
        profile = os.environ.get("BRIXTEST_MINIKUBE_PROFILE", "brixtest")
        _minikube_tools()
        selected = _minikube_profile(profile)
        _minikube_driver(selected)
        _minikube_status(profile)
        context.set_kubernetes_context(profile)


_BUILTINS = {
    "local": LocalCaseBackend(),
    "kubernetes": KubernetesCaseBackend(),
    "minikube": MinikubeCaseBackend(),
}


def case_backend(name: str):
    """Resolve a built-in or installed case backend through one contract."""
    if name in _BUILTINS:
        target = _BUILTINS[name]
        register_extension(
            "backend", name, target, replace=True, origin="brixtest",
            capabilities=tuple(sorted(backend_capabilities(name))),
        )
        return target
    return get_extension("backend", name)


for _name, _backend in _BUILTINS.items():
    with contextlib.suppress(SpecError):
        register_extension(
            "backend", _name, _backend, origin="brixtest",
            capabilities=tuple(sorted(backend_capabilities(_name))),
        )
