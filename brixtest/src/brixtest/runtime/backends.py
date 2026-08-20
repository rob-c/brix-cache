"""One case-level backend contract shared by local and Kubernetes execution."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Mapping

from brixtest.errors import SpecError
from brixtest.extensions import get_extension, register_extension
from brixtest.minikube import _status_is_running
from brixtest.runtime.executors import tool_executor
from brixtest.runtime.launchers import server_launcher

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

    def validate(self, declaration: object) -> None:
        for server in getattr(declaration, "servers", ()):
            placement = server.placement
            selected = "process" if placement.backend in ("inherit", "local") else placement.backend
            server_launcher(selected).validate(server)
        for client in getattr(declaration, "clients", ()):
            placement = client.placement
            selected = "local" if placement.backend == "inherit" else placement.backend
            tool_executor(selected).validate(client)
        return None

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

    def validate(self, declaration: object) -> None:
        for server in getattr(declaration, "servers", ()):
            if server.placement.backend not in ("inherit", "kubernetes", self.name):
                raise SpecError(
                    "server %s placement.backend" % server.name,
                    server.placement.backend,
                    "the Kubernetes case backend accepts inherit or kubernetes",
                )
            udp = [item.name for item in server.endpoints if item.protocol == "udp"]
            if udp:
                raise SpecError(
                    "server %s endpoints" % server.name, udp,
                    "kubectl port-forward cannot publish UDP endpoints",
                )
            if server.probe.kind == "log":
                raise SpecError(
                    "server %s probe.kind" % server.name, "log",
                    "Kubernetes logs are archived at teardown; use tcp, http, https, exec, or an extension probe",
                )
        for client in getattr(declaration, "clients", ()):
            placement = client.placement
            selected = "local" if placement.backend == "inherit" else placement.backend
            tool_executor(selected).validate(client)
            if selected == "kubernetes" and placement.namespace:
                requested = {
                    server.placement.namespace for server in declaration.servers
                    if server.placement.namespace
                }
                if requested and placement.namespace not in requested:
                    raise SpecError(
                        "client %s placement.namespace" % client.name,
                        placement.namespace,
                        "must match the case Kubernetes namespace prefix",
                    )
        return None

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


class MinikubeCaseBackend(KubernetesCaseBackend):
    """Run the Kubernetes engine against a Docker-backed Minikube profile."""

    name = "minikube"

    def plan(self, context: object) -> Mapping[str, object]:
        profile = os.environ.get("BRIXTEST_MINIKUBE_PROFILE", "brixtest")
        return {
            "backend": self.name, "profile": profile,
            "driver": "docker", "context": profile,
        }

    def prepare(self, context: object) -> None:
        profile = os.environ.get("BRIXTEST_MINIKUBE_PROFILE", "brixtest")
        missing = [
            name for name in ("docker", "minikube", "kubectl")
            if shutil.which(name) is None
        ]
        if missing:
            raise SpecError(
                "Minikube backend", missing,
                "requires Docker, minikube, and kubectl on PATH",
            )
        try:
            result = subprocess.run(
                ["minikube", "profile", "list", "--output=json"],
                capture_output=True, text=True, timeout=10.0, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SpecError(
                "Minikube backend", profile,
                "cannot inspect profiles: %s" % exc,
            ) from exc
        if result.returncode:
            raise SpecError(
                "Minikube backend", profile,
                "cannot inspect profiles: %s" % result.stderr.strip(),
            )
        try:
            payload = json.loads(result.stdout or "{}")
        except ValueError as exc:
            raise SpecError(
                "Minikube backend", profile,
                "profile list returned invalid JSON",
            ) from exc
        profiles = payload.get("valid", payload.get("Valid", ()))
        selected = next(
            (row for row in profiles if row.get("Name") == profile), None,
        )
        if selected is None:
            raise SpecError(
                "Minikube backend", profile,
                "profile is not running; use `brixtest minikube start`",
            )
        config = selected.get("Config", {})
        driver = config.get("Driver", selected.get("Driver", ""))
        if driver != "docker":
            raise SpecError(
                "Minikube backend driver", driver,
                "the first-class local target requires the Docker driver",
            )
        try:
            status = subprocess.run(
                ["minikube", "status", "--profile", profile, "--output=json"],
                capture_output=True, text=True, timeout=15.0, check=False,
            )
            status_payload = json.loads(status.stdout or "{}")
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            raise SpecError(
                "Minikube backend", profile,
                "cannot verify cluster readiness: %s" % exc,
            ) from exc
        if status.returncode or not _status_is_running(status_payload):
            raise SpecError(
                "Minikube backend", profile,
                "profile is not ready; use `brixtest minikube start`",
            )
        context.set_kubernetes_context(profile)


_BUILTINS = {
    "local": LocalCaseBackend(),
    "kubernetes": KubernetesCaseBackend(),
    "minikube": MinikubeCaseBackend(),
}


def case_backend(name: str):
    """Resolve a built-in or installed case backend through one contract."""
    if name in _BUILTINS:
        return _BUILTINS[name]
    return get_extension("backend", name)


for _name, _backend in _BUILTINS.items():
    try:
        register_extension(
            "backend", _name, _backend, origin="brixtest",
            capabilities=("artifacts", "logs", "metrics", "provenance"),
        )
    except SpecError:
        pass
