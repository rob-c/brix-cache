"""Kubernetes backend for the same case declarations used by local runs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, Mapping, Sequence, Tuple

from brixtest.design import Binary, Server, Task
from brixtest.errors import CaseRunError, SpecError
from brixtest.fleet.registry import InstanceSpec
from brixtest.util.configtext import render_cfg_strict

__all__ = ["KubernetesCaseManager", "secure_secret_resource", "server_resources"]


from brixtest.runtime.kubernetes_manifests import (
    _resource_name,
    _secret_environment,
    secure_secret_resource,
    server_resources,
)
from brixtest.runtime.kubernetes_addressing import pod_bind_hosts
from brixtest.runtime.kubernetes_preparation import KubernetesPreparationMixin
from brixtest.runtime.kubernetes_preparation import _artifact_remote_path, _referenced_names
from brixtest.runtime.kubernetes_provider_values import provider_outputs
from brixtest.runtime.kubernetes_lifecycle import KubernetesLifecycleMixin
from brixtest.runtime.kubernetes_tasks import task_resources
from brixtest.runtime.kubernetes_auth import authority_endpoints
from brixtest.runtime.managed import _task_order
from brixtest.runtime.commands import CommandResult
from brixtest.runtime.kubernetes_documents import KubernetesDocumentMixin
from brixtest.runtime.kubernetes_environments import KubernetesEnvironmentLayout
from brixtest.runtime.kubernetes_environment_resources import (
    KubernetesEnvironmentResourcesMixin,
)


def _selected_identity(identities, name: str):
    return next((item for item in identities if item.name == name), None)


def _server_peers(manager, ports) -> dict:
    return {
        item.name: (
            item, ports[item.name], manager.environments.for_server(item.name).namespace,
        )
        for item in manager.owner.definition.servers
    }


def _captured_config_text(captured) -> dict[str, str]:
    return {item.filename: item.rendered.read_text() for item in captured}


def _workload_document(documents) -> dict:
    return next(
        item for item in documents
        if item.get("kind") in ("Deployment", "StatefulSet")
    )


class KubernetesCaseManager(
    KubernetesDocumentMixin, KubernetesEnvironmentResourcesMixin,
    KubernetesLifecycleMixin, KubernetesPreparationMixin,
):
    def __init__(self, owner) -> None:
        self.owner = owner
        self.kubectl = os.environ.get("BRIXTEST_KUBECTL", "kubectl")
        self.context = str(
            getattr(owner, "kubernetes_context", "")
            or os.environ.get("BRIXTEST_KUBE_CONTEXT", "")
        )
        self.environments = KubernetesEnvironmentLayout(owner, self.context)
        self.namespace = self.environments.default.namespace
        self.test_instance = self.environments.test_instance
        self._forwards: Dict[str, subprocess.Popen] = {}
        self._forward_logs: Dict[str, str] = {}
        self._namespace_created = False
        self._quiesced = False
        self._namespace_uid = ""
        self._namespace_uids: Dict[tuple[str, str], str] = {}
        self._client_runtime: Dict[str, Mapping[str, object]] = {}
        self._client_secure_secret = ""
        self._client_secure_items: Sequence[dict] = ()
        self._client_secret_environment: Dict[str, str] = {}
        self._task_values: Mapping[str, object] = {}
        self._task_secure_secret = ""
        self._task_secure_items: Sequence[dict] = ()
        self._generated_images: Dict[str, str] = {}
        self._generated_binary_paths: Dict[str, Mapping[str, str]] = {}
        self._auth_services: Dict[str, object] = {}
        self._workload_kinds: Dict[str, str] = {}

    @classmethod
    def from_manager(cls, owner):
        backend = cls(owner)
        owner._kubernetes = backend
        owner._providers.bind_kubernetes(backend)
        return backend

    def _run(
        self, *args: str, input_text: str = "", timeout: float = 30.0,
        context: str = "",
    ) -> subprocess.CompletedProcess:
        argv = list(self.command_prefix(context))
        argv.extend(args)
        try:
            completed = self.owner.commands.run(
                *argv, input=input_text or None, timeout=timeout,
                check=False, output_limit=4 << 20,
            )
            result = subprocess.CompletedProcess(
                argv, completed.returncode, completed.stdout, completed.stderr,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CaseRunError(self.owner.nodeid, "kubernetes", str(exc)) from exc
        if result.returncode:
            raise CaseRunError(
                self.owner.nodeid, "kubernetes",
                "%s\n%s" % (" ".join(args), result.stderr.strip()),
            )
        return result

    def command_prefix(self, context: str = "") -> tuple[str, ...]:
        """Return kubectl plus the explicit context selected for this attempt."""
        argv = [self.kubectl]
        selected = context or self.context
        if selected:
            argv.extend(("--context", selected))
        return tuple(argv)

    def _case_values(
        self, servers: Sequence[Server], ports: Mapping[str, Mapping[str, int]],
    ) -> tuple[Dict[str, object], Path]:
        owner = self.owner
        secure_root = Path("/brixtest/secure")
        common = dict(owner._global_values(
            ports, credential_base=secure_root / "credentials", auth_base=secure_root / "auth",
        ))
        common.update({"workspace": Path("/brixtest/workspace"), "run_root": Path("/brixtest")})
        for server in servers:
            host = (
                self.environments.server_dns(server.name)
                if owner.definition.environments else _resource_name(server.name)
            )
            roles = ports[server.name]
            owner._add_declared_server_values(
                common, server.name, roles,
                {role: host for role in (*roles, "primary")},
            )
        return common, secure_root

    def _render_server_command(self, server: Server, values: Mapping[str, object]) -> list[str]:
        command = []
        for part in server.command:
            if isinstance(part, Binary):
                generated = self._generated_binary_paths.get(server.name, {}).get(part.name)
                if generated:
                    command.append(generated)
                elif part.image_path is None:
                    raise SpecError(
                        "server %s command" % server.name, part.name,
                        "every Binary used on Kubernetes needs image_path",
                    )
                else:
                    command.append(part.image_path)
            else:
                command.append(render_cfg_strict(
                    str(part), values, template="server %s command" % server.name,
                ))
        return command

    def _render_server_environment(
        self, server: Server, values: Mapping[str, object], secure_root: Path,
    ) -> Dict[str, str]:
        env = self._declared_server_environment(server, values)
        env.update(self.owner.security.environment(
            "server", credential_base=secure_root / "credentials",
            auth_base=secure_root / "auth",
        ))
        env.update(self._mount_environment(values))
        env.update(self._suite_server_environment(values))
        return env

    def _task_identity(self, task: Task):
        return next((
            item for item in self.owner.definition.identities
            if item.name == task.placement.identity
        ), None)

    def _render_task_command(self, task: Task) -> tuple[str, ...]:
        values = self._task_reference_values(task)
        command = []
        for part in task.command:
            if isinstance(part, Binary):
                if part.image_path is None:
                    raise SpecError(
                        "task %s command" % task.name, part.name,
                        "every Kubernetes Binary needs image_path",
                    )
                command.append(part.image_path)
            else:
                command.append(render_cfg_strict(
                    str(part), values,
                    template="task %s command" % task.name,
                ))
        return tuple(command)

    def _render_task_environment(self, task: Task) -> Dict[str, str]:
        values = self._task_reference_values(task)
        return {
            name: render_cfg_strict(
                str(value), values,
                template="task %s env[%s]" % (task.name, name),
            )
            for name, value in task.env.items()
        }

    def _task_reference_values(self, task: Task) -> Dict[str, object]:
        values = dict(self._task_values)
        catalog = {item.name: item for item in self.owner.definition.binaries}
        for name in _referenced_names(
            task, "binary", self.owner.definition.binaries, self.owner.source_root,
        ):
            path = catalog[name].image_path
            values["binary_%s" % name] = path
            values["binary_%s_dir" % name] = str(Path(path).parent)
        return values

    def run_task_phase(self, phase: str) -> None:
        selected = self._phase_tasks(phase)
        known = self._known_tasks()
        for task in _task_order(selected, self.owner._managed._completed, known):
            self._run_task(task)

    def _phase_tasks(self, phase: str) -> tuple[Task, ...]:
        return tuple(
            task for task in self.owner.definition.tasks
            if task.phase == phase and task.name not in self.owner._managed._completed
            and not (phase == "init" and task.placement.group)
        )

    def _known_tasks(self) -> set[str]:
        return {task.name for task in self.owner.definition.tasks}

    def _run_task(self, task: Task) -> None:
        target = self.environments.for_task(task.name)
        command = self._render_task_command(task)
        documents = task_resources(
            task, namespace=target.namespace, command=command,
            env=self._render_task_environment(task), identity=self._task_identity(task),
            secure_secret=self._task_secure_secret,
            secure_items=self._task_secure_items,
        )
        started = time.perf_counter()
        self._apply(documents, context=target.context)
        returncode, error = self._wait_task(task)
        log_result = self._task_log(task)
        result = CommandResult(
            command, returncode, log_result.stdout,
            error or log_result.stderr, time.perf_counter() - started,
        )
        self.owner._managed.record_external(task, result)
        self._archive_task_log(task, result.stdout + result.stderr)
        if returncode:
            raise CaseRunError(
                self.owner.nodeid, "Kubernetes task %s" % task.name,
                result.stderr or result.stdout or "Job failed",
            )

    def _wait_task(self, task: Task) -> tuple[int, str]:
        target = self.environments.for_task(task.name)
        deadline = time.monotonic() + task.timeout
        resource = "job/task-%s" % task.name.replace("_", "-")
        while time.monotonic() < deadline:
            result = self._run(
                "-n", target.namespace, "get", resource, "-o", "json",
                timeout=min(10.0, task.timeout),
                context=target.context,
            )
            try:
                status = json.loads(result.stdout).get("status", {})
            except (AttributeError, ValueError):
                status = {}
            if status.get("succeeded"):
                return 0, ""
            if status.get("failed"):
                return 1, "Kubernetes Job reported failure"
            time.sleep(0.1)
        return 124, "Kubernetes task exceeded %.3fs" % task.timeout

    def _task_log(self, task: Task) -> subprocess.CompletedProcess:
        target = self.environments.for_task(task.name)
        return self._run(
            "-n", target.namespace, "logs",
            "job/task-%s" % task.name.replace("_", "-"),
            "--all-containers=true", timeout=min(30.0, task.timeout),
            context=target.context,
        )

    def _archive_task_log(self, task: Task, content: str) -> None:
        path = self.owner.root / "runtime" / "tasks" / task.name / "task.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.owner.evidence.attach(
            path, name="task-%s-log" % task.name, role="task-log",
            description="Kubernetes managed task output",
        )

    @staticmethod
    def _declared_server_environment(
        server: Server, values: Mapping[str, object],
    ) -> Dict[str, str]:
        return {
            key: render_cfg_strict(
                str(value), values, template="server %s env[%s]" % (server.name, key),
            )
            for key, value in server.env.items()
        }

    @staticmethod
    def _mount_environment(values: Mapping[str, object]) -> Dict[str, str]:
        return {
            key.upper(): str(value) for key, value in values.items()
            if key.startswith("mount_") and not key.rpartition("_")[2].isdigit()
        }

    @staticmethod
    def _suite_server_environment(values: Mapping[str, object]) -> Dict[str, str]:
        from brixtest.runtime.manager import _environment

        return {
            key: render_cfg_strict(value, values, template="suite server env[%s]" % key)
            for key, value in _environment("BRIXTEST_SERVER_ENV_JSON").items()
        }

    def _render_server_resource(
        self, server: Server, common: Mapping[str, object],
        ports: Mapping[str, Mapping[str, int]], secure_root: Path,
        secret_name: str, secure_items: Sequence[dict], server_names: set[str],
    ) -> tuple[Tuple[dict, ...], InstanceSpec]:
        target = self.environments.for_server(server.name)
        values = self._server_values(server, common, ports[server.name])
        captured = self._capture_server_configs(server, values)
        mount_secret, mount_items, temporary, managed_volumes = self._server_mounts(
            server, captured, values, target,
        )
        command = self._render_server_command(server, values)
        env = self._render_server_environment(server, values, secure_root)
        identity = _selected_identity(
            self.owner.definition.identities, server.placement.identity,
        )
        peers = _server_peers(self, ports)
        image, pull_policy = self._server_image_options(server.name)
        documents = server_resources(
            server, namespace=target.namespace, command=command, env=env,
            ports=ports[server.name],
            config_text=_captured_config_text(captured),
            secure_secret=secret_name, secure_items=secure_items,
            host_aliases=self.owner.definition.hosts, mount_secret=mount_secret,
            mount_items=mount_items, temporary_mounts=temporary,
            managed_volumes=managed_volumes,
            provider_outputs=provider_outputs(self.owner),
            identity=identity, peers=peers, render_network_policy=True,
            authority_endpoints=authority_endpoints(self),
            image=image, image_pull_policy=pull_policy,
            probe_command=self._render_probe_command(server, values),
            shutdown_command=self._render_lifecycle_command(server, values),
            test_instance=self.test_instance,
        )
        workload = _workload_document(documents)
        self._workload_kinds[server.name] = workload["kind"].lower()
        return documents, self._instance_spec(server, ports[server.name], command, server_names)

    @staticmethod
    def _render_lifecycle_command(
        server: Server, values: Mapping[str, object],
    ) -> tuple[str, ...]:
        return tuple(
            render_cfg_strict(
                str(part), values, template="server %s shutdown command" % server.name,
            )
            for part in server.lifecycle.shutdown_command
        )

    def _server_image_options(self, name: str) -> tuple[str, str]:
        image = self._generated_images.get(name, "")
        local = image.startswith("brixtest.local/")
        return image, "Never" if local else "IfNotPresent"

    def _server_values(
        self, server: Server, common: Mapping[str, object], ports: Mapping[str, int],
    ) -> Dict[str, object]:
        values = dict(common)
        hosts = pod_bind_hosts(server)
        values.update({"name": server.name, "host": hosts["primary"]})
        for role, port in ports.items():
            key = "port" if role == "primary" else "%s_port" % role
            values[key] = port
            values["host" if role == "primary" else "%s_host" % role] = hosts.get(
                role, hosts["primary"],
            )
        values.update(self._server_binary_reference_values(server))
        values.update(self._server_artifact_reference_values(server))
        return values

    def _server_binary_reference_values(self, server: Server) -> Dict[str, object]:
        values = {}
        paths = dict(self._generated_binary_paths.get(server.name, {}))
        for declaration in self.owner.definition.binaries:
            if declaration.image_path:
                paths.setdefault(declaration.name, declaration.image_path)
        for name, path in paths.items():
            values["binary_%s" % name] = path
            values["binary_%s_dir" % name] = str(Path(path).parent)
        return values

    def _server_artifact_reference_values(self, server: Server) -> Dict[str, object]:
        values = {}
        for name in _referenced_names(
            server, "artifact", self.owner.definition.artifacts,
            self.owner.source_root,
        ):
            artifact = self.owner.artifact_store.get(name)
            _target, remote = _artifact_remote_path(name, artifact.path)
            values["artifact_%s" % name] = remote
            values["artifact_%s_dir" % name] = remote.parent
        return values

    def _capture_server_configs(self, server: Server, values: Dict[str, object]):
        captured = self.owner.config_store.capture_all(server, values)
        values["config"] = "/brixtest/config/%s" % server.config.destination
        for item in captured:
            placeholder = self.owner.config_store.placeholder(item.filename)
            values["config_%s" % placeholder] = "/brixtest/config/%s" % item.filename
        return captured

    def _server_mounts(
        self, server: Server, captured, values: Mapping[str, object], target,
    ):
        mount_files, temporary, managed = self._mount_files(server, captured, values)
        if not mount_files:
            return "", (), temporary, managed
        mount_secret = "%s-mounts" % _resource_name(server.name)
        mount_document, mount_items = secure_secret_resource(
            target.namespace, mount_files, name=mount_secret,
        )
        self._apply([mount_document], context=target.context)
        return mount_secret, mount_items, temporary, managed

    @staticmethod
    def _instance_spec(
        server: Server, ports: Mapping[str, int], command: Sequence[str],
        server_names: set[str],
    ) -> InstanceSpec:
        dependencies = (
            item.name if isinstance(item, Server) else item
            for item in server.depends_on
        )
        return InstanceSpec(
            name=server.name, kind="kubernetes", ports=ports,
            depends_on=tuple(item for item in dependencies if item in server_names),
            command=command,
        )
