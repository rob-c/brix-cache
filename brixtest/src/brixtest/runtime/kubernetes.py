"""Kubernetes backend for the same case declarations used by local runs."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Mapping, Sequence, Tuple

from brixtest.design import Binary, Server
from brixtest.errors import CaseRunError, SpecError
from brixtest.fleet.registry import InstanceSpec
from brixtest.runtime.topology import owned_servers
from brixtest.util.configtext import render_cfg_strict

__all__ = ["KubernetesCaseManager", "secure_secret_resource", "server_resources"]


from brixtest.runtime.kubernetes_manifests import (
    _resource_name,
    _secret_environment,
    secure_secret_resource,
    server_resources,
)
from brixtest.runtime.kubernetes_preparation import KubernetesPreparationMixin
from brixtest.runtime.kubernetes_lifecycle import KubernetesLifecycleMixin


class KubernetesCaseManager(KubernetesLifecycleMixin, KubernetesPreparationMixin):
    def __init__(self, owner) -> None:
        self.owner = owner
        requested = {
            server.placement.namespace for server in owned_servers(owner.definition)
            if server.placement.namespace
        }
        if len(requested) > 1:
            raise SpecError(
                "Kubernetes placement.namespace", sorted(requested),
                "all servers in one case must use the same namespace prefix",
            )
        prefix = next(iter(requested), "brixtest")
        if re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", prefix) is None:
            raise SpecError(
                "Kubernetes placement.namespace", prefix,
                "must be a lowercase DNS label used as the case namespace prefix",
            )
        suffix = owner.root.name.lower().replace("_", "-")[-32:]
        self.namespace = ("%s-%s" % (prefix, suffix))[-63:].strip("-")
        self.kubectl = os.environ.get("BRIXTEST_KUBECTL", "kubectl")
        self.context = str(
            getattr(owner, "kubernetes_context", "")
            or os.environ.get("BRIXTEST_KUBE_CONTEXT", "")
        )
        self._forwards: Dict[str, subprocess.Popen] = {}
        self._namespace_created = False
        self._client_runtime: Dict[str, Mapping[str, object]] = {}
        self._client_secure_secret = ""
        self._client_secure_items: Sequence[dict] = ()
        self._client_secret_environment: Dict[str, str] = {}

    @classmethod
    def from_manager(cls, owner):
        backend = cls(owner)
        owner._kubernetes = backend
        return backend

    def _run(self, *args: str, input_text: str = "", timeout: float = 30.0) -> subprocess.CompletedProcess:
        argv = list(self.command_prefix())
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

    def command_prefix(self) -> tuple[str, ...]:
        """Return kubectl plus the explicit context selected for this attempt."""
        argv = [self.kubectl]
        if self.context:
            argv.extend(("--context", self.context))
        return tuple(argv)

    def signal(self, name: str, signal_name: str) -> None:
        """Send a conventional POSIX signal to PID 1 in one server pod."""
        if signal_name not in ("TERM", "INT", "QUIT", "KILL", "HUP", "USR1", "USR2"):
            raise SpecError("Kubernetes server signal", signal_name, "has an unknown signal name")
        self._run(
            "-n", self.namespace, "exec", "deployment/%s" % _resource_name(name),
            "--", "kill", "-s", signal_name, "1", timeout=15.0,
        )

    def restart(self, name: str) -> None:
        """Roll out a fresh pod from the captured immutable deployment."""
        resource = "deployment/%s" % _resource_name(name)
        self._run("-n", self.namespace, "rollout", "restart", resource)
        self._run(
            "-n", self.namespace, "rollout", "status", resource,
            "--timeout=60s", timeout=65.0,
        )

    def _apply(self, documents: Sequence[dict]) -> None:
        text = "\n---\n".join(json.dumps(item) for item in documents) + "\n"
        self._run("apply", "-f", "-", input_text=text)

    def _case_values(
        self, servers: Sequence[Server], ports: Mapping[str, Mapping[str, int]],
    ) -> tuple[Dict[str, object], Path]:
        owner = self.owner
        secure_root = Path("/brixtest/secure")
        common = dict(owner._global_values(
            ports, credential_base=secure_root / "credentials", auth_base=secure_root / "auth",
        ))
        for server in servers:
            host = _resource_name(server.name)
            roles = ports[server.name]
            common["server_%s_host" % server.name] = host
            common["server_%s_url" % server.name] = "http://%s:%d" % (
                host, roles["primary"],
            )
            schemes = {item.name: item.scheme for item in server.endpoints}
            for role, port in roles.items():
                common["server_%s_%s_port" % (server.name, role)] = port
                common["server_%s_%s_url" % (server.name, role)] = "%s://%s:%d" % (
                    schemes.get(role) or "http", host, port,
                )
        return common, secure_root

    def _create_case_secrets(self) -> tuple[str, Sequence[dict]]:
        owner = self.owner
        self._apply([{
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {
                "name": self.namespace,
                "labels": {"app.kubernetes.io/managed-by": "brixtest"},
            },
        }])
        self._namespace_created = True
        secure_files = owner.security.secure_files("server")
        secret_name = "brixtest-secure" if secure_files else ""
        secure_items: Sequence[dict] = ()
        if secure_files:
            secret, secure_items = secure_secret_resource(
                self.namespace, secure_files, name=secret_name,
            )
            self._apply([secret])
        client_files = owner.security.secure_files("client")
        if client_files:
            self._client_secure_secret = "brixtest-client-secure"
            client_secret, self._client_secure_items = secure_secret_resource(
                self.namespace, client_files, name=self._client_secure_secret,
            )
            self._apply([client_secret])
            self._client_secret_environment.update(_secret_environment(
                client_files, self._client_secure_items,
                owner.security.environment("client"),
            ))
        return secret_name, secure_items

    @staticmethod
    def _render_server_command(server: Server, values: Mapping[str, object]) -> list[str]:
        command = []
        for part in server.command:
            if isinstance(part, Binary):
                if part.image_path is None:
                    raise SpecError(
                        "server %s command" % server.name, part.name,
                        "every Binary used on Kubernetes needs image_path",
                    )
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
    ) -> tuple[Tuple[dict, dict, dict], InstanceSpec]:
        values = self._server_values(server, common, ports[server.name])
        captured = self._capture_server_configs(server, values)
        mount_secret, mount_items, temporary, managed_volumes = self._server_mounts(
            server, captured, values,
        )
        command = self._render_server_command(server, values)
        env = self._render_server_environment(server, values, secure_root)
        identity = next((
            item for item in self.owner.definition.identities
            if item.name == server.placement.identity
        ), None)
        peers = {
            item.name: (item, ports[item.name])
            for item in self.owner.definition.servers
        }
        documents = server_resources(
            server, namespace=self.namespace, command=command, env=env,
            ports=ports[server.name],
            config_text={item.filename: item.rendered.read_text() for item in captured},
            secure_secret=secret_name, secure_items=secure_items,
            host_aliases=self.owner.definition.hosts, mount_secret=mount_secret,
            mount_items=mount_items, temporary_mounts=temporary,
            managed_volumes=managed_volumes,
            identity=identity, peers=peers, render_network_policy=True,
        )
        return documents, self._instance_spec(server, ports[server.name], command, server_names)

    @staticmethod
    def _server_values(
        server: Server, common: Mapping[str, object], ports: Mapping[str, int],
    ) -> Dict[str, object]:
        values = dict(common)
        values.update({
            "name": server.name,
            "host": "0.0.0.0",  # noqa: S104 - pods bind every container interface
        })
        for role, port in ports.items():
            key = "port" if role == "primary" else "%s_port" % role
            values[key] = port
        return values

    def _capture_server_configs(self, server: Server, values: Dict[str, object]):
        captured = self.owner.config_store.capture_all(server, values)
        values["config"] = "/brixtest/config/%s" % server.config.destination
        for item in captured:
            placeholder = self.owner.config_store.placeholder(item.filename)
            values["config_%s" % placeholder] = "/brixtest/config/%s" % item.filename
        return captured

    def _server_mounts(self, server: Server, captured, values: Mapping[str, object]):
        mount_files, temporary, managed = self._mount_files(server, captured, values)
        if not mount_files:
            return "", (), temporary, managed
        mount_secret = "%s-mounts" % _resource_name(server.name)
        mount_document, mount_items = secure_secret_resource(
            self.namespace, mount_files, name=mount_secret,
        )
        self._apply([mount_document])
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
