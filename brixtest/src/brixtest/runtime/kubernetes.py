"""Kubernetes backend for the same case declarations used by local runs."""

from __future__ import annotations

import base64
import json
import os
import re
import select
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Mapping, Sequence, Tuple, Union

from brixtest.credentials import Credential
from brixtest.design import Artifact, Binary, Client, ConfigFile, Server
from brixtest.errors import CaseRunError, SpecError
from brixtest.fleet.launcher import FleetPlan
from brixtest.fleet.registry import InstanceSpec, ServerEndpoint
from brixtest.network import HostMapping
from brixtest.resources import Reference
from brixtest.runtime.manager import Run, Service
from brixtest.runtime.topology import instance_for, owned_servers
from brixtest.runtime.resources import record_materialized_sizes
from brixtest.util.configtext import render_cfg_strict

__all__ = ["KubernetesCaseManager", "secure_secret_resource", "server_resources"]


def _pinned_image(value: str, field: str) -> str:
    if re.fullmatch(r"[^@]+@sha256:[0-9a-fA-F]{64}", value) is None:
        raise SpecError(
            field, value,
            "must use an immutable image digest (image@sha256:...) for reproducible runs",
        )
    return value


def _resource_name(value: str) -> str:
    """Translate a declaration name into a stable Kubernetes DNS label."""
    return value.replace("_", "-")[:63].strip("-")


def _image(server: Server) -> str:
    if server.placement.image:
        return _pinned_image(
            server.placement.image, "server %s placement.image" % server.name,
        )
    if server.image:
        return _pinned_image(server.image, "server %s image" % server.name)
    images: set[str] = set()
    for part in server.command:
        if isinstance(part, Binary) and part.image:
            images.add(part.image)
    for item in server.binaries:
        if item.image:
            images.add(item.image)
    if len(images) != 1:
        raise SpecError(
            "server %s image" % server.name, sorted(images),
            "Kubernetes needs server.image or exactly one Binary image",
        )
    return _pinned_image(next(iter(images)), "server %s image" % server.name)


def server_resources(
    server: Server, *, namespace: str, command: Sequence[str], env: Mapping[str, str],
    ports: Mapping[str, int], config_text: Union[str, Mapping[str, str]], secure_secret: str = "",
    secure_items: Sequence[dict] = (), host_aliases: Sequence[HostMapping] = (),
    mount_secret: str = "", mount_items: Sequence[dict] = (),
    temporary_mounts: Sequence[str] = (),
) -> Tuple[dict, dict, dict]:
    """Return ConfigMap, Deployment, and Service documents for one server."""
    for declaration in server.configs.files:
        if Path(declaration.destination).name != declaration.destination:
            raise SpecError(
                "server %s config.destination" % server.name,
                declaration.destination,
                "Kubernetes config destinations must be basenames",
            )
    resource_name = _resource_name(server.name)
    labels = {
        "app.kubernetes.io/name": resource_name, "brixtest.io/case": namespace,
        **dict(server.placement.labels),
    }
    config_name = "%s-config" % resource_name
    config_map = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": config_name, "namespace": namespace, "labels": labels},
        "data": (
            dict(config_text) if isinstance(config_text, Mapping)
            else {server.config.destination: config_text}
        ),
    }
    container_ports = [
        {"name": "port-%d" % index, "containerPort": port,
         "protocol": next(
             (item.protocol.upper() for item in server.endpoints if item.name == role),
             "TCP",
         )}
        for index, (role, port) in enumerate(
            (item for item in ports.items() if item[0] != "primary")
        )
    ]
    if not container_ports:
        container_ports = [{
            "name": "primary", "containerPort": ports["primary"], "protocol": "TCP"
        }]
    volume_mounts = [{
        "name": "config", "mountPath": "/brixtest/config", "readOnly": True,
    }]
    volumes = [{"name": "config", "configMap": {"name": config_name}}]
    if secure_secret:
        volume_mounts.append({
            "name": "secure", "mountPath": "/brixtest/secure", "readOnly": True,
        })
        volumes.append({
            "name": "secure",
            "secret": {"secretName": secure_secret, "items": list(secure_items)},
        })
    if mount_secret:
        volume_mounts.append({
            "name": "declared-mounts", "mountPath": "/brixtest/mounts",
            "readOnly": True,
        })
        volumes.append({
            "name": "declared-mounts",
            "secret": {"secretName": mount_secret, "items": list(mount_items)},
        })
    for index, target in enumerate(temporary_mounts):
        name = "temporary-%d" % index
        volume_mounts.append({
            "name": name, "mountPath": "/brixtest/mounts/%s" % target,
            "readOnly": False,
        })
        volumes.append({"name": name, "emptyDir": {}})
    container = {
            "name": "server", "image": _image(server),
            "imagePullPolicy": "IfNotPresent", "command": list(command),
            "env": [{"name": key, "value": value} for key, value in sorted(env.items())],
            "ports": container_ports, "volumeMounts": volume_mounts,
    }
    limits = server.placement.resources
    resource_values = {}
    if limits.cpu is not None:
        resource_values["cpu"] = str(limits.cpu)
    if limits.memory_bytes is not None:
        resource_values["memory"] = str(limits.memory_bytes)
    if resource_values:
        container["resources"] = {"limits": resource_values, "requests": resource_values}
    if limits.pids is not None:
        container.setdefault("env", []).append({
            "name": "BRIXTEST_PIDS_LIMIT", "value": str(limits.pids),
        })
    if server.placement.security_context:
        container["securityContext"] = dict(server.placement.security_context)
    declared_probe = server.probe
    if declared_probe.kind == "tcp":
        container["readinessProbe"] = {
            "tcpSocket": {"port": ports[declared_probe.endpoint]},
            "periodSeconds": max(1, int(declared_probe.interval)),
            "timeoutSeconds": max(1, min(10, int(declared_probe.timeout))),
        }
    elif declared_probe.kind in ("http", "https"):
        container["readinessProbe"] = {
            "httpGet": {
                "path": declared_probe.path, "port": ports[declared_probe.endpoint],
                "scheme": declared_probe.kind.upper(),
            },
            "periodSeconds": max(1, int(declared_probe.interval)),
            "timeoutSeconds": max(1, min(10, int(declared_probe.timeout))),
        }
    elif declared_probe.kind == "exec":
        container["readinessProbe"] = {
            "exec": {"command": [str(part) for part in declared_probe.command]},
            "periodSeconds": max(1, int(declared_probe.interval)),
            "timeoutSeconds": max(1, min(10, int(declared_probe.timeout))),
        }
    pod_spec = {
        "containers": [container],
        "volumes": volumes,
    }
    if server.placement.node_selector:
        pod_spec["nodeSelector"] = dict(server.placement.node_selector)
    if host_aliases:
        pod_spec["hostAliases"] = [
            {"ip": item.address, "hostnames": list(item.hostnames)}
            for item in host_aliases
        ]
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": resource_name, "namespace": namespace, "labels": labels},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": pod_spec,
            },
        },
    }
    service_ports = [
        {"name": "port-%d" % index, "port": port, "targetPort": port,
         "protocol": next(
             (item.protocol.upper() for item in server.endpoints if item.name == role),
             "TCP",
         )}
        for index, (role, port) in enumerate(
            (item for item in ports.items() if item[0] != "primary")
        )
    ]
    if not service_ports:
        service_ports = [{
            "name": "primary", "port": ports["primary"],
            "targetPort": ports["primary"], "protocol": "TCP",
        }]
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": resource_name, "namespace": namespace, "labels": labels},
        "spec": {"selector": labels, "ports": service_ports},
    }
    return config_map, deployment, service


def secure_secret_resource(
    namespace: str, files: Mapping[str, Path], *, name: str = "brixtest-secure",
) -> Tuple[dict, list[dict]]:
    """Build one Secret plus projection items without exposing paths as keys."""
    data = {}
    items = []
    for index, (relative, path) in enumerate(sorted(files.items())):
        if not isinstance(relative, str) or not relative:
            raise SpecError(
                "Kubernetes secret path", relative,
                "must be non-empty relative text",
            )
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts or not relative_path.parts:
            raise SpecError(
                "Kubernetes secret path", relative,
                "must be a confined relative path",
            )
        source = Path(path)
        if not source.is_file() or source.is_symlink():
            raise SpecError(
                "Kubernetes secret source", str(source),
                "must be a regular non-symlink file",
            )
        key = "file-%04d" % index
        data[key] = base64.b64encode(source.read_bytes()).decode()
        items.append({"key": key, "path": relative, "mode": 0o400})
    document = {
        "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
        "metadata": {
            "name": name, "namespace": namespace,
            "labels": {"app.kubernetes.io/managed-by": "brixtest"},
        },
        "data": data,
    }
    return document, items


def _secret_environment(
    files: Mapping[str, Path], items: Sequence[Mapping[str, object]],
    environment: Mapping[str, str],
) -> Mapping[str, str]:
    """Map content-valued environment entries to existing Secret data keys."""
    item_keys = {str(item["path"]): str(item["key"]) for item in items}
    selected: Dict[str, str] = {}
    for environment_name, environment_value in environment.items():
        for relative, path in files.items():
            try:
                content = path.read_text()
            except (OSError, UnicodeError):
                continue
            if environment_value == content:
                selected[environment_name] = item_keys[relative]
                break
    return selected


class KubernetesCaseManager:
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

    def _mount_files(
        self, server: Server, captured: Sequence[object], values: Dict[str, object],
    ) -> tuple[Mapping[str, Path], tuple[str, ...]]:
        """Resolve small read-only files and writable temporary projections."""
        owner = self.owner
        configs = {
            declaration.destination: item.rendered
            for declaration, item in zip(server.configs.files, captured)
        }
        files: Dict[str, Path] = {}
        temporary = []
        total = 0
        for index, declaration in enumerate(server.mounts):
            target = declaration.target
            values["mount_%s" % owner.config_store.placeholder(target)] = (
                "/brixtest/mounts/%s" % target
            )
            values["mount_%d" % index] = "/brixtest/mounts/%s" % target
            if declaration.kind == "tmp":
                temporary.append(target)
                continue
            if not declaration.read_only:
                raise SpecError(
                    "server %s mount" % server.name, target,
                    "Kubernetes writable projections must use kind='tmp'",
                )
            source = declaration.source
            if declaration.kind == "artifact" or isinstance(source, Artifact):
                path = owner.artifact_store.get(
                    source.name if isinstance(source, Artifact) else str(source)
                ).path
            elif declaration.kind == "credential" or isinstance(source, Credential):
                path = owner.security.credential(
                    source.name if isinstance(source, Credential) else str(source)
                ).path
            elif declaration.kind == "config" or isinstance(source, ConfigFile):
                destination = (
                    source.destination if isinstance(source, ConfigFile) else str(source)
                )
                try:
                    path = configs[destination]
                except KeyError:
                    raise SpecError(
                        "server %s mount.source" % server.name, destination,
                        "config mounts must belong to the mounted server",
                    ) from None
            elif hasattr(source, "path"):
                path = Path(str(getattr(source, "path"))).resolve()
            else:
                candidate = Path(str(source))
                path = candidate.resolve() if candidate.is_absolute() else (
                    owner.source_root / candidate
                ).resolve()
            if not path.is_file():
                raise SpecError(
                    "server %s mount.source" % server.name, str(source),
                    "Kubernetes projections require regular files",
                )
            total += path.stat().st_size
            files[target] = path
        if total > 768 << 10:
            raise SpecError(
                "server %s mounts" % server.name, total,
                "embedded Kubernetes projections are limited to 768 KiB; use an image, PVC, or backend extension",
            )
        return files, tuple(temporary)

    def _prepare_client_resources(self, client: Client) -> None:
        """Project only files required by one Kubernetes-executed client."""
        owner = self.owner
        files: Dict[str, Path] = {}
        temporary = []
        values: Dict[str, object] = {}

        def add_file(target: str, path: Path) -> None:
            if not path.is_file() or path.is_symlink():
                raise SpecError(
                    "client %s mount" % client.name, str(path),
                    "Kubernetes projections require regular non-symlink files",
                )
            files[target] = path

        for index, declaration in enumerate(client.mounts):
            target = declaration.target
            remote = Path("/brixtest/mounts") / target
            values["mount_%s" % owner.config_store.placeholder(target)] = remote
            values["mount_%d" % index] = remote
            if declaration.kind == "tmp":
                temporary.append(target)
                continue
            if not declaration.read_only:
                raise SpecError(
                    "client %s mount" % client.name, target,
                    "Kubernetes writable projections must use kind='tmp'",
                )
            source = declaration.source
            if declaration.kind == "artifact" or isinstance(source, Artifact):
                artifact = owner.artifact_store.get(
                    source.name if isinstance(source, Artifact) else str(source)
                )
                selected = artifact.path
                values["artifact_%s" % artifact.name] = remote
                values["artifact_%s_dir" % artifact.name] = remote.parent
            elif declaration.kind == "credential" or isinstance(source, Credential):
                selected = owner.security.credential(
                    source.name if isinstance(source, Credential) else str(source)
                ).path
            elif declaration.kind == "config" or isinstance(source, ConfigFile):
                raise SpecError(
                    "client %s mount" % client.name, target,
                    "client configs should be declared as artifacts",
                )
            elif hasattr(source, "path"):
                selected = Path(str(getattr(source, "path"))).resolve()
            else:
                candidate = Path(str(source))
                selected = candidate.resolve() if candidate.is_absolute() else (
                    owner.source_root / candidate
                ).resolve()
            add_file(target, selected)

        referenced = []
        for value in (*client.command, *client.env.values()):
            if isinstance(value, Reference) and value.kind == "artifact":
                referenced.append(value.name)
        for name in sorted(set(referenced)):
            artifact = owner.artifact_store.get(name)
            target = "auto/artifacts/%s/%s" % (name, artifact.path.name)
            remote = Path("/brixtest/mounts") / target
            add_file(target, artifact.path)
            values["artifact_%s" % name] = remote
            values["artifact_%s_dir" % name] = remote.parent

        total = sum(path.stat().st_size for path in files.values())
        if total > 768 << 10:
            raise SpecError(
                "client %s mounts" % client.name, total,
                "embedded Kubernetes projections are limited to 768 KiB; use an image, PVC, or executor extension",
            )
        mount_secret = ""
        mount_items: Sequence[dict] = ()
        if files:
            mount_secret = "%s-tool-mounts" % _resource_name(client.name)
            document, mount_items = secure_secret_resource(
                self.namespace, files, name=mount_secret,
            )
            self._apply([document])
        self._client_runtime[client.name] = {
            "secure_secret": self._client_secure_secret,
            "secure_items": tuple(self._client_secure_items),
            "secret_environment": dict(self._client_secret_environment),
            "mount_secret": mount_secret,
            "mount_items": tuple(mount_items),
            "temporary_mounts": tuple(temporary),
            "mount_values": values,
            "host_aliases": tuple(
                {"ip": item.address, "hostnames": list(item.hostnames)}
                for item in owner.definition.hosts
            ),
        }

    def client_metadata(self, client: Client) -> Mapping[str, object]:
        try:
            return self._client_runtime[client.name]
        except KeyError:
            raise SpecError(
                "Kubernetes client", client.name,
                "was not prepared for Kubernetes execution",
            ) from None

    @staticmethod
    def _internal_ports(servers: Sequence[Server]) -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        for index, server in enumerate(servers):
            roles = {}
            for offset, (role, requested) in enumerate(server.ports.items()):
                roles[role] = requested or (18000 + index * 100 + offset)
            if "primary" not in roles:
                role = (
                    server.probe.endpoint if server.probe.kind != "none"
                    else next(iter(server.ports))
                )
                roles["primary"] = roles[role]
            out[server.name] = roles
        return out

    def start(self) -> Run:
        if shutil.which(self.kubectl) is None:
            raise SpecError(
                "Kubernetes backend", self.kubectl,
                "kubectl is not installed or not on PATH",
            )
        owner = self.owner
        servers = owned_servers(owner.definition)
        resource_names = [_resource_name(item.name) for item in servers]
        if len(resource_names) != len(set(resource_names)):
            raise SpecError(
                "Kubernetes server names", resource_names,
                "names collide after Kubernetes DNS normalization",
            )
        owner.binary_store.capture_all(owner._all_binaries())
        owner.artifact_store.materialize_all(owner.definition.artifacts)
        owner.security.materialize()
        ports = self._internal_ports(servers)
        secure_root = Path("/brixtest/secure")
        common = owner._global_values(
            ports, credential_base=secure_root / "credentials",
            auth_base=secure_root / "auth",
        )
        for name, roles in ports.items():
            host = _resource_name(name)
            common["server_%s_host" % name] = host
            common["server_%s_url" % name] = "http://%s:%d" % (host, roles["primary"])
            declared = next(item for item in servers if item.name == name)
            schemes = {item.name: item.scheme for item in declared.endpoints}
            for role, port in roles.items():
                common["server_%s_%s_port" % (name, role)] = port
                common["server_%s_%s_url" % (name, role)] = "%s://%s:%d" % (
                    schemes.get(role) or "http", host, port,
                )
        self._apply([{
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": self.namespace,
                         "labels": {"app.kubernetes.io/managed-by": "brixtest"}},
        }])
        self._namespace_created = True
        secure_files = owner.security.secure_files("server")
        secret_name = "brixtest-secure" if secure_files else ""
        secure_items: List[dict] = []
        if secure_files:
            secret, secure_items = secure_secret_resource(
                self.namespace, secure_files, name=secret_name,
            )
            self._apply([secret])
        client_secure_files = owner.security.secure_files("client")
        if client_secure_files:
            self._client_secure_secret = "brixtest-client-secure"
            client_secret, self._client_secure_items = secure_secret_resource(
                self.namespace, client_secure_files, name=self._client_secure_secret,
            )
            self._apply([client_secret])
            self._client_secret_environment.update(_secret_environment(
                client_secure_files, self._client_secure_items,
                owner.security.environment("client"),
            ))
        resources: Dict[str, Tuple[dict, dict, dict]] = {}
        specs = []
        server_names = {server.name for server in servers}
        for server in servers:
            values = dict(common)
            values.update({"name": server.name, "host": "0.0.0.0"})
            for role, port in ports[server.name].items():
                values["port" if role == "primary" else "%s_port" % role] = port
            captured_files = owner.config_store.capture_all(server, values)
            values["config"] = "/brixtest/config/%s" % server.config.destination
            for item in captured_files:
                values["config_%s" % owner.config_store.placeholder(item.filename)] = (
                    "/brixtest/config/%s" % item.filename
                )
            mount_files, temporary_mounts = self._mount_files(
                server, captured_files, values,
            )
            mount_secret = ""
            mount_items: Sequence[dict] = ()
            if mount_files:
                mount_secret = "%s-mounts" % _resource_name(server.name)
                mount_document, mount_items = secure_secret_resource(
                    self.namespace, mount_files, name=mount_secret,
                )
                self._apply([mount_document])
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
                        str(part), values, template="server %s command" % server.name
                    ))
            rendered_env = {
                key: render_cfg_strict(str(value), values,
                                       template="server %s env[%s]" % (server.name, key))
                for key, value in server.env.items()
            }
            rendered_env.update(owner.security.environment(
                "server", credential_base=secure_root / "credentials",
                auth_base=secure_root / "auth",
            ))
            rendered_env.update({
                key.upper(): str(value) for key, value in values.items()
                if key.startswith("mount_") and not key.rpartition("_")[2].isdigit()
            })
            from brixtest.runtime.manager import _environment
            rendered_env.update({
                key: render_cfg_strict(value, values, template="suite server env[%s]" % key)
                for key, value in _environment("BRIXTEST_SERVER_ENV_JSON").items()
            })
            resources[server.name] = server_resources(
                server, namespace=self.namespace, command=command,
                env=rendered_env, ports=ports[server.name],
                config_text={
                    item.filename: item.rendered.read_text() for item in captured_files
                },
                secure_secret=secret_name, secure_items=secure_items,
                host_aliases=owner.definition.hosts,
                mount_secret=mount_secret, mount_items=mount_items,
                temporary_mounts=temporary_mounts,
            )
            specs.append(InstanceSpec(
                name=server.name, kind="kubernetes", ports=ports[server.name],
                depends_on=tuple(
                    item.name if isinstance(item, Server) else item
                    for item in server.depends_on
                    if (item.name if isinstance(item, Server) else item) in server_names
                ), command=command,
            ))
        plan = FleetPlan.build(specs)
        for level in plan.levels:
            for spec in level:
                with owner.metrics.timer(
                    "server.startup", labels={"server": spec.name}
                ):
                    self._apply(resources[spec.name])
                    declaration = next(item for item in servers if item.name == spec.name)
                    self._run(
                        "-n", self.namespace, "rollout", "status",
                        "deployment/%s" % _resource_name(spec.name),
                        "--timeout=%ds" % int(declaration.probe.timeout),
                        timeout=declaration.probe.timeout + 5.0,
                    )
        for server in servers:
            local_ports = self._forward(server, ports[server.name])
            if server.probe.kind == "tcp":
                self._wait_ready(
                    local_ports[server.probe.endpoint], server.probe.timeout,
                    server.name,
                )
            elif server.probe.kind not in ("none", "http", "https", "exec"):
                from brixtest.fleet.probes import probe_from_declaration

                probe_from_declaration(server.probe).wait(
                    ServerEndpoint(
                        server.name, "kubernetes", "127.0.0.1", local_ports,
                        owner.root / "runtime" / "kubernetes" / server.name,
                        owner.root / "runtime" / "logs" / (server.name + ".log"),
                        None,
                    ),
                    server.probe.timeout,
                )
            exposed = {role: local_ports[role] for role in server.ports}
            role = (
                server.probe.endpoint if server.probe.kind != "none"
                else next(iter(server.ports))
            )
            exposed.setdefault("primary", local_ports[role])
            config = owner.config_store.get(server.name)
            service = Service(
                name=server.name, host="127.0.0.1",
                ports=exposed,
                config=config.rendered,
                log=owner.root / "runtime" / "logs" / (server.name + ".log"),
                workdir=owner.root / "runtime" / "kubernetes" / server.name,
                instance_id=instance_for(owner.evidence.attempt_id, server.name),
                scope=server.scope, started_at=time.time(),
                config_filename=config.filename,
                config_sha256=config.rendered_sha256,
                config_source_sha256=config.source_sha256,
                config_declared_sha256=config.declared_sha256,
                configs={
                    item.filename: item.rendered
                    for item in owner.config_store.all(server.name)
                },
                schemes={item.name: item.scheme for item in server.endpoints if item.scheme},
                protocols={item.name: item.protocol for item in server.endpoints},
                metadata={**dict(server.metadata), "launcher": "kubernetes"},
            )
            object.__setattr__(service, "_controller", owner)
            owner._services[server.name] = service
        for client in owner.definition.clients:
            if client.placement.backend == "kubernetes":
                self._prepare_client_resources(client)
        local_values = owner._global_values({})
        common["workspace"] = Path("/brixtest/workspace")
        common["run_root"] = Path("/brixtest")
        owner._prepare_clients(local_values, (), remote_values=common)
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

    def _forward(self, server: Server, remote: Mapping[str, int]) -> Dict[str, int]:
        local = {role: self._free_port() for role in server.ports}
        argv = list(self.command_prefix())
        argv.extend(("-n", self.namespace, "port-forward",
                     "service/%s" % _resource_name(server.name)))
        argv.extend("%d:%d" % (local[role], remote[role]) for role in server.ports)
        process = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        )
        assert process.stdout is not None
        deadline = time.monotonic() + server.probe.timeout
        output = []
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            ready, _, _ = select.select([process.stdout], [], [], 0.1)
            if ready:
                line = process.stdout.readline()
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
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise CaseRunError(
            self.owner.nodeid, "kubernetes readiness",
            "%s did not answer forwarded port %d within %.1fs" % (server, port, timeout),
        )

    def close(self) -> None:
        errors = []
        for name, process in list(self._forwards.items()):
            try:
                process.terminate()
                process.wait(timeout=2.0)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
            self._forwards.pop(name, None)
        if self._namespace_created:
            log_dir = self.owner.root / "runtime" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            for server in owned_servers(self.owner.definition):
                try:
                    result = self._run(
                        "-n", self.namespace, "logs",
                        "deployment/%s" % _resource_name(server.name),
                        timeout=10.0,
                    )
                    (log_dir / (server.name + ".log")).write_text(
                        result.stdout + result.stderr
                    )
                    self.owner._apply_log_policy(
                        log_dir / (server.name + ".log"), server.logs,
                    )
                except CaseRunError as exc:
                    errors.append(str(exc))
            try:
                self._run(
                    "delete", "namespace", self.namespace, "--wait=false", timeout=20.0
                )
            except CaseRunError as exc:
                errors.append(str(exc))
            finally:
                self._namespace_created = False
        if errors:
            raise CaseRunError(self.owner.nodeid, "kubernetes teardown", "; ".join(errors))
