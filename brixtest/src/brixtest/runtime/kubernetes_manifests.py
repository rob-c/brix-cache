"""Kubernetes resource manifests generated from backend-neutral declarations."""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence, Tuple, Union

from brixtest._design_managed import Identity
from brixtest.design import Binary, Server
from brixtest.errors import SpecError
from brixtest.network import HostMapping
from brixtest.runtime.kubernetes_identity import apply_identity, identity_resources
from brixtest.runtime.kubernetes_addressing import service_family_fields
from brixtest.runtime.kubernetes_network import network_policy_resources
from brixtest.runtime.kubernetes_storage import kubernetes_volume_resources

_DEFAULT_FILESYSTEM_IMAGE = (
    "python@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a"
)


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
    images = _binary_images(server)
    if len(images) != 1:
        raise SpecError(
            "server %s image" % server.name, sorted(images),
            "Kubernetes needs server.image or exactly one Binary image",
        )
    return _pinned_image(next(iter(images)), "server %s image" % server.name)


def _selected_image(server: Server, generated: str) -> str:
    if not generated:
        return _image(server)
    pattern = r"[^@\s]+/[a-z0-9-]+:sha256-[0-9a-f]{64}"
    if re.fullmatch(pattern, generated) is None:
        raise SpecError(
            "server %s generated image" % server.name, generated,
            "must be a BriXTest content-addressed image tag",
        )
    return generated


def _binary_images(server: Server) -> set[str]:
    command_images = {
        part.image for part in server.command
        if isinstance(part, Binary) and part.image
    }
    declared_images = {item.image for item in server.binaries if item.image}
    return command_images | declared_images


def _endpoint_protocol(server: Server, role: str) -> str:
    for endpoint in server.endpoints:
        if endpoint.name == role:
            return endpoint.protocol.upper()
    return "TCP"


def _port_document(
    server: Server, index: int, role: str, port: int, *, service: bool,
) -> dict:
    document = {
        "name": "port-%d" % index,
        "protocol": _endpoint_protocol(server, role),
    }
    if service:
        document.update({"port": port, "targetPort": port})
    else:
        document["containerPort"] = port
    return document


def _primary_ports(port: int) -> tuple[list[dict], list[dict]]:
    return (
        [{"name": "primary", "containerPort": port, "protocol": "TCP"}],
        [{"name": "primary", "port": port, "targetPort": port, "protocol": "TCP"}],
    )


def _kubernetes_ports(
    server: Server, ports: Mapping[str, int],
) -> tuple[list[dict], list[dict]]:
    selected = [(role, port) for role, port in ports.items() if role != "primary"]
    if not selected:
        return _primary_ports(ports["primary"])
    container_ports = [
        _port_document(server, index, role, port, service=False)
        for index, (role, port) in enumerate(selected)
    ]
    service_ports = [
        _port_document(server, index, role, port, service=True)
        for index, (role, port) in enumerate(selected)
    ]
    return container_ports, service_ports


def _kubernetes_volumes(
    secure_secret: str, secure_items: Sequence[dict], mount_secret: str,
    mount_items: Sequence[dict], temporary_mounts: Sequence[str],
    managed_volumes: Sequence[tuple[object, object]], namespace: str,
    provider_outputs: Mapping[str, Mapping[str, object]],
) -> tuple[list[dict], list[dict], list[dict]]:
    volume_mounts = [
        {"name": "config", "mountPath": "/brixtest/config", "readOnly": True},
        {"name": "workspace", "mountPath": "/brixtest/workspace", "readOnly": False},
    ]
    volumes = [{"name": "config", "configMap": {}}, {"name": "workspace", "emptyDir": {}}]
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
            "name": "declared-mounts", "mountPath": "/brixtest/mounts", "readOnly": True,
        })
        volumes.append({
            "name": "declared-mounts",
            "secret": {"secretName": mount_secret, "items": list(mount_items)},
        })
    for index, target in enumerate(temporary_mounts):
        name = "temporary-%d" % index
        volume_mounts.append({
            "name": name, "mountPath": "/brixtest/mounts/%s" % target, "readOnly": False,
        })
        volumes.append({"name": name, "emptyDir": {}})
    managed_mounts, managed_sources, claims = kubernetes_volume_resources(
        managed_volumes, namespace, provider_outputs,
    )
    volume_mounts.extend(managed_mounts)
    volumes.extend(managed_sources)
    return volume_mounts, volumes, claims


def _kubernetes_resources(server: Server, container: dict) -> None:
    limits = server.placement.resources
    values = _resource_limits(limits)
    if values:
        container["resources"] = {"limits": values, "requests": values}
    _apply_security_context(container, server.placement.security_context)


def _resource_limits(limits) -> dict[str, str]:
    values = {}
    if limits.cpu is not None:
        values["cpu"] = str(limits.cpu)
    if limits.memory_bytes is not None:
        values["memory"] = str(limits.memory_bytes)
    return values


def _apply_security_context(container: dict, value: Mapping[str, object]) -> None:
    if value:
        container["securityContext"] = dict(value)


def _kubernetes_probe(
    server: Server, ports: Mapping[str, int], command: Sequence[str] = (),
) -> dict:
    probe = server.probe
    timing = {
        "periodSeconds": max(1, int(probe.interval)),
        "timeoutSeconds": max(1, min(10, int(probe.timeout))),
    }
    if probe.kind == "tcp":
        return {"tcpSocket": {"port": ports[probe.endpoint]}, **timing}
    if probe.kind in ("http", "https"):
        return {
            "httpGet": {
                "path": probe.path, "port": ports[probe.endpoint],
                "scheme": probe.kind.upper(),
            },
            **timing,
        }
    if probe.kind == "exec":
        selected = list(command or (str(part) for part in probe.command))
        return {"exec": {"command": selected}, **timing}
    return {}


def server_resources(
    server: Server, *, namespace: str, command: Sequence[str], env: Mapping[str, str],
    ports: Mapping[str, int], config_text: Union[str, Mapping[str, str]], secure_secret: str = "",
    secure_items: Sequence[dict] = (), host_aliases: Sequence[HostMapping] = (),
    mount_secret: str = "", mount_items: Sequence[dict] = (),
    temporary_mounts: Sequence[str] = (),
    managed_volumes: Sequence[tuple[object, object]] = (),
    provider_outputs: Optional[Mapping[str, Mapping[str, object]]] = None,
    identity: Optional[Identity] = None,
    peers: Optional[Mapping[str, tuple]] = None,
    authority_endpoints: Optional[Mapping[str, int]] = None,
    render_network_policy: bool = False,
    image: str = "", image_pull_policy: str = "IfNotPresent",
    probe_command: Sequence[str] = (), shutdown_command: Sequence[str] = (),
    filesystem_image: str = "",
    test_instance: str = "",
) -> Tuple[dict, ...]:
    """Return typed Kubernetes workload and service documents for one server."""
    providers = _optional_mapping(provider_outputs)
    peer_values = _optional_mapping(peers)
    authorities = _optional_mapping(authority_endpoints)
    _validate_config_destinations(server)
    resource_name = _resource_name(server.name)
    labels = _labels(server, resource_name, namespace)
    config_name = "%s-config" % resource_name
    config_map = _config_map(
        server, namespace, labels, config_name, config_text,
    )
    container_ports, service_ports = _kubernetes_ports(server, ports)
    volume_mounts, volumes, claims = _kubernetes_volumes(
        secure_secret, secure_items, mount_secret, mount_items, temporary_mounts,
        managed_volumes, namespace, providers,
    )
    volumes[0]["configMap"] = {"name": config_name}
    container = _server_container(
        server, command, env, container_ports, volume_mounts, ports,
        image, image_pull_policy, probe_command, shutdown_command,
    )
    filesystem = _filesystem_container(volume_mounts, filesystem_image)
    pod_spec = _pod_spec(server, container, filesystem, volumes, host_aliases)
    apply_identity(pod_spec, container, identity)
    apply_identity(pod_spec, filesystem, identity)
    workload, auxiliary = _workload(
        server, resource_name, namespace, labels, pod_spec, managed_volumes,
    )
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": resource_name, "namespace": namespace, "labels": labels},
        "spec": {
            "selector": labels, "ports": service_ports,
            **service_family_fields(server),
        },
    }
    identities = identity_resources(identity, namespace) if identity is not None else ()
    policies = network_policy_resources(
        server, namespace, ports, peer_values, authorities,
        test_instance=test_instance,
    ) if render_network_policy else ()
    return config_map, *claims, *identities, *policies, *auxiliary, workload, service


def _optional_mapping(value):
    return {} if value is None else value


def _validate_config_destinations(server: Server) -> None:
    for declaration in server.configs.files:
        if Path(declaration.destination).name != declaration.destination:
            raise SpecError(
                "server %s config.destination" % server.name, declaration.destination,
                "Kubernetes config destinations must be basenames",
            )


def _labels(server: Server, resource_name: str, namespace: str) -> dict:
    return {
        "app.kubernetes.io/name": resource_name, "brixtest.io/case": namespace,
        **dict(server.placement.labels),
    }


def _config_map(
    server: Server, namespace: str, labels: Mapping[str, str], config_name: str,
    config_text: Union[str, Mapping[str, str]],
) -> dict:
    data = dict(config_text) if isinstance(config_text, Mapping) else {
        server.config.destination: config_text
    }
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": config_name, "namespace": namespace, "labels": labels},
        "data": data,
    }


def _server_container(
    server: Server, command: Sequence[str], env: Mapping[str, str],
    container_ports: Sequence[dict], volume_mounts: Sequence[dict],
    ports: Mapping[str, int], image: str, image_pull_policy: str,
    probe_command: Sequence[str], shutdown_command: Sequence[str],
) -> dict:
    if image_pull_policy not in ("IfNotPresent", "Never"):
        raise SpecError(
            "server %s image pull policy" % server.name, image_pull_policy,
            "must be IfNotPresent or Never",
        )
    container = {
        "name": "server", "image": _selected_image(server, image),
        "imagePullPolicy": image_pull_policy,
        "command": list(command),
        "workingDir": _working_directory(server),
        "env": [{"name": key, "value": value} for key, value in sorted(env.items())],
        "ports": container_ports, "volumeMounts": volume_mounts,
    }
    _kubernetes_resources(server, container)
    readiness = _kubernetes_probe(server, ports, probe_command)
    if readiness:
        container["readinessProbe"] = readiness
    if shutdown_command:
        container["lifecycle"] = {
            "preStop": {"exec": {"command": list(shutdown_command)}},
        }
    return container


def _filesystem_container(volume_mounts: Sequence[dict], image: str) -> dict:
    selected = image or os.environ.get(
        "BRIXTEST_KUBERNETES_FILESYSTEM_IMAGE", _DEFAULT_FILESYSTEM_IMAGE,
    )
    return {
        "name": "brixtest-filesystem",
        "image": _pinned_image(selected, "Kubernetes filesystem helper image"),
        "imagePullPolicy": "IfNotPresent",
        "command": [
            "python3", "-c",
            "import signal,time;signal.signal(signal.SIGTERM,lambda *_:exit(0));time.sleep(31536000)",
        ],
        "volumeMounts": [dict(item) for item in volume_mounts],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "resources": {
            "requests": {"cpu": "10m", "memory": "32Mi"},
            "limits": {"cpu": "100m", "memory": "64Mi"},
        },
    }


def _working_directory(server: Server) -> str:
    root = Path("/brixtest/workspace")
    return str(root / server.cwd) if server.cwd else str(root)


def _pod_spec(
    server: Server, container: dict, filesystem: dict, volumes: Sequence[dict],
    host_aliases: Sequence[HostMapping],
) -> dict:
    pod_spec = {
        "containers": [container, filesystem], "volumes": volumes,
        "terminationGracePeriodSeconds": max(1, int(server.lifecycle.stop_timeout)),
    }
    if server.placement.node_selector:
        pod_spec["nodeSelector"] = dict(server.placement.node_selector)
    selected_aliases = _server_host_aliases(host_aliases)
    if selected_aliases:
        pod_spec["hostAliases"] = selected_aliases
    return pod_spec


def _server_host_aliases(values: Sequence[HostMapping]) -> list[dict]:
    return [
        {"ip": item.address, "hostnames": list(item.hostnames)}
        for item in values if item.libc and "server" in item.targets
    ]


def _deployment(
    resource_name: str, namespace: str, labels: Mapping[str, str], pod_spec: dict,
    *, replicas: int,
) -> dict:
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": resource_name, "namespace": namespace, "labels": labels},
        "spec": {
            "replicas": replicas, "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": pod_spec},
        },
    }


def _workload(server, name, namespace, labels, pod_spec, managed_volumes):
    if not any(_stateful_volume(volume) for _mount, volume in managed_volumes):
        return _deployment(
            name, namespace, labels, pod_spec, replicas=server.replicas,
        ), ()
    headless_name = "%s-headless" % name
    workload = {
        "apiVersion": "apps/v1", "kind": "StatefulSet",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "serviceName": headless_name, "replicas": server.replicas,
            "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": pod_spec},
        },
    }
    headless = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": headless_name, "namespace": namespace, "labels": labels},
        "spec": {"clusterIP": "None", "selector": labels},
    }
    return workload, (headless,)


def _stateful_volume(volume) -> bool:
    return bool(
        volume.persistent or volume.kind in ("persistent", "shared", "provider")
    )


def _secret_entry(relative: object, path: Path, index: int) -> tuple[str, str, dict]:
    _validate_secret_relative(relative)
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise SpecError(
            "Kubernetes secret source", str(source),
            "must be a regular non-symlink file",
        )
    key = "file-%04d" % index
    encoded = base64.b64encode(source.read_bytes()).decode()
    return key, encoded, {"key": key, "path": relative, "mode": 0o400}


def _validate_secret_relative(relative: object) -> None:
    if not isinstance(relative, str) or not relative:
        raise SpecError(
            "Kubernetes secret path", relative, "must be non-empty relative text",
        )
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise SpecError(
            "Kubernetes secret path", relative, "must be a confined relative path",
        )


def secure_secret_resource(
    namespace: str, files: Mapping[str, Path], *, name: str = "brixtest-secure",
) -> Tuple[dict, list[dict]]:
    """Build one Secret plus projection items without exposing paths as keys."""
    data = {}
    items = []
    for index, (relative, path) in enumerate(sorted(files.items())):
        key, encoded, item = _secret_entry(relative, path, index)
        data[key] = encoded
        items.append(item)
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
