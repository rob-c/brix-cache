"""Shared shell-free primitives for remote tool executors."""

from __future__ import annotations

import re
import subprocess
import uuid
from pathlib import Path
from typing import Mapping, Sequence, Union

from brixtest.errors import SpecError
from brixtest.resources import Placement
from brixtest.runtime.commands import CommandRunner
from brixtest.runtime.executors import ToolExecutionRequest

DIGEST_IMAGE = re.compile(r"[^@]+@sha256:[0-9a-fA-F]{64}")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

def kubectl(
    executable: Union[str, Sequence[str]], *args: str,
    input_text: str = "", timeout: float = 30.0,
    output_limit: int = 1 << 20,
) -> subprocess.CompletedProcess:
    prefix = [executable] if isinstance(executable, str) else list(executable)
    argv = [*prefix, *args]
    try:
        result = CommandRunner(None, cwd=Path.cwd()).run(
            *argv, input=input_text or None, timeout=timeout, check=False,
            output_limit=output_limit,
        )
        return subprocess.CompletedProcess(
            argv, result.returncode, result.stdout, result.stderr,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(
            argv, 124, "", "%s: %s" % (type(exc).__name__, exc),
        )


def declared_image(declaration: object) -> str:
    placement = getattr(declaration, "placement", Placement())
    if placement.image:
        return placement.image
    images = {
        getattr(value, "image", None)
        for value in (
            *getattr(declaration, "command", ()), *getattr(declaration, "binaries", ()),
        )
        if getattr(value, "image", None)
    }
    return next(iter(images)) if len(images) == 1 else ""


def pod_name(name: str, attempt: int) -> str:
    suffix = uuid.uuid4().hex[:10]
    return ("brixtest-%s-%d-%s" % (name.replace("_", "-"), attempt, suffix))[-63:]


def _tool_volumes(runtime: Mapping[str, object]):
    mounts = [{"name": "workspace", "mountPath": "/brixtest/workspace"}]
    volumes = [{"name": "workspace", "emptyDir": {}}]
    for volume_name, secret_key, items_key, mount_path in (
        ("secure", "secure_secret", "secure_items", "/brixtest/secure"),
        ("declared-mounts", "mount_secret", "mount_items", "/brixtest/mounts"),
    ):
        secret = str(runtime.get(secret_key, ""))
        if secret:
            mounts.append({"name": volume_name, "mountPath": mount_path, "readOnly": True})
            volumes.append({
                "name": volume_name,
                "secret": {"secretName": secret, "items": list(runtime.get(items_key, ()))},
            })
    for index, target in enumerate(runtime.get("temporary_mounts", ())):
        volume_name = "temporary-%d" % index
        mounts.append({"name": volume_name, "mountPath": "/brixtest/mounts/%s" % target})
        volumes.append({"name": volume_name, "emptyDir": {}})
    return mounts, volumes


def _tool_secret_environment(container, runtime: Mapping[str, object]) -> None:
    environment = runtime.get("secret_environment", {})
    if not isinstance(environment, Mapping):
        raise SpecError("Kubernetes tool secret environment", environment, "must be a mapping")
    secret_name = str(runtime.get("secure_secret", ""))
    if environment and not secret_name:
        raise SpecError(
            "Kubernetes tool secret environment", environment,
            "requires a projected secure_secret",
        )
    for name, key in sorted(environment.items()):
        if _ENV_NAME.fullmatch(str(name)) is None or not str(key):
            raise SpecError(
                "Kubernetes tool secret environment", environment,
                "must map portable environment names to Secret data keys",
            )
        container["env"].append({
            "name": str(name),
            "valueFrom": {"secretKeyRef": {"name": secret_name, "key": str(key)}},
        })


def _tool_resources(placement: Placement) -> dict[str, str]:
    limits = placement.resources
    resources = {}
    if limits.cpu is not None:
        resources["cpu"] = str(limits.cpu)
    if limits.memory_bytes is not None:
        resources["memory"] = str(limits.memory_bytes)
    return resources


def _tool_pod_spec(container, volumes, placement: Placement, runtime):
    pod_spec: dict[str, object] = {
        "restartPolicy": "Never", "containers": [container], "volumes": volumes,
    }
    if placement.node_selector:
        pod_spec["nodeSelector"] = dict(placement.node_selector)
    host_aliases = runtime.get("host_aliases", ())
    if host_aliases:
        pod_spec["hostAliases"] = list(host_aliases)
    return pod_spec


def tool_pod(
    name: str, namespace: str, request: ToolExecutionRequest,
) -> Mapping[str, object]:
    placement = request.placement
    runtime = dict(request.metadata)
    _validate_tool_environment(request.env)
    volume_mounts, volumes = _tool_volumes(runtime)
    container = _tool_container(request, volume_mounts)
    _tool_secret_environment(container, runtime)
    _apply_tool_resources(container, placement)
    _apply_tool_security(container, placement)
    pod_spec = _tool_pod_spec(container, volumes, placement, runtime)
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": name, "namespace": namespace,
            "labels": {"app.kubernetes.io/managed-by": "brixtest", **dict(placement.labels)},
        },
        "spec": pod_spec,
    }


def _validate_tool_environment(environment: Mapping[str, str]) -> None:
    if not all(_ENV_NAME.fullmatch(key) is not None for key in environment):
        raise SpecError(
            "Kubernetes tool environment", tuple(sorted(environment)),
            "names must be portable [A-Za-z_][A-Za-z0-9_]* values",
        )


def _tool_container(request: ToolExecutionRequest, volume_mounts) -> dict[str, object]:
    return {
        "name": "tool", "image": request.image, "imagePullPolicy": "IfNotPresent",
        "command": list(request.argv),
        "env": [{"name": key, "value": value} for key, value in sorted(request.env.items())],
        "workingDir": str(request.cwd or Path("/brixtest/workspace")),
        "volumeMounts": volume_mounts,
    }


def _apply_tool_resources(container: dict, placement: Placement) -> None:
    resources = _tool_resources(placement)
    if resources:
        container["resources"] = {"limits": resources, "requests": resources}


def _apply_tool_security(container: dict, placement: Placement) -> None:
    if placement.security_context:
        container["securityContext"] = dict(placement.security_context)


def bounded(value: str, limit: int) -> tuple[str, bool]:
    payload = value.encode("utf-8", errors="replace")
    if len(payload) <= limit:
        return value, False
    marker = b"\n[BriXTest output truncated]\n"
    available = max(0, limit - len(marker))
    head = available // 2
    tail = available - head
    selected = payload[:head] + marker[:limit] + (payload[-tail:] if tail else b"")
    return selected[:limit].decode("utf-8", errors="replace"), True
