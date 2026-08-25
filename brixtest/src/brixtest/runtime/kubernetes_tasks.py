"""Render finite managed tasks as supervised Kubernetes Jobs."""

from __future__ import annotations

import re
from typing import Mapping, Optional, Sequence

from brixtest._design_inputs import Binary
from brixtest._design_managed import Identity, Task
from brixtest.errors import SpecError
from brixtest.runtime.kubernetes_identity import apply_identity, identity_resources

_DIGEST = re.compile(r"^[^@\s]+@sha256:[0-9a-fA-F]{64}$")


def _image(task: Task) -> str:
    selected = task.placement.image or _binary_image(task)
    if _DIGEST.fullmatch(str(selected)) is None:
        raise SpecError(
            "task %s image" % task.name, selected,
            "Kubernetes tasks require exactly one digest-pinned image",
        )
    return str(selected)


def _binary_image(task: Task) -> str:
    images = {
        item.image for item in (*task.binaries, *task.command)
        if isinstance(item, Binary) and item.image
    }
    return next(iter(images)) if len(images) == 1 else ""


def _resources(task: Task) -> dict:
    limits = task.placement.resources
    values = {}
    if limits.cpu is not None:
        values["cpu"] = str(limits.cpu)
    if limits.memory_bytes is not None:
        values["memory"] = str(limits.memory_bytes)
    return {"limits": values, "requests": values} if values else {}


def _secure_projection(
    secret_name: str, items: Sequence[dict], container: dict, pod_spec: dict,
) -> None:
    if not secret_name:
        return
    container["volumeMounts"] = [{
        "name": "secure", "mountPath": "/brixtest/secure", "readOnly": True,
    }]
    pod_spec["volumes"] = [{
        "name": "secure", "secret": {
            "secretName": secret_name, "items": list(items),
        },
    }]


def task_resources(
    task: Task, *, namespace: str, command: Sequence[str], env: Mapping[str, str],
    identity: Optional[Identity] = None, secure_secret: str = "",
    secure_items: Sequence[dict] = (),
) -> tuple[dict, ...]:
    """Return identity resources and one bounded, non-retrying Job."""
    name = "task-%s" % task.name.replace("_", "-")
    labels = {
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/managed-by": "brixtest",
        "brixtest.io/task": task.name,
        "brixtest.io/phase": task.phase,
        **dict(task.placement.labels),
    }
    container = _container(task, command, env)
    pod_spec = _pod_spec(task, container)
    _secure_projection(secure_secret, secure_items, container, pod_spec)
    apply_identity(pod_spec, container, identity)
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": max(1, int(task.timeout)),
            "template": {"metadata": {"labels": labels}, "spec": pod_spec},
        },
    }
    identities = identity_resources(identity, namespace) if identity is not None else ()
    return *identities, job


def task_init_container(
    task: Task, *, command: Sequence[str], env: Mapping[str, str],
    identity: Optional[Identity] = None, secure_secret: str = "",
    secure_items: Sequence[dict] = (),
) -> tuple[dict, tuple[dict, ...]]:
    """Render a grouped init task without exposing Pod dictionaries to tests."""
    container = _container(task, command, env)
    container["name"] = "init-%s" % task.name.replace("_", "-")
    pod_spec: dict = {"volumes": []}
    if secure_secret:
        container["volumeMounts"] = [{
            "name": "init-secure", "mountPath": "/brixtest/secure", "readOnly": True,
        }]
        pod_spec["volumes"].append({
            "name": "init-secure",
            "secret": {"secretName": secure_secret, "items": list(secure_items)},
        })
    apply_identity(pod_spec, container, identity)
    return container, tuple(pod_spec["volumes"])


def _container(task: Task, command: Sequence[str], env: Mapping[str, str]) -> dict:
    container = {
        "name": "task", "image": _image(task), "imagePullPolicy": "IfNotPresent",
        "command": list(command),
        "env": [{"name": key, "value": value} for key, value in sorted(env.items())],
    }
    resources = _resources(task)
    if resources:
        container["resources"] = resources
    if task.placement.security_context:
        container["securityContext"] = dict(task.placement.security_context)
    return container


def _pod_spec(task: Task, container: dict) -> dict:
    pod_spec = {"restartPolicy": "Never", "containers": [container]}
    if task.placement.node_selector:
        pod_spec["nodeSelector"] = dict(task.placement.node_selector)
    return pod_spec


__all__ = ["task_init_container", "task_resources"]
