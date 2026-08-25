"""Secure Kubernetes Job manifests for remote BriXTest helpers."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.isolation import Isolation
from brixtest.network import HostMapping

_REMOTE_ROOT = "/brixtest"
REMOTE_RESULT = _REMOTE_ROOT + "/control/result.json"
REMOTE_RUN = _REMOTE_ROOT + "/output/run"
REMOTE_SESSION = _REMOTE_ROOT + "/session"
REMOTE_DONE = _REMOTE_ROOT + "/control/done"
REMOTE_WORKSPACE = "/workspace"


def _secret_data(environment: Mapping[str, str]) -> dict[str, str]:
    result = {}
    for key, value in sorted(environment.items()):
        if not isinstance(key, str) or not isinstance(value, str):
            raise SpecError("Kubernetes helper environment", key, "must map text to text")
        if "\x00" in value:
            raise SpecError("Kubernetes helper environment", key, "cannot contain NUL")
        result[key] = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return result


def _host_aliases(values: Sequence[HostMapping]) -> list[dict[str, object]]:
    return [
        {"ip": mapping.address, "hostnames": list(mapping.hostnames)}
        for mapping in values if mapping.libc and "test" in mapping.targets
    ]


def _watcher(python: str) -> list[str]:
    script = (
        "import pathlib,sys,time;"
        "p=pathlib.Path(%r);"
        "\nwhile not p.exists(): time.sleep(0.2);"
        "\nsys.exit(int(p.read_text().strip() or '1'))"
    ) % REMOTE_DONE
    return [python, "-c", script]


def _volumes() -> list[dict[str, object]]:
    return [
        {"name": "workspace", "emptyDir": {}},
        {"name": "package", "emptyDir": {}},
        {"name": "state", "emptyDir": {}},
        {"name": "tmp", "emptyDir": {}},
    ]


def _mounts() -> list[dict[str, str]]:
    return [
        {"name": "workspace", "mountPath": REMOTE_WORKSPACE},
        {"name": "package", "mountPath": "/opt/brixtest"},
        {"name": "state", "mountPath": _REMOTE_ROOT},
        {"name": "tmp", "mountPath": "/tmp"},
    ]


def helper_resources(
    isolation: Isolation, *, job: str, secret: str,
    environment: Mapping[str, str], host_aliases: Sequence[HostMapping] = (),
) -> dict[str, object]:
    """Render one Secret and one non-retrying, least-privilege helper Job."""
    if isolation.kind != "kubernetes":
        raise SpecError("Kubernetes helper isolation", isolation.kind, "must be kubernetes")
    labels = {
        "app.kubernetes.io/name": "brixtest-helper",
        "app.kubernetes.io/instance": job,
        "brixtest.dev/managed": "true",
    }
    container = {
        "name": "helper", "image": isolation.image,
        "imagePullPolicy": "IfNotPresent",
        "command": _watcher(isolation.python),
        "workingDir": REMOTE_WORKSPACE,
        "envFrom": [{"secretRef": {"name": secret}}],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "readOnlyRootFilesystem": True,
        },
        "volumeMounts": _mounts(),
    }
    template_spec = {
        "restartPolicy": "Never",
        "serviceAccountName": isolation.service_account,
        "automountServiceAccountToken": True,
        "enableServiceLinks": False,
        "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container], "volumes": _volumes(),
    }
    aliases = _host_aliases(host_aliases)
    if aliases:
        template_spec["hostAliases"] = aliases
    return {
        "apiVersion": "v1", "kind": "List", "items": [
            {
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": secret, "namespace": isolation.namespace, "labels": labels},
                "type": "Opaque", "data": _secret_data(environment),
            },
            {
                "apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": job, "namespace": isolation.namespace, "labels": labels},
                "spec": {
                    "backoffLimit": 0, "ttlSecondsAfterFinished": 300,
                    "template": {"metadata": {"labels": labels}, "spec": template_spec},
                },
            },
        ],
    }


def write_helper_manifest(path: Path, resources: Mapping[str, object]) -> None:
    """Write a controller-private manifest without leaking values through argv."""
    path.write_text(json.dumps(resources, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


__all__ = [
    "REMOTE_DONE", "REMOTE_RESULT", "REMOTE_RUN", "REMOTE_SESSION",
    "REMOTE_WORKSPACE", "helper_resources", "write_helper_manifest",
]
