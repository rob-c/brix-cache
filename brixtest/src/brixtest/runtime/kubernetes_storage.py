"""Translate managed Volume mounts into typed Kubernetes storage resources."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from brixtest._design_managed import Volume
from brixtest.errors import SpecError
from brixtest.resources import Mount

_ACCESS = {
    "read-write-once": "ReadWriteOnce",
    "read-write-many": "ReadWriteMany",
    "read-only-many": "ReadOnlyMany",
}
_PROPAGATION = {
    "host-to-container": "HostToContainer",
    "bidirectional": "Bidirectional",
}


def _resource_name(value: str) -> str:
    return value.replace("_", "-")[:63].strip("-")


def _volume_name(volume: Volume) -> str:
    return "managed-%s" % _resource_name(volume.name)


def _claim(volume: Volume, namespace: str) -> dict:
    request = str(volume.size) if volume.size else "1Gi"
    spec = {
        "accessModes": [_ACCESS[volume.access]],
        "resources": {"requests": {"storage": request}},
    }
    storage_class = volume.options.get("storage_class")
    if storage_class is not None:
        if not isinstance(storage_class, str):
            raise SpecError(
                "volume %s options.storage_class" % volume.name, storage_class,
                "must be text",
            )
        spec["storageClassName"] = storage_class
    return {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": _volume_name(volume), "namespace": namespace,
            "labels": {"app.kubernetes.io/managed-by": "brixtest"},
        },
        "spec": spec,
    }


def _volume_source(volume: Volume) -> dict:
    if volume.kind == "tmp" and not volume.persistent:
        empty = {}
        if volume.size:
            empty["sizeLimit"] = str(volume.size)
        return {"emptyDir": empty}
    if volume.kind in ("persistent", "shared") or volume.persistent:
        return {"persistentVolumeClaim": {"claimName": _volume_name(volume)}}
    if volume.kind == "host":
        source = Path(str(volume.source))
        if not source.is_absolute():
            raise SpecError(
                "volume %s source" % volume.name, str(source),
                "Kubernetes host volumes require an absolute node path",
            )
        return {"hostPath": {"path": str(source), "type": "DirectoryOrCreate"}}
    raise SpecError(
        "volume %s kind" % volume.name, volume.kind,
        "requires a Kubernetes storage provider",
    )


def _volume_mount(declaration: Mount, volume: Volume) -> dict:
    value = {
        "name": _volume_name(volume),
        "mountPath": "/brixtest/mounts/%s" % declaration.target,
        "readOnly": declaration.read_only or volume.access == "read-only-many",
    }
    propagation = _PROPAGATION.get(declaration.propagation)
    if propagation:
        value["mountPropagation"] = propagation
    return value


def kubernetes_volume_resources(
    entries: Sequence[tuple[Mount, Volume]], namespace: str,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Return container mounts, pod volumes, and owned claim documents."""
    mounts = []
    volumes = {}
    claims = {}
    for declaration, volume in entries:
        mounts.append(_volume_mount(declaration, volume))
        name = _volume_name(volume)
        source = _volume_source(volume)
        previous = volumes.get(name)
        if previous is not None and previous != source:
            raise SpecError("volume", volume.name, "has conflicting Kubernetes projections")
        volumes[name] = source
        if "persistentVolumeClaim" in source:
            claims[name] = _claim(volume, namespace)
    pod_volumes = [{"name": name, **source} for name, source in sorted(volumes.items())]
    return mounts, pod_volumes, [claims[name] for name in sorted(claims)]


__all__ = ["kubernetes_volume_resources"]
