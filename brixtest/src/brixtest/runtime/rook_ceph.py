"""First-class Rook/Ceph managed-resource provider."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Mapping, Sequence

from brixtest._design_managed import Resource
from brixtest.errors import SpecError
from brixtest.runtime.providers import ProviderContext, ProviderInstance, ProviderPlan

_ALLOWED = frozenset({
    "managed", "operator_namespace", "operator_name", "cluster_name",
    "pool_name", "filesystem_name", "storage_class", "ceph_image",
    "data_dir", "device_filter",
})
_DEFAULTS = {
    "managed": False, "operator_namespace": "rook-ceph",
    "operator_name": "rook-ceph-operator", "cluster_name": "brixtest-ceph",
    "pool_name": "brixtest-pool", "filesystem_name": "brixtest-filesystem",
    "storage_class": "rook-cephfs", "ceph_image": "",
    "data_dir": "/var/lib/rook-brixtest", "device_filter": "",
}


def _settings(declaration: Resource) -> dict[str, object]:
    unknown = sorted(set(declaration.options) - _ALLOWED)
    if unknown:
        raise SpecError("rook-ceph options", unknown, "contain unsupported settings")
    values = {**_DEFAULTS, **dict(declaration.options)}
    _validate_settings(values)
    return values


def _validate_settings(values: Mapping[str, object]) -> None:
    if not isinstance(values["managed"], bool):
        raise SpecError("rook-ceph managed", values["managed"], "must be boolean")
    for key in (
        "operator_namespace", "operator_name", "cluster_name", "pool_name",
        "filesystem_name", "storage_class",
    ):
        _dns_name(values[key], "rook-ceph %s" % key)
    if values["managed"]:
        _managed_settings(values)


def _dns_name(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or any(
        char not in "abcdefghijklmnopqrstuvwxyz0123456789-." for char in value
    ):
        raise SpecError(field, value, "must be a lowercase Kubernetes name")
    return value


def _managed_settings(values: Mapping[str, object]) -> None:
    image = values["ceph_image"]
    if not isinstance(image, str) or "@sha256:" not in image:
        raise SpecError("rook-ceph ceph_image", image, "must be digest pinned in managed mode")
    data_dir = Path(str(values["data_dir"]))
    if not data_dir.is_absolute() or ".." in data_dir.parts:
        raise SpecError("rook-ceph data_dir", values["data_dir"], "must be an absolute normalized path")
    if not isinstance(values["device_filter"], str):
        raise SpecError("rook-ceph device_filter", values["device_filter"], "must be text")


def _cluster(values: Mapping[str, object]) -> dict:
    storage = {"useAllNodes": True, "useAllDevices": False}
    if values["device_filter"]:
        storage["deviceFilter"] = values["device_filter"]
    return {
        "apiVersion": "ceph.rook.io/v1", "kind": "CephCluster",
        "metadata": {"name": values["cluster_name"]},
        "spec": {
            "cephVersion": {"image": values["ceph_image"]},
            "dataDirHostPath": values["data_dir"],
            "mon": {"count": 1, "allowMultiplePerNode": True},
            "mgr": {"count": 1}, "dashboard": {"enabled": False},
            "storage": storage,
        },
    }


def _pool(values: Mapping[str, object]) -> dict:
    return {
        "apiVersion": "ceph.rook.io/v1", "kind": "CephBlockPool",
        "metadata": {"name": values["pool_name"]},
        "spec": {"failureDomain": "host", "replicated": {"size": 1}},
    }


def _filesystem(values: Mapping[str, object]) -> dict:
    replicated = {"replicated": {"size": 1}}
    return {
        "apiVersion": "ceph.rook.io/v1", "kind": "CephFilesystem",
        "metadata": {"name": values["filesystem_name"]},
        "spec": {
            "metadataPool": replicated, "dataPools": [replicated],
            "metadataServer": {"activeCount": 1, "activeStandby": True},
        },
    }


def _documents(values: Mapping[str, object]) -> tuple[dict, ...]:
    return (_cluster(values), _pool(values), _filesystem(values)) if values["managed"] else ()


def _uid(value: Mapping[str, object]) -> str:
    metadata = value.get("metadata", {})
    return str(metadata.get("uid", "")) if isinstance(metadata, Mapping) else ""


def _identity_list(instance: ProviderInstance) -> tuple[Mapping[str, str], ...]:
    values = instance.ownership.get("objects", ())
    if not isinstance(values, Sequence):
        raise SpecError("rook-ceph ownership", values, "must contain object identities")
    return tuple(item for item in values if isinstance(item, Mapping))


def _ready(value: Mapping[str, object]) -> bool:
    status = value.get("status", {})
    if not isinstance(status, Mapping):
        return False
    phase = status.get("phase") or status.get("state")
    health = status.get("ceph", {}).get("health") if isinstance(status.get("ceph"), Mapping) else ""
    return phase in ("Ready", "Created", "Connected") or health in ("HEALTH_OK", "HEALTH_WARN")


class RookCephProvider:
    """Discover external Rook or own a minimal case-scoped Ceph topology."""

    brixtest_api_version = 1
    brixtest_capabilities = ("confined", "ownership", "provenance", "storage.ceph")

    def validate(self, declaration: Resource) -> None:
        if not isinstance(declaration, Resource) or declaration.kind != "rook-ceph":
            raise SpecError("rook-ceph declaration", declaration, "must be resource(..., 'rook-ceph')")
        _settings(declaration)

    def plan(self, declaration: Resource, context: ProviderContext) -> ProviderPlan:
        if context.backend not in ("kubernetes", "minikube"):
            raise SpecError("rook-ceph backend", context.backend, "requires Kubernetes or Minikube")
        values = _settings(declaration)
        return ProviderPlan(declaration.name, declaration.kind, {
            "settings": values, "objects": _documents(values),
        })

    def create(self, plan: ProviderPlan, context: ProviderContext) -> ProviderInstance:
        values = plan.fragment["settings"]
        objects = context.kubernetes()
        operator = objects.discover(
            "deployment", str(values["operator_name"]),
            namespace=str(values["operator_namespace"]),
        )
        storage_class = objects.discover("storageclass", str(values["storage_class"]))
        documents = plan.fragment["objects"]
        identities = objects.apply(plan.name, documents) if documents else ()
        return ProviderInstance(
            plan.name, plan.provider,
            {"mode": "managed" if identities else "external", "objects": identities},
            {
                "storage_class": values["storage_class"],
                "pool": values["pool_name"], "filesystem": values["filesystem_name"],
            },
            {"operator_uid": _uid(operator), "storage_class_uid": _uid(storage_class)},
        )

    def ready(
        self, instance: ProviderInstance, context: ProviderContext, timeout: float,
    ) -> None:
        identities = _identity_list(instance)
        if not identities:
            return
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(_ready(context.kubernetes().get(item)) for item in identities):
                return
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        raise SpecError("rook-ceph readiness", instance.name, "did not become healthy before its deadline")

    def collect(
        self, instance: ProviderInstance, context: ProviderContext,
    ) -> Mapping[str, object]:
        identities = _identity_list(instance)
        observations = []
        for index, item in enumerate(identities):
            selector = "rook_cluster=%s" % item["namespace"] if index == 0 else ""
            observations.append(
                context.kubernetes().observe(item, pod_selector=selector)
            )
        return {
            "objects": observations, "metadata": dict(instance.metadata),
            "storage": dict(instance.outputs),
        }

    def destroy(self, instance: ProviderInstance, context: ProviderContext) -> None:
        for item in reversed(_identity_list(instance)):
            context.kubernetes().delete(item)


_PROVIDER = RookCephProvider()


def rook_ceph_provider() -> RookCephProvider:
    """Return the built-in singleton used for ``resource(..., 'rook-ceph')``."""
    return _PROVIDER
