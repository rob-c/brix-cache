"""First-class Rook/Ceph provider contracts without Kubernetes in test declarations."""

from dataclasses import replace

import pytest

from brixtest import case, get_case, resource, volume
from brixtest.errors import SpecError
from brixtest.runtime.manager import CaseManager
from brixtest.runtime.providers import ProviderContext
from brixtest.runtime.rook_ceph import RookCephProvider


class _Objects:
    def __init__(self):
        self.created = []
        self.deleted = []

    def discover(self, kind, name, *, namespace=""):
        return {"kind": kind, "metadata": {"name": name, "namespace": namespace, "uid": "external"}}

    def apply(self, owner, documents):
        self.created.extend(documents)
        return tuple({
            "api_version": item["apiVersion"], "kind": item["kind"],
            "namespace": "case", "name": item["metadata"]["name"],
            "uid": "uid-%d" % index,
        } for index, item in enumerate(documents))

    def get(self, identity):
        return {
            "apiVersion": identity["api_version"], "kind": identity["kind"],
            "metadata": {"name": identity["name"], "uid": identity["uid"]},
            "status": {"phase": "Ready"},
        }

    def observe(self, identity, *, pod_selector=""):
        return {
            "identity": identity, "object": self.get(identity),
            "events": {"items": []}, "workloads": {"selector": pod_selector},
        }

    def delete(self, identity):
        self.deleted.append(identity)


def _context(tmp_path, objects):
    context = ProviderContext("ceph::unit", tmp_path, "kubernetes", object(), object())
    object.__setattr__(context, "_kubernetes_objects", objects)
    return context


def test_external_rook_storage_is_minimal_and_test_declaration_stays_generic(tmp_path):
    declaration = resource("ceph", "rook-ceph", storage_class="rook-cephfs")
    data = volume("data", kind="provider", provider=declaration.name, size=1 << 30)
    assert data.provider == "ceph"
    provider = RookCephProvider()
    context = _context(tmp_path, _Objects())
    plan = provider.plan(declaration, context)
    instance = provider.create(plan, context)
    provider.ready(instance, context, 1.0)
    assert instance.outputs["storage_class"] == "rook-cephfs"
    assert instance.ownership["mode"] == "external"
    collected = provider.collect(instance, context)
    assert collected["objects"] == []
    assert collected["storage"]["storage_class"] == "rook-cephfs"
    provider.destroy(instance, context)


def test_managed_rook_plan_owns_cluster_pool_and_filesystem(tmp_path):
    declaration = resource(
        "ceph", "rook-ceph", managed=True,
        ceph_image="quay.io/ceph/ceph@sha256:" + "a" * 64,
    )
    provider, objects = RookCephProvider(), _Objects()
    context = _context(tmp_path, objects)
    plan = provider.plan(declaration, context)
    assert [item["kind"] for item in plan.fragment["objects"]] == [
        "CephCluster", "CephBlockPool", "CephFilesystem",
    ]
    instance = provider.create(plan, context)
    provider.ready(instance, context, 1.0)
    collected = provider.collect(instance, context)
    assert len(collected["objects"]) == 3
    assert collected["objects"][0]["workloads"]["selector"] == "rook_cluster=case"
    assert collected["objects"][0]["identity"]["uid"] == "uid-0"
    provider.destroy(instance, context)
    assert [item["kind"] for item in objects.deleted] == [
        "CephFilesystem", "CephBlockPool", "CephCluster",
    ]


def test_rook_provider_rejects_unpinned_managed_image_and_local_backend(tmp_path):
    provider = RookCephProvider()
    with pytest.raises(SpecError, match="digest pinned"):
        provider.validate(resource("ceph", "rook-ceph", managed=True, ceph_image="ceph:latest"))
    declaration = resource("ceph", "rook-ceph")
    context = replace(_context(tmp_path, _Objects()), backend="local")
    with pytest.raises(SpecError, match="requires Kubernetes"):
        provider.plan(declaration, context)


def test_rook_provider_is_built_in_and_planning_does_not_create_run_root(tmp_path):
    storage = resource("ceph", "rook-ceph")

    @case(storage, backend="kubernetes")
    def declared(run):
        return None

    root = tmp_path / "run"
    manager = CaseManager(get_case(declared), "ceph::planning", root=root)
    assert isinstance(manager._providers.providers["ceph"], RookCephProvider)
    assert manager._providers.plan_all()["ceph"]["provider"] == "rook-ceph"
    assert not root.exists()
