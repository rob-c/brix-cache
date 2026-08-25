"""Typed Resource-to-Volume storage binding on Kubernetes."""

import pytest

from brixtest import case, get_case, mount, resource, server, volume
from brixtest.errors import SpecError
from brixtest.planning import compile_case
from brixtest.runtime.backend_validation import validate_kubernetes_volumes
from brixtest.runtime.kubernetes_manifests import server_resources


def _definition(*resources):
    @case(*resources, backend="kubernetes")
    def declared(run):
        return None

    return get_case(declared)


def test_provider_volume_has_graph_dependency_and_rendered_storage_class():
    storage = resource("ceph", "unit-storage")
    data = volume("data", kind="provider", provider=storage.name, size=8 << 20)
    mounted = mount(data, "data")
    origin = server(
        "origin", command=("/server",), mounts=(mounted,),
        image="example/server@sha256:" + "a" * 64,
    )
    definition = _definition(storage, data, origin)
    validate_kubernetes_volumes(definition.volumes, definition.managed_resources)
    graph = compile_case(definition, "kubernetes")
    assert any(
        edge.source == "resource:ceph" and edge.target == "volume:data"
        and edge.relation == "produces" for edge in graph.edges
    )
    documents = server_resources(
        origin, namespace="case", command=("/server",), env={},
        ports={"primary": 18000}, config_text="",
        managed_volumes=((mounted, data),),
        provider_outputs={"ceph": {"storage_class": "ceph-filesystem"}},
    )
    claim = next(item for item in documents if item["kind"] == "PersistentVolumeClaim")
    assert claim["spec"]["storageClassName"] == "ceph-filesystem"


def test_provider_volume_requires_declared_resource_and_storage_class():
    data = volume("data", kind="provider", provider="missing")
    with pytest.raises(SpecError, match="same case"):
        validate_kubernetes_volumes((data,), ())
    mounted = mount(data, "data")
    origin = server("origin", command=("/server",), mounts=(mounted,))
    with pytest.raises(SpecError, match="storage_class output"):
        server_resources(
            origin, namespace="case", command=("/server",), env={},
            ports={"primary": 18000}, config_text="",
            managed_volumes=((mounted, data),), provider_outputs={},
        )
