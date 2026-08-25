"""Unsupported public semantics fail before any attempt resource is created."""

from pathlib import Path

import pytest

from brixtest import Placement, case, client, endpoint, identity, server, volume
from brixtest.errors import SpecError
from brixtest.planning import compile_case, validate_capabilities
from brixtest.runtime.manager import CaseManager


def _definition(*resources, backend="local"):
    @case(*resources, backend=backend, observe=())
    def declared(run):
        return None

    return declared.__brixtest_case__


def _external_endpoint():
    return _definition(server(
        "origin", command=("true",),
        endpoints=(endpoint("primary", exposure="external"),),
    ))


def _runc_ipv6():
    return _definition(server(
        "origin", command=("true",), placement=Placement(backend="runc"),
        endpoints=(endpoint("primary", family="ipv6"),),
    ))


def _runc_pty():
    return _definition(client(
        "terminal", command=("true",), mode="pty",
        placement=Placement(backend="runc"),
    ))


def _local_device():
    return _definition(volume("fuse", kind="device", source="/dev/fuse"))


def _kubernetes_userns():
    runner = identity("runner", user_namespace=True)
    origin = server(
        "origin", command=("/server",),
        image="registry.test/server@sha256:" + "a" * 64,
        placement=Placement(identity=runner),
    )
    return _definition(runner, origin, backend="kubernetes")


def _local_quota():
    return _definition(volume("data", size=4096))


@pytest.mark.parametrize("factory,diagnostic", [
    (_external_endpoint, "network.external"),
    (_runc_ipv6, "launcher extension"),
    (_runc_pty, "executor extension"),
    (_local_device, "storage.device"),
    (_kubernetes_userns, "identity.userns"),
    (_local_quota, "storage.quota"),
])
def test_unsupported_semantics_fail_during_planning_without_a_run_root(
    tmp_path: Path, factory, diagnostic,
):
    root = tmp_path / "must-not-exist"
    with pytest.raises(SpecError, match=diagnostic):
        CaseManager(factory(), "capability::unsupported", root=root)
    assert not root.exists()


@pytest.mark.parametrize("selected,missing", [
    (endpoint("primary", family="ipv6"), "network.ipv6"),
    (endpoint("primary", protocol="udp"), "network.udp"),
])
def test_capability_plan_explains_unsupported_network_backend_and_alternatives(
    monkeypatch, selected, missing,
):
    from brixtest.planning import capabilities

    monkeypatch.setitem(
        capabilities._BUILTIN_BY_KIND["launcher"],
        "unit-no-ipv6", capabilities._COMMON,
    )
    origin = server(
        "origin", command=("true",),
        placement=Placement(backend="unit-no-ipv6"),
        endpoints=(selected,),
    )
    graph = compile_case(_definition(origin), "local")
    with pytest.raises(
        SpecError, match=r"%s.*backend unit-no-ipv6.*alternatives" % missing,
    ):
        validate_capabilities(graph.nodes)


@pytest.mark.parametrize("placement,field", [
    (Placement(namespace="ignored"), "namespace"),
    (Placement(options={"mystery": True}), "options"),
    (Placement(allow_mutable_image=True), "mutable"),
])
def test_process_launcher_rejects_every_nonportable_placement_field_before_mutation(
    tmp_path: Path, placement, field,
):
    root = tmp_path / "must-not-exist"
    definition = _definition(server("origin", command=("true",), placement=placement))
    with pytest.raises(SpecError, match=field):
        CaseManager(definition, "capability::placement", root=root)
    assert not root.exists()


def test_process_group_is_a_planned_shared_local_isolation_unit(tmp_path):
    placement = Placement(group="stack")
    definition = _definition(
        server("origin", command=("true",), placement=placement),
        server("monitor", command=("true",), placement=placement),
    )
    manager = CaseManager(definition, "unit::local-group", root=tmp_path / "run")
    nodes = _server_nodes(manager._resource_graph)
    assert _node_groups(nodes) == {"stack"}
    assert _has_shared_runtime_edge(manager._resource_graph)
    assert not manager.root.exists()


def _server_nodes(graph):
    return [node for node in graph.nodes if node.kind == "server"]


def _node_groups(nodes):
    return {node.group for node in nodes}


def _has_shared_runtime_edge(graph):
    return any(edge.relation == "shares-runtime-with" for edge in graph.edges)
