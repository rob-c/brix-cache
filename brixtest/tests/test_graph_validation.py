"""Strict pre-mutation validation for typed graph relationships."""

import pytest

from brixtest import (
    Placement,
    Reference,
    case,
    client,
    environment,
    resource,
    server,
    task,
)
from brixtest.errors import SpecError
from brixtest.planning import compile_case


def _definition(*resources):
    @case(*resources, observe=())
    def declared(run):
        return None

    return declared.__brixtest_case__


def test_output_reference_requires_an_explicit_output_name():
    with pytest.raises(SpecError, match="must name a task or resource output"):
        Reference("task", "prepare", "output")


def test_dangling_reference_is_rejected_during_case_declaration():
    reader = client(
        "reader", command=("reader", Reference("server", "missing", "url")),
    )
    with pytest.raises(SpecError, match="declared by the same case"):
        _definition(reader)


def test_unknown_task_output_is_rejected_for_any_consumer():
    prepare = task("prepare", command=("true",), outputs={"result": "result"})
    reader = client(
        "reader", command=("reader", Reference("task", "prepare", "output", "other")),
    )
    with pytest.raises(SpecError, match="declared task output"):
        _definition(prepare, reader)


def test_unknown_server_endpoint_role_is_rejected():
    origin = server("origin", command=("true",))
    reader = client("reader", command=("reader", origin.url("admin")))
    with pytest.raises(SpecError, match="declared server endpoint"):
        _definition(origin, reader)


def test_direct_cross_environment_reference_requires_transport():
    origin = server(
        "origin", command=("true",), placement=Placement(environment="east"),
    )
    reader = client(
        "reader", command=("reader", origin.url()),
        placement=Placement(environment="west"),
    )
    with pytest.raises(SpecError, match="managed transport"):
        _definition(
            environment("east", context="cluster-east"),
            environment("west", context="cluster-west"), origin, reader,
        )


def test_cross_environment_server_dependency_requires_transport():
    upstream = server(
        "upstream", command=("true",), placement=Placement(environment="east"),
    )
    downstream = server(
        "downstream", command=("true",), depends_on=(upstream,),
        placement=Placement(environment="west"),
    )
    definition = _definition(
        environment("east", context="cluster-east"),
        environment("west", context="cluster-west"), upstream, downstream,
    )
    with pytest.raises(SpecError, match="managed transport"):
        compile_case(definition)


def test_same_context_kubernetes_environments_use_the_builtin_transport():
    upstream = server(
        "upstream", command=("true",), placement=Placement(environment="east"),
    )
    downstream = server(
        "downstream", command=("true",), depends_on=(upstream,),
        placement=Placement(environment="west"),
    )
    definition = _definition(
        environment("east", backend="kubernetes"),
        environment("west", backend="kubernetes"), upstream, downstream,
    )
    graph = compile_case(definition, "kubernetes")
    assert any(
        edge.source == "server:downstream" and edge.target == "server:upstream"
        for edge in graph.edges
    )


def test_dependency_name_must_not_be_ambiguous_across_resource_kinds():
    prepare = task("shared", command=("true",))
    upstream = server("shared", command=("true",))
    downstream = server("downstream", command=("true",), depends_on=("shared",))
    with pytest.raises(SpecError, match="exactly one"):
        compile_case(_definition(prepare, upstream, downstream))


def test_provider_resource_cannot_depend_on_running_server():
    origin = server("origin", command=("true",))
    store = resource("store", "unit", depends_on=(origin,))
    with pytest.raises(SpecError, match="ready before servers start"):
        compile_case(_definition(origin, store))
