"""Address-family contracts for backend-neutral Kubernetes services."""

import pytest

from brixtest import Probe, endpoint, server
from brixtest.planning import compile_case, validate_capabilities
from brixtest.runtime.kubernetes_addressing import pod_bind_hosts
from brixtest.runtime.kubernetes_manifests import server_resources


_IMAGE = "registry.test/server@sha256:" + "a" * 64


def _server(*families):
    endpoints = tuple(
        endpoint("port%d" % index, family=family)
        for index, family in enumerate(families)
    )
    return server(
        "origin", command=("/server",), image=_IMAGE, endpoints=endpoints,
        probe=Probe("none"),
    )


def _service(declaration):
    ports = {
        endpoint.name: 18000 + index
        for index, endpoint in enumerate(declaration.endpoints)
    }
    ports["primary"] = next(iter(ports.values()))
    documents = server_resources(
        declaration, namespace="case", command=("/server",), env={},
        ports=ports, config_text="",
    )
    return next(item for item in documents if item["kind"] == "Service")


@pytest.mark.parametrize("family,kubernetes,bind", [
    ("ipv4", {"ipFamilies": ["IPv4"], "ipFamilyPolicy": "SingleStack"}, "0.0.0.0"),
    ("ipv6", {"ipFamilies": ["IPv6"], "ipFamilyPolicy": "SingleStack"}, "::"),
    ("dual", {"ipFamilies": ["IPv4", "IPv6"], "ipFamilyPolicy": "RequireDualStack"}, "::"),
])
def test_kubernetes_service_and_pod_bind_use_declared_family(family, kubernetes, bind):
    declaration = _server(family)
    service_spec = _service(declaration)["spec"]
    assert {key: service_spec[key] for key in kubernetes} == kubernetes
    assert pod_bind_hosts(declaration)["port0"] == bind


def test_kubernetes_mixed_families_require_dual_stack_service():
    service_spec = _service(_server("ipv4", "ipv6"))["spec"]
    assert service_spec["ipFamilies"] == ["IPv4", "IPv6"]
    assert service_spec["ipFamilyPolicy"] == "RequireDualStack"


def test_unspecified_family_preserves_cluster_default():
    service_spec = _service(_server("any"))["spec"]
    assert "ipFamilies" not in service_spec
    assert "ipFamilyPolicy" not in service_spec


@pytest.mark.parametrize("backend", ["docker", "podman", "kubernetes", "minikube"])
def test_capable_backends_accept_ipv6_endpoint_during_planning(backend):
    graph = compile_case(_definition(_server("ipv6"), backend), backend)
    validate_capabilities(graph.nodes)


def _definition(origin, backend):
    from brixtest import case

    @case(origin, backend=backend, observe=())
    def declared(run):
        return None

    return declared.__brixtest_case__
