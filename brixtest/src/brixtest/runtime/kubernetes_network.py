"""Derive Kubernetes NetworkPolicy documents from service declarations."""

from __future__ import annotations

from typing import Mapping, Optional, Sequence

from brixtest.design import Server


def _selector(name: str) -> dict:
    return {"matchLabels": {"app.kubernetes.io/name": name.replace("_", "-")}}


def _ports(server: Server, ports: Mapping[str, int]) -> list[dict]:
    protocols = {endpoint.name: endpoint.protocol.upper() for endpoint in server.endpoints}
    return [
        {"port": port, "protocol": protocols.get(role, "TCP")}
        for role, port in sorted(ports.items()) if role != "primary"
    ] or [{"port": ports["primary"], "protocol": "TCP"}]


def _dependency_rules(
    server: Server, peers: Mapping[str, tuple], namespace: str,
    test_instance: str,
) -> list[dict]:
    rules = []
    for dependency in server.depends_on:
        name = getattr(dependency, "name", dependency)
        peer = peers.get(name)
        if peer is None:
            continue
        declaration, ports = peer[:2]
        peer_namespace = peer[2] if len(peer) > 2 else namespace
        target = {"podSelector": _selector(declaration.name)}
        if peer_namespace != namespace and test_instance:
            target["namespaceSelector"] = _case_namespace_selector(test_instance)
        rules.append({
            "to": [target],
            "ports": _ports(declaration, ports),
        })
    return rules


def _case_namespace_selector(test_instance: str) -> dict:
    return {"matchLabels": {"brixtest.io/test-instance": test_instance}}


def _authority_rules(
    authorities: Mapping[str, int], test_instance: str,
) -> list[dict]:
    return [
        {
            "to": [{
                "podSelector": {"matchLabels": {"brixtest.io/authority": name}},
                **({"namespaceSelector": _case_namespace_selector(test_instance)}
                   if test_instance else {}),
            }],
            "ports": [
                {"port": port, "protocol": "TCP"},
                {"port": port, "protocol": "UDP"},
            ],
        }
        for name, port in sorted(authorities.items())
    ]


def _endpoint_fields(server: Server) -> tuple[dict[str, str], dict[str, str]]:
    protocols = {item.name: item.protocol.upper() for item in server.endpoints}
    exposures = {item.name: item.exposure for item in server.endpoints}
    return protocols, exposures


def _named_ports(ports: Mapping[str, int]) -> list[tuple[str, int]]:
    return [(role, port) for role, port in sorted(ports.items()) if role != "primary"]


def _ingress_rules(
    server: Server, ports: Mapping[str, int], namespace: str, test_instance: str,
) -> list[dict]:
    named_ports = _named_ports(ports)
    if named_ports:
        protocols, exposures = _endpoint_fields(server)
        return [
            _ingress_rule(role, port, protocols, exposures, namespace, test_instance)
            for role, port in named_ports
        ]
    source = _case_ingress_source(namespace, test_instance)
    return [{"from": [source], "ports": _ports(server, ports)}]


def _case_ingress_source(namespace: str, test_instance: str) -> dict:
    if test_instance:
        return {"namespaceSelector": _case_namespace_selector(test_instance)}
    return {"podSelector": {"matchLabels": {"brixtest.io/case": namespace}}}


def _ingress_rule(
    role, port, protocols, exposures, namespace: str, test_instance: str,
) -> dict:
    rule = {"ports": [{"port": port, "protocol": protocols.get(role, "TCP")}]}
    exposure = exposures.get(role, "case")
    if exposure == "case":
        rule["from"] = [_case_ingress_source(namespace, test_instance)]
    elif exposure == "environment":
        rule["from"] = [{"podSelector": {}}]
    return rule


def network_policy_resources(
    server: Server, namespace: str, ports: Mapping[str, int],
    peers: Mapping[str, tuple],
    authorities: Optional[Mapping[str, int]] = None,
    *, test_instance: str = "",
) -> tuple[dict, ...]:
    """Return the default-deny policy selected by ``Placement.network_policy``."""
    policy = server.placement.network_policy
    if policy == "open":
        return ()
    labels = {
        "app.kubernetes.io/managed-by": "brixtest",
        "brixtest.io/workload": server.name,
    }
    spec = {
        "podSelector": _selector(server.name),
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [], "egress": [],
    }
    if policy == "declared":
        spec["ingress"] = _ingress_rules(server, ports, namespace, test_instance)
        spec["egress"] = [
            *_dependency_rules(server, peers, namespace, test_instance),
            *_authority_rules({} if authorities is None else authorities, test_instance),
            {"ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]},
        ]
    return ({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {
            "name": "brixtest-%s" % server.name.replace("_", "-"),
            "namespace": namespace, "labels": labels,
        },
        "spec": spec,
    },)


__all__ = ["network_policy_resources"]
