"""Derive Kubernetes NetworkPolicy documents from service declarations."""

from __future__ import annotations

from typing import Mapping, Sequence

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
    server: Server, peers: Mapping[str, tuple[Server, Mapping[str, int]]],
) -> list[dict]:
    rules = []
    for dependency in server.depends_on:
        name = getattr(dependency, "name", dependency)
        peer = peers.get(name)
        if peer is None:
            continue
        declaration, ports = peer
        rules.append({
            "to": [{"podSelector": _selector(declaration.name)}],
            "ports": _ports(declaration, ports),
        })
    return rules


def network_policy_resources(
    server: Server, namespace: str, ports: Mapping[str, int],
    peers: Mapping[str, tuple[Server, Mapping[str, int]]],
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
        spec["ingress"] = [{"from": [{"podSelector": {}}], "ports": _ports(server, ports)}]
        spec["egress"] = [
            *_dependency_rules(server, peers),
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
