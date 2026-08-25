"""Normalized declared and realized network evidence for one managed attempt."""

from __future__ import annotations

from typing import Mapping

from brixtest.planning.model import digest


def network_snapshot(manager) -> Mapping[str, object]:
    """Return a secret-free, checksummed network plan and realization."""
    payload = {
        "environments": [_environment(item) for item in manager.definition.environments],
        "dns": [_dns(item) for item in manager.definition.hosts],
        "routes": _routes(manager.definition.servers),
        "policies": _policies(manager.definition.servers),
        "services": [
            _service(manager, declaration)
            for declaration in manager.definition.servers
            if declaration.name in manager._services
        ],
    }
    return {**payload, "sha256": digest(payload)}


def _environment(item) -> dict:
    return {
        "name": item.name, "backend": item.backend, "context": item.context,
        "namespace": item.namespace, "family": item.family,
        "dns_domain": item.dns_domain, "isolated": item.isolated,
    }


def _dns(item) -> dict:
    return {
        "name": item.name, "hostname": item.hostname, "aliases": list(item.aliases),
        "address": item.address, "reverse": item.reverse,
    }


def _routes(servers) -> list[dict]:
    return [
        {"source": server.name, "target": getattr(target, "name", target)}
        for server in servers for target in server.depends_on
    ]


def _policies(servers) -> list[dict]:
    return [
        {
            "server": item.name, "policy": item.placement.network_policy,
            "environment": item.placement.environment or "default",
        }
        for item in servers
    ]


def _service(manager, declaration) -> dict:
    service = manager._services[declaration.name]
    endpoints = [
        _endpoint(service, item, manager.backend_name)
        for item in declaration.endpoints
    ]
    return {
        "name": declaration.name, "endpoints": endpoints,
        "replicas": [item.as_dict() for item in service.replicas],
        "gateway": _gateway(manager.backend_name),
    }


def _endpoint(service, declaration, backend: str) -> dict:
    role = declaration.name
    external = service.endpoint(role)
    internal_host = service.host
    internal_port = service.ports[role]
    if backend in ("kubernetes", "minikube"):
        internal_host = service.name.replace("_", "-")
        if service.replicas:
            internal_port = service.replicas[0].ports.get(role, internal_port)
    return {
        "name": role, "protocol": declaration.protocol,
        "family": declaration.family, "exposure": declaration.exposure,
        "internal": {"host": internal_host, "port": internal_port},
        "external": {"host": external["host"], "port": external["port"]},
        "gateway": _gateway(backend, declaration.protocol),
    }


def _gateway(backend: str, protocol: str = "tcp") -> dict:
    kind = "direct"
    if backend in ("kubernetes", "minikube"):
        kind = "kubectl-exec-udp" if protocol == "udp" else "kubectl-port-forward"
    return {"kind": kind, "supervised": kind != "direct"}


__all__ = ["network_snapshot"]
