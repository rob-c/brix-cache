"""Translate endpoint address-family declarations into Kubernetes semantics."""

from __future__ import annotations

from brixtest.design import Server


def _declared_families(server: Server) -> set[str]:
    return {
        endpoint.family for endpoint in server.endpoints
        if endpoint.family != "any"
    }


def service_family_fields(server: Server) -> dict[str, object]:
    """Return the native Service family policy required by a server."""
    families = _declared_families(server)
    if not families:
        return {}
    if "dual" in families or len(families) > 1:
        return {
            "ipFamilies": ["IPv4", "IPv6"],
            "ipFamilyPolicy": "RequireDualStack",
        }
    family = next(iter(families))
    return {
        "ipFamilies": ["IPv6" if family == "ipv6" else "IPv4"],
        "ipFamilyPolicy": "SingleStack",
    }


def pod_bind_hosts(server: Server) -> dict[str, str]:
    """Return wildcard bind addresses for each endpoint inside a Pod."""
    hosts = {
        endpoint.name: "::" if endpoint.family in ("ipv6", "dual") else "0.0.0.0"
        for endpoint in server.endpoints
    }
    primary = _primary_role(server)
    hosts["primary"] = hosts.get(primary, hosts.get("primary", "0.0.0.0"))
    return hosts


def endpoint_protocols(server: Server) -> dict[str, str]:
    """Return per-role protocols including the stable primary alias."""
    protocols = {endpoint.name: endpoint.protocol for endpoint in server.endpoints}
    primary = _primary_role(server)
    protocols["primary"] = protocols.get(primary, protocols.get("primary", "tcp"))
    return protocols


def endpoint_families(server: Server) -> dict[str, str]:
    """Return per-role families including the stable primary alias."""
    families = {endpoint.name: endpoint.family for endpoint in server.endpoints}
    primary = _primary_role(server)
    families["primary"] = families.get(primary, families.get("primary", "any"))
    return families


def _primary_role(server: Server) -> str:
    if "primary" in server.ports:
        return "primary"
    if server.probe.kind != "none":
        return server.probe.endpoint
    return next(iter(server.ports))


__all__ = [
    "endpoint_families", "endpoint_protocols", "pod_bind_hosts",
    "service_family_fields",
]
