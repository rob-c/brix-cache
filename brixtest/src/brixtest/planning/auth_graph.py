"""Normalize authentication authorities and role-scoped material into graph nodes."""

from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from brixtest.planning.model import GraphEdge, GraphNode, digest, jsonable


_ROLE_MATERIAL: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "token": {
        "test": ("bearer-token",), "client": ("bearer-token",),
        "server": ("verification-key", "discovery"),
    },
    "tls": {
        "test": ("client-identity", "trust"),
        "client": ("client-identity", "trust"),
        "server": ("host-identity", "crl", "trust"),
    },
    "voms": {
        "test": ("user-proxy", "voms-trust"),
        "client": ("user-proxy", "voms-trust"),
        "server": ("host-identity", "voms-trust"),
    },
    "kerberos": {
        "test": ("ticket-cache", "realm-config"),
        "client": ("ticket-cache", "realm-config"),
        "server": ("service-keytab", "realm-config"),
    },
}


def authority_nodes(recipes: Sequence[object], backend: str) -> list[GraphNode]:
    """Build authority and issued-material nodes without generating credentials."""
    return [node for recipe in recipes for node in _recipe_nodes(recipe, backend)]


def authority_edges(definition: object) -> Iterable[GraphEdge]:
    """Link authorities to material and material to its declared consumer role."""
    for recipe in definition.auth:
        for role in _roles(recipe):
            source = _authority_id(recipe)
            material = _material_id(recipe, role)
            yield GraphEdge(source, material, "issues")
            if _refreshable(recipe):
                yield GraphEdge(source, material, "refreshes")
            if _revocable(recipe):
                yield GraphEdge(source, material, "revokes")
            yield from _consumer_edges(material, role, definition)


def _recipe_nodes(recipe: object, backend: str) -> list[GraphNode]:
    attributes = jsonable(recipe)
    authority = GraphNode(
        _authority_id(recipe), "authority", recipe.name, backend,
        fingerprint=digest({"kind": "authority", "declaration": attributes}),
        attributes=attributes,
    )
    return [authority, *(
        _material_node(recipe, role, backend) for role in _roles(recipe)
    )]


def _material_node(recipe: object, role: str, backend: str) -> GraphNode:
    attributes = {
        "authority": recipe.name, "authority_kind": recipe.kind, "role": role,
        "material": list(_materials(recipe, role)),
        "refresh": _refresh_policy(recipe), "revocable": _revocable(recipe),
        "consumers": ["test-helper"] if role == "test" else [],
    }
    return GraphNode(
        _material_id(recipe, role), "authority-material",
        "%s.%s" % (recipe.name, role), backend,
        fingerprint=digest(attributes), attributes=attributes,
    )


def _materials(recipe: object, role: str) -> tuple[str, ...]:
    selected = _ROLE_MATERIAL.get(recipe.kind, {}).get(role, ())
    if recipe.kind == "token" and role == "server" and recipe.algorithm != "HS256":
        return ("public-key", "jwks", "discovery")
    return selected


def _roles(recipe: object) -> tuple[str, ...]:
    return tuple(sorted(_ROLE_MATERIAL.get(recipe.kind, {})))


def _consumer_edges(material: str, role: str, definition: object) -> Iterable[GraphEdge]:
    declarations = {
        "server": definition.servers, "client": definition.clients,
    }.get(role, ())
    for declaration in declarations:
        yield GraphEdge(material, "%s:%s" % (role, declaration.name), "consumes")


def _refresh_policy(recipe: object) -> str:
    if recipe.kind == "token" and getattr(recipe, "rotate_on_restart", False):
        return "authority-restart"
    if _refreshable(recipe):
        return "manual"
    return "none"


def _refreshable(recipe: object) -> bool:
    return recipe.kind in ("token", "tls", "voms")


def _revocable(recipe: object) -> bool:
    return recipe.kind in ("tls", "voms")


def _authority_id(recipe: object) -> str:
    return "authority:%s" % recipe.name


def _material_id(recipe: object, role: str) -> str:
    return "authority-material:%s:%s" % (recipe.name, role)


__all__ = ["authority_edges", "authority_nodes"]
