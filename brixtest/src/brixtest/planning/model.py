"""Immutable normalized resource-graph records."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from brixtest.util.immutable import freeze_mapping
from brixtest.errors import SpecError

GRAPH_SCHEMA_VERSION = 1
EDGE_RELATIONS = frozenset({
    "connects-to", "consumes", "identifies", "mounts", "places", "produces",
    "issues", "ready-before", "refreshes", "revokes", "shares-runtime-with",
    "tears-down-before",
})


def jsonable(value: object) -> object:
    """Return a deterministic, secret-conscious representation for planning."""
    if dataclasses.is_dataclass(value):
        return _jsonable_dataclass(value)
    if isinstance(value, Mapping):
        return _jsonable_mapping(value)
    if isinstance(value, (tuple, list, set, frozenset)):
        return [jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    return repr(value)


def _jsonable_dataclass(value: object) -> Mapping[str, object]:
    redacted = {"secret", "password", "master_password", "value"}
    return {
        field.name: jsonable(getattr(value, field.name))
        for field in dataclasses.fields(value) if field.name not in redacted
    }


def _jsonable_mapping(value: Mapping[object, object]) -> Mapping[str, object]:
    return {str(key): jsonable(item) for key, item in sorted(value.items())}


def digest(value: object) -> str:
    encoded = json.dumps(
        jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclasses.dataclass(frozen=True)
class GraphNode:
    """One planned resource and the capabilities required to realize it."""

    id: str
    kind: str
    name: str
    backend: str
    environment: str = "default"
    group: str = ""
    requires: Sequence[str] = ()
    fingerprint: str = ""
    attributes: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "requires", tuple(sorted(set(self.requires))))
        object.__setattr__(self, "attributes", freeze_mapping(self.attributes))
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", digest(self.as_dict(include_hash=False)))

    def as_dict(self, *, include_hash: bool = True) -> Mapping[str, object]:
        result = {
            "id": self.id, "kind": self.kind, "name": self.name,
            "backend": self.backend, "environment": self.environment,
            "group": self.group, "requires": list(self.requires),
            "attributes": jsonable(self.attributes),
        }
        if include_hash:
            result["fingerprint"] = self.fingerprint
        return result


@dataclasses.dataclass(frozen=True, order=True)
class GraphEdge:
    """A typed relationship between two graph nodes."""

    source: str
    target: str
    relation: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source:
            raise SpecError("graph edge source", self.source, "must be a resource ID")
        if not isinstance(self.target, str) or not self.target:
            raise SpecError("graph edge target", self.target, "must be a resource ID")
        if self.relation not in EDGE_RELATIONS:
            raise SpecError(
                "graph edge relation", self.relation,
                "known: %s" % ", ".join(sorted(EDGE_RELATIONS)),
            )

    def as_dict(self) -> Mapping[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ResourceGraph:
    """The complete normalized resource plan for one collected case."""

    nodes: Sequence[GraphNode]
    edges: Sequence[GraphEdge]
    schema_version: int = GRAPH_SCHEMA_VERSION
    fingerprint: str = ""

    def __post_init__(self) -> None:
        selected_nodes = tuple(sorted(self.nodes, key=lambda item: item.id))
        selected_edges = tuple(sorted(set(self.edges)))
        object.__setattr__(self, "nodes", selected_nodes)
        object.__setattr__(self, "edges", selected_edges)
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", digest(self.as_dict(include_hash=False)))

    def node(self, node_id: str) -> GraphNode:
        return next(item for item in self.nodes if item.id == node_id)

    def as_dict(self, *, include_hash: bool = True) -> Mapping[str, object]:
        result = {
            "schema_version": self.schema_version,
            "nodes": [item.as_dict() for item in self.nodes],
            "edges": [item.as_dict() for item in self.edges],
        }
        if include_hash:
            result["fingerprint"] = self.fingerprint
        return result
