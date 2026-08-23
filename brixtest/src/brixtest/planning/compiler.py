"""Expand a CaseDefinition into one deterministic resource graph."""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Mapping

from brixtest._design_inputs import Binary
from brixtest._design_managed import Identity, Resource, Task, Volume
from brixtest.errors import SpecError
from brixtest.planning.model import GraphEdge, GraphNode, ResourceGraph, digest, jsonable


def _backend(value: str, fallback: str, *, client: bool = False) -> str:
    if value not in ("", "inherit"):
        return value
    return "local" if client else fallback


def _placement(declaration: object) -> tuple[str, str, str]:
    placement = getattr(declaration, "placement", None)
    return (
        str(getattr(placement, "backend", "inherit")),
        str(getattr(placement, "environment", "") or "default"),
        str(getattr(placement, "group", "")),
    )


def _endpoint_requirements(declaration: object) -> set[str]:
    required = set()
    for endpoint in getattr(declaration, "endpoints", ()):
        required.add("network.%s" % endpoint.protocol)
        if endpoint.family in ("ipv6", "dual"):
            required.add("network.ipv6")
        if endpoint.family == "dual":
            required.add("network.dual")
        if endpoint.exposure == "external":
            required.add("network.external")
    return required


def _mount_requirements(declaration: object) -> set[str]:
    required = set()
    for declared_mount in getattr(declaration, "mounts", ()):
        source = declared_mount.source
        if isinstance(source, Volume):
            required.add("storage.%s" % source.kind)
        if declared_mount.propagation != "none":
            required.add("storage.mount-propagation")
    return required


def _identity_requirements(value: Identity) -> set[str]:
    required = set()
    if value.user_namespace or value.uid_map or value.gid_map:
        required.add("identity.userns")
    if value.service_account or value.permissions:
        required.add("identity.rbac")
    if value.uid is not None or value.gid is not None or value.groups:
        required.add("identity.posix")
    if value.capabilities:
        required.add("identity.capabilities")
    return required


def _node_requirements(kind: str, declaration: object) -> set[str]:
    required = _endpoint_requirements(declaration) | _mount_requirements(declaration)
    required.update(_workload_requirements(kind, declaration))
    required.update(_resource_requirements(kind, declaration))
    return required


def _resource_requirements(kind: str, declaration: object) -> set[str]:
    handlers = {
        "client": _client_resource_requirements,
        "volume": _volume_requirements,
        "identity": _identity_resource_requirements,
        "environment": _environment_requirements,
        "resource": lambda _value: {"resource.provider"},
    }
    handler = handlers.get(kind)
    return handler(declaration) if handler else set()


def _client_resource_requirements(declaration: object) -> set[str]:
    has_volume = any(
        isinstance(item.source, Volume) for item in getattr(declaration, "mounts", ())
    )
    return {"storage.client-volume"} if has_volume else set()


def _volume_requirements(declaration: object) -> set[str]:
    selected_kind = "persistent" if declaration.persistent else declaration.kind
    required = {"storage.volume", "storage.%s" % selected_kind}
    return required | ({"storage.quota"} if declaration.size else set())


def _identity_resource_requirements(declaration: object) -> set[str]:
    return {"identity.materialization"} | _identity_requirements(declaration)


def _environment_requirements(declaration: object) -> set[str]:
    required = {"environment.named"}
    if declaration.isolated:
        required.add("environment.isolated")
    if declaration.family in ("ipv6", "dual"):
        required.add("network.ipv6")
    return required


def _workload_requirements(kind: str, declaration: object) -> set[str]:
    if kind == "server":
        return {
            "workload.service",
            *({"workload.replicas"} if declaration.replicas > 1 else set()),
            *({"network.policy"} if declaration.placement.network_policy == "isolated" else set()),
        }
    if kind == "client":
        return {
            "execution.capture",
            *({"execution.pty"} if declaration.mode == "pty" else set()),
            *({"execution.stdin"} if declaration.input is not None else set()),
        }
    if kind == "task":
        return {
            "workload.task",
            *({"workload.init"} if declaration.phase == "init" else set()),
        }
    return set()


def _declaration_node(kind: str, declaration: object, fallback: str) -> GraphNode:
    selected, environment, group = _placement(declaration)
    backend = _backend(selected, fallback, client=kind == "client")
    attributes = jsonable(declaration)
    return GraphNode(
        "%s:%s" % (kind, declaration.name), kind, declaration.name, backend,
        environment, group, _node_requirements(kind, declaration),
        digest({"kind": kind, "declaration": attributes}),
        attributes if isinstance(attributes, Mapping) else {"value": attributes},
    )


def _simple_node(kind: str, declaration: object, backend: str) -> GraphNode:
    attributes = jsonable(declaration)
    selected = getattr(declaration, "backend", "inherit")
    selected_backend = backend if selected in ("", "inherit") else selected
    return GraphNode(
        "%s:%s" % (kind, declaration.name), kind, declaration.name, selected_backend,
        requires=_node_requirements(kind, declaration),
        fingerprint=digest({"kind": kind, "declaration": attributes}),
        attributes=attributes if isinstance(attributes, Mapping) else {"value": attributes},
    )


def _case_nodes(definition: object, backend: str) -> list[GraphNode]:
    nodes = []
    for kind, declarations in (
        ("environment", definition.environments), ("volume", definition.volumes),
        ("identity", definition.identities), ("resource", definition.managed_resources),
    ):
        nodes.extend(_simple_node(kind, item, backend) for item in declarations)
    for kind, declarations in (
        ("task", definition.tasks), ("server", definition.servers),
        ("client", definition.clients),
    ):
        nodes.extend(_declaration_node(kind, item, backend) for item in declarations)
    for kind, declarations in (
        ("artifact", definition.artifacts), ("binary", definition.binaries),
        ("credential", definition.credentials), ("authority", definition.auth),
        ("host", definition.hosts), ("collector", definition.observe),
    ):
        nodes.extend(_simple_node(kind, item, backend) for item in declarations)
    if not definition.environments:
        nodes.append(GraphNode(
            "environment:default", "environment", "default", backend,
            attributes={"implicit": True},
        ))
    return nodes


def _dependency_edges(definition: object) -> Iterable[GraphEdge]:
    for kind, declarations in (
        ("server", definition.servers), ("task", definition.tasks),
        ("resource", definition.managed_resources),
    ):
        for declaration in declarations:
            for dependency in declaration.depends_on:
                yield GraphEdge(_dependency_id(definition, dependency), "%s:%s" % (kind, declaration.name), "ready-before")


def _dependency_id(definition: object, name: str) -> str:
    for kind, declarations in (
        ("server", definition.servers), ("task", definition.tasks),
        ("resource", definition.managed_resources),
    ):
        if any(item.name == name for item in declarations):
            return "%s:%s" % (kind, name)
    raise SpecError("resource dependency", name, "does not name a planned resource")


def _placement_edges(definition: object) -> Iterable[GraphEdge]:
    for kind, declarations in (
        ("server", definition.servers), ("client", definition.clients),
        ("task", definition.tasks),
    ):
        for declaration in declarations:
            target = "%s:%s" % (kind, declaration.name)
            placement = declaration.placement
            yield GraphEdge(
                "environment:%s" % (placement.environment or "default"),
                target, "places",
            )
            if placement.identity:
                yield GraphEdge("identity:%s" % placement.identity, target, "identifies")
            for declared_mount in declaration.mounts:
                source = declared_mount.source
                source_kind = getattr(source, "resource_kind", "")
                if source_kind:
                    yield GraphEdge("%s:%s" % (source_kind, source.name), target, "mounts")


def _binary_edges(definition: object) -> Iterable[GraphEdge]:
    for kind, declarations in (
        ("server", definition.servers), ("client", definition.clients),
        ("task", definition.tasks),
    ):
        for declaration in declarations:
            selected = {*declaration.binaries, *(
                item for item in declaration.command if isinstance(item, Binary)
            )}
            for binary in selected:
                yield GraphEdge("binary:%s" % binary.name, "%s:%s" % (kind, declaration.name), "consumes")


def _group_edges(nodes: Iterable[GraphNode]) -> Iterable[GraphEdge]:
    grouped = Counter(item.group for item in nodes if item.group)
    anchors = {}
    for node in nodes:
        if not node.group or grouped[node.group] < 2:
            continue
        anchor = anchors.setdefault(node.group, node.id)
        if anchor != node.id:
            yield GraphEdge(anchor, node.id, "shares-runtime-with")


def _validate_graph(nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
    node_ids = {item.id for item in nodes}
    if len(node_ids) != len(nodes):
        raise SpecError("resource graph", "duplicate node", "resource IDs must be unique")
    dangling = [edge for edge in edges if edge.source not in node_ids or edge.target not in node_ids]
    if dangling:
        raise SpecError("resource graph edge", dangling[0], "must connect planned nodes")
    _validate_dependency_cycles(node_ids, edges)


def _validate_lifetimes(definition: object) -> None:
    tasks = {task.name: task for task in definition.tasks}
    servers = {server.name for server in definition.servers}
    for task in definition.tasks:
        _validate_task_lifetime(task, tasks, servers)
    for server in definition.servers:
        for dependency in server.depends_on:
            selected = tasks.get(dependency)
            if selected is not None and selected.phase == "finalize":
                raise SpecError(
                    "server %s dependency" % server.name, dependency,
                    "cannot depend on a finalization task",
                )
    _validate_groups(definition)


def _validate_task_lifetime(
    task: object, tasks: Mapping[str, object], servers: set[str],
) -> None:
    for dependency in task.depends_on:
        if dependency in servers and task.phase != "finalize":
            raise SpecError(
                "task %s dependency" % task.name, dependency,
                "only finalization tasks can depend on a running server",
            )
        selected = tasks.get(dependency)
        if selected is not None and _PHASE_ORDER[selected.phase] > _PHASE_ORDER[task.phase]:
            raise SpecError(
                "task %s dependency" % task.name, dependency,
                "cannot depend on a later task phase",
            )


def _validate_groups(definition: object) -> None:
    groups: dict[str, set[tuple[str, str]]] = {}
    for declaration in (*definition.tasks, *definition.servers, *definition.clients):
        placement = declaration.placement
        if placement.group:
            groups.setdefault(placement.group, set()).add((
                placement.backend, placement.environment or "default",
            ))
    conflict = next((name for name, values in groups.items() if len(values) > 1), "")
    if conflict:
        raise SpecError(
            "placement.group", conflict,
            "all members must select the same backend and environment",
        )


def _validate_dependency_cycles(node_ids: set[str], edges: list[GraphEdge]) -> None:
    selected = [edge for edge in edges if edge.relation == "ready-before"]
    outgoing, incoming = _dependency_indexes(node_ids, selected)
    visited = _visit_acyclic(outgoing, incoming)
    if visited != len(node_ids):
        cycle = sorted(node_id for node_id, count in incoming.items() if count)
        raise SpecError("resource graph", cycle, "dependency relationships must be acyclic")


def _dependency_indexes(
    node_ids: set[str], edges: list[GraphEdge],
) -> tuple[dict[str, list[str]], dict[str, int]]:
    outgoing = {node_id: [] for node_id in node_ids}
    incoming = dict.fromkeys(node_ids, 0)
    for edge in edges:
        outgoing[edge.source].append(edge.target)
        incoming[edge.target] += 1
    return outgoing, incoming


def _visit_acyclic(
    outgoing: Mapping[str, list[str]], incoming: dict[str, int],
) -> int:
    ready = [node_id for node_id, count in incoming.items() if count == 0]
    visited = 0
    while ready:
        current = ready.pop()
        visited += 1
        for target in outgoing[current]:
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    return visited


def compile_case(definition: object, backend: str = "") -> ResourceGraph:
    """Build and validate a deterministic graph without creating resources."""
    selected = backend or ("local" if definition.backend == "auto" else definition.backend)
    _validate_lifetimes(definition)
    nodes = _case_nodes(definition, selected)
    edges = [
        *_dependency_edges(definition), *_placement_edges(definition),
        *_binary_edges(definition), *_group_edges(nodes),
    ]
    _validate_graph(nodes, edges)
    return ResourceGraph(nodes, edges)


_PHASE_ORDER = {"prepare": 0, "init": 1, "finalize": 2}
