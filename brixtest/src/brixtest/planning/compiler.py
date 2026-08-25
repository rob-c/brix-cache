"""Expand a CaseDefinition into one deterministic resource graph."""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Mapping, Sequence

from brixtest._design_inputs import Binary
from brixtest._design_managed import Identity, Resource, Task, Volume
from brixtest.errors import SpecError
from brixtest._environment_transport import environment_transportable
from brixtest.planning.auth_graph import authority_edges, authority_nodes
from brixtest.planning.model import GraphEdge, GraphNode, ResourceGraph, digest, jsonable
from brixtest.resources import Reference


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
    return set(filter(None, (
        _userns_requirement(value), _rbac_requirement(value),
        _posix_requirement(value), _capability_requirement(value),
    )))


def _userns_requirement(value: Identity) -> str:
    return "identity.userns" if value.user_namespace or value.uid_map or value.gid_map else ""


def _rbac_requirement(value: Identity) -> str:
    return "identity.rbac" if value.service_account or value.permissions else ""


def _posix_requirement(value: Identity) -> str:
    selected = value.uid is not None or value.gid is not None or bool(value.groups)
    return "identity.posix" if selected else ""


def _capability_requirement(value: Identity) -> str:
    return "identity.capabilities" if value.capabilities else ""


def _node_requirements(kind: str, declaration: object) -> set[str]:
    required = _endpoint_requirements(declaration) | _mount_requirements(declaration)
    required.update(_workload_requirements(kind, declaration))
    required.update(_resource_requirements(kind, declaration))
    required.update(_placement_requirements(declaration))
    return required


def _placement_requirements(declaration: object) -> set[str]:
    placement = getattr(declaration, "placement", None)
    required = {"workload.group"} if getattr(placement, "group", "") else set()
    if getattr(placement, "network_policy", "declared") == "isolated":
        required.add("network.policy")
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
    simple = (
        ("environment", definition.environments), ("volume", definition.volumes),
        ("identity", definition.identities), ("resource", definition.managed_resources),
    )
    placed = (
        ("task", definition.tasks), ("server", definition.servers),
        ("client", definition.clients),
    )
    inputs = (
        ("artifact", definition.artifacts), ("binary", definition.binaries),
        ("credential", definition.credentials),
        ("host", definition.hosts), ("collector", definition.observe),
    )
    nodes = [
        *_nodes(simple, backend, _simple_node),
        *_nodes(placed, backend, _declaration_node),
        *_nodes(inputs, backend, _simple_node),
        *authority_nodes(definition.auth, backend),
    ]
    if not definition.environments:
        nodes.append(GraphNode(
            "environment:default", "environment", "default", backend,
            attributes={"implicit": True},
        ))
    return nodes


def _nodes(groups, backend: str, factory) -> list[GraphNode]:
    return [factory(kind, item, backend) for kind, values in groups for item in values]


def _dependency_edges(definition: object) -> Iterable[GraphEdge]:
    for kind, declarations in (
        ("server", definition.servers), ("task", definition.tasks),
        ("resource", definition.managed_resources),
    ):
        for declaration in declarations:
            yield from _declaration_dependency_edges(definition, kind, declaration)


def _declaration_dependency_edges(
    definition: object, kind: str, declaration: object,
) -> Iterable[GraphEdge]:
    target = "%s:%s" % (kind, declaration.name)
    for dependency in declaration.depends_on:
        source = _dependency_id(definition, dependency)
        yield GraphEdge(source, target, "ready-before")
        yield GraphEdge(target, source, "tears-down-before")
        if kind == "server" and source.startswith("server:"):
            yield GraphEdge(target, source, "connects-to")


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
            yield from _declaration_placement_edges(kind, declaration)


def _declaration_placement_edges(kind: str, declaration: object) -> Iterable[GraphEdge]:
    target = "%s:%s" % (kind, declaration.name)
    placement = declaration.placement
    yield GraphEdge(
        "environment:%s" % (placement.environment or "default"), target, "places",
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


def _generated_input_edges(definition: object) -> Iterable[GraphEdge]:
    for kind, declarations in (
        ("binary", definition.binaries), ("artifact", definition.artifacts),
    ):
        for declaration in declarations:
            source = getattr(declaration, "path" if kind == "binary" else "source", None)
            if isinstance(source, Reference) and source.kind == "task":
                yield GraphEdge(
                    "task:%s" % source.name,
                    "%s:%s" % (kind, declaration.name), "produces",
                )


def _volume_provider_edges(definition: object) -> Iterable[GraphEdge]:
    for volume in definition.volumes:
        if not volume.provider:
            continue
        source, target = "resource:%s" % volume.provider, "volume:%s" % volume.name
        yield GraphEdge(source, target, "produces")
        yield GraphEdge(target, source, "tears-down-before")


def _group_edges(nodes: Iterable[GraphNode]) -> Iterable[GraphEdge]:
    grouped = Counter(item.group for item in nodes if item.group)
    anchors = {}
    for node in nodes:
        edge = _group_edge(node, grouped, anchors)
        if edge is not None:
            yield edge


def _group_edge(node: GraphNode, grouped, anchors) -> object:
    if not node.group or grouped[node.group] < 2:
        return None
    anchor = anchors.setdefault(node.group, node.id)
    return GraphEdge(anchor, node.id, "shares-runtime-with") if anchor != node.id else None


def _validate_graph(nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
    node_ids = {item.id for item in nodes}
    _validate_node_ids(node_ids, nodes)
    _validate_edge_nodes(node_ids, edges)
    _validate_dependency_cycles(node_ids, edges)


def _validate_edge_nodes(node_ids: set[str], edges: Sequence[GraphEdge]) -> None:
    dangling = [
        edge for edge in edges
        if edge.source not in node_ids or edge.target not in node_ids
    ]
    if dangling:
        raise SpecError("resource graph edge", dangling[0], "must connect planned nodes")


def _validate_node_ids(node_ids: set[str], nodes: Sequence[GraphNode]) -> None:
    if len(node_ids) != len(nodes):
        raise SpecError("resource graph", "duplicate node", "resource IDs must be unique")


def _validate_lifetimes(definition: object) -> None:
    tasks = {task.name: task for task in definition.tasks}
    servers = {server.name for server in definition.servers}
    for task in definition.tasks:
        _validate_task_lifetime(task, tasks, servers)
    _validate_server_lifetimes(definition.servers, tasks)
    _validate_resource_lifetimes(definition.managed_resources, servers)
    _validate_dependency_names(definition)
    _validate_cross_environment_dependencies(definition)
    _validate_groups(definition)


def _validate_server_lifetimes(servers: Sequence[object], tasks: Mapping[str, object]) -> None:
    for server in servers:
        for dependency in server.depends_on:
            selected = tasks.get(dependency)
            if selected is not None and selected.phase == "finalize":
                raise SpecError(
                    "server %s dependency" % server.name, dependency,
                    "cannot depend on a finalization task",
                )


def _validate_resource_lifetimes(resources: Sequence[object], servers: set[str]) -> None:
    for resource in resources:
        invalid = sorted(set(resource.depends_on) & servers)
        if invalid:
            raise SpecError(
                "resource %s dependency" % resource.name, invalid,
                "provider resources must be ready before servers start",
            )


def _validate_dependency_names(definition: object) -> None:
    groups = definition.servers, definition.tasks, definition.managed_resources
    counts = _dependency_counts(groups)
    referenced = _referenced_dependencies(groups)
    ambiguous = sorted(name for name in referenced if counts[name] > 1)
    if ambiguous:
        raise SpecError(
            "resource dependencies", ambiguous,
            "names must identify exactly one server, task, or provider resource",
        )


def _dependency_counts(groups) -> Counter:
    return Counter(item.name for values in groups for item in values)


def _referenced_dependencies(groups) -> set[str]:
    return {name for values in groups for item in values for name in item.depends_on}


def _validate_cross_environment_dependencies(definition: object) -> None:
    servers = {server.name: server for server in definition.servers}
    for consumer in definition.servers:
        _validate_consumer_environment(consumer, servers, definition.environments)


def _validate_consumer_environment(consumer, servers, environments) -> None:
    source = consumer.placement.environment or "default"
    for name in consumer.depends_on:
        producer = servers.get(name)
        if producer is None:
            continue
        destination = producer.placement.environment or "default"
        if not environment_transportable(source, destination, environments):
            raise SpecError(
                "server %s dependency" % consumer.name, name,
                "cannot cross execution contexts without a managed transport",
            )


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
    groups = _placement_groups((*definition.tasks, *definition.servers, *definition.clients))
    conflict = next((name for name, values in groups.items() if len(values) > 1), "")
    if conflict:
        raise SpecError(
            "placement.group", conflict,
            "all members must select the same backend and environment",
        )


def _placement_groups(declarations) -> dict[str, set[tuple[str, str]]]:
    groups: dict[str, set[tuple[str, str]]] = {}
    for declaration in declarations:
        placement = declaration.placement
        if placement.group:
            groups.setdefault(placement.group, set()).add((
                placement.backend, placement.environment or "default",
            ))
    return groups


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
        *_binary_edges(definition), *_generated_input_edges(definition),
        *_volume_provider_edges(definition), *authority_edges(definition),
        *_group_edges(nodes),
    ]
    _validate_graph(nodes, edges)
    return ResourceGraph(nodes, edges)


_PHASE_ORDER = {"prepare": 0, "init": 1, "finalize": 2}
