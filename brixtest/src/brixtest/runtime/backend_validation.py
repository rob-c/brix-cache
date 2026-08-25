"""Pre-mutation validation shared by built-in case backends."""

from pathlib import Path

from brixtest.errors import SpecError


def validate_local_server_groups(servers) -> None:
    """Require OCI group members to agree on container-level policy."""
    groups = _local_server_groups(servers)
    for name, members in groups.items():
        _validate_local_group(name, members)


def _local_server_groups(servers) -> dict:
    groups = {}
    for server in servers:
        placement = server.placement
        if placement.group and placement.backend in ("docker", "podman"):
            groups.setdefault(placement.group, []).append(server)
    return groups


def _validate_local_group(name: str, members) -> None:
    shapes = {_container_group_shape(item) for item in members}
    if len(shapes) > 1:
        raise SpecError(
            "placement.group", name,
            "OCI members must share image, identity, limits, labels, options, and runtime mounts",
        )


def _container_group_shape(server) -> tuple:
    placement = server.placement
    runtime_mounts = tuple(
        (
            getattr(mount.source, "name", str(mount.source)),
            mount.target, mount.read_only, mount.propagation,
        )
        for mount in server.mounts
        if mount.propagation != "none" or getattr(mount.source, "kind", "") == "device"
    )
    return (
        placement.backend, placement.image or server.image, placement.identity,
        tuple(sorted(placement.labels.items())), placement.resources,
        repr(dict(placement.options)), placement.allow_mutable_image,
        runtime_mounts,
    )


def validate_local_volumes(volumes) -> None:
    for volume in volumes:
        _validate_builtin_volume(volume, "local")
        if volume.options:
            raise SpecError(
                "volume %s options" % volume.name, dict(volume.options),
                "the local backend has no volume options",
            )


def validate_kubernetes_volumes(volumes, resources=()) -> None:
    for volume in volumes:
        _validate_kubernetes_volume(volume, resources)


def _validate_kubernetes_volume(volume, resources) -> None:
    if volume.provider:
        _validate_provider_volume(volume, resources)
    else:
        _validate_builtin_volume(volume, "Kubernetes")
    allowed = {"storage_class"} if _uses_claim(volume) else set()
    unknown = sorted(set(volume.options) - allowed)
    if unknown:
        raise SpecError(
            "volume %s options" % volume.name, unknown,
            "known for this Kubernetes volume: %s" % (
                ", ".join(sorted(allowed)) or "none"
            ),
        )
    _validate_storage_class(volume)
    _validate_host_path(volume)


def _validate_provider_volume(volume, resources) -> None:
    known = {item.name for item in resources}
    if volume.provider not in known:
        raise SpecError(
            "volume %s provider" % volume.name, volume.provider,
            "must name a Resource declaration in the same case",
        )
    if volume.kind != "provider" or volume.source is not None:
        raise SpecError(
            "volume %s" % volume.name, volume,
            "provider-backed storage requires kind='provider' and no source path",
        )


def _validate_storage_class(volume) -> None:
    storage_class = volume.options.get("storage_class")
    if storage_class is not None and not isinstance(storage_class, str):
        raise SpecError(
            "volume %s options.storage_class" % volume.name, storage_class,
            "must be text",
        )


def _validate_host_path(volume) -> None:
    if volume.kind == "host" and not Path(str(volume.source)).is_absolute():
        raise SpecError(
            "volume %s source" % volume.name, str(volume.source),
            "Kubernetes host volumes require an absolute node path",
        )


def _validate_builtin_volume(volume, backend: str) -> None:
    if volume.provider:
        raise SpecError(
            "volume %s provider" % volume.name, volume.provider,
            "%s provider-backed volumes require an installed volume adapter" % backend,
        )
    if volume.source is not None and volume.kind not in ("host", "device"):
        raise SpecError(
            "volume %s source" % volume.name, str(volume.source),
            "%s built-in %s volumes do not consume a source" % (backend, volume.kind),
        )


def _uses_claim(volume) -> bool:
    return volume.kind in ("persistent", "shared", "provider") or volume.persistent


def validate_kubernetes_server_policy(server) -> None:
    placement = server.placement
    if placement.options or placement.allow_mutable_image:
        raise SpecError(
            "server %s placement" % server.name, placement,
            "Kubernetes does not consume runtime options or mutable images",
        )
    if placement.resources.pids is not None:
        raise SpecError(
            "server %s placement.resources.pids" % server.name,
            placement.resources.pids,
            "Kubernetes has no portable per-container PID limit",
        )
    _validate_kubernetes_lifecycle(server)


def validate_kubernetes_groups(declaration) -> None:
    """Reject group definitions that cannot become one deterministic Pod."""
    groups = _kubernetes_server_groups(_declarations(declaration, "servers"))
    _validate_kubernetes_group_members(groups)
    _validate_kubernetes_grouped_clients(_declarations(declaration, "clients"))
    _validate_kubernetes_grouped_tasks(_declarations(declaration, "tasks"), groups)


def _declarations(declaration, name: str) -> tuple:
    return tuple(getattr(declaration, name, ()))


def _kubernetes_server_groups(servers) -> dict:
    groups = {}
    for server in servers:
        if server.placement.group:
            groups.setdefault(server.placement.group, []).append(server)
    return groups


def _validate_kubernetes_group_members(groups) -> None:
    for name, members in groups.items():
        _validate_server_group(name, members)


def _validate_kubernetes_grouped_clients(clients) -> None:
    for client in clients:
        if client.placement.group:
            raise SpecError(
                "client %s placement.group" % client.name, client.placement.group,
                "clients are finite Pod executions and cannot be server sidecars",
            )


def _validate_kubernetes_grouped_tasks(tasks, groups) -> None:
    for task in tasks:
        if task.placement.group:
            _validate_grouped_task(task, groups)


def validate_kubernetes_environments(declaration, backend: str) -> None:
    """Reject environment fields the built-in Kubernetes transport cannot honor."""
    accepted = {"inherit", "kubernetes", backend}
    declared = _declarations(declaration, "environments")
    environments = {item.name: item for item in declared}
    _validate_environment_declarations(declared, accepted, backend)
    _validate_environment_placements(declaration, environments)
    _validate_context_bound_resources(declaration)


def _validate_environment_declarations(declarations, accepted, backend: str) -> None:
    for item in declarations:
        if item.backend not in accepted or item.options:
            raise SpecError(
                "environment %s" % item.name, item,
                "%s accepts inherit/kubernetes realms without extension options" % backend,
            )


def _validate_environment_placements(declaration, environments) -> None:
    for kind, values in (
        ("server", _declarations(declaration, "servers")),
        ("task", _declarations(declaration, "tasks")),
        ("client", _declarations(declaration, "clients")),
    ):
        for item in values:
            _validate_environment_placement(kind, item, environments)


def _validate_context_bound_resources(declaration) -> None:
    explicit = {
        item.name for item in _declarations(declaration, "environments") if item.context
    }
    _validate_context_bound_auth(declaration, explicit)
    _validate_context_bound_volumes(declaration, explicit)


def _validate_context_bound_auth(declaration, explicit: set[str]) -> None:
    placed = {
        item.placement.environment for item in (
            *_declarations(declaration, "servers"),
            *_declarations(declaration, "tasks"),
            *_declarations(declaration, "clients"),
        )
        if item.placement.environment in explicit
    }
    auth = _declarations(declaration, "auth")
    if placed and any(getattr(item, "kind", "") == "kerberos" for item in auth):
        raise SpecError(
            "Kubernetes Kerberos environments", sorted(placed),
            "managed KDC consumers must inherit the case context",
        )


def _validate_context_bound_volumes(declaration, explicit: set[str]) -> None:
    provider_volumes = {
        item.name for item in _declarations(declaration, "volumes") if item.provider
    }
    for server in _declarations(declaration, "servers"):
        _validate_server_provider_context(server, explicit, provider_volumes)


def _validate_server_provider_context(server, explicit, provider_volumes) -> None:
    if server.placement.environment not in explicit:
        return
    mounted = {getattr(item.source, "name", "") for item in server.mounts}
    if mounted & provider_volumes:
        raise SpecError(
            "server %s environment" % server.name,
            server.placement.environment,
            "provider-backed storage must inherit the provider context",
        )


def _validate_environment_placement(kind: str, item, environments) -> None:
    placement = item.placement
    if placement.environment and placement.namespace:
        raise SpecError(
            "%s %s placement" % (kind, item.name), placement,
            "select namespace through Environment, not both placement fields",
        )
    if kind == "client" and placement.environment and placement.backend != "kubernetes":
        raise SpecError(
            "client %s placement.backend" % item.name, placement.backend,
            "a named Kubernetes environment requires backend='kubernetes'",
        )


def _validate_server_group(name: str, members) -> None:
    if _group_has_mixed_placement(members):
        raise SpecError(
            "placement.group", name,
            "server members must use the same environment, same replicas, identity, and node selector",
        )
    if _group_internal_dependencies(members):
        raise SpecError(
            "placement.group", name,
            "Pod sidecars start together and cannot declare group-internal ordering",
        )


def _group_has_mixed_placement(members) -> bool:
    shapes = {
        (
            item.replicas, item.placement.identity,
            tuple(sorted(item.placement.node_selector.items())),
            item.placement.environment,
        )
        for item in members
    }
    return len(shapes) > 1


def _group_internal_dependencies(members) -> tuple[str, ...]:
    names = {item.name for item in members}
    return tuple(
        dependency for item in members for dependency in item.depends_on
        if dependency in names
    )


def _validate_grouped_task(task, groups) -> None:
    members = groups.get(task.placement.group, ())
    if task.phase != "init" or not members:
        raise SpecError(
            "task %s placement.group" % task.name, task.placement.group,
            "must be an init task sharing a group with a server",
        )
    anchor = members[0]
    if task.placement.environment != anchor.placement.environment:
        raise SpecError(
            "task %s placement.environment" % task.name,
            task.placement.environment, "must match the grouped servers",
        )
    if task.placement.identity != anchor.placement.identity:
        raise SpecError(
            "task %s placement.identity" % task.name, task.placement.identity,
            "must match the grouped server identity",
        )
    if task.placement.node_selector != anchor.placement.node_selector:
        raise SpecError(
            "task %s placement.node_selector" % task.name,
            dict(task.placement.node_selector), "must match the grouped servers",
        )
    if any(item.replicas != 1 for item in members):
        raise SpecError(
            "task %s placement.group" % task.name, task.placement.group,
            "init containers require a single-replica group",
        )


def _validate_kubernetes_lifecycle(server) -> None:
    lifecycle = server.lifecycle
    unsupported = (
        not lifecycle.background or lifecycle.shutdown_signal != "TERM"
        or lifecycle.expected_exit
    )
    if unsupported:
        raise SpecError(
            "server %s lifecycle" % server.name, lifecycle,
            "Kubernetes services require background=True, TERM shutdown, and expected_exit=False",
        )


def validate_kubernetes_task_placement(task) -> None:
    placement = task.placement
    unsupported = (
        placement.namespace or placement.options or placement.allow_mutable_image
        or placement.network_policy != "declared"
    )
    if unsupported:
        raise SpecError(
            "task %s placement" % task.name, placement,
            "Kubernetes tasks use the case namespace and do not consume runtime options, mutable images, or network policies",
        )


__all__ = [
    "validate_kubernetes_environments", "validate_kubernetes_groups",
    "validate_kubernetes_server_policy",
    "validate_kubernetes_task_placement",
    "validate_kubernetes_volumes", "validate_local_server_groups",
    "validate_local_volumes",
]
