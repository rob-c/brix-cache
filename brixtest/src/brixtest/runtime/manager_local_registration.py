"""Low-complexity local launch registration for the case manager."""

from __future__ import annotations

from brixtest.fleet.registry import InstanceSpec
from brixtest.runtime.launchers import ServerLaunchContext, ServerLaunchRequest, server_launcher


def local_launch_plan(manager, declaration, values, mounts, library_dirs, binary_dirs, group_anchor):
    """Render and prepare one backend-specific server launch."""
    from brixtest.runtime.manager_local import (
        _launcher_name, _ordered_mount_paths, _server_identity, _server_workdir,
    )
    launcher_name = _launcher_name(declaration)
    launcher = server_launcher(launcher_name)
    launcher.validate(declaration)
    containerized = launcher_name in ("docker", "podman")
    command = tuple(
        manager._server_command_part(part, declaration, values, containerized)
        for part in declaration.command
    )
    shutdown = _shutdown_parts(manager, declaration, values)
    env = manager._local_server_environment(declaration, values, mounts)
    manager._local_server_search_paths(env, library_dirs, binary_dirs)
    context = ServerLaunchContext(manager.nodeid, manager.root, manager.workspace)
    request = ServerLaunchRequest(
        declaration, command, env, _server_workdir(manager.root, declaration),
        _ordered_mount_paths(declaration, mounts),
        _server_identity(manager.definition, declaration), manager._server_host_aliases(),
    )
    plan = _prepare_plan(launcher, context, request, containerized, group_anchor)
    return launcher, plan, _container_shutdown(launcher_name, plan, shutdown, containerized)


def _shutdown_parts(manager, declaration, values) -> tuple[str, ...]:
    return tuple(
        manager._render_part(
            part, values, "server %s shutdown command" % declaration.name,
        )
        for part in declaration.lifecycle.shutdown_command
    )


def _prepare_plan(launcher, context, request, containerized: bool, group_anchor):
    if not containerized or group_anchor is None:
        return launcher.prepare(context, request)
    from brixtest.runtime.launcher_groups import prepare_container_group_member
    return prepare_container_group_member(launcher, context, request, group_anchor)


def _container_shutdown(launcher_name, plan, shutdown, containerized: bool):
    if not containerized or not shutdown:
        return shutdown
    return launcher_name, "exec", str(plan.metadata["container_name"]), *shutdown


def register_local_servers(manager, servers, allocated, common, library_dirs, binary_dirs) -> None:
    """Register all logical local servers and shared OCI group relationships."""
    names = {server.name for server in servers}
    anchors = {}
    for declaration in servers:
        _register_local_server(
            manager, declaration, allocated[declaration.name], common,
            library_dirs, binary_dirs, names, anchors,
        )


def _register_local_server(
    manager, declaration, roles, common, library_dirs, binary_dirs, names, anchors,
) -> None:
    values, mounts = manager._local_server_values(declaration, roles, common)
    manager._server_mounts[declaration.name] = tuple(dict.fromkeys(mounts.values()))
    group, grouped, anchor = _group_context(declaration, anchors)
    launcher, plan, shutdown = manager._local_launch_plan(
        declaration, values, mounts, library_dirs, binary_dirs,
        group_anchor=None if anchor is None else anchor[1],
    )
    _remember_group_anchor(anchors, group, grouped, anchor, declaration.name, plan)
    manager._server_launchers[declaration.name] = launcher
    manager._server_launch_plans[declaration.name] = plan
    dependencies = _group_dependencies(declaration, names, anchor)
    manager.registry.register(_instance_spec(declaration, roles, plan, dependencies, shutdown))


def _group_context(declaration, anchors):
    group = declaration.placement.group
    grouped = bool(group and declaration.placement.backend in ("docker", "podman"))
    return group, grouped, anchors.get(group) if grouped else None


def _remember_group_anchor(anchors, group, grouped, anchor, name, plan) -> None:
    if grouped and anchor is None:
        anchors[group] = name, plan


def _group_dependencies(declaration, names, anchor) -> tuple[str, ...]:
    from brixtest.runtime.manager_local import _local_dependencies
    dependencies = _local_dependencies(declaration, names)
    if anchor is None:
        return dependencies
    return tuple(dict.fromkeys((*dependencies, anchor[0])))


def _instance_spec(declaration, roles, plan, dependencies, shutdown) -> InstanceSpec:
    from brixtest.runtime.manager import _KIND, _server_hosts
    from brixtest.runtime.manager_local import _instance_workdir
    hosts = _server_hosts(declaration, bind=False)
    return InstanceSpec(
        name=declaration.name, kind=_KIND.name, ports=roles, host=hosts["primary"],
        hosts=hosts, command=plan.argv, env=plan.env, depends_on=dependencies,
        readiness=declaration.readiness.kind,
        readiness_timeout=declaration.readiness.timeout, probe=declaration.probe,
        critical=True, stop_timeout=declaration.lifecycle.stop_timeout,
        shutdown_signal=declaration.lifecycle.shutdown_signal,
        shutdown_command=shutdown, expected_exit=declaration.lifecycle.expected_exit,
        background=declaration.lifecycle.background,
        log_max_bytes=declaration.logs.max_bytes, workdir=_instance_workdir(declaration),
    )


__all__ = ["local_launch_plan", "register_local_servers"]
