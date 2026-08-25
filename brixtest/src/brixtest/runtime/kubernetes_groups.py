"""Compile execution groups into native multi-container Kubernetes workloads."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
from typing import Mapping, Optional, Sequence

from brixtest.errors import SpecError
from brixtest.fleet.registry import InstanceSpec
from brixtest.runtime.commands import CommandResult
from brixtest.runtime.kubernetes_manifests import _resource_name
from brixtest.runtime.kubernetes_tasks import task_init_container
from brixtest.runtime.managed import _task_order

_WORKLOADS = ("Deployment", "StatefulSet")
_POD_POLICY = ("serviceAccountName", "securityContext", "nodeSelector", "hostAliases")
_COMMON_VOLUMES = ("workspace", "secure", "identity-nss")


@dataclasses.dataclass(frozen=True)
class InitPlan:
    """One already-rendered task destined for a Pod init-container sequence."""

    task: object
    container: Mapping[str, object]
    volumes: Sequence[Mapping[str, object]]


def _groups(servers) -> dict[str, tuple[object, ...]]:
    values: dict[str, list[object]] = {}
    for server in servers:
        if server.placement.group:
            values.setdefault(server.placement.group, []).append(server)
    return {name: tuple(items) for name, items in values.items()}


def _server_for_group(groups, name: str):
    members = groups.get(name, ())
    if not members:
        raise SpecError(
            "placement.group", name,
            "a grouped init task must share its group with at least one server",
        )
    return members[0]


def _validate_init_task(task, servers) -> None:
    anchor = _server_for_group(servers, task.placement.group)
    if task.phase != "init":
        raise SpecError(
            "task %s placement.group" % task.name, task.placement.group,
            "only init tasks can share a long-lived server workload",
        )
    if task.placement.identity != anchor.placement.identity:
        raise SpecError(
            "task %s placement.identity" % task.name, task.placement.identity,
            "grouped init tasks must use the Pod identity",
        )
    if task.placement.node_selector != anchor.placement.node_selector:
        raise SpecError(
            "task %s placement.node_selector" % task.name,
            dict(task.placement.node_selector), "must match the grouped servers",
        )
    if any(member.replicas != 1 for member in servers[task.placement.group]):
        raise SpecError(
            "task %s placement.group" % task.name, task.placement.group,
            "grouped init tasks require a single-replica workload",
        )


def render_grouped_init_plans(backend, servers) -> Mapping[str, tuple[InitPlan, ...]]:
    """Render dependency-ordered grouped init tasks before workload compilation."""
    groups = _groups(servers)
    tasks = _grouped_tasks(backend.owner.definition.tasks)
    for task in tasks:
        _validate_init_task(task, groups)
    known = {task.name for task in backend.owner.definition.tasks}
    ordered = _task_order(tasks, backend.owner._managed._completed, known)
    return _render_init_plans(backend, ordered)


def _grouped_tasks(tasks) -> tuple:
    return tuple(task for task in tasks if task.placement.group)


def _render_init_plans(backend, ordered) -> Mapping[str, tuple[InitPlan, ...]]:
    values: dict[str, list[InitPlan]] = {}
    for task in ordered:
        container, volumes = task_init_container(
            task, command=backend._render_task_command(task),
            env=backend._render_task_environment(task),
            identity=backend._task_identity(task),
            secure_secret=backend._task_secure_secret,
            secure_items=backend._task_secure_items,
        )
        values.setdefault(task.placement.group, []).append(
            InitPlan(task, container, volumes),
        )
    return _frozen_init_plans(values)


def _frozen_init_plans(values) -> Mapping[str, tuple[InitPlan, ...]]:
    return {name: tuple(items) for name, items in values.items()}


def _one_workload(documents, server: str) -> dict:
    found = [item for item in documents if item.get("kind") in _WORKLOADS]
    if len(found) != 1:
        raise SpecError(
            "server %s Kubernetes workload" % server, len(found),
            "must render exactly one Deployment or StatefulSet",
        )
    return found[0]


def _pod_spec(workload: Mapping[str, object]) -> dict:
    return copy.deepcopy(workload["spec"]["template"]["spec"])


def _validate_group(group: str, members, pod_specs) -> None:
    _validate_group_shape(group, members)
    for field in _POD_POLICY:
        _validate_group_policy_field(group, field, pod_specs)


def _validate_group_shape(group: str, members) -> None:
    replicas = {member.replicas for member in members}
    identities = {member.placement.identity for member in members}
    if len(replicas) != 1 or len(identities) != 1:
        raise SpecError(
            "placement.group", group,
            "all server members must use the same replicas and identity",
        )


def _validate_group_policy_field(group: str, field: str, pod_specs) -> None:
    values = [spec.get(field) for spec in pod_specs]
    if any(value != values[0] for value in values[1:]):
        raise SpecError(
            "placement.group", group,
            "all server members must share Pod field %s" % field,
        )


def _scoped_name(member: str, name: str) -> str:
    selected = "%s-%s" % (_resource_name(member), name)
    if len(selected) <= 63:
        return selected
    suffix = hashlib.sha256(selected.encode()).hexdigest()[:8]
    return "%s-%s" % (selected[:54].strip("-"), suffix)


def _shared_volume(name: str) -> bool:
    return name in _COMMON_VOLUMES or name.startswith("managed-")


def _volume_mapping(member: str, volumes) -> dict[str, str]:
    return {
        item["name"]: item["name"] if _shared_volume(item["name"])
        else _scoped_name(member, item["name"])
        for item in volumes
    }


def _renamed_volumes(volumes, names: Mapping[str, str]) -> tuple[dict, ...]:
    selected = []
    for item in volumes:
        value = copy.deepcopy(item)
        value["name"] = names[value["name"]]
        selected.append(value)
    return tuple(selected)


def _container(member: str, pod: dict, names: Mapping[str, str]) -> dict:
    candidates = [
        item for item in pod["containers"] if item.get("name") != "brixtest-filesystem"
    ]
    if len(candidates) != 1:
        raise SpecError(
            "placement.group", member, "each server must render one primary container",
        )
    selected = copy.deepcopy(candidates[0])
    selected["name"] = _resource_name(member)
    for mount in selected.get("volumeMounts", ()):
        mount["name"] = names[mount["name"]]
    return selected


def _helper_mount(member: str, mount, names: Mapping[str, str]) -> dict:
    selected = copy.deepcopy(mount)
    original = selected["name"]
    selected["name"] = names[original]
    if not _shared_volume(original):
        selected["mountPath"] = "/brixtest/groups/%s%s" % (
            _resource_name(member), selected["mountPath"],
        )
    elif original.startswith("managed-"):
        selected["mountPath"] = "/brixtest/groups/%s%s" % (
            _resource_name(member), selected["mountPath"],
        )
    return selected


def _filesystem_template(pod: dict) -> dict:
    return copy.deepcopy(next(
        item for item in pod["containers"] if item.get("name") == "brixtest-filesystem"
    ))


def _add_unique(catalog: dict, item: Mapping[str, object], field: str) -> None:
    name = str(item[field])
    selected = copy.deepcopy(item)
    previous = catalog.get(name)
    if previous is not None and previous != selected:
        raise SpecError("Kubernetes execution group", name, "has conflicting projections")
    catalog[name] = selected


def _merged_pod(group: str, members, workloads, init_plans) -> dict:
    pods = [_pod_spec(workload) for workload in workloads]
    _validate_group(group, members, pods)
    containers = []
    volumes: dict[str, dict] = {}
    helper_mounts: dict[tuple[str, str, str], dict] = {}
    for member, pod in zip(members, pods):
        _merge_group_member(member, pod, containers, volumes, helper_mounts)
    result = _merged_pod_result(pods, containers, volumes, helper_mounts)
    _add_initializers(result, init_plans)
    return result


def _merge_group_member(member, pod, containers, volumes, helper_mounts) -> None:
    names = _volume_mapping(member.name, pod.get("volumes", ()))
    containers.append(_container(member.name, pod, names))
    for item in _renamed_volumes(pod.get("volumes", ()), names):
        _add_unique(volumes, item, "name")
    helper = _filesystem_template(pod)
    for item in helper.get("volumeMounts", ()):
        mount = _helper_mount(member.name, item, names)
        key = (mount["name"], mount["mountPath"], str(mount.get("subPath", "")))
        helper_mounts[key] = mount


def _merged_pod_result(pods, containers, volumes, helper_mounts) -> dict:
    helper = _filesystem_template(pods[0])
    helper["volumeMounts"] = list(helper_mounts.values())
    policy = {
        key: copy.deepcopy(pods[0][key]) for key in _POD_POLICY if key in pods[0]
    }
    policy.update({
        "containers": [*containers, helper], "volumes": list(volumes.values()),
        "terminationGracePeriodSeconds": _termination_grace_period(pods),
    })
    return policy


def _termination_grace_period(pods) -> int:
    return max(int(pod.get("terminationGracePeriodSeconds", 1)) for pod in pods)


def _add_initializers(pod: dict, plans: Sequence[InitPlan]) -> None:
    if not plans:
        return
    pod["initContainers"] = [copy.deepcopy(plan.container) for plan in plans]
    volumes = {item["name"]: item for item in pod.get("volumes", ())}
    for plan in plans:
        for item in plan.volumes:
            _add_unique(volumes, item, "name")
    pod["volumes"] = list(volumes.values())


def _group_workload(
    group: str, members, workloads, pod: dict,
) -> tuple[dict, Optional[dict]]:
    name = _resource_name(group)
    namespace = workloads[0]["metadata"]["namespace"]
    labels = {
        "app.kubernetes.io/name": name, "brixtest.io/case": namespace,
        "brixtest.io/group": group,
    }
    stateful = _has_stateful_member(workloads)
    spec = {
        "replicas": members[0].replicas, "selector": {"matchLabels": labels},
        "template": {"metadata": {"labels": labels}, "spec": pod},
    }
    if stateful:
        spec["serviceName"] = "%s-headless" % name
    workload = {
        "apiVersion": "apps/v1", "kind": "StatefulSet" if stateful else "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": spec,
    }
    if not stateful:
        return workload, None
    return workload, _headless_service(name, namespace, labels)


def _has_stateful_member(workloads) -> bool:
    return any(item["kind"] == "StatefulSet" for item in workloads)


def _headless_service(name: str, namespace: str, labels: dict) -> dict:
    return {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "%s-headless" % name, "namespace": namespace, "labels": labels},
        "spec": {"clusterIP": "None", "selector": labels},
    }


def _member_documents(documents, selector) -> list[dict]:
    selected = []
    for document in documents:
        if document.get("kind") in _WORKLOADS:
            continue
        value = copy.deepcopy(document)
        if value.get("kind") == "Service" and value["spec"].get("clusterIP") == "None":
            continue
        if value.get("kind") == "Service":
            value["spec"]["selector"] = dict(selector)
        if value.get("kind") == "NetworkPolicy":
            value["spec"]["podSelector"] = {"matchLabels": dict(selector)}
        selected.append(value)
    return selected


def _document_key(value) -> tuple[str, str, str]:
    metadata = value.get("metadata", {})
    return value.get("apiVersion", ""), value.get("kind", ""), metadata.get("name", "")


def _deduplicate(documents) -> tuple[dict, ...]:
    result = {}
    for document in documents:
        key = _document_key(document)
        previous = result.get(key)
        if previous is not None and previous != document:
            raise SpecError("Kubernetes execution group object", key, "has conflicting definitions")
        result[key] = document
    return tuple(result.values())


def _group_spec(members, specs, anchors) -> InstanceSpec:
    names = {member.name for member in members}
    selected = _selected_group_specs(names, specs)
    dependencies = _external_group_dependencies(names, selected, anchors)
    return selected[0].replace(
        name=members[0].name, depends_on=dependencies,
    )


def _selected_group_specs(names, specs) -> list[InstanceSpec]:
    return [specs[name] for name in names]


def _external_group_dependencies(names, selected, anchors) -> tuple[str, ...]:
    dependencies = {
        anchors.get(dependency, dependency)
        for spec in selected for dependency in spec.depends_on
        if dependency not in names
    }
    return tuple(sorted(dependencies))


def _group_anchors(groups) -> dict[str, str]:
    return {
        member.name: members[0].name
        for members in groups.values() for member in members
    }


def _ungrouped_resources(resources, grouped_names) -> dict[str, tuple[dict, ...]]:
    return {
        name: tuple(value) for name, value in resources.items()
        if name not in grouped_names
    }


def _ungrouped_launches(specs, grouped_names, anchors) -> list[InstanceSpec]:
    return [
        item.replace(depends_on=tuple(
            dict.fromkeys(anchors.get(name, name) for name in item.depends_on)
        ))
        for item in specs if item.name not in grouped_names
    ]


def _compile_group(group, members, resources, initializers):
    workloads = [_one_workload(resources[item.name], item.name) for item in members]
    selector = {"brixtest.io/group": group}
    pod = _merged_pod(group, members, workloads, initializers.get(group, ()))
    workload, headless = _group_workload(group, members, workloads, pod)
    documents = [
        document for member in members
        for document in _member_documents(resources[member.name], selector)
    ]
    documents.append(workload)
    if headless is not None:
        documents.append(headless)
    return workload, _deduplicate(documents)


def _record_group_runtime(backend, group, members, workload, workload_names, selectors) -> None:
    for member in members:
        workload_names[member.name] = _resource_name(group)
        selectors[member.name] = "brixtest.io/group=%s" % group
        backend._workload_kinds[member.name] = workload["kind"].lower()


def _grouped_names(groups) -> set[str]:
    return {member.name for members in groups.values() for member in members}


def _server_workload_names(servers) -> dict[str, str]:
    return {server.name: _resource_name(server.name) for server in servers}


def _server_workload_selectors(servers) -> dict[str, str]:
    return {
        server.name: "app.kubernetes.io/name=%s" % _resource_name(server.name)
        for server in servers
    }


def _realize_groups(
    backend, groups, resources, initializers, by_spec, anchors,
    output, launches, workload_names, selectors,
) -> None:
    for group, members in groups.items():
        workload, documents = _compile_group(group, members, resources, initializers)
        output[members[0].name] = documents
        launches.append(_group_spec(members, by_spec, anchors))
        _record_group_runtime(
            backend, group, members, workload, workload_names, selectors,
        )


def _record_group_metadata(backend, initializers, workload_names, selectors) -> None:
    backend._workload_names = workload_names
    backend._workload_selectors = selectors
    backend._grouped_init_tasks = _grouped_init_tasks(initializers)


def _grouped_init_tasks(initializers) -> dict[str, tuple[object, ...]]:
    return {
        group: tuple(plan.task for plan in plans)
        for group, plans in initializers.items()
    }


def compile_grouped_resources(backend, servers, resources, specs):
    """Merge grouped server resources and return physical launch specifications."""
    groups = _groups(servers)
    initializers = render_grouped_init_plans(backend, servers)
    by_spec = {item.name: item for item in specs}
    anchors = _group_anchors(groups)
    grouped_names = _grouped_names(groups)
    output = _ungrouped_resources(resources, grouped_names)
    launches = _ungrouped_launches(specs, grouped_names, anchors)
    workload_names = _server_workload_names(servers)
    selectors = _server_workload_selectors(servers)
    _realize_groups(
        backend, groups, resources, initializers, by_spec, anchors,
        output, launches, workload_names, selectors,
    )
    _record_group_metadata(backend, initializers, workload_names, selectors)
    return output, launches


def record_grouped_init_tasks(backend) -> None:
    """Archive successful init-container output as normal managed task evidence."""
    for group, tasks in getattr(backend, "_grouped_init_tasks", {}).items():
        anchor = _groups(backend.owner.definition.servers)[group][0].name
        target = backend._server_target(anchor)
        resource = backend._workload_resource(anchor)
        for task in tasks:
            command = backend._render_task_command(task)
            result = backend._run(
                "-n", target.namespace, "logs", resource,
                "-c", "init-%s" % task.name.replace("_", "-"), timeout=task.timeout,
                context=target.context,
            )
            completed = CommandResult(command, 0, result.stdout, result.stderr, 0.0)
            backend.owner._managed.record_external(task, completed)
            backend._archive_task_log(task, result.stdout + result.stderr)


__all__ = [
    "compile_grouped_resources", "record_grouped_init_tasks",
    "render_grouped_init_plans",
]
