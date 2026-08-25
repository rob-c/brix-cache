"""Validation for immutable case composition, references, and lifetimes."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import Mapping, Optional, Sequence

from brixtest._design_clients import Client
from brixtest._design_inputs import Artifact, Binary
from brixtest._design_managed import Environment, Identity, Resource, Task, Volume
from brixtest._design_servers import Server
from brixtest.errors import SpecError
from brixtest._environment_transport import environment_transportable
from brixtest.evidence.collectors import CollectorSpec
from brixtest.isolation import Isolation
from brixtest.resources import Reference
from brixtest.util.immutable import freeze_mapping

_PLACEHOLDER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_BACKENDS = frozenset({"auto", "local", "kubernetes", "minikube"})
_SEQUENCE_FIELDS = (
    "servers", "clients", "artifacts", "binaries", "credentials", "auth",
    "hosts", "observe", "environments", "volumes", "identities", "tasks",
    "managed_resources",
)


def freeze_declaration_sequences(definition: object) -> None:
    for field in _SEQUENCE_FIELDS:
        values = getattr(definition, field)
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise SpecError("case.%s" % field, values, "must be a declaration sequence")
        object.__setattr__(definition, field, tuple(values))


def case_source(value: object) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise SpecError("case.source", value, "must be a source file path")
    return Path(value).resolve()


def case_parameters(value: object) -> Mapping[str, object]:
    valid = isinstance(value, Mapping) and all(
        isinstance(name, str) and _PLACEHOLDER_NAME.fullmatch(name) for name in value
    )
    if not valid:
        raise SpecError(
            "case.parameters", value,
            "must map valid pytest parameter names to values",
        )
    return freeze_mapping(value)


def _duplicates(values: Sequence[str]) -> list[str]:
    return sorted({value for value in values if values.count(value) > 1})


def _unique(items: Sequence[object], label: str) -> None:
    duplicates = _duplicates([item.name for item in items])
    if duplicates:
        raise SpecError(label, ", ".join(duplicates), "names must be unique in a case")


def _positive_number(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value > 0


def _integer_at_least(value: object, minimum: int) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= minimum


def _validate_attempts(trials: int, warmup: int, timeout: float) -> None:
    if not _positive_number(timeout):
        raise SpecError("case.timeout", timeout, "must be > 0")
    if not _integer_at_least(trials, 1):
        raise SpecError("case.trials", trials, "must be an integer >= 1")
    if not _integer_at_least(warmup, 0):
        raise SpecError("case.warmup", warmup, "must be an integer >= 0")
    if trials + warmup > 1000:
        raise SpecError("case attempts", trials + warmup, "must not exceed 1000")


def _validate_policy(
    *, trials: int, warmup: int, timeout: float, backend: object,
    isolation: object, keep: object,
) -> None:
    _validate_attempts(trials, warmup, timeout)
    if not _valid_backend(backend):
        raise SpecError(
            "case.backend", backend,
            "must be auto, local, kubernetes, minikube, or a registered backend name",
        )
    _validate_isolation(isolation)
    _validate_keep(keep)


def _valid_backend(value: object) -> bool:
    return isinstance(value, str) and (
        value in _BACKENDS or _NAME.fullmatch(value) is not None
    )


def _validate_isolation(value: object) -> None:
    if value is not None and not isinstance(value, Isolation):
        raise SpecError("case.isolation", value, "must be an Isolation declaration")


def _validate_keep(value: object) -> None:
    if not isinstance(value, str) or value not in ("never", "failed", "always"):
        raise SpecError("case.keep", value, "must be never, failed, or always")


def _validate_groups(groups: Sequence[tuple[object, type, str]]) -> None:
    for values, expected, field in groups:
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise SpecError(field, values, "must be a declaration sequence")
        if not all(isinstance(item, expected) for item in values):
            raise SpecError(field, values, "contains an invalid declaration")


def _validate_credentials(
    credentials: Sequence[object], artifacts: Sequence[Artifact],
) -> None:
    artifact_names = {item.name for item in artifacts}
    for declaration in credentials:
        selected = declaration.artifact
        if selected is not None and selected.name not in artifact_names:
            raise SpecError(
                "credential %s artifact" % declaration.name, selected.name,
                "must be declared by the same case",
            )


def _validate_hosts(hosts: Sequence[object]) -> None:
    _reject_duplicates(
        [hostname for item in hosts for hostname in item.hostnames],
        "hostnames and aliases must be unique",
    )
    _reject_duplicates(
        [mapping.address for mapping in hosts if mapping.reverse],
        "reverse-enabled addresses must be unique",
    )


def _reject_duplicates(values: Sequence[str], rule: str) -> None:
    duplicates = _duplicates(values)
    if duplicates:
        raise SpecError("case.hosts", duplicates, rule)


def _validate_server_dependencies(
    servers: Sequence[Server], tasks: Sequence[Task], resources: Sequence[Resource],
) -> None:
    names, scopes = _server_dependency_catalogs(servers, tasks, resources)
    for declaration in servers:
        _validate_server_probe(declaration)
        _validate_server_dependency_names(declaration, names)
        _validate_dependency_scopes(declaration, scopes)


def _server_dependency_catalogs(servers, tasks, resources):
    names = {item.name for values in (servers, tasks, resources) for item in values}
    scopes = {item.name: item.scope for item in servers}
    return names, scopes


def _validate_server_dependency_names(declaration: Server, names: set[str]) -> None:
    missing = sorted(set(declaration.depends_on) - names)
    if missing:
        raise SpecError(
            "server %s depends_on" % declaration.name, ", ".join(missing),
            "dependencies must be servers, tasks, or resources declared by the same case",
        )


def _validate_server_probe(declaration: Server) -> None:
    selected = declaration.probe
    if selected.kind != "none" and selected.endpoint not in declaration.ports:
        raise SpecError(
            "server %s readiness.port" % declaration.name, selected.endpoint,
            "must name a declared endpoint",
        )


def _validate_dependency_scopes(
    declaration: Server, scopes: Mapping[str, str],
) -> None:
    if declaration.scope not in ("class", "module", "package", "session"):
        return
    _reject_non_server_dependencies(declaration, scopes)
    _reject_shorter_dependencies(declaration, scopes)


def _reject_non_server_dependencies(declaration: Server, scopes) -> None:
    values = sorted(name for name in declaration.depends_on if name not in scopes)
    if values:
        raise SpecError(
            "server %s depends_on" % declaration.name, ", ".join(values),
            "a shared server can depend only on servers with the same lifetime",
        )


def _reject_shorter_dependencies(declaration: Server, scopes) -> None:
    values = sorted(name for name in declaration.depends_on if scopes[name] != declaration.scope)
    if values:
        raise SpecError(
            "server %s depends_on" % declaration.name, ", ".join(values),
            "a %s server can only depend on servers with the same scope" % declaration.scope,
        )


def _owner_kind(owner: object) -> str:
    return str(getattr(owner, "resource_kind", "server"))


def _validate_placement(owner: object, environments: set[str], identities: set[str]) -> None:
    placement = owner.placement
    if placement.environment and placement.environment not in environments:
        raise SpecError(
            "%s %s placement.environment" % (_owner_kind(owner), owner.name),
            placement.environment, "must name an environment declared by the same case",
        )
    if placement.identity and placement.identity not in identities:
        raise SpecError(
            "%s %s placement.identity" % (_owner_kind(owner), owner.name),
            placement.identity, "must name an identity declared by the same case",
        )


def _validate_owner_mounts(owner: object, volume_names: set[str]) -> None:
    for declared_mount in owner.mounts:
        source = declared_mount.source
        if isinstance(source, Volume) and source.name not in volume_names:
            raise SpecError(
                "%s %s mount" % (_owner_kind(owner), owner.name), source.name,
                "volume must be declared by the same case",
            )


def _validate_managed_references(
    servers: Sequence[Server], clients: Sequence[Client],
    environments: Sequence[Environment], volumes: Sequence[Volume],
    identities: Sequence[Identity], tasks: Sequence[Task],
    managed_resources: Sequence[Resource],
) -> None:
    _validate_owners(
        (*servers, *clients, *tasks), environments, identities, volumes,
    )
    dependency_names = _dependency_names(servers, tasks, managed_resources)
    for owner in (*tasks, *managed_resources):
        _validate_managed_dependencies(owner, dependency_names)


def _validate_owners(owners, environments, identities, volumes) -> None:
    environment_names = _names(environments)
    identity_names = _names(identities)
    volume_names = _names(volumes)
    for owner in owners:
        _validate_placement(owner, environment_names, identity_names)
        _validate_owner_mounts(owner, volume_names)


def _names(values) -> set[str]:
    return {item.name for item in values}


def _dependency_names(servers, tasks, resources) -> set[str]:
    return {item.name for values in (servers, tasks, resources) for item in values}


def _validate_managed_dependencies(owner, known: set[str]) -> None:
    missing = sorted(set(owner.depends_on) - known)
    if missing:
        raise SpecError(
            "%s %s depends_on" % (owner.resource_kind, owner.name), missing,
            "dependencies must be declared by the same case",
        )


def _validate_output_producer(
    field: str, reference: Reference, producers: Mapping[str, Task],
) -> None:
    producer = producers.get(reference.name)
    if producer is None or reference.role not in getattr(producer, "outputs", {}):
        raise SpecError(field, reference, "must name a declared task output")
    if producer.phase == "finalize":
        raise SpecError(field, reference, "cannot consume a finalization task output")


def _deferred_artifact_names(artifacts: Sequence[Artifact]) -> set[str]:
    return {
        item.name for item in artifacts
        if isinstance(item.source, Reference) and item.source.kind == "task"
    }


def _validate_credential_inputs(
    credentials: Sequence[object], deferred_artifacts: set[str],
) -> None:
    selected = sorted(
        item.artifact.name for item in credentials
        if item.artifact is not None and item.artifact.name in deferred_artifacts
    )
    if selected:
        raise SpecError(
            "credential artifacts", selected,
            "must be available before managed tasks and cannot be task outputs",
        )


def _validate_task_consumers(
    tasks: Sequence[Task], binaries: Sequence[Binary], deferred_artifacts: set[str],
) -> None:
    deferred_binaries = {
        item.name for item in binaries
        if isinstance(item.path, Reference) and item.path.kind == "task"
    }
    for task_value in tasks:
        if _task_uses_deferred_input(
            task_value, deferred_binaries, deferred_artifacts,
        ):
            raise SpecError(
                "task %s inputs" % task_value.name, task_value.name,
                "tasks should consume producer.output() directly; deferred input capture is for later workloads",
            )


def _task_uses_deferred_input(task_value, binaries: set[str], artifacts: set[str]) -> bool:
    used_binaries = {
        item.name for item in (*task_value.binaries, *task_value.command)
        if isinstance(item, Binary)
    }
    mounted_artifacts = {
        getattr(item.source, "name", "") for item in task_value.mounts
    }
    return bool(used_binaries & binaries or mounted_artifacts & artifacts)


def _validate_task_output_inputs(
    binaries: Sequence[Binary], artifacts: Sequence[Artifact],
    credentials: Sequence[object], tasks: Sequence[Task],
) -> None:
    producers = {task.name: task for task in tasks}
    _validate_generated_inputs(binaries, artifacts, producers)
    deferred_artifacts = _deferred_artifact_names(artifacts)
    _validate_credential_inputs(credentials, deferred_artifacts)
    _validate_task_consumers(tasks, binaries, deferred_artifacts)


def _validate_generated_inputs(binaries, artifacts, producers) -> None:
    inputs = [
        *[("binary %s path" % item.name, item.path) for item in binaries],
        *[("artifact %s source" % item.name, item.source) for item in artifacts],
    ]
    for field, value in inputs:
        if isinstance(value, Reference) and value.kind == "task":
            _validate_output_producer(field, value, producers)


def _references(value: object) -> tuple[Reference, ...]:
    found = []
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, Reference):
            found.append(item)
        elif dataclasses.is_dataclass(item):
            pending.extend(getattr(item, field.name) for field in dataclasses.fields(item))
        elif isinstance(item, Mapping):
            pending.extend(item.values())
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
            pending.extend(item)
    return tuple(found)


def _reference_catalog(**groups: Sequence[object]) -> Mapping[str, Mapping[str, object]]:
    return {
        kind: {item.name: item for item in values}
        for kind, values in groups.items()
    }


def _validate_reference_target(
    owner: object, reference: Reference, catalog: Mapping[str, Mapping[str, object]],
) -> None:
    if reference.kind in ("run", "workspace", "config", "mount", "parameter"):
        return
    declared = catalog.get(reference.kind, {})
    if reference.name not in declared:
        raise SpecError(
            "%s %s reference" % (_owner_kind(owner), owner.name), reference,
            "must name a resource declared by the same case",
        )
    target = declared[reference.name]
    if reference.kind == "task" and reference.role not in target.outputs:
        raise SpecError(
            "%s %s reference" % (_owner_kind(owner), owner.name), reference,
            "must name a declared task output",
        )
    if reference.kind == "server" and reference.role:
        roles = {item.name for item in target.endpoints}
        if reference.role not in roles:
            raise SpecError(
                "%s %s reference" % (_owner_kind(owner), owner.name), reference,
                "must name a declared server endpoint",
            )


def _validate_reference_environment(owner: object, reference: Reference, catalog) -> None:
    if reference.kind != "server":
        return
    target = catalog[reference.kind][reference.name]
    source = owner.placement.environment or "default"
    destination = target.placement.environment or "default"
    if not environment_transportable(
        source, destination, catalog.get("environment", {}),
    ):
        raise SpecError(
            "%s %s reference" % (_owner_kind(owner), owner.name), reference,
            "cannot cross execution contexts without a managed transport",
        )


def _validate_declared_references(
    *, servers, clients, artifacts, binaries, credentials, environments,
    identities, tasks, managed_resources, volumes,
) -> None:
    catalog = _reference_catalog(
        server=servers, artifact=artifacts, binary=binaries,
        credential=credentials, environment=environments, identity=identities,
        task=tasks, resource=managed_resources, volume=volumes,
    )
    for owner in (*servers, *clients, *tasks):
        for reference in _references(owner):
            _validate_reference_target(owner, reference, catalog)
            _validate_reference_environment(owner, reference, catalog)


def validate_case_values(
    *, servers: Sequence[Server], clients: Sequence[Client],
    artifacts: Sequence[Artifact], binaries: Sequence[Binary],
    credentials: Sequence[object], auth: Sequence[object], hosts: Sequence[object],
    observe: Sequence[CollectorSpec], trials: int, warmup: int, timeout: float,
    backend: str, isolation: Optional[Isolation], keep: str,
    environments: Sequence[Environment], volumes: Sequence[Volume],
    identities: Sequence[Identity], tasks: Sequence[Task],
    managed_resources: Sequence[Resource],
) -> None:
    from brixtest.auth.models import AuthRecipe
    from brixtest.credentials import Credential
    from brixtest.network import HostMapping

    _validate_policy(
        trials=trials, warmup=warmup, timeout=timeout, backend=backend,
        isolation=isolation, keep=keep,
    )
    groups = (
        (servers, Server, "case.servers"), (clients, Client, "case.clients"),
        (artifacts, Artifact, "case.artifacts"), (binaries, Binary, "case.binaries"),
        (credentials, Credential, "case.credentials"), (auth, AuthRecipe, "case.auth"),
        (hosts, HostMapping, "case.hosts"), (observe, CollectorSpec, "case.observe"),
        (environments, Environment, "case.environments"),
        (volumes, Volume, "case.volumes"), (identities, Identity, "case.identities"),
        (tasks, Task, "case.tasks"),
        (managed_resources, Resource, "case.managed_resources"),
    )
    _validate_groups(groups)
    if _duplicates([item.name for item in observe]):
        raise SpecError("case.observe", "duplicate", "collector names must be unique")
    for values, field in ((items, field) for items, _kind, field in groups):
        _unique(values, field)
    _validate_credentials(credentials, artifacts)
    _validate_hosts(hosts)
    _validate_server_dependencies(servers, tasks, managed_resources)
    _validate_managed_references(
        servers, clients, environments, volumes, identities, tasks, managed_resources,
    )
    _validate_task_output_inputs(binaries, artifacts, credentials, tasks)
    _validate_declared_references(
        servers=servers, clients=clients, artifacts=artifacts, binaries=binaries,
        credentials=credentials, environments=environments, identities=identities,
        tasks=tasks, managed_resources=managed_resources, volumes=volumes,
    )


__all__ = [
    "case_parameters", "case_source", "freeze_declaration_sequences",
    "validate_case_values",
]
