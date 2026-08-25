"""Case composition and the :func:`case` decorator."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping, Optional, Sequence, Tuple, TypeVar

from brixtest._case_validation import (
    case_parameters, case_source, freeze_declaration_sequences,
    validate_case_values,
)
from brixtest._design_clients import Client, Tool
from brixtest._design_inputs import Artifact, Binary
from brixtest._design_managed import Environment, Identity, Resource, Task, Volume
from brixtest._design_servers import Server
from brixtest.errors import SpecError
from brixtest.evidence.collectors import CollectorSpec, process_tree
from brixtest.isolation import Isolation
from brixtest.isolation import process as process_isolation
from brixtest.util.immutable import freeze_mapping

if TYPE_CHECKING:
    from brixtest.auth.models import AuthRecipe
    from brixtest.credentials import Credential
    from brixtest.network import HostMapping

_Function = TypeVar("_Function", bound=Callable[..., object])
_RESOURCE_FIELDS = (
    "servers", "clients", "artifacts", "binaries", "credentials", "auth",
    "hosts", "observe", "environments", "volumes", "identities", "tasks",
    "managed_resources",
)


@dataclasses.dataclass(frozen=True)
class CaseDefinition:
    """The immutable resource and execution contract attached by ``@case``."""

    servers: Tuple[Server, ...]
    clients: Tuple[Client, ...]
    artifacts: Tuple[Artifact, ...]
    binaries: Tuple[Binary, ...]
    credentials: Tuple[Credential, ...]
    auth: Tuple[AuthRecipe, ...]
    hosts: Tuple[HostMapping, ...]
    observe: Tuple[CollectorSpec, ...]
    trials: int
    warmup: int
    timeout: float
    backend: str
    isolation: Isolation
    keep: str
    source: Path
    parameters: Mapping[str, object] = dataclasses.field(default_factory=dict)
    environments: Tuple[Environment, ...] = ()
    volumes: Tuple[Volume, ...] = ()
    identities: Tuple[Identity, ...] = ()
    tasks: Tuple[Task, ...] = ()
    managed_resources: Tuple[Resource, ...] = ()

    def __post_init__(self) -> None:
        freeze_declaration_sequences(self)
        object.__setattr__(self, "source", case_source(self.source))
        object.__setattr__(self, "parameters", case_parameters(self.parameters))
        validate_case_values(
            servers=self.servers, clients=self.clients, artifacts=self.artifacts,
            binaries=self.binaries, credentials=self.credentials, auth=self.auth,
            hosts=self.hosts, observe=self.observe, trials=self.trials,
            warmup=self.warmup, timeout=self.timeout, backend=self.backend,
            isolation=self.isolation, keep=self.keep,
            environments=self.environments, volumes=self.volumes,
            identities=self.identities, tasks=self.tasks,
            managed_resources=self.managed_resources,
        )

    @property
    def resource_names(self) -> Mapping[str, Tuple[str, ...]]:
        """Names grouped by resource kind for discovery and tooling."""
        return {
            field: tuple(item.name for item in getattr(self, field))
            for field in _RESOURCE_FIELDS
        }

    @property
    def tools(self) -> Tuple[Tool, ...]:
        """Named tool declarations, excluding compatibility-only Client values."""
        return tuple(item for item in self.clients if isinstance(item, Tool))

    def as_dict(self) -> Mapping[str, object]:
        """Return a JSON-safe, secret-free summary of the case contract."""
        return {
            "resources": {
                name: list(values) for name, values in self.resource_names.items()
            },
            "trials": self.trials, "warmup": self.warmup,
            "timeout": float(self.timeout), "backend": self.backend,
            "isolation": self.isolation.kind, "keep": self.keep,
            "source": str(self.source),
            "parameters": {
                name: _json_value(value) for name, value in self.parameters.items()
            },
        }


def _json_value(value: object) -> object:
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    return repr(value)


def _merge_resources(
    explicit: Sequence[object], inferred: Sequence[object], field: str,
) -> tuple[object, ...]:
    """Merge shorthand with explicit declarations while rejecting disagreement."""
    result = list(explicit)
    by_name = {getattr(item, "name", None): item for item in result}
    for item in inferred:
        name = getattr(item, "name", None)
        previous = by_name.get(name)
        if previous is not None:
            if previous != item:
                raise SpecError(field, name, "same name has conflicting declarations")
            continue
        result.append(item)
        by_name[name] = item
    return tuple(result)


def _resource_types() -> tuple[tuple[type, str], ...]:
    from brixtest.auth.models import AuthRecipe
    from brixtest.credentials import Credential
    from brixtest.network import HostMapping

    return (
        (Server, "servers"), (Client, "clients"), (Artifact, "artifacts"),
        (Binary, "binaries"), (Credential, "credentials"),
        (AuthRecipe, "auth"), (HostMapping, "hosts"),
        (CollectorSpec, "observe"), (Environment, "environments"),
        (Volume, "volumes"), (Identity, "identities"), (Task, "tasks"),
        (Resource, "managed_resources"),
    )


def _classify_resources(values: Sequence[object]) -> Mapping[str, tuple[object, ...]]:
    groups: dict[str, list[object]] = {field: [] for field in _RESOURCE_FIELDS}
    types = _resource_types()
    for item in values:
        selected = _resource_field(item, types)
        groups[selected].append(item)
    return freeze_mapping({name: tuple(items) for name, items in groups.items()})


def _resource_field(item: object, types) -> str:
    selected = next((field for expected, field in types if isinstance(item, expected)), "")
    if not selected:
        raise SpecError(
            "case.resources", item,
            "must contain a supported BriXTest resource declaration",
        )
    return selected


def _owner_dependencies(
    owner: object, binaries: list, artifacts: list, credentials: list, volumes: list,
) -> None:
    from brixtest.credentials import Credential

    binaries.extend(owner.binaries)
    binaries.extend(part for part in owner.command if isinstance(part, Binary))
    for declaration in owner.mounts:
        source = declaration.source
        if isinstance(source, Artifact):
            artifacts.append(source)
        elif isinstance(source, Credential):
            credentials.append(source)
        elif isinstance(source, Volume):
            volumes.append(source)


def _resource_dependencies(
    servers: Sequence[Server], clients: Sequence[Client], tasks: Sequence[Task],
) -> Mapping[str, tuple[object, ...]]:
    binaries, artifacts, credentials, volumes = [], [], [], []
    for owner in (*servers, *clients, *tasks):
        _owner_dependencies(owner, binaries, artifacts, credentials, volumes)
    artifacts.extend(
        item.artifact for item in credentials if item.artifact is not None
    )
    return freeze_mapping({
        "binaries": tuple(binaries), "artifacts": tuple(artifacts),
        "credentials": tuple(credentials), "volumes": tuple(volumes),
    })


def _merge_case_resources(explicit: dict, inferred: Mapping[str, Sequence[object]]) -> dict:
    return {
        field: _merge_resources(explicit[field], inferred[field], "case.%s" % field)
        for field in _RESOURCE_FIELDS
    }


def _merge_dependencies(values: dict) -> None:
    dependencies = _resource_dependencies(
        values["servers"], values["clients"], values["tasks"],
    )
    for field, inferred in dependencies.items():
        values[field] = _merge_resources(values[field], inferred, "case.%s" % field)


def case(
    *declared_resources: object,
    resources: Sequence[object] = (), servers: Sequence[Server] = (),
    clients: Sequence[Client] = (), artifacts: Sequence[Artifact] = (),
    binaries: Sequence[Binary] = (), credentials: Sequence[Credential] = (),
    auth: Sequence[AuthRecipe] = (), hosts: Sequence[HostMapping] = (),
    environments: Sequence[Environment] = (), volumes: Sequence[Volume] = (),
    identities: Sequence[Identity] = (), tasks: Sequence[Task] = (),
    managed_resources: Sequence[Resource] = (),
    observe: Sequence[CollectorSpec] = (process_tree(),), trials: int = 1,
    warmup: int = 0, timeout: float = 120.0, backend: str = "auto",
    isolation: Optional[Isolation] = None, keep: str = "failed",
) -> Callable[[_Function], _Function]:
    """Decorate a pytest function; positional/``resources`` values are inferred."""
    if isinstance(resources, (str, bytes)) or not isinstance(resources, Sequence):
        raise SpecError("case.resources", resources, "must be a declaration sequence")
    explicit = dict(
        servers=servers, clients=clients, artifacts=artifacts, binaries=binaries,
        credentials=credentials, auth=auth, hosts=hosts, observe=observe,
        environments=environments, volumes=volumes, identities=identities,
        tasks=tasks, managed_resources=managed_resources,
    )
    inferred = _classify_resources((*declared_resources, *tuple(resources)))
    values = _merge_case_resources(explicit, inferred)
    _merge_dependencies(values)
    policy = dict(
        trials=trials, warmup=warmup, timeout=timeout, backend=backend,
        isolation=isolation, keep=keep,
    )
    validate_case_values(**values, **policy)

    def decorate(function: _Function) -> _Function:
        definition = CaseDefinition(
            **{name: tuple(selected) for name, selected in values.items()},
            trials=trials, warmup=warmup, timeout=timeout, backend=backend,
            isolation=isolation or process_isolation(), keep=keep,
            source=Path(function.__code__.co_filename).resolve(),
        )
        function.__brixtest_case__ = definition
        return function

    return decorate


def is_case(value: object) -> bool:
    """Return whether ``value`` is decorated with :func:`case`."""
    return isinstance(getattr(value, "__brixtest_case__", None), CaseDefinition)


def get_case(value: object) -> CaseDefinition:
    """Return a decorated function's contract with a structured error."""
    definition = getattr(value, "__brixtest_case__", None)
    if not isinstance(definition, CaseDefinition):
        raise SpecError("case function", value, "must be decorated with @brixtest.case")
    return definition


__all__ = ["CaseDefinition", "case", "get_case", "is_case"]
