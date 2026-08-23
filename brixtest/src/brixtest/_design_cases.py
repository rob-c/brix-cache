"""Case composition and the ``case`` decorator."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping, Optional, Sequence, Tuple, TypeVar

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

_PLACEHOLDER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_BACKENDS = frozenset({"auto", "local", "kubernetes", "minikube"})
_Function = TypeVar("_Function", bound=Callable[..., object])


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
        _freeze_declaration_sequences(self)
        object.__setattr__(self, "source", _case_source(self.source))
        object.__setattr__(self, "parameters", _case_parameters(self.parameters))
        _validate_case_values(
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
            for field in (
                "servers", "clients", "artifacts", "binaries", "credentials",
                "auth", "hosts", "observe", "environments", "volumes",
                "identities", "tasks", "managed_resources",
            )
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
                name: value if isinstance(value, (str, int, float, bool, type(None)))
                else repr(value)
                for name, value in self.parameters.items()
            },
        }


def _freeze_declaration_sequences(definition: CaseDefinition) -> None:
    for field in (
        "servers", "clients", "artifacts", "binaries", "credentials",
        "auth", "hosts", "observe", "environments", "volumes", "identities",
        "tasks", "managed_resources",
    ):
        values = getattr(definition, field)
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise SpecError("case.%s" % field, values, "must be a declaration sequence")
        object.__setattr__(definition, field, tuple(values))


def _case_source(value: object) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise SpecError("case.source", value, "must be a source file path")
    return Path(value).resolve()


def _case_parameters(value: object) -> Mapping[str, object]:
    valid = isinstance(value, Mapping) and all(
        isinstance(name, str) and _PLACEHOLDER_NAME.fullmatch(name)
        for name in value
    )
    if not valid:
        raise SpecError(
            "case.parameters", value,
            "must map valid pytest parameter names to values",
        )
    return freeze_mapping(value)


def _unique(items: Sequence[object], label: str) -> None:
    names = [item.name for item in items]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SpecError(label, ", ".join(duplicates), "names must be unique in a case")


def _validate_case_attempts(trials: int, warmup: int, timeout: float) -> None:
    if not _positive_number(timeout):
        raise SpecError("case.timeout", timeout, "must be > 0")
    if not _integer_at_least(trials, 1):
        raise SpecError("case.trials", trials, "must be an integer >= 1")
    if not _integer_at_least(warmup, 0):
        raise SpecError("case.warmup", warmup, "must be an integer >= 0")
    if trials + warmup > 1000:
        raise SpecError("case attempts", trials + warmup, "must not exceed 1000")


def _positive_number(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value > 0


def _integer_at_least(value: object, minimum: int) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= minimum


def _validate_case_policy(
    *, trials: int, warmup: int, timeout: float, backend: str,
    isolation: Optional[Isolation], keep: str,
) -> None:
    _validate_case_attempts(trials, warmup, timeout)
    _validate_backend(backend)
    _validate_isolation(isolation)
    _validate_keep(keep)


def _validate_backend(backend: object) -> None:
    valid_backend = isinstance(backend, str) and (
        backend in _BACKENDS or _NAME.fullmatch(backend) is not None
    )
    if not valid_backend:
        raise SpecError(
            "case.backend", backend,
            "must be auto, local, kubernetes, minikube, or a registered backend name",
        )


def _validate_isolation(isolation: object) -> None:
    if isolation is not None and not isinstance(isolation, Isolation):
        raise SpecError("case.isolation", isolation, "must be an Isolation declaration")


def _validate_keep(keep: object) -> None:
    if not isinstance(keep, str) or keep not in ("never", "failed", "always"):
        raise SpecError("case.keep", keep, "must be never, failed, or always")


def _validate_declaration_groups(groups: Sequence[tuple[object, type, str]]) -> None:
    for values, expected, field in groups:
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise SpecError(field, values, "must be a declaration sequence")
        if not all(isinstance(item, expected) for item in values):
            raise SpecError(field, values, "contains an invalid declaration")


def _validate_case_credentials(
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


def _duplicates(values: Sequence[str]) -> list[str]:
    return sorted({value for value in values if values.count(value) > 1})


def _validate_case_hosts(hosts: Sequence[object]) -> None:
    hostnames = [hostname for item in hosts for hostname in item.hostnames]
    _validate_hostnames(hostnames)
    addresses = [mapping.address for mapping in hosts if mapping.reverse]
    _validate_reverse_addresses(addresses)


def _validate_hostnames(hostnames: Sequence[str]) -> None:
    duplicates = _duplicates(hostnames)
    if duplicates:
        raise SpecError("case.hosts", duplicates, "hostnames and aliases must be unique")


def _validate_reverse_addresses(addresses: Sequence[str]) -> None:
    duplicates = _duplicates(addresses)
    if duplicates:
        raise SpecError("case.hosts", duplicates, "reverse-enabled addresses must be unique")


def _validate_server_dependencies(
    servers: Sequence[Server], tasks: Sequence[Task], resources: Sequence[Resource],
) -> None:
    names = {
        *(item.name for item in servers), *(item.name for item in tasks),
        *(item.name for item in resources),
    }
    scopes = {item.name: item.scope for item in servers}
    for declaration in servers:
        _validate_server_probe(declaration)
        _validate_dependency_names(declaration, names)
        _validate_dependency_scopes(declaration, scopes)


def _validate_server_probe(declaration: Server) -> None:
    probe = declaration.probe
    if probe.kind != "none" and probe.endpoint not in declaration.ports:
        raise SpecError(
            "server %s readiness.port" % declaration.name, probe.endpoint,
            "must name a declared endpoint",
        )


def _validate_dependency_names(declaration: Server, names: set[str]) -> None:
    missing = sorted(set(declaration.depends_on) - names)
    if missing:
        raise SpecError(
            "server %s depends_on" % declaration.name, ", ".join(missing),
            "dependencies must be servers, tasks, or resources declared by the same case",
        )


def _validate_dependency_scopes(
    declaration: Server, scopes: Mapping[str, str],
) -> None:
    if declaration.scope not in ("class", "module", "package", "session"):
        return
    non_servers = sorted(name for name in declaration.depends_on if name not in scopes)
    if non_servers:
        raise SpecError(
            "server %s depends_on" % declaration.name, ", ".join(non_servers),
            "a shared server can depend only on servers with the same lifetime",
        )
    shorter = sorted(
        name for name in declaration.depends_on if scopes[name] != declaration.scope
    )
    if shorter:
        raise SpecError(
            "server %s depends_on" % declaration.name, ", ".join(shorter),
            "a %s server can only depend on servers with the same scope" % declaration.scope,
        )


def _validate_case_values(
    *, servers: Sequence[Server], clients: Sequence[Client],
    artifacts: Sequence[Artifact], binaries: Sequence[Binary],
    credentials: Sequence[Credential], auth: Sequence[AuthRecipe],
    hosts: Sequence[HostMapping], observe: Sequence[CollectorSpec],
    trials: int, warmup: int, timeout: float, backend: str,
    isolation: Optional[Isolation], keep: str,
    environments: Sequence[Environment], volumes: Sequence[Volume],
    identities: Sequence[Identity], tasks: Sequence[Task],
    managed_resources: Sequence[Resource],
) -> None:
    from brixtest.auth.models import AuthRecipe
    from brixtest.credentials import Credential
    from brixtest.network import HostMapping

    _validate_case_policy(
        trials=trials, warmup=warmup, timeout=timeout, backend=backend,
        isolation=isolation, keep=keep,
    )
    groups = (
        (servers, Server, "case.servers"), (clients, Client, "case.clients"),
        (artifacts, Artifact, "case.artifacts"), (binaries, Binary, "case.binaries"),
        (credentials, Credential, "case.credentials"), (auth, AuthRecipe, "case.auth"),
        (hosts, HostMapping, "case.hosts"), (observe, CollectorSpec, "case.observe"),
        (environments, Environment, "case.environments"),
        (volumes, Volume, "case.volumes"),
        (identities, Identity, "case.identities"),
        (tasks, Task, "case.tasks"),
        (managed_resources, Resource, "case.managed_resources"),
    )
    _validate_declaration_groups(groups)
    duplicates = _duplicates([item.name for item in observe])
    if duplicates:
        raise SpecError("case.observe", duplicates, "collector names must be unique")
    for values, field in (
        (servers, "case.servers"), (clients, "case.clients"),
        (artifacts, "case.artifacts"), (binaries, "case.binaries"),
        (credentials, "case.credentials"), (auth, "case.auth"), (hosts, "case.hosts"),
        (environments, "case.environments"), (volumes, "case.volumes"),
        (identities, "case.identities"), (tasks, "case.tasks"),
        (managed_resources, "case.managed_resources"),
    ):
        _unique(values, field)
    _validate_case_credentials(credentials, artifacts)
    _validate_case_hosts(hosts)
    _validate_server_dependencies(servers, tasks, managed_resources)
    _validate_managed_references(
        servers, clients, environments, volumes, identities, tasks, managed_resources,
    )


def _validate_managed_references(
    servers: Sequence[Server], clients: Sequence[Client],
    environments: Sequence[Environment], volumes: Sequence[Volume],
    identities: Sequence[Identity], tasks: Sequence[Task],
    managed_resources: Sequence[Resource],
) -> None:
    environment_names = {item.name for item in environments}
    identity_names = {item.name for item in identities}
    volume_names = {item.name for item in volumes}
    dependency_names = {
        *(item.name for item in servers), *(item.name for item in tasks),
        *(item.name for item in managed_resources),
    }
    for owner in (*servers, *clients, *tasks):
        _validate_placement_reference(owner, environment_names, identity_names)
        for declared_mount in owner.mounts:
            if isinstance(declared_mount.source, Volume) and declared_mount.source.name not in volume_names:
                raise SpecError(
                    "%s %s mount" % (_owner_kind(owner), owner.name),
                    declared_mount.source.name, "volume must be declared by the same case",
                )
    for owner in (*tasks, *managed_resources):
        missing = sorted(set(owner.depends_on) - dependency_names)
        if missing:
            raise SpecError(
                "%s %s depends_on" % (owner.resource_kind, owner.name), missing,
                "dependencies must be declared by the same case",
            )


def _validate_placement_reference(owner, environments: set[str], identities: set[str]) -> None:
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


def _owner_kind(owner: object) -> str:
    return str(getattr(owner, "resource_kind", "server"))


def _merge_resources(
    explicit: Sequence[object], inferred: Sequence[object], field: str,
) -> tuple[object, ...]:
    """Merge resource shorthand with explicit lists while rejecting disagreement."""
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


def _classify_resources(values: Sequence[object]) -> Mapping[str, tuple[object, ...]]:
    from brixtest.auth.models import AuthRecipe
    from brixtest.credentials import Credential
    from brixtest.network import HostMapping

    groups: dict[str, list[object]] = {
        "servers": [], "clients": [], "artifacts": [], "binaries": [],
        "credentials": [], "auth": [], "hosts": [], "observe": [],
        "environments": [], "volumes": [], "identities": [], "tasks": [],
        "managed_resources": [],
    }
    types = (
        (Server, "servers"), (Client, "clients"), (Artifact, "artifacts"),
        (Binary, "binaries"), (Credential, "credentials"),
        (AuthRecipe, "auth"), (HostMapping, "hosts"),
        (CollectorSpec, "observe"),
        (Environment, "environments"), (Volume, "volumes"),
        (Identity, "identities"), (Task, "tasks"),
        (Resource, "managed_resources"),
    )
    for item in values:
        for expected, field in types:
            if isinstance(item, expected):
                groups[field].append(item)
                break
        else:
            raise SpecError(
                "case.resources", item,
                "must contain a supported BriXTest resource declaration",
            )
    return freeze_mapping({name: tuple(items) for name, items in groups.items()})


def _resource_dependencies(
    servers: Sequence[Server], clients: Sequence[Client], tasks: Sequence[Task],
) -> Mapping[str, tuple[object, ...]]:
    from brixtest.credentials import Credential

    binaries: list[Binary] = []
    artifacts: list[Artifact] = []
    credentials: list[Credential] = []
    volumes: list[Volume] = []
    for owner in (*servers, *clients, *tasks):
        _owner_dependencies(owner, binaries, artifacts, credentials, volumes)
    artifacts.extend(_credential_artifacts(credentials))
    return freeze_mapping({
        "binaries": tuple(binaries), "artifacts": tuple(artifacts),
        "credentials": tuple(credentials), "volumes": tuple(volumes),
    })


def _owner_dependencies(
    owner, binaries: list, artifacts: list, credentials: list, volumes: list,
) -> None:
    from brixtest.credentials import Credential

    binaries.extend(owner.binaries)
    binaries.extend(part for part in owner.command if isinstance(part, Binary))
    for declared_mount in owner.mounts:
        source = declared_mount.source
        if isinstance(source, Artifact):
            artifacts.append(source)
        elif isinstance(source, Credential):
            credentials.append(source)
        elif isinstance(source, Volume):
            volumes.append(source)


def _credential_artifacts(credentials: Sequence[object]) -> list[Artifact]:
    return [item.artifact for item in credentials if item.artifact is not None]


def case(
    *declared_resources: object,
    resources: Sequence[object] = (),
    servers: Sequence[Server] = (),
    clients: Sequence[Client] = (),
    artifacts: Sequence[Artifact] = (),
    binaries: Sequence[Binary] = (),
    credentials: Sequence[Credential] = (),
    auth: Sequence[AuthRecipe] = (),
    hosts: Sequence[HostMapping] = (),
    environments: Sequence[Environment] = (),
    volumes: Sequence[Volume] = (),
    identities: Sequence[Identity] = (),
    tasks: Sequence[Task] = (),
    managed_resources: Sequence[Resource] = (),
    observe: Sequence[CollectorSpec] = (process_tree(),),
    trials: int = 1,
    warmup: int = 0,
    timeout: float = 120.0,
    backend: str = "auto",
    isolation: Optional[Isolation] = None,
    keep: str = "failed",
) -> Callable[[_Function], _Function]:
    """Decorate a pytest function; positional/``resources`` values are inferred."""
    if isinstance(resources, (str, bytes)) or not isinstance(resources, Sequence):
        raise SpecError("case.resources", resources, "must be a declaration sequence")
    inferred = _classify_resources((*declared_resources, *tuple(resources)))
    servers = _merge_resources(servers, inferred["servers"], "case.servers")
    clients = _merge_resources(clients, inferred["clients"], "case.clients")
    artifacts = _merge_resources(artifacts, inferred["artifacts"], "case.artifacts")
    binaries = _merge_resources(binaries, inferred["binaries"], "case.binaries")
    credentials = _merge_resources(
        credentials, inferred["credentials"], "case.credentials"
    )
    auth = _merge_resources(auth, inferred["auth"], "case.auth")
    hosts = _merge_resources(hosts, inferred["hosts"], "case.hosts")
    environments = _merge_resources(
        environments, inferred["environments"], "case.environments",
    )
    volumes = _merge_resources(volumes, inferred["volumes"], "case.volumes")
    identities = _merge_resources(
        identities, inferred["identities"], "case.identities",
    )
    tasks = _merge_resources(tasks, inferred["tasks"], "case.tasks")
    managed_resources = _merge_resources(
        managed_resources, inferred["managed_resources"], "case.managed_resources",
    )
    observe = _merge_resources(observe, inferred["observe"], "case.observe")
    dependencies = _resource_dependencies(servers, clients, tasks)
    binaries = _merge_resources(binaries, dependencies["binaries"], "case.binaries")
    artifacts = _merge_resources(artifacts, dependencies["artifacts"], "case.artifacts")
    credentials = _merge_resources(
        credentials, dependencies["credentials"], "case.credentials"
    )
    volumes = _merge_resources(volumes, dependencies["volumes"], "case.volumes")
    _validate_case_values(
        servers=servers, clients=clients, artifacts=artifacts, binaries=binaries,
        credentials=credentials, auth=auth, hosts=hosts, observe=observe,
        trials=trials, warmup=warmup, timeout=timeout, backend=backend,
        isolation=isolation, keep=keep,
        environments=environments, volumes=volumes, identities=identities,
        tasks=tasks, managed_resources=managed_resources,
    )

    def decorate(function: _Function) -> _Function:
        source = Path(function.__code__.co_filename).resolve()
        definition = CaseDefinition(
            servers=tuple(servers), clients=tuple(clients), artifacts=tuple(artifacts),
            binaries=tuple(binaries), credentials=tuple(credentials), auth=tuple(auth),
            hosts=tuple(hosts), observe=tuple(observe), trials=trials, warmup=warmup,
            timeout=timeout, backend=backend,
            isolation=isolation or process_isolation(), keep=keep, source=source,
            environments=tuple(environments), volumes=tuple(volumes),
            identities=tuple(identities), tasks=tuple(tasks),
            managed_resources=tuple(managed_resources),
        )
        function.__brixtest_case__ = definition
        return function

    return decorate


def is_case(value: object) -> bool:
    """Return whether ``value`` is a function decorated with :func:`case`."""
    return isinstance(getattr(value, "__brixtest_case__", None), CaseDefinition)


def get_case(value: object) -> CaseDefinition:
    """Return a decorated function's case contract with a structured error."""
    definition = getattr(value, "__brixtest_case__", None)
    if not isinstance(definition, CaseDefinition):
        raise SpecError("case function", value, "must be decorated with @brixtest.case")
    return definition
