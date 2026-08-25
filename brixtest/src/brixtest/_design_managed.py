"""Backend-neutral declarations for managed execution infrastructure."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Mapping, Optional, Sequence, Union

from brixtest._design_inputs import Binary, _argv, _name, _string_mapping
from brixtest.errors import SpecError
from brixtest.resources import Mount, Placement, Reference
from brixtest.util.immutable import freeze_mapping

_FAMILIES = ("any", "ipv4", "ipv6", "dual")
_VOLUME_KINDS = ("tmp", "persistent", "shared", "host", "device", "provider")
_ACCESS_MODES = ("read-write-once", "read-write-many", "read-only-many")
_TASK_PHASES = ("prepare", "init", "finalize")


def _text(value: object, field: str, *, empty: bool = True) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise SpecError(field, value, "must be text%s" % ("" if empty else " and non-empty"))
    return value


def _options(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(name, str) and bool(name) for name in value
    ):
        raise SpecError(field, value, "must map non-empty option names to immutable values")
    return freeze_mapping(value)


def _names(values: object, field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise SpecError(field, values, "must be a name sequence")
    selected = tuple(values)
    for value in selected:
        _name(value, field)
    if len(set(selected)) != len(selected):
        raise SpecError(field, selected, "must not contain duplicates")
    return selected


def _optional_id(value: object, field: str) -> Optional[int]:
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or value < 0
    ):
        raise SpecError(field, value, "must be a non-negative integer or None")
    return value


def _id_map(value: object, field: str) -> tuple[tuple[int, int, int], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError(field, value, "must contain (inside, outside, count) rows")
    rows = tuple(tuple(row) for row in value)
    if not all(_valid_id_map_row(row) for row in rows):
        raise SpecError(field, rows, "must contain non-negative IDs and positive counts")
    _validate_id_map_ranges(rows, field)
    return rows


def _validate_id_map_ranges(rows: tuple[tuple[int, int, int], ...], field: str) -> None:
    for position, label in ((0, "inside"), (1, "outside")):
        ranges = sorted((row[position], row[position] + row[2]) for row in rows)
        if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
            raise SpecError(field, rows, "%s ID ranges must not overlap" % label)


def _valid_id_map_row(row: tuple[object, ...]) -> bool:
    if len(row) != 3:
        return False
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in row):
        return False
    return row[0] >= 0 and row[1] >= 0 and row[2] > 0


def _permissions(value: object) -> Mapping[str, tuple[str, ...]]:
    if not isinstance(value, Mapping):
        raise SpecError("identity.permissions", value, "must map resources to verbs")
    selected = {}
    for resource, verbs in value.items():
        _text(resource, "identity permission resource", empty=False)
        selected[resource] = _names(verbs, "identity permission verbs")
    return freeze_mapping(selected)


@dataclasses.dataclass(frozen=True)
class Environment:
    """One addressable execution realm selected by a placement policy."""

    name: str
    backend: str = "inherit"
    context: str = ""
    namespace: str = ""
    family: str = "any"
    dns_domain: str = ""
    isolated: bool = True
    options: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        _name(self.name, "environment.name")
        _name(self.backend, "environment.backend")
        _text(self.context, "environment.context")
        _text(self.namespace, "environment.namespace")
        if self.family not in _FAMILIES:
            raise SpecError("environment.family", self.family, "must be any, ipv4, ipv6, or dual")
        _text(self.dns_domain, "environment.dns_domain")
        if not isinstance(self.isolated, bool):
            raise SpecError("environment.isolated", self.isolated, "must be true or false")
        object.__setattr__(self, "options", _options(self.options, "environment.options"))

    @property
    def resource_kind(self) -> str:
        """Return the stable resource discriminator used by case inference."""
        return "environment"


def environment(
    name: str, *, backend: str = "inherit", context: str = "", namespace: str = "",
    family: str = "any", dns_domain: str = "", isolated: bool = True,
    options: Optional[Mapping[str, object]] = None,
) -> Environment:
    """Declare an execution realm; ordinary single-environment cases omit it."""
    return Environment(
        name, backend, context, namespace, family, dns_domain, isolated,
        {} if options is None else options,
    )


@dataclasses.dataclass(frozen=True)
class Volume:
    """Managed storage mounted into one or more workloads."""

    name: str
    kind: str = "tmp"
    size: int = 0
    source: Optional[Union[str, Path]] = None
    access: str = "read-write-once"
    persistent: bool = False
    provider: str = ""
    options: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        _name(self.name, "volume.name")
        _validate_volume_source(self)
        _validate_volume_policy(self)
        object.__setattr__(self, "options", _options(self.options, "volume.options"))

    def ref(self, *, attribute: str = "path") -> Reference:
        """Reference the realized volume path or backend claim identity."""
        return Reference("volume", self.name, attribute)

    @property
    def resource_kind(self) -> str:
        """Return the stable resource discriminator used by case inference."""
        return "volume"


def _validate_volume_source(value: Volume) -> None:
    _name(value.kind, "volume.kind")
    _validate_volume_kind(value)
    _validate_volume_size(value)
    _validate_volume_path(value)


def _validate_volume_kind(value: Volume) -> None:
    if value.kind not in _VOLUME_KINDS and not value.provider:
        raise SpecError("volume.kind", value.kind, "custom kinds require a provider")


def _validate_volume_size(value: Volume) -> None:
    if isinstance(value.size, bool) or not isinstance(value.size, int) or value.size < 0:
        raise SpecError("volume.size", value.size, "must be an integer >= 0")


def _validate_volume_path(value: Volume) -> None:
    if value.source is not None and not isinstance(value.source, (str, Path)):
        raise SpecError("volume.source", value.source, "must be a path or None")
    if value.kind in ("host", "device") and value.source is None:
        raise SpecError("volume.source", value.source, "%s volumes require a path" % value.kind)


def _validate_volume_policy(value: Volume) -> None:
    if value.access not in _ACCESS_MODES:
        raise SpecError("volume.access", value.access, "has an unknown access mode")
    if not isinstance(value.persistent, bool):
        raise SpecError("volume.persistent", value.persistent, "must be true or false")
    if value.provider:
        _name(value.provider, "volume.provider")


def volume(
    name: str, *, kind: str = "tmp", size: int = 0,
    source: Optional[Union[str, Path]] = None, access: str = "read-write-once",
    persistent: bool = False, provider: str = "",
    options: Optional[Mapping[str, object]] = None,
) -> Volume:
    """Declare backend-neutral temporary, persistent, host, or device storage."""
    return Volume(
        name, kind, size, source, access, persistent, provider,
        {} if options is None else options,
    )


@dataclasses.dataclass(frozen=True)
class Identity:
    """Least-privilege process, container, or Kubernetes workload identity."""

    name: str
    uid: Optional[int] = None
    gid: Optional[int] = None
    groups: Sequence[int] = ()
    user_namespace: bool = False
    uid_map: Sequence[tuple[int, int, int]] = ()
    gid_map: Sequence[tuple[int, int, int]] = ()
    capabilities: Sequence[str] = ()
    permissions: Mapping[str, Sequence[str]] = dataclasses.field(default_factory=dict)
    service_account: str = ""

    def __post_init__(self) -> None:
        _name(self.name, "identity.name")
        _optional_id(self.uid, "identity.uid")
        _optional_id(self.gid, "identity.gid")
        groups = tuple(_optional_id(value, "identity.groups") for value in self.groups)
        if len(set(groups)) != len(groups):
            raise SpecError("identity.groups", groups, "must not contain duplicates")
        if not isinstance(self.user_namespace, bool):
            raise SpecError("identity.user_namespace", self.user_namespace, "must be true or false")
        object.__setattr__(self, "groups", groups)
        object.__setattr__(self, "uid_map", _id_map(self.uid_map, "identity.uid_map"))
        object.__setattr__(self, "gid_map", _id_map(self.gid_map, "identity.gid_map"))
        _validate_identity_map_targets(self)
        object.__setattr__(self, "capabilities", _names(self.capabilities, "identity.capabilities"))
        object.__setattr__(self, "permissions", _permissions(self.permissions))
        _text(self.service_account, "identity.service_account")

    @property
    def resource_kind(self) -> str:
        """Return the stable resource discriminator used by case inference."""
        return "identity"


def _validate_identity_map_targets(value: Identity) -> None:
    _validate_uid_map_target(value)
    missing = _unmapped_gids(value)
    if missing:
        raise SpecError("identity.groups", missing, "must be covered by identity.gid_map")


def _validate_uid_map_target(value: Identity) -> None:
    selected = value.uid is not None and value.uid_map
    if selected and not _mapped(value.uid, value.uid_map):
        raise SpecError("identity.uid", value.uid, "must be covered by identity.uid_map")


def _unmapped_gids(value: Identity) -> tuple[int, ...]:
    gids = tuple(item for item in (value.gid, *value.groups) if item is not None)
    return tuple(item for item in gids if value.gid_map and not _mapped(item, value.gid_map))


def _mapped(value: int, rows: Sequence[tuple[int, int, int]]) -> bool:
    return any(inside <= value < inside + count for inside, _outside, count in rows)


def identity(
    name: str, *, uid: Optional[int] = None, gid: Optional[int] = None,
    groups: Sequence[int] = (), user_namespace: bool = False,
    uid_map: Sequence[tuple[int, int, int]] = (),
    gid_map: Sequence[tuple[int, int, int]] = (), capabilities: Sequence[str] = (),
    permissions: Optional[Mapping[str, Sequence[str]]] = None,
    service_account: str = "",
) -> Identity:
    """Declare one portable least-privilege workload identity."""
    return Identity(
        name, uid, gid, groups, user_namespace, uid_map, gid_map, capabilities,
        {} if permissions is None else permissions, service_account,
    )


def _task_dependencies(values: object) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise SpecError("task.depends_on", values, "must be a task/server sequence")
    selected = tuple(item.name if hasattr(item, "name") else item for item in values)
    return _names(selected, "task.depends_on")


@dataclasses.dataclass(frozen=True)
class Task:
    """One supervised, finite action owned by the case resource graph."""

    name: str
    command: Sequence[object]
    phase: str = "prepare"
    depends_on: Sequence[object] = ()
    env: Mapping[str, object] = dataclasses.field(default_factory=dict)
    outputs: Mapping[str, str] = dataclasses.field(default_factory=dict)
    timeout: float = 30.0
    binaries: Sequence[Binary] = ()
    mounts: Sequence[Mount] = ()
    placement: Placement = dataclasses.field(default_factory=Placement)
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        _name(self.name, "task.name")
        object.__setattr__(self, "command", _argv(self.command, "task.command"))
        if self.phase not in _TASK_PHASES:
            raise SpecError("task.phase", self.phase, "must be prepare, init, or finalize")
        object.__setattr__(self, "depends_on", _task_dependencies(self.depends_on))
        object.__setattr__(self, "env", _string_mapping(self.env, "task.env"))
        object.__setattr__(self, "outputs", _task_outputs(self.outputs))
        _validate_task_policy(self)
        object.__setattr__(self, "binaries", tuple(self.binaries))
        object.__setattr__(self, "mounts", tuple(self.mounts))
        object.__setattr__(self, "metadata", _options(self.metadata, "task.metadata"))

    def output(self, name: str) -> Reference:
        """Reference one declared content-addressed task output."""
        if name not in self.outputs:
            raise SpecError("task output", name, "known: %s" % ", ".join(sorted(self.outputs)))
        return Reference("task", self.name, "output", name)

    @property
    def resource_kind(self) -> str:
        """Return the stable resource discriminator used by case inference."""
        return "task"


def _task_outputs(value: object) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise SpecError("task.outputs", value, "must map names to confined basenames")
    outputs = {name: str(path) for name, path in value.items()}
    if not all(isinstance(name, str) and name and Path(path).name == path for name, path in outputs.items()):
        raise SpecError("task.outputs", outputs, "must map names to confined basenames")
    return freeze_mapping(outputs)


def _validate_task_policy(value: Task) -> None:
    if not _valid_timeout(value.timeout):
        raise SpecError("task.timeout", value.timeout, "must be > 0")
    if not all(isinstance(item, Binary) for item in value.binaries):
        raise SpecError("task.binaries", value.binaries, "must contain Binary declarations")
    if not all(isinstance(item, Mount) for item in value.mounts):
        raise SpecError("task.mounts", value.mounts, "must contain Mount declarations")
    if not isinstance(value.placement, Placement):
        raise SpecError("task.placement", value.placement, "must be a Placement declaration")


def _valid_timeout(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value > 0


def task(
    name: str, *, command: Sequence[object], phase: str = "prepare",
    depends_on: Sequence[object] = (), env: Optional[Mapping[str, object]] = None,
    outputs: Optional[Mapping[str, str]] = None, timeout: float = 30.0,
    binaries: Sequence[Binary] = (), mounts: Sequence[Mount] = (),
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Task:
    """Declare a finite preparation, init, or finalization action."""
    return Task(
        name, command, phase, depends_on, {} if env is None else env,
        {} if outputs is None else outputs, timeout, binaries, mounts,
        Placement() if placement is None else placement,
        {} if metadata is None else metadata,
    )


@dataclasses.dataclass(frozen=True)
class Resource:
    """Provider-managed infrastructure represented by a typed plan fragment."""

    name: str
    kind: str
    options: Mapping[str, object] = dataclasses.field(default_factory=dict)
    depends_on: Sequence[object] = ()

    def __post_init__(self) -> None:
        _name(self.name, "resource.name")
        _name(self.kind, "resource.kind")
        object.__setattr__(self, "options", _options(self.options, "resource.options"))
        object.__setattr__(self, "depends_on", _task_dependencies(self.depends_on))

    def ref(self, output: str = "value") -> Reference:
        """Reference one named output published by the resource provider."""
        _name(output, "resource output")
        return Reference("resource", self.name, "output", output)

    @property
    def resource_kind(self) -> str:
        """Return the stable resource discriminator used by case inference."""
        return "resource"


def resource(
    name: str, kind: str, *, depends_on: Sequence[object] = (), **options: object,
) -> Resource:
    """Declare infrastructure materialized by a versioned resource provider."""
    return Resource(name, kind, options, depends_on)


__all__ = [
    "Environment", "Identity", "Resource", "Task", "Volume",
    "environment", "identity", "resource", "task", "volume",
]
