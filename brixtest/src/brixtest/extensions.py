"""Versioned extension discovery and public runtime contracts.

Only behaviour that BriXTest can actually invoke is advertised here.  Author
conveniences (for example an nginx-specific ``server()`` factory) remain plain
Python composition returning the generic declarations; runtime seams use this
registry so they receive validation, lazy loading, capability metadata, and a
reusable conformance suite.
"""

from __future__ import annotations

import dataclasses
import re
import threading
from importlib import metadata
from typing import TYPE_CHECKING, Dict, Mapping, Optional, Protocol, Sequence, runtime_checkable

from brixtest.errors import SpecError

if TYPE_CHECKING:
    from brixtest.design import Artifact, CaseDefinition, Client, Server
    from brixtest._design_managed import Resource
    from brixtest.evidence.collectors import CollectorSpec
    from brixtest.runtime.api import Run
    from brixtest.runtime.artifacts import ArtifactProviderContext
    from brixtest.runtime.backends import BackendContext
    from brixtest.runtime.executors import ToolExecutionContext, ToolExecutionRequest
    from brixtest.runtime.launchers import (
        ServerLaunchContext,
        ServerLaunchPlan,
        ServerLaunchRequest,
    )
    from brixtest.runtime.providers import ProviderContext, ProviderInstance, ProviderPlan

EXTENSION_API_VERSION = 1
_EXTENSION_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
__all__ = [
    "ENTRY_POINT_GROUPS",
    "EXTENSION_API_VERSION",
    "Analyzer",
    "CaseBackend",
    "Collector",
    "Exporter",
    "ExtensionInfo",
    "ExtensionRegistry",
    "ProbeDriver",
    "ManagedResourceProvider",
    "VolumeProvider",
    "IdentityProvider",
    "FilesystemTransport",
    "ImageProvider",
    "ResourceProvider",
    "ServerLauncher",
    "ToolExecutor",
    "extension_registry",
    "get_extension",
    "installed_extensions",
    "register_extension",
]
ENTRY_POINT_GROUPS: Mapping[str, str] = {
    "probe": "brixtest.probes",
    "backend": "brixtest.backends",
    "executor": "brixtest.executors",
    "provider": "brixtest.providers",
    "collector": "brixtest.collectors",
    "analyzer": "brixtest.analyzers",
    "exporter": "brixtest.exporters",
    "launcher": "brixtest.launchers",
    "resource": "brixtest.resources",
    "volume": "brixtest.volumes",
    "identity": "brixtest.identities",
    "transport": "brixtest.transports",
    "image": "brixtest.images",
}

_REQUIRED: Mapping[str, tuple[str, ...]] = {
    "probe": ("validate", "wait"),
    "backend": ("validate", "plan", "prepare", "start", "stop", "collect"),
    "executor": ("validate", "execute"),
    "provider": ("validate", "materialize"),
    "collector": (),
    "analyzer": (),
    "exporter": (),
    "launcher": ("validate", "prepare", "cleanup"),
    "resource": ("validate", "plan", "create", "ready", "collect", "destroy"),
    "volume": ("validate", "plan", "create", "ready", "collect", "destroy"),
    "identity": ("validate", "plan", "create", "ready", "collect", "destroy"),
    "transport": (
        "read_bytes", "write_bytes", "stat", "list", "mkdir", "remove",
    ),
    "image": ("build",),
}


@runtime_checkable
class CaseBackend(Protocol):
    """Placement contract for the complete server graph of one managed case."""

    def validate(self, declaration: "CaseDefinition") -> None: ...
    def plan(self, context: "BackendContext") -> Mapping[str, object]: ...
    def prepare(self, context: "BackendContext") -> None: ...
    def start(self, context: "BackendContext") -> "Run": ...
    def stop(self, context: "BackendContext") -> None: ...
    def collect(self, context: "BackendContext") -> Mapping[str, object]: ...


@runtime_checkable
class ToolExecutor(Protocol):
    """Execute a resolved client/tool request in one placement environment."""

    def validate(self, declaration: "Client") -> None: ...
    def execute(
        self, context: "ToolExecutionContext", request: "ToolExecutionRequest",
    ) -> object: ...


@runtime_checkable
class ServerLauncher(Protocol):
    """Translate one server declaration into a supervised launch plan."""

    def validate(self, declaration: "Server") -> None: ...
    def prepare(
        self, context: "ServerLaunchContext", request: "ServerLaunchRequest",
    ) -> "ServerLaunchPlan": ...
    def cleanup(
        self, context: "ServerLaunchContext", plan: "ServerLaunchPlan",
    ) -> None: ...


@runtime_checkable
class ProbeDriver(Protocol):
    """Validate and wait for a custom server readiness declaration."""

    def validate(self, declaration: object) -> None: ...
    def wait(self, declaration: object, endpoint: object, timeout: float) -> object: ...


@runtime_checkable
class ResourceProvider(Protocol):
    """Materialize a custom artifact declaration into its confined destination."""

    def validate(self, declaration: "Artifact") -> None: ...
    def materialize(
        self, declaration: "Artifact", destination: object,
        context: "ArtifactProviderContext",
    ) -> object: ...


@runtime_checkable
class ManagedResourceProvider(Protocol):
    """Lifecycle for typed infrastructure requested by :func:`resource`."""

    def validate(self, declaration: "Resource") -> None: ...
    def plan(
        self, declaration: "Resource", context: "ProviderContext",
    ) -> "ProviderPlan": ...
    def create(
        self, plan: "ProviderPlan", context: "ProviderContext",
    ) -> "ProviderInstance": ...
    def ready(
        self, instance: "ProviderInstance", context: "ProviderContext",
        timeout: float,
    ) -> None: ...
    def collect(
        self, instance: "ProviderInstance", context: "ProviderContext",
    ) -> Mapping[str, object]: ...
    def destroy(
        self, instance: "ProviderInstance", context: "ProviderContext",
    ) -> None: ...


@runtime_checkable
class VolumeProvider(ManagedResourceProvider, Protocol):
    """Versioned managed lifecycle for an installed volume kind."""


@runtime_checkable
class IdentityProvider(ManagedResourceProvider, Protocol):
    """Versioned managed lifecycle for an installed identity kind."""


@runtime_checkable
class FilesystemTransport(Protocol):
    """Binary-safe operations used by :class:`ServiceFilesystem`."""

    def read_bytes(self, path: object) -> bytes: ...
    def write_bytes(self, path: object, value: bytes) -> None: ...
    def stat(self, path: object, *, follow_symlinks: bool = True) -> Mapping[str, object]: ...
    def list(self, path: object = ".") -> Sequence[str]: ...
    def mkdir(self, path: object, *, parents: bool = False, exist_ok: bool = False) -> None: ...
    def remove(self, path: object, *, recursive: bool = False) -> None: ...


@runtime_checkable
class ImageProvider(Protocol):
    """Build one immutable image from captured binary inputs."""

    def build(
        self, name: str, binaries: Sequence[object], *, base_image: str = "",
    ) -> object: ...


@runtime_checkable
class Collector(Protocol):
    """Collect observations for a running managed attempt."""

    def __call__(self, manager: object, declaration: "CollectorSpec") -> object: ...


@runtime_checkable
class Analyzer(Protocol):
    """Analyze a normalized evidence payload and return JSON-safe results."""

    def __call__(self, payload: Mapping[str, object], context: Mapping[str, object]) -> object: ...


@runtime_checkable
class Exporter(Protocol):
    """Export a normalized evidence payload to a declared destination."""

    def __call__(
        self, payload: Mapping[str, object], destination: object,
        context: Mapping[str, object],
    ) -> object: ...


def _validate_kind(kind: str) -> str:
    if kind not in ENTRY_POINT_GROUPS:
        raise SpecError(
            "extension kind", kind,
            "known: %s" % ", ".join(sorted(ENTRY_POINT_GROUPS)),
        )
    return kind


def _validate_target(kind: str, target: object) -> None:
    if kind in ("collector", "analyzer", "exporter"):
        if not callable(target):
            raise SpecError("%s extension" % kind, target, "must be callable")
        return
    missing = [name for name in _REQUIRED[kind] if not callable(getattr(target, name, None))]
    if missing:
        raise SpecError(
            "%s extension" % kind, target,
            "must implement: %s" % ", ".join(_REQUIRED[kind]),
        )


def _extension_capabilities(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError(
            "extension capabilities", value,
            "must be a sequence of non-empty names",
        )
    raw_values = tuple(value)
    if not all(isinstance(item, str) and bool(item) for item in raw_values):
        raise SpecError(
            "extension capabilities", raw_values, "must contain non-empty text",
        )
    return tuple(sorted(set(raw_values)))


@dataclasses.dataclass(frozen=True)
class ExtensionInfo:
    """Secret-free metadata for one built-in, programmatic, or packaged extension."""

    kind: str
    name: str
    api_version: int = EXTENSION_API_VERSION
    capabilities: Sequence[str] = ()
    origin: str = "programmatic"
    loaded: bool = False

    def __post_init__(self) -> None:
        _validate_kind(self.kind)
        if not isinstance(self.name, str) or _EXTENSION_NAME.fullmatch(self.name) is None:
            raise SpecError(
                "extension name", self.name,
                "must match [a-z][a-z0-9_-]*",
            )
        if self.api_version != EXTENSION_API_VERSION:
            raise SpecError(
                "extension api_version", self.api_version,
                "BriXTest supports version %d" % EXTENSION_API_VERSION,
            )
        object.__setattr__(self, "capabilities", _extension_capabilities(self.capabilities))
        if not isinstance(self.origin, str) or not self.origin:
            raise SpecError("extension origin", self.origin, "must be non-empty text")


class ExtensionRegistry:
    """Thread-safe registry with lazy package-entry-point discovery."""

    def __init__(self) -> None:
        self._targets: Dict[tuple[str, str], object] = {}
        self._info: Dict[tuple[str, str], ExtensionInfo] = {}
        self._entry_points: Dict[tuple[str, str], metadata.EntryPoint] = {}
        self._discovered = False
        self._lock = threading.RLock()

    def register(
        self, kind: str, name: str, target: object, *, replace: bool = False,
        api_version: int = EXTENSION_API_VERSION,
        capabilities: Sequence[str] = (), origin: str = "programmatic",
    ) -> ExtensionInfo:
        """Validate and register one extension implementation."""
        _validate_kind(kind)
        _validate_target(kind, target)
        key = kind, name
        declared = capabilities or getattr(target, "brixtest_capabilities", ())
        info = ExtensionInfo(kind, name, api_version, declared, origin, True)
        with self._lock:
            if key in self._info and not replace:
                raise SpecError("extension", "%s:%s" % key, "is already registered")
            self._targets[key] = target
            self._info[key] = info
        return info

    def discover(self, *, refresh: bool = False) -> tuple[ExtensionInfo, ...]:
        """Discover installed extension entry points without importing their code."""
        with self._lock:
            if self._discovered and not refresh:
                return self.describe()
            self._refresh_discovery(refresh)
            found = metadata.entry_points()
            for kind, group in ENTRY_POINT_GROUPS.items():
                self._discover_group(found, kind, group)
            self._discovered = True
            return self.describe()

    def _refresh_discovery(self, refresh: bool) -> None:
        if not refresh:
            return
        for key in tuple(self._entry_points):
            if key not in self._targets:
                self._info.pop(key, None)
        self._entry_points.clear()

    def _discover_group(self, found, kind: str, group: str) -> None:
        for entry in _selected_entries(found, group):
            self._record_entry(kind, entry)

    def _record_entry(self, kind: str, entry: metadata.EntryPoint) -> None:
        key = kind, entry.name
        if key in self._targets:
            return
        self._entry_points[key] = entry
        self._info[key] = ExtensionInfo(
            kind, entry.name, origin="entry-point:%s" % entry.value,
        )

    def load(self, kind: str, name: str) -> object:
        """Return a validated extension, lazily importing an entry point if needed."""
        _validate_kind(kind)
        self.discover()
        key = kind, name
        with self._lock:
            if key in self._targets:
                return self._targets[key]
            try:
                entry = self._entry_points[key]
            except KeyError:
                raise SpecError(
                    "%s extension" % kind, name,
                    "known: %s" % ", ".join(self.names(kind)),
                ) from None
            target = entry.load()
            _validate_target(kind, target)
            previous = self._info[key]
            api_version = getattr(target, "brixtest_api_version", EXTENSION_API_VERSION)
            capabilities = getattr(target, "brixtest_capabilities", previous.capabilities)
            if api_version != EXTENSION_API_VERSION:
                raise SpecError(
                    "%s extension api_version" % kind, api_version,
                    "BriXTest supports version %d" % EXTENSION_API_VERSION,
                )
            self._targets[key] = target
            self._info[key] = dataclasses.replace(
                previous, loaded=True, api_version=api_version,
                capabilities=capabilities,
            )
            return target

    def names(self, kind: Optional[str] = None) -> tuple[str, ...]:
        """List extension names, optionally restricted to one kind."""
        if kind is not None:
            _validate_kind(kind)
        self.discover()
        with self._lock:
            return tuple(sorted(
                name for selected_kind, name in self._info
                if kind is None or selected_kind == kind
            ))

    def describe(self, kind: Optional[str] = None) -> tuple[ExtensionInfo, ...]:
        """Return stable metadata without loading extension implementations."""
        if kind is not None:
            _validate_kind(kind)
        with self._lock:
            return tuple(
                self._info[key] for key in sorted(self._info)
                if kind is None or key[0] == kind
            )

    def clear(self) -> None:
        """Remove programmatic and discovered entries; intended for contract tests."""
        with self._lock:
            self._targets.clear()
            self._info.clear()
            self._entry_points.clear()
            self._discovered = False


def _selected_entries(found, group: str):
    if hasattr(found, "select"):
        return found.select(group=group)
    return found.get(group, ())


extension_registry = ExtensionRegistry()


def register_extension(
    kind: str, name: str, target: object, *, replace: bool = False,
    api_version: int = EXTENSION_API_VERSION,
    capabilities: Sequence[str] = (), origin: str = "programmatic",
) -> ExtensionInfo:
    """Register a process-local extension in the shared registry."""
    return extension_registry.register(
        kind, name, target, replace=replace, api_version=api_version,
        capabilities=capabilities, origin=origin,
    )


def get_extension(kind: str, name: str) -> object:
    """Resolve and validate one built-in or package-provided extension."""
    return extension_registry.load(kind, name)


def installed_extensions(kind: Optional[str] = None) -> tuple[ExtensionInfo, ...]:
    """Describe installed extensions without importing their implementations."""
    extension_registry.discover()
    return extension_registry.describe(kind)
