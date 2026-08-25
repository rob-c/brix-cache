"""Versioned lifecycle for provider-managed infrastructure resources."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Mapping, Sequence

from brixtest._design_managed import Resource
from brixtest.errors import SpecError
from brixtest.extensions import get_extension
from brixtest.planning.model import digest, jsonable
from brixtest.util.immutable import freeze_mapping

if TYPE_CHECKING:
    from brixtest.runtime.provider_kubernetes import KubernetesProviderObjects


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(name, str) and bool(name) for name in value
    ):
        raise SpecError(field, value, "must map non-empty names to values")
    jsonable(value)
    return freeze_mapping(value)


@dataclasses.dataclass(frozen=True)
class ProviderContext:
    """Confined run identity exposed to infrastructure providers."""

    nodeid: str
    root: Path
    backend: str
    evidence: object = dataclasses.field(repr=False, compare=False)
    metrics: object = dataclasses.field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.nodeid, str) or not self.nodeid:
            raise SpecError("provider nodeid", self.nodeid, "must be non-empty text")
        if not isinstance(self.backend, str) or not self.backend:
            raise SpecError("provider backend", self.backend, "must be non-empty text")
        object.__setattr__(self, "root", Path(self.root).resolve())

    def resource_root(self, name: str) -> Path:
        """Return the confined directory owned by one provider resource."""
        selected = (self.root / name).resolve()
        if self.root not in selected.parents:
            raise SpecError("provider resource", name, "escapes the provider root")
        return selected

    def kubernetes(self) -> "KubernetesProviderObjects":
        """Return confined namespaced object operations on Kubernetes backends."""
        selected = getattr(self, "_kubernetes_objects", None)
        if selected is None:
            raise SpecError(
                "provider Kubernetes operations", self.backend,
                "are available only during create/ready/collect/destroy on Kubernetes",
            )
        return selected


@dataclasses.dataclass(frozen=True)
class ProviderPlan:
    """Side-effect-free typed plan fragment returned by a provider."""

    name: str
    provider: str
    fragment: Mapping[str, object]
    fingerprint: str = ""

    def __post_init__(self) -> None:
        _identity(self.name, self.provider, "provider plan")
        object.__setattr__(self, "fragment", _mapping(self.fragment, "provider plan"))
        if not isinstance(self.fingerprint, str):
            raise SpecError(
                "provider fingerprint", self.fingerprint, "must be text",
            )
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", digest({
                "name": self.name, "provider": self.provider,
                "fragment": self.fragment,
            }))

    def as_dict(self) -> Mapping[str, object]:
        """Return the JSON-safe plan persisted in run evidence."""
        return {
            "name": self.name, "provider": self.provider,
            "fragment": jsonable(self.fragment), "fingerprint": self.fingerprint,
        }


@dataclasses.dataclass(frozen=True)
class ProviderInstance:
    """Owned realized resource, its public outputs, and provenance metadata."""

    name: str
    provider: str
    ownership: Mapping[str, object]
    outputs: Mapping[str, object] = dataclasses.field(default_factory=dict)
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        _identity(self.name, self.provider, "provider instance")
        object.__setattr__(self, "ownership", _mapping(
            self.ownership, "provider ownership",
        ))
        if not self.ownership:
            raise SpecError(
                "provider ownership", self.ownership,
                "must identify at least one conservatively owned object",
            )
        object.__setattr__(self, "outputs", _mapping(self.outputs, "provider outputs"))
        object.__setattr__(self, "metadata", _mapping(self.metadata, "provider metadata"))

    def as_dict(self) -> Mapping[str, object]:
        """Return secret-free ownership and output-name provenance."""
        return {
            "name": self.name, "provider": self.provider,
            "ownership": jsonable(self.ownership),
            "output_names": sorted(self.outputs), "metadata": jsonable(self.metadata),
        }


def _identity(name: object, provider: object, field: str) -> None:
    if not isinstance(name, str) or not name:
        raise SpecError("%s name" % field, name, "must be non-empty text")
    if not isinstance(provider, str) or not provider:
        raise SpecError("%s provider" % field, provider, "must be non-empty text")


class ProviderRuntime:
    """Plan, create, observe, and reverse-destroy local infrastructure."""

    def __init__(self, manager: object) -> None:
        self.manager = manager
        self.context = ProviderContext(
            manager.nodeid, manager.root / "runtime" / "providers",
            manager.backend_name, manager.evidence, manager.metrics,
        )
        self.providers: Dict[str, object] = {}
        self.plans: Dict[str, ProviderPlan] = {}
        self.instances: Dict[str, ProviderInstance] = {}
        self._order: list[str] = []
        for declaration in manager.definition.managed_resources:
            provider = _resource_provider(declaration.kind)
            provider.validate(declaration)
            self.providers[declaration.name] = provider

    def bind_kubernetes(self, backend: object) -> None:
        """Expose a confined post-plan object adapter to providers."""
        from brixtest.runtime.provider_kubernetes import bind_kubernetes_provider_api

        bind_kubernetes_provider_api(self.context, backend)

    def plan_all(self) -> Mapping[str, object]:
        for declaration in self.manager.definition.managed_resources:
            value = self.providers[declaration.name].plan(declaration, self.context)
            if not isinstance(value, ProviderPlan):
                raise SpecError(
                    "resource %s plan" % declaration.name, type(value).__name__,
                    "must return ProviderPlan",
                )
            if value.name != declaration.name or value.provider != declaration.kind:
                raise SpecError(
                    "resource %s plan identity" % declaration.name, value.as_dict(),
                    "must match the Resource declaration",
                )
            self.plans[declaration.name] = value
        return {name: plan.as_dict() for name, plan in sorted(self.plans.items())}

    def start_ready(self) -> None:
        pending = [
            item for item in self.manager.definition.managed_resources
            if item.name not in self.instances
        ]
        progressed = True
        while pending and progressed:
            progressed = False
            for declaration in tuple(pending):
                if self._dependencies_ready(declaration.depends_on):
                    self._create(declaration)
                    pending.remove(declaration)
                    progressed = True

    def _dependencies_ready(self, names: Sequence[str]) -> bool:
        completed_tasks = self.manager._managed._completed
        known_servers = {item.name for item in self.manager.definition.servers}
        return all(
            name in self.instances or name in completed_tasks
            for name in names if name not in known_servers
        ) and not any(name in known_servers for name in names)

    def ensure_complete(self) -> None:
        missing = sorted(
            item.name for item in self.manager.definition.managed_resources
            if item.name not in self.instances
        )
        if missing:
            raise SpecError(
                "provider resources", missing,
                "have unresolved or server-lifetime dependencies",
            )

    def _create(self, declaration: Resource) -> None:
        provider = self.providers[declaration.name]
        root = self.context.resource_root(declaration.name)
        root.mkdir(parents=True, exist_ok=False)
        instance = None
        try:
            with self.manager.metrics.timer(
                "provider.create", labels={"provider": declaration.kind},
            ):
                instance = provider.create(self.plans[declaration.name], self.context)
                if not isinstance(instance, ProviderInstance):
                    raise SpecError(
                        "resource %s create" % declaration.name,
                        type(instance).__name__, "must return ProviderInstance",
                    )
                self._validate_instance(declaration, instance)
                provider.ready(instance, self.context, 30.0)
        except Exception:
            if isinstance(instance, ProviderInstance):
                provider.destroy(instance, self.context)
            raise
        self.instances[declaration.name] = instance
        self._order.append(declaration.name)
        self.manager.evidence.event("provider-resource", instance.as_dict())

    @staticmethod
    def _validate_instance(declaration: Resource, instance: ProviderInstance) -> None:
        if instance.name != declaration.name or instance.provider != declaration.kind:
            raise SpecError(
                "resource %s instance identity" % declaration.name,
                instance.as_dict(), "must match the Resource declaration",
            )

    @property
    def values(self) -> Mapping[str, object]:
        return {
            "resource_%s_%s" % (name, output): value
            for name, instance in self.instances.items()
            for output, value in instance.outputs.items()
        }

    def close(self) -> list[str]:
        errors = []
        for name in reversed(self._order):
            instance, provider = self.instances[name], self.providers[name]
            try:
                collected = provider.collect(instance, self.context)
                if not isinstance(collected, Mapping):
                    raise SpecError(
                        "resource %s collection" % name, type(collected).__name__,
                        "must be a mapping",
                    )
                self.manager.evidence.attach_json(
                    "provider-%s.json" % name, dict(collected),
                    role="provider-result", description="provider resource collection",
                )
            except Exception as exc:
                errors.append("%s collect: %s" % (name, exc))
            try:
                provider.destroy(instance, self.context)
            except Exception as exc:
                errors.append("%s destroy: %s" % (name, exc))
        self._order.clear()
        return errors


def _resource_provider(kind: str):
    if kind == "rook-ceph":
        from brixtest.runtime.rook_ceph import rook_ceph_provider

        return rook_ceph_provider()
    return get_extension("resource", kind)


__all__ = [
    "ProviderContext", "ProviderInstance", "ProviderPlan", "ProviderRuntime",
]
