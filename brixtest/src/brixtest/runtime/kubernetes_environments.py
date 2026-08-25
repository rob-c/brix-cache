"""Resolve backend-neutral Environment declarations to Kubernetes targets."""

from __future__ import annotations

import dataclasses
import re
from typing import Mapping

from brixtest.errors import SpecError
from brixtest.runtime.kubernetes_manifests import _resource_name

_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


@dataclasses.dataclass(frozen=True)
class EnvironmentTarget:
    """One immutable namespace/context/DNS routing target."""

    name: str
    namespace: str
    context: str
    dns_domain: str
    isolated: bool


class KubernetesEnvironmentLayout:
    """Map placed resources to unique, run-owned Kubernetes namespaces."""

    def __init__(self, owner, default_context: str) -> None:
        selected = owner.root.name.lower().replace("_", "-")[-32:].strip("-")
        self.test_instance = selected or "case"
        self.default_context = default_context
        self._default_prefix = self._placement_namespace(owner.definition)
        self._targets = self._build_targets(owner.definition.environments)
        self._resources = self._resource_environments(owner.definition)
        self._validate_context_dependencies(owner.definition)

    def _build_targets(self, declarations) -> Mapping[str, EnvironmentTarget]:
        targets = {"default": self._target("default", None)}
        for declaration in declarations:
            targets[declaration.name] = self._target(declaration.name, declaration)
        return targets

    def _target(self, name: str, declaration) -> EnvironmentTarget:
        isolated = declaration is None or declaration.isolated
        raw_namespace = self._target_namespace(declaration, isolated)
        prefix = self._validated_label(name, raw_namespace)
        context = self._target_value(declaration, "context", self.default_context)
        domain = self._target_value(declaration, "dns_domain", "cluster.local")
        self._validate_domain(name, domain)
        namespace = ("%s-%s" % (prefix, self.test_instance))[-63:].strip("-")
        return EnvironmentTarget(name, namespace, context, domain, isolated)

    def _target_namespace(self, declaration, isolated: bool) -> str:
        if declaration is None:
            return self._default_prefix
        return declaration.namespace or (declaration.name if isolated else "brixtest")

    @staticmethod
    def _validated_label(name: str, raw_namespace: str) -> str:
        prefix = _resource_name(raw_namespace)
        if _DNS_LABEL.fullmatch(prefix) is None:
            raise SpecError(
                "environment %s namespace" % name, raw_namespace,
                "must become a lowercase Kubernetes DNS label",
            )
        return prefix

    @staticmethod
    def _target_value(declaration, attribute: str, fallback: str) -> str:
        return fallback if declaration is None else getattr(declaration, attribute) or fallback

    @staticmethod
    def _validate_domain(name: str, domain: str) -> None:
        if any(_DNS_LABEL.fullmatch(part) is None for part in domain.split(".")):
            raise SpecError(
                "environment %s dns_domain" % name, domain,
                "must be a lowercase dotted DNS name",
            )

    @staticmethod
    def _placement_namespace(definition) -> str:
        requested = {
            item.placement.namespace
            for item in (*definition.servers, *definition.tasks, *definition.clients)
            if item.placement.namespace and not item.placement.environment
        }
        if len(requested) > 1:
            raise SpecError(
                "Kubernetes placement.namespace", sorted(requested),
                "use named Environment declarations for multiple namespaces",
            )
        return next(iter(requested), "brixtest")

    @staticmethod
    def _resource_environments(definition) -> Mapping[tuple[str, str], str]:
        values = {}
        for kind, declarations in (
            ("server", definition.servers), ("task", definition.tasks),
            ("client", definition.clients),
        ):
            for declaration in declarations:
                values[(kind, declaration.name)] = declaration.placement.environment or "default"
        return values

    def _validate_context_dependencies(self, definition) -> None:
        servers = {item.name: item for item in definition.servers}
        for server in definition.servers:
            source = self.for_server(server.name)
            for name in server.depends_on:
                target = servers.get(name)
                if target is not None and source.context != self.for_server(name).context:
                    raise SpecError(
                        "server %s dependency" % server.name, name,
                        "cannot cross Kubernetes contexts without an installed transport",
                    )

    @property
    def targets(self) -> tuple[EnvironmentTarget, ...]:
        """Return unique physical targets in deterministic declaration order."""
        values = []
        identities = set()
        for target in self._targets.values():
            identity = target.context, target.namespace
            if identity not in identities:
                identities.add(identity)
                values.append(target)
        return tuple(values)

    @property
    def default(self) -> EnvironmentTarget:
        return self._targets["default"]

    def for_resource(self, kind: str, name: str) -> EnvironmentTarget:
        environment = self._resources.get((kind, name), "default")
        return self._targets[environment]

    def for_server(self, name: str) -> EnvironmentTarget:
        return self.for_resource("server", name)

    def for_task(self, name: str) -> EnvironmentTarget:
        return self.for_resource("task", name)

    def for_client(self, name: str) -> EnvironmentTarget:
        return self.for_resource("client", name)

    def has_resource(self, target: EnvironmentTarget, kind: str) -> bool:
        """Return whether a physical target owns at least one resource of a kind."""
        identity = target.context, target.namespace
        for (resource_kind, _name), environment in self._resources.items():
            selected = self._targets[environment]
            if resource_kind == kind and (selected.context, selected.namespace) == identity:
                return True
        return False

    def name_for(self, context: str, namespace: str) -> str:
        """Resolve one physical Kubernetes identity to its declaration name."""
        selected_context = context or self.default_context
        for target in self._targets.values():
            if (target.context, target.namespace) == (selected_context, namespace):
                return target.name
        return ""

    def server_dns(self, name: str) -> str:
        target = self.for_server(name)
        return "%s.%s.svc.%s" % (_resource_name(name), target.namespace, target.dns_domain)


__all__ = ["EnvironmentTarget", "KubernetesEnvironmentLayout"]
