"""Translate backend-neutral Identity declarations into Kubernetes resources."""

from __future__ import annotations

import re
from typing import Mapping, Optional, Sequence

from brixtest._design_managed import Identity
from brixtest.errors import SpecError

_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_-]*$")


def _name(identity: Identity) -> str:
    selected = identity.service_account or "brixtest-%s" % identity.name.replace("_", "-")
    if len(selected) > 63 or _DNS_LABEL.fullmatch(selected) is None:
        raise SpecError(
            "identity %s service_account" % identity.name, selected,
            "must be a Kubernetes DNS label no longer than 63 characters",
        )
    return selected


def _permission_rule(resource: str, verbs: Sequence[str]) -> dict:
    group, separator, selected = resource.partition(":")
    api_group = group if separator else ""
    resource_name = selected if separator else group
    if not resource_name or not all(part for part in resource_name.split("/")):
        raise SpecError(
            "identity permission resource", resource,
            "must be resource[/subresource] or api-group:resource",
        )
    return {
        "apiGroups": [api_group], "resources": [resource_name],
        "verbs": list(verbs),
    }


def identity_resources(identity: Identity, namespace: str) -> tuple[dict, ...]:
    """Return an owned ServiceAccount and optional least-privilege RBAC pair."""
    service_account = _name(identity)
    labels = {
        "app.kubernetes.io/managed-by": "brixtest",
        "brixtest.io/identity": identity.name,
    }
    account = {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {
            "name": service_account, "namespace": namespace, "labels": labels,
        },
        "automountServiceAccountToken": bool(identity.permissions),
    }
    if not identity.permissions:
        return (account,)
    role_name = "%s-role" % service_account
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": role_name, "namespace": namespace, "labels": labels},
        "rules": [
            _permission_rule(resource, verbs)
            for resource, verbs in sorted(identity.permissions.items())
        ],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": role_name, "namespace": namespace, "labels": labels},
        "subjects": [{
            "kind": "ServiceAccount", "name": service_account,
            "namespace": namespace,
        }],
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
            "name": role_name,
        },
    }
    return account, role, binding


def apply_identity(
    pod_spec: dict, container: dict, identity: Optional[Identity],
) -> None:
    """Apply one identity without weakening an explicit security context."""
    if identity is None:
        return
    if identity.user_namespace or identity.uid_map or identity.gid_map:
        raise SpecError(
            "identity %s user namespace" % identity.name, identity.uid_map,
            "is not supported by the Kubernetes backend",
        )
    pod_spec["serviceAccountName"] = _name(identity)
    pod_security = _posix_context(identity)
    if pod_security:
        pod_spec["securityContext"] = pod_security
    additions = _linux_capabilities(identity.capabilities)
    if additions:
        security = container.setdefault("securityContext", {})
        existing = security.setdefault("capabilities", {})
        if existing.get("add") not in (None, additions):
            raise SpecError(
                "identity %s capabilities" % identity.name, identity.capabilities,
                "conflict with placement.security_context capabilities.add",
            )
        existing["add"] = additions


def _posix_context(identity: Identity) -> dict:
    values = {}
    if identity.uid is not None:
        values["runAsUser"] = identity.uid
    if identity.gid is not None:
        values["runAsGroup"] = identity.gid
    if identity.groups:
        values["supplementalGroups"] = list(identity.groups)
    return values


def _linux_capabilities(values: Sequence[str]) -> list[str]:
    if not all(_CAPABILITY.fullmatch(value) for value in values):
        raise SpecError(
            "identity.capabilities", tuple(values),
            "must contain portable lowercase Linux capability names",
        )
    return [value.replace("-", "_").upper() for value in values]


__all__ = ["apply_identity", "identity_resources"]
