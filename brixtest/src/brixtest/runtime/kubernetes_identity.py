"""Translate backend-neutral Identity declarations into Kubernetes resources."""

from __future__ import annotations

import re
from typing import Mapping, Optional, Sequence

from brixtest._design_managed import Identity
from brixtest.errors import SpecError
from brixtest.runtime.linux_identity import linux_capabilities
from brixtest.runtime.identity_nss import nss_records

_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


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
    _validate_permission_resource(resource, resource_name)
    return {
        "apiGroups": [api_group], "resources": [resource_name],
        "verbs": list(verbs),
    }


def _validate_permission_resource(declared: str, resource_name: str) -> None:
    if not resource_name or not all(part for part in resource_name.split("/")):
        raise SpecError(
            "identity permission resource", declared,
            "must be resource[/subresource] or api-group:resource",
        )


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
    nss = _nss_config_map(identity, namespace, labels)
    if not identity.permissions:
        return tuple(item for item in (account, nss) if item is not None)
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
    return tuple(item for item in (account, nss, role, binding) if item is not None)


def _nss_config_map(identity: Identity, namespace: str, labels: Mapping[str, str]):
    records = nss_records(identity)
    if records is None:
        return None
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {
            "name": "%s-nss" % _name(identity), "namespace": namespace,
            "labels": labels,
        },
        "data": dict(records),
    }


def apply_identity(
    pod_spec: dict, container: dict, identity: Optional[Identity],
) -> None:
    """Apply one identity without weakening an explicit security context."""
    if identity is None:
        return
    _reject_user_namespace(identity)
    pod_spec["serviceAccountName"] = _name(identity)
    _apply_posix_identity(pod_spec, identity)
    _apply_capabilities(container, identity)
    _apply_nss(pod_spec, container, identity)


def _reject_user_namespace(identity: Identity) -> None:
    if identity.user_namespace or identity.uid_map or identity.gid_map:
        raise SpecError(
            "identity %s user namespace" % identity.name, identity.uid_map,
            "is not supported by the Kubernetes backend",
        )


def _apply_posix_identity(pod_spec: dict, identity: Identity) -> None:
    pod_security = _posix_context(identity)
    if pod_security:
        pod_spec["securityContext"] = pod_security


def _apply_capabilities(container: dict, identity: Identity) -> None:
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


def _apply_nss(pod_spec: dict, container: dict, identity: Identity) -> None:
    if nss_records(identity) is None:
        return
    volume_name = "identity-nss"
    pod_spec.setdefault("volumes", []).append({
        "name": volume_name, "configMap": {"name": "%s-nss" % _name(identity)},
    })
    mounts = container.setdefault("volumeMounts", [])
    for name in ("passwd", "group"):
        mounts.append({
            "name": volume_name, "mountPath": "/etc/%s" % name,
            "subPath": name, "readOnly": True,
        })


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
    return list(linux_capabilities(values))


__all__ = ["apply_identity", "identity_resources"]
