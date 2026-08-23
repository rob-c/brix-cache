"""Capability vocabulary and strict backend negotiation."""

from __future__ import annotations

from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.extensions import get_extension, installed_extensions

_COMMON = frozenset({
    "execution.capture", "network.ipv4", "network.tcp", "storage.tmp",
    "workload.service",
})
_BUILTIN: Mapping[str, frozenset[str]] = {
    "local": _COMMON | {
        "execution.pty", "execution.stdin", "filesystem.native", "network.dual",
        "network.ipv6", "network.udp",
        "storage.client-volume", "storage.host", "storage.persistent",
        "storage.shared", "storage.volume",
        "workload.init", "workload.task",
    },
    "process": _COMMON | {
        "execution.pty", "execution.stdin", "filesystem.native", "network.dual",
        "network.ipv6", "network.udp",
        "storage.client-volume", "storage.host", "storage.persistent",
        "storage.shared", "storage.volume",
        "workload.init", "workload.task",
    },
    "docker": _COMMON | {
        "execution.stdin", "filesystem.oci", "network.udp", "storage.client-volume",
        "storage.host",
    },
    "podman": _COMMON | {
        "execution.stdin", "filesystem.oci", "network.udp", "storage.client-volume",
        "storage.host",
    },
    "runc": _COMMON | {"filesystem.oci", "network.udp", "storage.host"},
    "kubernetes": _COMMON | {
        "filesystem.kubernetes", "storage.host", "storage.mount-propagation",
        "storage.persistent", "storage.quota", "storage.shared", "storage.volume",
        "identity.capabilities", "identity.materialization", "identity.posix",
        "identity.rbac", "network.policy",
        "workload.replicas",
    },
    "minikube": _COMMON | {
        "filesystem.kubernetes", "storage.host", "storage.mount-propagation",
        "storage.persistent", "storage.quota", "storage.shared", "storage.volume",
        "identity.capabilities", "identity.materialization", "identity.posix",
        "identity.rbac", "network.policy",
        "workload.replicas",
    },
}


def backend_capabilities(name: str, kind: str = "backend") -> frozenset[str]:
    """Return stable capabilities for a built-in or installed extension."""
    selected = "local" if name in ("", "auto", "inherit") else name
    if selected in _BUILTIN:
        return _BUILTIN[selected]
    extension, selected_kind = _load_extension(kind, selected)
    described = next(
        (item.capabilities for item in installed_extensions(selected_kind) if item.name == selected),
        (),
    )
    values = getattr(extension, "brixtest_capabilities", described)
    return frozenset(str(value) for value in values) or _COMMON


def _load_extension(kind: str, name: str) -> tuple[object, str]:
    try:
        return get_extension(kind, name), kind
    except SpecError as exc:
        if kind == "backend" or exc.field != "%s extension" % kind:
            raise
    return get_extension("backend", name), "backend"


def validate_capabilities(nodes: Sequence[object]) -> None:
    """Reject the first resource whose selected backend cannot honor its plan."""
    for node in nodes:
        available = backend_capabilities(node.backend, _extension_kind(node.kind))
        missing = sorted(set(node.requires) - available)
        if missing:
            alternatives = _alternatives(set(node.requires), node.backend, node.kind)
            raise SpecError(
                "resource %s capabilities" % node.id, missing,
                "backend %s provides: %s; alternatives: %s" % (
                    node.backend, ", ".join(sorted(available)) or "none",
                    ", ".join(alternatives) or "none",
                ),
            )


def _alternatives(required: set[str], selected: str, resource_kind: str) -> tuple[str, ...]:
    candidates = {
        name for name, capabilities in _BUILTIN.items()
        if name != selected and required <= capabilities
    }
    extension_kind = _extension_kind(resource_kind)
    candidates.update(
        item.name for item in installed_extensions(extension_kind)
        if item.name != selected and required <= set(item.capabilities)
    )
    return tuple(sorted(candidates))


def _extension_kind(resource_kind: str) -> str:
    if resource_kind == "client":
        return "executor"
    if resource_kind == "server":
        return "launcher"
    return "backend"
