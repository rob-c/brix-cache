"""Capability vocabulary and strict backend negotiation."""

from __future__ import annotations

from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.extensions import get_extension, installed_extensions

_COMMON = frozenset({
    "execution.capture", "network.ipv4", "network.tcp", "storage.tmp",
    "workload.service",
})
_BACKENDS: Mapping[str, frozenset[str]] = {
    "local": _COMMON | {
        "execution.pty", "execution.stdin", "filesystem.native", "network.dual",
        "network.ipv6", "network.udp",
        "storage.client-volume", "storage.host", "storage.persistent",
        "storage.shared", "storage.volume",
        "identity.capabilities", "identity.materialization", "identity.posix",
        "identity.userns",
        "resource.provider",
        "workload.group", "workload.init", "workload.task",
    },
    "process": _COMMON | {
        "execution.pty", "execution.stdin", "filesystem.native", "network.dual",
        "network.ipv6", "network.udp",
        "storage.client-volume", "storage.host", "storage.persistent",
        "storage.shared", "storage.volume",
        "identity.capabilities", "identity.materialization", "identity.posix",
        "identity.userns",
        "resource.provider",
        "workload.group", "workload.init", "workload.task",
    },
    "docker": _COMMON | {
        "execution.pty", "execution.stdin", "filesystem.oci", "network.dual",
        "network.ipv6", "network.udp", "storage.client-volume",
        "storage.device", "storage.host", "storage.mount-propagation",
        "storage.volume", "identity.capabilities", "identity.materialization",
        "identity.posix", "workload.task",
    },
    "podman": _COMMON | {
        "execution.pty", "execution.stdin", "filesystem.oci", "network.dual",
        "network.ipv6", "network.udp", "storage.client-volume",
        "storage.device", "storage.host", "storage.mount-propagation",
        "storage.volume", "identity.capabilities", "identity.materialization",
        "identity.posix", "identity.userns", "workload.task",
    },
    "runc": _COMMON | {"filesystem.oci", "network.udp", "storage.host"},
    "kubernetes": _COMMON | {
        "environment.isolated", "environment.named",
        "execution.pty", "execution.stdin",
        "filesystem.kubernetes", "network.dual", "network.ipv6", "network.udp",
        "storage.host", "storage.mount-propagation",
        "storage.device", "storage.persistent", "storage.quota", "storage.shared", "storage.volume",
        "storage.provider", "resource.provider",
        "identity.capabilities", "identity.materialization", "identity.posix",
        "identity.rbac", "network.policy",
        "workload.group", "workload.init", "workload.replicas", "workload.task",
    },
    "minikube": _COMMON | {
        "environment.isolated", "environment.named",
        "execution.pty", "execution.stdin",
        "filesystem.kubernetes", "network.dual", "network.ipv6", "network.udp",
        "storage.host", "storage.mount-propagation",
        "storage.device", "storage.persistent", "storage.quota", "storage.shared", "storage.volume",
        "storage.provider", "resource.provider",
        "identity.capabilities", "identity.materialization", "identity.posix",
        "identity.rbac", "network.policy",
        "workload.group", "workload.init", "workload.replicas", "workload.task",
    },
}

_PROCESS_LAUNCHER = _COMMON | {
    "filesystem.native", "network.dual", "network.ipv6", "network.udp",
    "storage.host", "storage.persistent", "storage.shared", "storage.volume",
    "identity.capabilities", "identity.materialization", "identity.posix",
    "identity.userns",
    "workload.group",
}
_KUBERNETES_WORKLOAD = _COMMON | {
    "filesystem.kubernetes", "network.dual", "network.ipv6", "network.udp",
    "storage.host", "storage.mount-propagation",
    "storage.device", "storage.persistent", "storage.quota", "storage.shared", "storage.volume",
    "storage.provider",
    "identity.capabilities", "identity.materialization", "identity.posix",
    "identity.rbac", "network.policy", "workload.group", "workload.init", "workload.replicas",
    "workload.task",
}
_BUILTIN_BY_KIND: Mapping[str, Mapping[str, frozenset[str]]] = {
    "backend": _BACKENDS,
    "launcher": {
        "local": _PROCESS_LAUNCHER, "process": _PROCESS_LAUNCHER,
        "docker": _COMMON | {
            "identity.capabilities", "identity.materialization", "identity.posix",
            "network.dual", "network.ipv6", "network.udp",
            "storage.device", "storage.host",
            "storage.mount-propagation", "storage.volume", "workload.group",
        },
        "podman": _COMMON | {
            "identity.capabilities", "identity.materialization", "identity.posix",
            "identity.userns",
            "network.dual", "network.ipv6", "network.udp",
            "storage.device", "storage.host",
            "storage.mount-propagation", "storage.volume", "workload.group",
        },
        "kubernetes": _KUBERNETES_WORKLOAD,
        "minikube": _KUBERNETES_WORKLOAD,
    },
    "executor": {
        "local": frozenset({
            "execution.capture", "execution.pty", "execution.stdin",
            "identity.capabilities", "identity.materialization", "identity.posix",
            "identity.userns", "network.ipv4", "network.tcp", "storage.client-volume",
        }),
        "docker": frozenset({
            "execution.capture", "execution.pty", "execution.stdin", "network.ipv4",
            "identity.capabilities", "identity.materialization", "identity.posix",
            "network.tcp", "network.udp", "storage.client-volume",
        }),
        "podman": frozenset({
            "execution.capture", "execution.pty", "execution.stdin", "network.ipv4",
            "identity.capabilities", "identity.materialization", "identity.posix",
            "identity.userns", "network.tcp", "network.udp", "storage.client-volume",
        }),
        "kubernetes": frozenset({
            "execution.capture", "execution.pty", "execution.stdin",
            "network.ipv4", "network.tcp",
        }),
    },
    "provider": {
        name: frozenset({"checksum", "confined", "provenance"})
        for name in ("noise", "text", "file")
    },
    "transport": {
        "native-filesystem": frozenset({
            "filesystem.binary", "filesystem.confined", "filesystem.native",
            "filesystem.xattr",
        }),
    },
    "image": {
        "oci": frozenset({
            "image.content-addressed", "image.minikube-load", "image.sbom",
        }),
    },
}


def backend_capabilities(name: str, kind: str = "backend") -> frozenset[str]:
    """Return stable capabilities for a built-in or installed extension."""
    selected = "local" if name in ("", "auto", "inherit") else name
    builtins = _BUILTIN_BY_KIND.get(kind, {})
    if selected in builtins:
        return builtins[selected]
    extension, selected_kind = _load_extension(kind, selected)
    described = _described_capabilities(selected_kind, selected)
    values = getattr(extension, "brixtest_capabilities", described)
    return frozenset(str(value) for value in values) or _COMMON


def _described_capabilities(kind: str, name: str) -> Sequence[str]:
    return next(
        (item.capabilities for item in installed_extensions(kind) if item.name == name),
        (),
    )


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
    candidates = _builtin_alternatives(required, selected)
    candidates.update(_extension_alternatives(required, selected, resource_kind))
    return tuple(sorted(candidates))


def _builtin_alternatives(required: set[str], selected: str) -> set[str]:
    return {
        name for name, capabilities in _BACKENDS.items()
        if name != selected and required <= capabilities
    }


def _extension_alternatives(required, selected, resource_kind) -> set[str]:
    extension_kind = _extension_kind(resource_kind)
    return {
        item.name for item in installed_extensions(extension_kind)
        if item.name != selected and required <= set(item.capabilities)
    }


def _extension_kind(resource_kind: str) -> str:
    if resource_kind == "client":
        return "executor"
    if resource_kind == "server":
        return "launcher"
    return "backend"
