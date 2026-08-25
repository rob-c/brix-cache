"""Backend-neutral validation for references between execution realms."""

from __future__ import annotations

from typing import Mapping


def environment_transportable(source: str, destination: str, declarations) -> bool:
    """Return whether the built-in Kubernetes DNS transport joins two realms."""
    if source == destination:
        return True
    catalog = declarations if isinstance(declarations, Mapping) else {
        item.name: item for item in declarations
    }
    left = catalog.get(source)
    right = catalog.get(destination)
    backends = {
        getattr(left, "backend", "inherit"), getattr(right, "backend", "inherit"),
    }
    contexts = {getattr(left, "context", ""), getattr(right, "context", "")}
    return backends <= {"inherit", "kubernetes", "minikube"} and len(contexts) == 1


__all__ = ["environment_transportable"]
