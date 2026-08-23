"""Compatibility facade for BriXTest's single versioned extension registry."""

from __future__ import annotations

from typing import Callable

from brixtest.extensions import ENTRY_POINT_GROUPS, get_extension, installed_extensions

GROUPS = {
    kind: ENTRY_POINT_GROUPS[kind]
    for kind in ("collector", "analyzer", "exporter")
}


def discover(kind: str) -> dict[str, object]:
    """Return discovered extension metadata without importing implementations."""
    return {
        item.name: item for item in installed_extensions(kind)
    }


def load(kind: str, name: str) -> Callable:
    """Load a callable through the validated shared registry."""
    return get_extension(kind, name)
