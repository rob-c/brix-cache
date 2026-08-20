"""Reusable conformance assertions for third-party BriXTest extensions."""

from __future__ import annotations

from typing import Mapping

from brixtest.extensions import EXTENSION_API_VERSION, ExtensionRegistry


def assert_extension_contract(kind: str, name: str, target: object) -> Mapping[str, object]:
    """Validate registration, lookup, metadata, and duplicate protection."""
    registry = ExtensionRegistry()
    info = registry.register(kind, name, target, origin="contract-test")
    assert info.api_version == EXTENSION_API_VERSION
    assert registry.load(kind, name) is target
    assert registry.names(kind) == (name,)
    described = registry.describe(kind)
    assert described == (info,)
    return {
        "kind": info.kind, "name": info.name,
        "api_version": info.api_version, "capabilities": info.capabilities,
    }
