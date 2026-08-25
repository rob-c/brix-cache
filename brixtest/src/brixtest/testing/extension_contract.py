"""Reusable conformance assertions for third-party BriXTest extensions."""

from __future__ import annotations

from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.extensions import EXTENSION_API_VERSION, ExtensionInfo, ExtensionRegistry


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


def check_extension_capabilities(
    kind: str, target: object, required: Sequence[str] = (),
) -> list[str]:
    """Validate an extension's versioned capability declaration."""
    if getattr(target, "brixtest_api_version", None) != EXTENSION_API_VERSION:
        return ["api_version: must equal %d" % EXTENSION_API_VERSION]
    if not hasattr(target, "brixtest_capabilities"):
        return ["capabilities: must be declared"]
    try:
        info = ExtensionInfo(
            kind, "contract", capabilities=target.brixtest_capabilities,
        )
    except SpecError as exc:
        return ["capabilities: %s" % exc]
    missing = sorted(set(required) - set(info.capabilities))
    return ["capabilities: missing %s" % ", ".join(missing)] if missing else []


__all__ = ["assert_extension_contract", "check_extension_capabilities"]
