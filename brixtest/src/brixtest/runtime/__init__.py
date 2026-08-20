"""Lazy runtime conveniences without orchestration import side effects."""

from __future__ import annotations

from importlib import import_module

__all__ = ["CaseManager", "Run", "Service"]

_EXPORTS = {
    "CaseManager": "brixtest.runtime.manager",
    "Run": "brixtest.runtime.api",
    "Service": "brixtest.runtime.api",
}


def __getattr__(name: str) -> object:
    try:
        module = _EXPORTS[name]
    except KeyError:
        raise AttributeError(
            "module 'brixtest.runtime' has no attribute %r" % name
        ) from None
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
