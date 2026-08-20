"""BriXTest's small public declaration surface.

Names are loaded lazily so plain ``import brixtest`` remains side-effect free;
``from brixtest import case, server`` still gives test authors the complete DSL.
"""

from __future__ import annotations

from importlib import import_module

from brixtest._api import PUBLIC_EXPORTS

__version__ = "0.15.0"
__all__ = ["__version__", *sorted(PUBLIC_EXPORTS)]


def __getattr__(name: str) -> object:
    try:
        module = PUBLIC_EXPORTS[name]
    except KeyError:
        raise AttributeError("module 'brixtest' has no attribute %r" % name) from None
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
