"""Machine-readable introspection for BriXTest's supported author surface."""

from __future__ import annotations

from typing import Mapping

from brixtest import __version__
from brixtest._api import (
    PUBLIC_ATTRIBUTES,
    PUBLIC_CALL_SHAPES,
    PUBLIC_CLASS_CALL_SHAPES,
    PUBLIC_EXPORTS,
    PUBLIC_GROUPS,
    PUBLIC_MEMBER_CALL_SHAPES,
    PUBLIC_METHODS,
    PUBLIC_PROPERTIES,
)
from brixtest.pytest_options import (
    PUBLIC_PYTEST_FIXTURES,
    PUBLIC_PYTEST_HOOKS,
    PUBLIC_PYTEST_INI,
    PUBLIC_PYTEST_MARKERS,
    PUBLIC_PYTEST_OPTIONS,
)
from brixtest.util.immutable import freeze_mapping


def api_contract() -> Mapping[str, object]:
    """Return the complete, immutable, JSON-compatible public API contract.

    The contract describes stable top-level symbols, function call shapes,
    readable attributes, class methods and properties, plus the public pytest
    integration surface.
    It is suitable for documentation generators, editor integrations, and
    compatibility checks without inspecting BriXTest source code.
    """
    group_by_name = {
        name: group
        for group, members in PUBLIC_GROUPS.items()
        for name in members
    }
    names = ("__version__", *sorted(PUBLIC_EXPORTS))
    symbols = []
    for name in names:
        if name in PUBLIC_CALL_SHAPES:
            kind = "function"
        elif name in PUBLIC_METHODS:
            kind = "class"
        else:
            kind = "constant"
        symbols.append({
            "name": name,
            "group": group_by_name.get(name, "package"),
            "module": PUBLIC_EXPORTS.get(name, "brixtest"),
            "kind": kind,
            "call_shape": list(
                PUBLIC_CALL_SHAPES.get(name, PUBLIC_CLASS_CALL_SHAPES.get(name, ()))
            ) if kind != "constant" else None,
            "members": list(PUBLIC_METHODS.get(name, ())),
            "attributes": list(PUBLIC_ATTRIBUTES.get(name, ())),
            "member_call_shapes": {
                member: list(PUBLIC_MEMBER_CALL_SHAPES[name + "." + member])
                for member in PUBLIC_METHODS.get(name, ())
            },
            "properties": list(PUBLIC_PROPERTIES.get(name, ())),
        })

    groups = {"package": ["__version__"]}
    groups.update({
        group: sorted(members)
        for group, members in PUBLIC_GROUPS.items()
    })
    return freeze_mapping({
        "schema_version": 2,
        "package": "brixtest",
        "version": __version__,
        "groups": groups,
        "symbols": symbols,
        "pytest": {
            "options": sorted(PUBLIC_PYTEST_OPTIONS),
            "fixtures": sorted(PUBLIC_PYTEST_FIXTURES),
            "markers": sorted(PUBLIC_PYTEST_MARKERS),
            "ini": sorted(PUBLIC_PYTEST_INI),
            "hooks": sorted(PUBLIC_PYTEST_HOOKS),
        },
    })


__all__ = ["api_contract"]
