"""Small dependency-free immutable containers used by public value objects."""

from __future__ import annotations

import copy
from typing import Any, Mapping


class FrozenDict(dict):
    """A JSON-compatible dictionary that refuses every mutation operation."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        dict.__init__(self, *args, **kwargs)

    @staticmethod
    def _blocked(*args: object, **kwargs: object) -> None:
        raise TypeError("BriXTest immutable mapping cannot be modified")

    __setitem__ = _blocked
    __delitem__ = _blocked
    clear = _blocked
    pop = _blocked
    popitem = _blocked  # type: ignore[assignment]
    setdefault = _blocked
    update = _blocked
    __ior__ = _blocked  # type: ignore[assignment]

    def __copy__(self) -> "FrozenDict":
        return self

    def __deepcopy__(self, memo: dict) -> "FrozenDict":
        copied = FrozenDict(
            (copy.deepcopy(key, memo), copy.deepcopy(value, memo))
            for key, value in self.items()
        )
        memo[id(self)] = copied
        return copied

    def __reduce__(self):
        return FrozenDict, (dict(self),)

    def __hash__(self) -> int:  # type: ignore[override]
        rows = ((_hashable(key), _hashable(value)) for key, value in self.items())
        return hash(tuple(sorted(rows, key=repr)))


def _hashable(value: Any) -> Any:
    if isinstance(value, Mapping):
        rows = ((_hashable(key), _hashable(item)) for key, item in value.items())
        return tuple(sorted(rows, key=repr))
    if isinstance(value, (list, tuple)):
        return tuple(_hashable(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_hashable(item) for item in value)
    try:
        hash(value)
        return value
    except TypeError:
        return repr(value)


def freeze(value: Any) -> Any:
    """Recursively freeze mappings and sequences while preserving JSON shape."""
    if isinstance(value, Mapping):
        return FrozenDict((key, freeze(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(freeze(item) for item in value)
    return value


def freeze_mapping(value: Mapping) -> FrozenDict:
    """Return an isolated, recursively immutable copy of ``value``."""
    return freeze(value)


__all__ = ["FrozenDict", "freeze", "freeze_mapping"]
