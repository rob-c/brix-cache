"""Conservative recursive redaction for remote evidence transports."""

from __future__ import annotations

import re
from typing import Mapping

_SECRET_KEY = re.compile(r"(?i)(authorization|password|passwd|secret|token|private.?key|cookie)")
_INLINE = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)((?:password|passwd|secret|token)\s*[=:]\s*)[^\s,;]+"),
)


def text(value: str) -> str:
    result = str(value)
    for pattern in _INLINE:
        result = pattern.sub(r"\1[REDACTED]", result)
    return result


def value(item: object, *, key: str = "") -> object:
    if key and _SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(item, Mapping):
        return _mapping(item)
    if isinstance(item, list):
        return _sequence(item)
    if isinstance(item, tuple):
        return _sequence(item)
    if isinstance(item, str):
        return text(item)
    return item


def _mapping(item: Mapping) -> dict:
    return {str(name): value(found, key=str(name)) for name, found in item.items()}


def _sequence(item) -> list:
    return [value(found) for found in item]
