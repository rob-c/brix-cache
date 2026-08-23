"""Validation for JSON suite profiles."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Mapping

from brixtest.errors import SpecError

_BACKEND_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_FIELDS = {
    "backend", "isolation", "binaries", "sanitizer",
    "test_env", "server_env", "client_env",
}


def load_profile(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise SpecError("suite profile", str(path), "cannot load JSON: %s" % exc) from exc
    if not isinstance(value, Mapping):
        raise SpecError("suite profile", str(path), "must contain a JSON object")
    return value


def validate_profile(value: Mapping[str, object]) -> None:
    unexpected = sorted(set(value) - _FIELDS)
    if unexpected:
        raise SpecError("suite profile", unexpected, "contains unknown fields")
    for field in ("binaries", "test_env", "server_env", "client_env"):
        _validate_mapping(field, value.get(field, {}))
    if value.get("sanitizer") not in (None, "asan", "ubsan", "asan-ubsan"):
        raise SpecError("suite profile.sanitizer", value.get("sanitizer"), "has an unknown sanitizer")
    _validate_backend(value.get("backend"))
    _validate_isolation(value.get("isolation"))


def _validate_mapping(field: str, selected: object) -> None:
    if not isinstance(selected, Mapping):
        raise SpecError("suite profile.%s" % field, selected, "must map strings to strings")
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in selected.items()):
        raise SpecError("suite profile.%s" % field, selected, "must map strings to strings")


def _validate_backend(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, str) or _BACKEND_NAME.fullmatch(value) is None:
        raise SpecError("suite profile.backend", value, "has an invalid backend name")


def _validate_isolation(value: object) -> None:
    if value is not None and not isinstance(value, Mapping):
        raise SpecError("suite profile.isolation", value, "must be an isolation object")
