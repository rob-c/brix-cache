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
    "test_env", "server_env", "client_env", "images",
}
_IMAGE_FIELDS = {"base_image", "registry"}
_PINNED_IMAGE = re.compile(r"[^@\s]+@sha256:[0-9a-fA-F]{64}")
_REGISTRY = re.compile(
    r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
)


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
    validate_image_settings(value.get("images", {}), "suite profile.images")
    _validate_backend(value.get("backend"))
    _validate_isolation(value.get("isolation"))


def validate_image_settings(value: object, field: str = "image settings") -> None:
    """Validate project/profile defaults used by the generated-image pipeline."""
    if not isinstance(value, Mapping):
        raise SpecError(field, value, "must be an object")
    unexpected = sorted(set(value) - _IMAGE_FIELDS)
    if unexpected:
        raise SpecError(field, unexpected, "contains unknown fields")
    base_image = value.get("base_image", "")
    registry = value.get("registry", "")
    if base_image and (
        not isinstance(base_image, str) or _PINNED_IMAGE.fullmatch(base_image) is None
    ):
        raise SpecError(
            "%s.base_image" % field, base_image,
            "must be a digest-pinned image (image@sha256:...)",
        )
    if registry and (
        not isinstance(registry, str) or _REGISTRY.fullmatch(registry) is None
    ):
        raise SpecError(
            "%s.registry" % field, registry,
            "must be a registry host with an optional repository prefix",
        )


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
