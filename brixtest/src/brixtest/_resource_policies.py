"""Placement and log-retention policies shared by declared resources."""

from __future__ import annotations

import dataclasses
from typing import Mapping, Optional, Sequence

from brixtest.errors import SpecError

# Imported after these names have been defined by resources.py. Keeping the
# validation primitives central avoids subtly different declaration rules.
from brixtest.resources import ResourceLimits, _name, _strings
from brixtest.util.immutable import freeze_mapping


def _non_empty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _integer_at_least(value: object, minimum: int) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= minimum


def _validate_options(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SpecError("placement.options", value, "must be a mapping")
    if not all(_non_empty_text(name) for name in value):
        raise SpecError(
            "placement.options", value,
            "must map non-empty option names to immutable values",
        )
    return freeze_mapping(value)


def _resource_name(value: object, field: str) -> str:
    selected = getattr(value, "name", value)
    if not isinstance(selected, str):
        raise SpecError(field, value, "must be a resource name or declaration")
    if selected:
        _name(selected, field)
    return selected

@dataclasses.dataclass(frozen=True)
class Placement:
    """Backend-neutral resource placement and container policy."""

    backend: str = "inherit"
    image: Optional[str] = None
    namespace: str = ""
    labels: Mapping[str, str] = dataclasses.field(default_factory=dict)
    node_selector: Mapping[str, str] = dataclasses.field(default_factory=dict)
    security_context: Mapping[str, object] = dataclasses.field(default_factory=dict)
    resources: ResourceLimits = dataclasses.field(default_factory=ResourceLimits)
    options: Mapping[str, object] = dataclasses.field(default_factory=dict)
    allow_mutable_image: bool = False
    environment: object = ""
    group: str = ""
    identity: object = ""
    network_policy: str = "declared"

    def __post_init__(self) -> None:
        _name(self.backend, "placement.backend")
        if self.image is not None and not _non_empty_text(self.image):
            raise SpecError("placement.image", self.image, "must be non-empty text or None")
        if not isinstance(self.namespace, str):
            raise SpecError("placement.namespace", self.namespace, "must be text")
        object.__setattr__(self, "labels", _strings(self.labels, "placement.labels"))
        object.__setattr__(self, "node_selector", _strings(self.node_selector, "placement.node_selector"))
        if not isinstance(self.security_context, Mapping):
            raise SpecError("placement.security_context", self.security_context, "must be a mapping")
        object.__setattr__(self, "security_context", freeze_mapping(self.security_context))
        if not isinstance(self.resources, ResourceLimits):
            raise SpecError("placement.resources", self.resources, "must be ResourceLimits")
        object.__setattr__(self, "options", _validate_options(self.options))
        if not isinstance(self.allow_mutable_image, bool):
            raise SpecError(
                "placement.allow_mutable_image", self.allow_mutable_image,
                "must be true or false",
            )
        object.__setattr__(
            self, "environment", _resource_name(self.environment, "placement.environment"),
        )
        object.__setattr__(self, "group", _resource_name(self.group, "placement.group"))
        object.__setattr__(
            self, "identity", _resource_name(self.identity, "placement.identity"),
        )
        if self.network_policy not in ("open", "declared", "isolated"):
            raise SpecError(
                "placement.network_policy", self.network_policy,
                "must be open, declared, or isolated",
            )


@dataclasses.dataclass(frozen=True)
class LogPolicy:
    """Capture, retention, redaction, and failure-tail policy for one resource."""

    capture: bool = True
    max_bytes: int = 64 << 20
    tail_lines: int = 40
    redact: Sequence[str] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.capture, bool):
            raise SpecError("logs.capture", self.capture, "must be true or false")
        if not _integer_at_least(self.max_bytes, 1):
            raise SpecError("logs.max_bytes", self.max_bytes, "must be an integer >= 1")
        if not _integer_at_least(self.tail_lines, 0):
            raise SpecError("logs.tail_lines", self.tail_lines, "must be an integer >= 0")
        patterns = tuple(self.redact)
        if not all(_non_empty_text(value) for value in patterns):
            raise SpecError("logs.redact", patterns, "must contain non-empty text patterns")
        object.__setattr__(self, "redact", patterns)
