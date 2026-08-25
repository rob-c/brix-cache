"""Backend-neutral status for one realized server replica."""

from __future__ import annotations

import dataclasses
from typing import Dict, Mapping

from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping


def _ports(value: object) -> Mapping[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise SpecError("replica.ports", value, "must map roles to valid ports")
    for role, port in value.items():
        _text("port role", role, required=True)
        _port(role, port)
    return freeze_mapping(value)


def _port(role: str, value: object) -> None:
    field = "replica.ports[%s]" % role
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError(field, value, "must be an integer port")
    if value < 1 or value > 65535:
        raise SpecError(field, value, "must be between 1 and 65535")


def _text(field: str, value: object, *, required: bool = False) -> None:
    if not isinstance(value, str) or "\x00" in value:
        raise SpecError("replica.%s" % field, value, "must be NUL-free text")
    if required and not value:
        raise SpecError("replica.%s" % field, value, "must be non-empty text")


def _validate_text_fields(value: "Replica") -> None:
    for field in ("name", "host"):
        _text(field, getattr(value, field), required=True)
    for field in ("uid", "phase", "started_at"):
        _text(field, getattr(value, field))


def _validate_status(value: "Replica") -> None:
    if not isinstance(value.ready, bool):
        raise SpecError("replica.ready", value.ready, "must be true or false")
    if isinstance(value.restarts, bool) or not isinstance(value.restarts, int):
        raise SpecError("replica.restarts", value.restarts, "must be an integer >= 0")
    if value.restarts < 0:
        raise SpecError("replica.restarts", value.restarts, "must be an integer >= 0")


def _validated_metadata(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SpecError("replica.metadata", value, "must be a mapping")
    return freeze_mapping(value)


@dataclasses.dataclass(frozen=True)
class Replica:
    """Immutable address, health, and provenance for one server replica."""

    name: str
    host: str
    ports: Mapping[str, int]
    uid: str = ""
    phase: str = "unknown"
    ready: bool = False
    restarts: int = 0
    started_at: str = ""
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_text_fields(self)
        _validate_status(self)
        object.__setattr__(self, "ports", _ports(self.ports))
        object.__setattr__(self, "metadata", _validated_metadata(self.metadata))

    def port(self, role: str = "primary") -> int:
        """Return the declared in-environment port for an endpoint role."""
        try:
            return self.ports[role]
        except (KeyError, TypeError):
            raise SpecError(
                "replica port role", role,
                "known roles: %s" % ", ".join(sorted(self.ports)),
            ) from None

    def address(self, role: str = "primary") -> tuple[str, int]:
        """Return the replica's direct in-environment address."""
        return self.host, self.port(role)

    def endpoint(self, role: str = "primary") -> Mapping[str, object]:
        """Return an immutable direct endpoint record."""
        return freeze_mapping({
            "role": role, "host": self.host, "port": self.port(role),
        })

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-safe replica status and provenance record."""
        return {
            "name": self.name, "host": self.host, "ports": dict(self.ports),
            "uid": self.uid, "phase": self.phase, "ready": self.ready,
            "restarts": self.restarts, "started_at": self.started_at,
            "metadata": dict(self.metadata),
        }
