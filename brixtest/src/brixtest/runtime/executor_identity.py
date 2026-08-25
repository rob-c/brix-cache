"""Resolve typed identities for local and OCI tool execution."""

from __future__ import annotations

from typing import Mapping, Optional

from brixtest._design_managed import Identity
from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping


def identity_catalog(value: object) -> Mapping[str, Identity]:
    """Validate and freeze a name-to-Identity execution catalog."""
    valid = isinstance(value, Mapping) and all(
        isinstance(name, str) and isinstance(identity, Identity)
        and name == identity.name for name, identity in value.items()
    )
    if not valid:
        raise SpecError(
            "tool context identities", value,
            "must map each declared identity name to that Identity",
        )
    return freeze_mapping(value)


def execution_identity(context, request) -> Optional[Identity]:
    """Resolve a request identity or fail before invoking its executor."""
    name = request.placement.identity
    if not name:
        return None
    try:
        return context.identities[name]
    except KeyError:
        raise SpecError(
            "tool execution identity", name,
            "is not available in this execution context",
        ) from None


__all__ = ["execution_identity", "identity_catalog"]
