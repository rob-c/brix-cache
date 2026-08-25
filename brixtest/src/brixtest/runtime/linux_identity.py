"""Shared normalization for portable Linux identity declarations."""

from __future__ import annotations

import re
from typing import Sequence

from brixtest.errors import SpecError

_CAPABILITY = re.compile(r"^[a-z][a-z0-9_-]*$")


def linux_capabilities(values: Sequence[str]) -> tuple[str, ...]:
    """Return normalized kernel capability names or reject unsafe spelling."""
    if not all(_CAPABILITY.fullmatch(value) for value in values):
        raise SpecError(
            "identity.capabilities", tuple(values),
            "must contain portable lowercase Linux capability names",
        )
    return tuple(value.replace("-", "_").upper() for value in values)


__all__ = ["linux_capabilities"]
