"""Declarative test host mappings shared by local and container backends."""

from __future__ import annotations

import dataclasses
import ipaddress
from typing import Iterable, Tuple

from brixtest.design import _name
from brixtest.errors import SpecError

__all__ = ["HostMapping", "host_mapping"]


def _hostname(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) > 253 or not value:
        raise SpecError(field, value, "must be a non-empty DNS hostname")
    labels = value.rstrip(".").split(".")
    if any(
        not label or len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum()
        or any(not (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        raise SpecError(field, value, "must contain valid DNS labels")
    return value.rstrip(".").lower()


@dataclasses.dataclass(frozen=True)
class HostMapping:
    """A canonical hostname, aliases, address, and optional reverse identity."""

    name: str
    hostname: str
    address: str = "127.0.0.1"
    aliases: Tuple[str, ...] = ()
    reverse: bool = True

    def __post_init__(self) -> None:
        _name(self.name, "host.name")
        object.__setattr__(self, "hostname", _hostname(self.hostname, "host.hostname"))
        try:
            normalized = str(ipaddress.ip_address(self.address))
        except ValueError as exc:
            raise SpecError("host.address", self.address, "must be an IPv4 or IPv6 address") from exc
        object.__setattr__(self, "address", normalized)
        if isinstance(self.aliases, (str, bytes)):
            raise SpecError("host.aliases", self.aliases, "must be a hostname sequence")
        aliases = tuple(_hostname(item, "host.alias") for item in self.aliases)
        if len(set(aliases)) != len(aliases) or self.hostname in aliases:
            raise SpecError("host.aliases", self.aliases, "must be unique and exclude the canonical hostname")
        object.__setattr__(self, "aliases", aliases)

    @property
    def hostnames(self) -> Tuple[str, ...]:
        """Canonical hostname followed by every normalized alias."""
        return (self.hostname, *self.aliases)


def host_mapping(
    name: str, hostname: str, *, address: str = "127.0.0.1",
    aliases: Iterable[str] = (), reverse: bool = True,
) -> HostMapping:
    """Declare backend-neutral forward and optional reverse test DNS."""
    if isinstance(aliases, (str, bytes)):
        raise SpecError("host.aliases", aliases, "must be a hostname sequence")
    return HostMapping(name, hostname, address, tuple(aliases), reverse)
