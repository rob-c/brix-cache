"""Declarative test host mappings shared by local and container backends."""

from __future__ import annotations

import dataclasses
import ipaddress
from typing import Iterable, Sequence, Tuple

from brixtest.design import _name
from brixtest.errors import SpecError

__all__ = ["HostMapping", "host_mapping"]


def _hostname(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) > 253 or not value:
        raise SpecError(field, value, "must be a non-empty DNS hostname")
    labels = value.rstrip(".").split(".")
    if not all(_dns_label(label) for label in labels):
        raise SpecError(field, value, "must contain valid DNS labels")
    return value.rstrip(".").lower()


def _dns_label(label: str) -> bool:
    if not label or len(label) > 63:
        return False
    if not label[0].isalnum() or not label[-1].isalnum():
        return False
    return all(char.isalnum() or char == "-" for char in label)


def _mapping_policy(reverse: object, libc: object) -> None:
    if not isinstance(reverse, bool) or not isinstance(libc, bool):
        raise SpecError(
            "host mapping policy", (reverse, libc),
            "reverse and libc must be booleans",
        )


def _mapping_targets(values: object) -> Tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise SpecError("host.targets", values, "must be a role sequence")
    selected = tuple(values)
    if not _valid_targets(selected):
        raise SpecError(
            "host.targets", selected,
            "must contain unique server, client, or test roles",
        )
    return selected


def _valid_targets(values: Tuple[object, ...]) -> bool:
    if not all(isinstance(item, str) for item in values):
        return False
    unique = set(values)
    return len(unique) == len(values) and unique <= {"server", "client", "test"}


def _require_libc_target(
    reverse: bool, libc: bool, targets: Tuple[str, ...],
) -> None:
    if libc and not targets:
        raise SpecError("host.targets", targets, "libc mappings need at least one consumer role")
    if libc and not reverse:
        raise SpecError(
            "host.libc", libc,
            "hosts-file backends cannot provide forward-only libc mappings",
        )


@dataclasses.dataclass(frozen=True)
class HostMapping:
    """A canonical hostname, aliases, address, and optional reverse identity."""

    name: str
    hostname: str
    address: str = "127.0.0.1"
    aliases: Tuple[str, ...] = ()
    reverse: bool = True
    libc: bool = False
    targets: Tuple[str, ...] = ("server", "client")

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
        _mapping_policy(self.reverse, self.libc)
        targets = _mapping_targets(self.targets)
        _require_libc_target(self.reverse, self.libc, targets)
        object.__setattr__(self, "targets", targets)

    @property
    def hostnames(self) -> Tuple[str, ...]:
        """Canonical hostname followed by every normalized alias."""
        return (self.hostname, *self.aliases)


def host_mapping(
    name: str, hostname: str, *, address: str = "127.0.0.1",
    aliases: Iterable[str] = (), reverse: bool = True, libc: bool = False,
    targets: Sequence[str] = ("server", "client"),
) -> HostMapping:
    """Declare backend-neutral forward and optional reverse test DNS."""
    if isinstance(aliases, (str, bytes)):
        raise SpecError("host.aliases", aliases, "must be a hostname sequence")
    return HostMapping(
        name, hostname, address, tuple(aliases), reverse, libc, tuple(targets),
    )
