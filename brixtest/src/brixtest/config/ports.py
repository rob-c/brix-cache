"""The port ledger (feature F7).

Named ports are data, not module globals.  A ``PortLedger`` derives
every named port from the lane's ``port_base`` plus a per-name offset,
honours per-name environment overrides (``TEST_<NAME>`` by
convention), and can enumerate itself — which is what makes the
undeclared-server gate's port-binding channel and the CLI's
``lane status`` table possible.  The grown suite kept these as ~40
module-level integer constants that a launcher mutated in place;
the ledger is that capability with the mutation removed.
"""

from __future__ import annotations

import os
from typing import Dict, Iterator, Mapping, Optional, Tuple

from brixtest.errors import SpecError

__all__ = ["PortLedger"]


class PortLedger:
    """Immutable name → port mapping derived from a base.

    ``offsets`` maps a symbolic name (``"WEBDAV_PORT"``) to its offset
    from ``port_base``.  An environment variable ``<env_prefix><NAME>``
    overrides the derived value for that name only — the override is
    read once, at construction, so a ledger never changes underneath a
    running fleet.

    ``aliases`` maps a second spelling onto an owning name: one socket,
    two names (the grown suite's ``XRDHTTP_HTTPS_PORT`` is the same
    listener as ``XRDHTTP_HTTP_PORT``).  An alias resolves to its
    owner's port, is enumerated by ``iter_named_ports`` like any name,
    but never participates in duplicate detection — ``name_of`` answers
    with the owner.
    """

    def __init__(
        self,
        port_base: int,
        offsets: Mapping[str, int],
        *,
        aliases: Optional[Mapping[str, str]] = None,
        env_prefix: str = "TEST_",
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        if port_base < 1024:
            raise SpecError("port_base", port_base, "must be an unprivileged port (>= 1024)")
        environ = os.environ if env is None else env
        self.port_base = port_base
        self._ports: Dict[str, int] = {}
        for name, offset in offsets.items():
            if offset < 0:
                raise SpecError("offsets[%s]" % name, offset, "offset must be >= 0")
            override = environ.get(env_prefix + name)
            self._ports[name] = int(override) if override else port_base + offset
        reverse: Dict[int, str] = {}
        for name, port in self._ports.items():
            if port in reverse:
                raise SpecError(
                    "offsets", name,
                    "port %d assigned to both %r and %r" % (port, reverse[port], name),
                )
            reverse[port] = name
        self._by_port = reverse
        for alias, owner in (aliases or {}).items():
            if owner not in self._ports:
                raise SpecError(
                    "aliases[%s]" % alias, owner, "owner is not a ledger name")
            if alias in self._ports:
                raise SpecError(
                    "aliases[%s]" % alias, owner, "alias collides with a ledger name")
            self._ports[alias] = self._ports[owner]

    def __getitem__(self, name: str) -> int:
        try:
            return self._ports[name]
        except KeyError:
            raise SpecError(
                "port name", name,
                "not in the ledger — known names: %s" % ", ".join(sorted(self._ports)),
            ) from None

    def __getattr__(self, name: str) -> int:
        # Attribute-style access for the named constants (§9.2.1: "one
        # named attribute per constant").  Only called for names not found
        # normally, so _ports/port_base/methods are never shadowed.
        try:
            return self.__dict__["_ports"][name]
        except KeyError:
            raise AttributeError(name) from None

    def get(self, name: str, default: Optional[int] = None) -> Optional[int]:
        return self._ports.get(name, default)

    def name_of(self, port: int) -> Optional[str]:
        return self._by_port.get(port)

    def iter_named_ports(self) -> Iterator[Tuple[str, int]]:
        """(name, port) pairs in name order — the gate and CLI both walk this."""
        for name in sorted(self._ports):
            yield name, self._ports[name]

    def as_values(self) -> Dict[str, int]:
        """A template-values mapping for ``render_cfg`` (name → port)."""
        return dict(self._ports)

    def __contains__(self, name: str) -> bool:
        return name in self._ports

    def __len__(self) -> int:
        return len(self._ports)

    def __repr__(self) -> str:
        return "PortLedger(base=%d, %d names)" % (self.port_base, len(self._ports))
