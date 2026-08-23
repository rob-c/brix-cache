"""Immutable named-port allocation."""

from __future__ import annotations

import os
from typing import Dict, Iterator, Mapping, Optional, Tuple

from brixtest.errors import SpecError

__all__ = ["PortLedger"]


class PortLedger:
    """Name-to-port mapping derived from a base and optional overrides."""

    @staticmethod
    def _resolved_ports(
        port_base: int, offsets: Mapping[str, int], env_prefix: str,
        environ: Mapping[str, str],
    ) -> Dict[str, int]:
        ports: Dict[str, int] = {}
        for name, offset in offsets.items():
            if offset < 0:
                raise SpecError("offsets[%s]" % name, offset, "offset must be >= 0")
            override = environ.get(env_prefix + name)
            ports[name] = int(override) if override else port_base + offset
        return ports

    @staticmethod
    def _reverse(ports: Mapping[str, int]) -> Dict[int, str]:
        reverse: Dict[int, str] = {}
        for name, port in ports.items():
            if port in reverse:
                raise SpecError(
                    "offsets", name,
                    "port %d assigned to both %r and %r" % (port, reverse[port], name),
                )
            reverse[port] = name
        return reverse

    @staticmethod
    def _add_aliases(ports: Dict[str, int], aliases: Mapping[str, str]) -> None:
        for alias, owner in aliases.items():
            if owner not in ports:
                raise SpecError("aliases[%s]" % alias, owner, "owner is not a ledger name")
            if alias in ports:
                raise SpecError("aliases[%s]" % alias, owner, "alias collides with a ledger name")
            ports[alias] = ports[owner]

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
        self._ports = self._resolved_ports(port_base, offsets, env_prefix, environ)
        self._by_port = self._reverse(self._ports)
        self._add_aliases(self._ports, aliases or {})

    def __getitem__(self, name: str) -> int:
        try:
            return self._ports[name]
        except KeyError:
            raise SpecError(
                "port name", name,
                "not in the ledger — known names: %s" % ", ".join(sorted(self._ports)),
            ) from None

    def __getattr__(self, name: str) -> int:
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
