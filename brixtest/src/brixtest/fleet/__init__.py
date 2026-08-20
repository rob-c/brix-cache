"""Fleet layer: what runs (registry), how each kind behaves (kinds),
how readiness is proven (probes), what tests need (declares), what must
exist first (prep), and the start/stop engine (launcher, orphans)."""

from brixtest.fleet.kinds import KindProfile, get_kind, known_kinds, register_kind
from brixtest.fleet.registry import InstanceSpec, Registry, ServerEndpoint

__all__ = [
    "InstanceSpec",
    "KindProfile",
    "Registry",
    "ServerEndpoint",
    "get_kind",
    "known_kinds",
    "register_kind",
]
