"""Registered lifecycle profiles for server kinds.

A kind defines where its pidfile lives, how it
stops, how its process is spawned, and how readiness defaults.  The
core ships no rows — ``nginx``, ``xrootd`` and friends are adapter
registrations — so the generic engine never needs to know what an
nginx is.

Stop strategies understood by the local backend:

- ``"signal-pidfile"`` — SIGTERM the pid from ``pidfile``, escalate to
  SIGKILL after the spec's ``stop_timeout``.
- ``"port-kill"``      — find the pids holding the spec's ports and
  signal those (kinds with no pidfile, e.g. bare processes).
- ``"process-group"``  — signal only the backend-spawned process group;
  for case-owned non-daemonizing processes.
- ``"never"``          — the instance is externally managed; stopping
  the fleet must not touch it.
- a callable ``(backend, spec) -> None`` — kind-specific shutdown
  for kind-specific shutdown.
"""

from __future__ import annotations

import dataclasses
import threading
from typing import Callable, Dict, Optional, Sequence, Tuple, Union

from brixtest.errors import RegistrationError, UnknownKindError

__all__ = ["KindProfile", "clear_kinds", "get_kind", "known_kinds", "register_kind"]

StopStrategy = Union[str, Callable[..., None]]
_STOP_NAMES = ("signal-pidfile", "port-kill", "process-group", "never")

# argv builder: (spec, lane, values) -> argv.  ``values`` is the merged
# template mapping the backend used to render the instance config, so a
# command line can reference the same names the config file does.
CommandBuilder = Callable[..., Sequence[str]]


@dataclasses.dataclass(frozen=True)
class KindProfile:
    """Everything the engine needs to know about one kind of instance."""

    name: str
    pidfile: Optional[str]          # relative to the instance workdir, or None
    stop: StopStrategy              # see module docstring
    command: Optional[CommandBuilder] = None  # None: the spec must carry its own
    default_probe: str = "tcp"      # readiness alias when the spec says nothing
    ports_only_quiescence: bool = False  # proc-style kinds: no pidfile to consult

    def __post_init__(self) -> None:
        if isinstance(self.stop, str) and self.stop not in _STOP_NAMES:
            raise UnknownKindError(
                "%s (stop strategy %r)" % (self.name, self.stop), _STOP_NAMES
            )


_kinds: Dict[str, KindProfile] = {}
_lock = threading.Lock()


def register_kind(profile: KindProfile, *, replace: bool = False) -> KindProfile:
    with _lock:
        existing = _kinds.get(profile.name)
        if existing is not None and not replace:
            raise RegistrationError(profile.name, existing.name, "kind")
        _kinds[profile.name] = profile
    return profile


def get_kind(name: str) -> KindProfile:
    with _lock:
        try:
            return _kinds[name]
        except KeyError:
            raise UnknownKindError(name, sorted(_kinds)) from None


def known_kinds() -> Tuple[str, ...]:
    with _lock:
        return tuple(sorted(_kinds))


def clear_kinds() -> None:
    """Forget every registration — contract-kit and REPL use only."""
    with _lock:
        _kinds.clear()
