"""Fixed-port ledgers for the lifecycle-harness test instances.

The ledger data lives in three sibling modules, split by band (and, for the
larger shared band, by conversion generation) so each stays inside the
file-size tiers:

* ``fleet_ports_exclusive`` — the ``lifecycle-exclusive`` band: mutation
  subjects (reload/restart/reopen/kill-worker).
* ``fleet_ports_shared_waves`` — the ``lifecycle-shared`` band, conversion
  waves 1-7a.
* ``fleet_ports_shared_phase5`` — the same band, wave-7b singletons, the
  Phase-5 close-out and everything ledgered since; **new entries go here.**

They are plain modules rather than ``split_continuation`` shards because the
ledger is data with no backward references: each half is independently
importable, and the merge below is the only place the two meet.

This module is the whole import surface: consumers keep importing
``LIFECYCLE_EXCLUSIVE_PORTS``, ``LIFECYCLE_SHARED_PORTS``,
``PARSE_PLACEHOLDER_PORT``, ``SHARED_PARSE_PLACEHOLDER_PORT`` and
``lifecycle_ports_for`` from here — and only here are the ports the ladder-rebased
ones.  ``test_fleet_ports`` lints the merged result.
"""

from __future__ import annotations

from fleet_ports_exclusive import LIFECYCLE_EXCLUSIVE_PORTS
from fleet_ports_shared_phase5 import LIFECYCLE_SHARED_PORTS_PHASE5
from fleet_ports_shared_waves import LIFECYCLE_SHARED_PORTS_WAVES

__all__ = [
    "LIFECYCLE_EXCLUSIVE_PORTS",
    "LIFECYCLE_SHARED_PORTS",
    "PARSE_PLACEHOLDER_PORT",
    "SHARED_PARSE_PLACEHOLDER_PORT",
    "lifecycle_ports_for",
]

# A name declared in both halves would be silently resolved by the merge below
# (last one wins), and the collision linter only catches it when the two entries
# disagree on the number — so reject the duplicate outright here.
_shared_dupes = sorted(
    set(LIFECYCLE_SHARED_PORTS_WAVES) & set(LIFECYCLE_SHARED_PORTS_PHASE5))
if _shared_dupes:
    raise AssertionError(
        "lifecycle-shared spec name(s) declared in both ledger halves: "
        + ", ".join(_shared_dupes))

# Waves first, then Phase-5: the merge order IS the ladder-slot order (see the
# rebase at the foot of this module), so it must match the halves' own order.
# The entry objects are shared with the halves, so the in-place rebase below
# reaches them too — a half never holds a stale port.
LIFECYCLE_SHARED_PORTS: dict[str, dict] = {
    **LIFECYCLE_SHARED_PORTS_WAVES,
    **LIFECYCLE_SHARED_PORTS_PHASE5,
}

# Non-binding placeholder port for standalone `nginx_t` parse tests (nginx -t
# never binds a listen) that render a config needing a {PORT} value.  Kept in the
# lifecycle-exclusive band but deliberately NOT a registered listener (well clear
# of the allocated ledger ports above).
PARSE_PLACEHOLDER_PORT = 31999

# Non-binding placeholder for lifecycle-shared-band `nginx -t`-only instances
# (register + render + nginx_test, never a live listen).  Distinct from the
# exclusive-band placeholder; kept well clear of the allocated shared ports.
SHARED_PARSE_PLACEHOLDER_PORT = 30999


def lifecycle_ports_for(name: str) -> tuple[int | None, dict[str, int]]:
    """Fixed ``(primary_port, extra_ports)`` for a lifecycle-subject spec name.

    Consults the exclusive (Bucket-2 mutation) ledger first, then the shared
    (Bucket-1 idempotent) ledger.  Returns ``(None, {})`` when the name is on
    neither, so the caller falls back to the legacy per-pid dynamic-port path
    unchanged.
    """
    entry = LIFECYCLE_EXCLUSIVE_PORTS.get(name) or LIFECYCLE_SHARED_PORTS.get(name)
    if entry is None:
        return None, {}
    return entry["port"], dict(entry.get("extra", {}))


# Values written in the two ledgers above are the original ports used by the
# tests that introduced them.  Runtime listeners are packed into the shared
# TEST_PORT_START ladder only after the complete ledgers have been declared.
from port_ladder import placeholder_port, rebase_lifecycle_ledger
rebase_lifecycle_ledger(LIFECYCLE_SHARED_PORTS, shared=True)
rebase_lifecycle_ledger(LIFECYCLE_EXCLUSIVE_PORTS, shared=False)
SHARED_PARSE_PLACEHOLDER_PORT = placeholder_port(0)
PARSE_PLACEHOLDER_PORT = placeholder_port(1)
