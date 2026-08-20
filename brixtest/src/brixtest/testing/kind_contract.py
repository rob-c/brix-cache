"""The kind contract kit: what every registered ``KindProfile`` owes.

An adapter calls ``check_kind_contract(profile)`` from a test of its
own (BriXTest itself ships no tests initially — the kits exist so the
*adapter's* suite can hold its registrations to the core's bar).

Six enumerated obligations:

1. the profile is registered under its own name;
2. the stop strategy is a known name or a callable;
3. a ``pidfile`` kind's stop strategy can actually use it —
   ``signal-pidfile`` without a pidfile path is a contradiction;
4. a pidfile path is relative (the workdir prefixes it);
5. ``default_probe`` resolves through the alias table;
6. a ``ports_only_quiescence`` kind must not claim a pidfile —
   quiescence-by-ports exists precisely because there is none.
"""

from __future__ import annotations

from pathlib import PurePath
from typing import List

from brixtest.fleet.kinds import KindProfile, get_kind
from brixtest.fleet.probes import probe_from_alias

__all__ = ["check_kind_contract"]


def check_kind_contract(profile: KindProfile) -> List[str]:
    """Returns violation strings; an empty list is a pass.  The adapter's
    test asserts ``== []`` so every violation prints at once."""
    violations: List[str] = []

    registered = None
    try:
        registered = get_kind(profile.name)
    except Exception:
        violations.append("1: kind %r is not registered" % profile.name)
    if registered is not None and registered is not profile:
        violations.append("1: a different profile is registered under %r" % profile.name)

    if not callable(profile.stop) and profile.stop not in (
        "signal-pidfile", "port-kill", "never"
    ):
        violations.append("2: stop strategy %r is neither known nor callable" % (profile.stop,))

    if profile.stop == "signal-pidfile" and profile.pidfile is None:
        violations.append("3: signal-pidfile stop with no pidfile path")

    if profile.pidfile is not None and PurePath(profile.pidfile).is_absolute():
        violations.append("4: pidfile %r must be workdir-relative" % profile.pidfile)

    try:
        probe_from_alias(profile.default_probe)
    except Exception as exc:
        violations.append("5: default_probe %r does not resolve (%s)" % (profile.default_probe, exc))

    if profile.ports_only_quiescence and profile.pidfile is not None:
        violations.append(
            "6: ports_only_quiescence with a pidfile — pick one story for shutdown proof"
        )

    return violations
