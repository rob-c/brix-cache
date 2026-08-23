"""Contract checks for registered server kinds."""

from __future__ import annotations

from pathlib import PurePath
from typing import List

from brixtest.fleet.kinds import KindProfile, get_kind
from brixtest.fleet.probes import probe_from_alias

__all__ = ["check_kind_contract"]


def check_kind_contract(profile: KindProfile) -> List[str]:
    """Return every contract violation for one kind profile."""
    violations = _registration_violations(profile)
    checks = (
        _stop_violation(profile), _pidfile_stop_violation(profile),
        _pidfile_path_violation(profile), _probe_violation(profile),
        _quiescence_violation(profile),
    )
    violations.extend(item for item in checks if item is not None)
    return violations


def _registration_violations(profile: KindProfile) -> List[str]:
    violations = []
    registered = None
    try:
        registered = get_kind(profile.name)
    except Exception:
        violations.append("1: kind %r is not registered" % profile.name)
    if registered is not None and registered is not profile:
        violations.append("1: a different profile is registered under %r" % profile.name)
    return violations


def _stop_violation(profile: KindProfile):
    if not callable(profile.stop) and profile.stop not in (
        "signal-pidfile", "port-kill", "never"
    ):
        return "2: stop strategy %r is neither known nor callable" % (profile.stop,)
    return None


def _pidfile_stop_violation(profile: KindProfile):
    if profile.stop == "signal-pidfile" and profile.pidfile is None:
        return "3: signal-pidfile stop with no pidfile path"
    return None


def _pidfile_path_violation(profile: KindProfile):
    if profile.pidfile is not None and PurePath(profile.pidfile).is_absolute():
        return "4: pidfile %r must be workdir-relative" % profile.pidfile
    return None


def _probe_violation(profile: KindProfile):
    try:
        probe_from_alias(profile.default_probe)
    except Exception as exc:
        return "5: default_probe %r does not resolve (%s)" % (profile.default_probe, exc)
    return None


def _quiescence_violation(profile: KindProfile):
    if profile.ports_only_quiescence and profile.pidfile is not None:
        return (
            "6: ports_only_quiescence with a pidfile; choose one shutdown mechanism"
        )
    return None
