"""Host capability probes for fleet members with host-specific prerequisites.

Some registered fleet members exec a third-party daemon (``haproxy``, the
reference ``xrootd``) that a host may not have installed, and a config
template may one day need a directive this host cannot honour.  On such a
host the member's launch fails and, because the registry launcher treats
every failure as fatal, the WHOLE collection-time fleet barrier aborts —
zero tests run.

This module answers "which registered specs cannot start here, and why", so
the barrier boots the rest of the fleet and the tests that declared the
missing member are skipped with that reason instead.  Probes are cached for
the process; they never change mid-session.

``brix_require_vo`` needs no probe: VOMS attribute certificates are verified
natively by the module (``shared/voms/``), so the ``vo-acl`` member boots on
every host, macOS included.
"""
from __future__ import annotations

import functools
import os
import shutil
import sys
from typing import Callable, Iterable

from brix_suite.settings import TESTS_DIR

#: (directive substring, human reason, probe) — a template containing the
#: directive is unavailable when the probe is False.  Empty today; the
#: template scan stays so a future host-bound directive is a one-line entry.
_DIRECTIVE_NEEDS: tuple[tuple[str, str, Callable[[], bool]], ...] = ()


@functools.lru_cache(maxsize=None)
def template_unavailable_reason(template: str) -> str | None:
    """Why a config template cannot start on this host, or None if it can."""
    path = os.path.join(TESTS_DIR, "configs", template)
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return None
    for directive, reason, probe in _DIRECTIVE_NEEDS:
        if directive in text and not probe():
            return f"{template} uses {directive}: {reason}"
    return None


#: Member kinds that exec a third-party daemon: kind → binary on PATH.
_KIND_BINARIES = {
    "haproxy": "haproxy",
    "xrootd": "xrootd",
    "xrdhttp": "xrootd",
}


@functools.lru_cache(maxsize=None)
def kind_unavailable_reason(kind: str) -> str | None:
    binary = _KIND_BINARIES.get(kind)
    if binary and shutil.which(binary) is None:
        return f"{binary} is not installed on this host"
    return None


def _direct_reason(spec) -> str | None:
    return (kind_unavailable_reason(spec.kind)
            or template_unavailable_reason(spec.template))


def _blocked_by_requires(spec, reasons: dict[str, str]) -> str | None:
    for dep in spec.requires:
        if dep in reasons:
            return f"requires {dep}: {reasons[dep]}"
    return None


def unavailable_specs(specs: Iterable) -> dict[str, str]:
    """``{spec.name: reason}`` for every spec that cannot start here, plus
    every spec that ``requires`` one of them (transitively)."""
    specs = list(specs)
    reasons = {spec.name: reason for spec in specs
               if (reason := _direct_reason(spec))}
    while _propagate_once(specs, reasons):
        pass
    return reasons


def _propagate_once(specs, reasons: dict[str, str]) -> bool:
    """Mark specs blocked by an already-unavailable dependency; True if any."""
    added = {spec.name: reason for spec in specs
             if spec.name not in reasons
             and (reason := _blocked_by_requires(spec, reasons))}
    reasons.update(added)
    return bool(added)


def boot_specs(specs: Iterable) -> list:
    """The specs to boot on this host; each one left out is reported on stderr."""
    kept, dropped = filter_available(specs)
    for name, reason in sorted(dropped.items()):
        print(f"[conftest] fleet member {name!r} not started: {reason}", file=sys.stderr)
    return kept


def declared_members(item) -> list[str]:
    """Fleet member names a collected pytest item declares via its markers."""
    names: list[str] = []
    for marker_name in ("registry_server", "registry_servers"):
        marker = item.get_closest_marker(marker_name)
        if marker:
            names.extend(str(arg) for arg in marker.args)
    return names


def skip_unavailable_items(items, specs, skip_marker) -> None:
    """Add ``skip_marker(reason)`` to every item declaring an unavailable member."""
    dropped = unavailable_specs(specs)
    if not dropped:
        return
    for item in items:
        missing = [name for name in declared_members(item) if name in dropped]
        if missing:
            item.add_marker(skip_marker(
                reason=f"fleet member {missing[0]} unavailable: {dropped[missing[0]]}"))


def filter_available(specs: Iterable) -> tuple[list, dict[str, str]]:
    """Split ``specs`` into (startable, {name: reason}) for this host."""
    specs = list(specs)
    dropped = unavailable_specs(specs)
    return [spec for spec in specs if spec.name not in dropped], dropped
