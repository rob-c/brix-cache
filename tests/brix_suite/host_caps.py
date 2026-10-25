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
import re
import shutil
import shlex
import sys
from typing import Callable, Iterable

from brix_suite.settings import TESTS_DIR

def _worker_subprocess_supported() -> bool:
    """Match BRIX_HAS_WORKER_EXEC in the server PAL host headers."""
    return sys.platform != "darwin" and not sys.platform.startswith("win")


#: (directive substring, human reason, probe) — a template containing the
#: directive is unavailable when the probe is False.
_DIRECTIVE_NEEDS: tuple[tuple[str, str, Callable[[], bool]], ...] = tuple(
    (directive,
     "hardened workers cannot execute subprocesses on this host",
     _worker_subprocess_supported)
    for directive in ("brix_prepare_command", "brix_frm_stagecmd",
                      "brix_frm_purge_polprog", "brix_cms_perf_pgm", "brix_cms_fsxeq")
)


def configuration_unavailable_reason(text: str) -> str | None:
    """Probe real directives, never explanatory comments or quoted values."""
    if _worker_subprocess_supported():
        return None
    try:
        commands = list(_configuration_commands(text))
    except ValueError:
        return None  # nginx, not a capability probe, owns malformed syntax
    for command in commands:
        reason = _command_unavailable_reason(command)
        if reason:
            return reason
    return None


def _command_unavailable_reason(command):
    """Check an already-tokenized command on a worker-exec-limited host."""
    for directive, reason, probe in _DIRECTIVE_NEEDS:
        if command[0] == directive and not probe():
            return f"{directive}: {reason}"
    return _external_storage_reason(command)


def _external_storage_reason(command):
    """Only actual exec-based storage adapters need a worker subprocess."""
    if command[0] != "brix_storage_backend" or len(command) < 2:
        return None
    if re.match(r"^(frm|tape)://(exec|hpss|cta)(/|\?|$)", command[1]):
        return "external MSS adapter: hardened workers cannot execute subprocesses on this host"
    return None


def _configuration_commands(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";{}")
    lexer.whitespace_split = True
    command = []
    for token in lexer:
        if set(token) <= set(";{}"):
            if command:
                yield command
            command = []
        else:
            command.append(token)


@functools.lru_cache(maxsize=None)
def template_unavailable_reason(template: str) -> str | None:
    """Why a config template cannot start on this host, or None if it can."""
    path = os.path.join(TESTS_DIR, "configs", template)
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return None
    reason = configuration_unavailable_reason(text)
    return f"{template} uses {reason}" if reason else None


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


def _external_unavailable_reason(spec) -> str | None:
    """Probe external orchestrators whose prerequisite is not one executable."""
    if spec.name != "krb5-kdc":
        return None
    from brix_suite.security.kdc import krb5_tools_available  # noqa: PLC0415

    if not krb5_tools_available():
        return "MIT KDC tooling is not installed on this host"
    return None


def _direct_reason(spec) -> str | None:
    return (kind_unavailable_reason(spec.kind)
            or _external_unavailable_reason(spec)
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
