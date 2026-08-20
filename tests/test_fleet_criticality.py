# tests/test_fleet_criticality.py
"""Pins the all-or-nothing fleet-start barrier.

`critical` means "no suite without this": main nginx and the reference xrootd.
It must stay fatal when such an instance genuinely FAILS — a config error, a
port already bound, a dead binary — because a fleet missing main nginx tests
nothing.

Every declared server is now equally required by the collection barrier:
ordinary launch failures and unavailable optional tooling both abort before the
first test can run. These cases are fleet-free: `start` is stubbed.

    PYTHONPATH=tests pytest tests/test_fleet_criticality.py -v
"""

from __future__ import annotations

import pytest

import _server_launcher_part2_mixina as mixina
from fleet_specs import core_specs
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.timeout(60)

UNAVAILABLE = "selected xrootd binary is unavailable: xrootd"


class _StubLauncher(mixina._RegistryLauncherMixinA):
    """A launcher whose `start` raises to order, so only the verdict is tested.

    WHAT: maps spec name -> exception to raise (absent name = starts cleanly)
    and records what actually started.
    WHY: the decision under test is "does this abort start-all", which needs no
    process, port or config — spawning a real fleet would only add flakiness.
    HOW: overrides `start`, the single seam both `_start_guarded` and
    `_start_level` go through.
    """

    def __init__(self, failures: dict[str, BaseException] | None = None) -> None:
        self.failures = failures or {}
        self.started: list[str] = []

    def start(self, spec: NginxInstanceSpec) -> None:
        """Raise this spec's scripted exception, else record it as started."""
        exc = self.failures.get(spec.name)
        if exc is not None:
            raise exc
        self.started.append(spec.name)


def _spec(name: str, *, critical: bool, kind: str = "nginx") -> NginxInstanceSpec:
    """Build a minimal spec — only name, tags and kind matter to the verdict."""
    tags = ("core", "critical") if critical else ("core",)
    return NginxInstanceSpec(name=name, template=f"{name}.conf", tags=tags, kind=kind)


def test_unavailable_critical_spec_aborts_the_fleet() -> None:
    """A missing required binary fails collection before tests are dispatched."""
    launcher = _StubLauncher({"ref-anon": pytest.skip.Exception(UNAVAILABLE)})
    with pytest.raises(RuntimeError, match="ref-anon.*failed to launch"):
        launcher._start_guarded(_spec("ref-anon", critical=True, kind="xrootd"))


def test_failing_critical_spec_still_aborts_the_fleet() -> None:
    """A real failure stays fatal — an unbindable main nginx must not be absorbed."""
    boom = RuntimeError("bind() to 0.0.0.0:10001 failed (98: Address already in use)")  # net-literal-allow: synthetic error text
    launcher = _StubLauncher({"main": boom})
    with pytest.raises(RuntimeError, match="Address already in use"):
        launcher._start_guarded(_spec("main", critical=True))


def test_the_parallel_path_fails_for_an_unavailable_server() -> None:
    """Parallel launch applies the same all-or-nothing barrier."""
    level = [_spec("main", critical=True), _spec("ref-anon", critical=True, kind="xrootd")]
    launcher = _StubLauncher({"ref-anon": pytest.skip.Exception(UNAVAILABLE)})
    with pytest.raises(RuntimeError, match="ref-anon.*failed to launch"):
        launcher._start_level(level, 2)

    launcher = _StubLauncher({"main": RuntimeError("nginx: [emerg] still could not bind()")})
    with pytest.raises(RuntimeError, match="could not bind"):
        launcher._start_level(level, workers=2)


def test_non_critical_specs_also_abort_collection() -> None:
    """No optional failure can be hidden behind a green test run."""
    launcher = _StubLauncher(
        {
            "krb5-kdc": pytest.skip.Exception("krb5-kdc: subsystem unavailable (rc=3)"),
            "compress": RuntimeError("failed rc=1"),
        }
    )
    with pytest.raises(RuntimeError, match="krb5-kdc.*failed to launch"):
        launcher._start_guarded(_spec("krb5-kdc", critical=False))
    with pytest.raises(RuntimeError, match="compress.*failed to launch"):
        launcher._start_guarded(_spec("compress", critical=False))


def test_missing_xrootd_binary_skips_rather_than_fails(monkeypatch) -> None:
    """The input to the whole verdict: an absent binary raises Skipped, not an error.

    If `_start_xrootd` ever reported a missing binary as a hard failure instead,
    it would be indistinguishable from a broken reference server and would abort
    start-all again — with the same green-but-empty CI lane as the result.
    """
    monkeypatch.setattr(mixina.shutil, "which", lambda _name: None)
    with pytest.raises(pytest.skip.Exception, match="unavailable"):
        _StubLauncher()._start_xrootd(_spec("ref-anon", critical=True, kind="xrootd"))


def test_only_main_and_the_reference_xrootd_are_critical() -> None:
    """Guards the blast radius: the tag stays on the two specs reasoned about above."""
    critical = {s.name: s.kind for s in core_specs() if "critical" in s.tags}
    assert critical == {"main": "nginx", "ref-anon": "xrootd"}
