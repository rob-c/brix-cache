# tests/test_fleet_criticality.py
"""Pins what a `critical` fleet spec is allowed to do to `start-all`.

`critical` means "no suite without this": main nginx and the reference xrootd.
It must stay fatal when such an instance genuinely FAILS — a config error, a
port already bound, a dead binary — because a fleet missing main nginx tests
nothing.

It must NOT be fatal when the instance is merely UNAVAILABLE on this host.
Every `pytest.skip` the launcher raises is that second signal (stock `xrootd`,
the XrdHttp libs, `haproxy`, an external subsystem, root privileges). GitHub's
`ubuntu-latest` has no stock XRootD, so the critical `ref-anon` spec skipped,
`start-all` aborted, and the `asan` lane reported success having booted no
fleet and exercised nothing:

    [registry] non-critical spec 'interop-off' did not start (Skipped: selected
        xrootd binary is unavailable: xrootd); continuing.
    Skipped: selected xrootd binary is unavailable: xrootd
    asan: SKIP — sanitized fleet failed to boot on this runner

These cases are fleet-free: `start` is stubbed, so nothing is spawned.

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


def _must_not_abort(call, *args) -> None:
    """Run a start path, turning an aborted fleet into a FAILURE, not a skip.

    WHAT: calls `call(*args)` and converts a propagating `Skipped` into
    `pytest.fail`.
    WHY: a critical spec that aborts start-all does so by letting `Skipped`
    escape — which pytest would charge to this very test, marking the guard
    skipped and therefore quietly green in CI at the exact moment the bug
    returned. Confirmed: against the pre-fix launcher these cases skip; with
    this conversion they fail.
    HOW: only `Skipped` is intercepted; a real error still surfaces as an error.
    """
    try:
        call(*args)
    except pytest.skip.Exception as exc:
        pytest.fail(f"an unavailable critical spec aborted start-all: {exc}")


def test_unavailable_critical_spec_does_not_abort_the_fleet(capsys) -> None:
    """The CI shape: stock xrootd absent -> ref-anon skips, main still boots."""
    launcher = _StubLauncher({"ref-anon": pytest.skip.Exception(UNAVAILABLE)})
    for spec in (_spec("main", critical=True), _spec("ref-anon", critical=True, kind="xrootd")):
        _must_not_abort(launcher._start_guarded, spec)
    assert launcher.started == ["main"]
    assert "critical spec 'ref-anon' did not start" in capsys.readouterr().err


def test_failing_critical_spec_still_aborts_the_fleet() -> None:
    """A real failure stays fatal — an unbindable main nginx must not be absorbed."""
    boom = RuntimeError("bind() to 0.0.0.0:10001 failed (98: Address already in use)")
    launcher = _StubLauncher({"main": boom})
    with pytest.raises(RuntimeError, match="Address already in use"):
        launcher._start_guarded(_spec("main", critical=True))


def test_the_parallel_path_reaches_the_same_verdict(capsys) -> None:
    """`_start_level` must not diverge from `_start_guarded` on either answer."""
    level = [_spec("main", critical=True), _spec("ref-anon", critical=True, kind="xrootd")]
    launcher = _StubLauncher({"ref-anon": pytest.skip.Exception(UNAVAILABLE)})
    _must_not_abort(launcher._start_level, level, 2)
    assert launcher.started == ["main"]
    assert "critical spec 'ref-anon' did not start" in capsys.readouterr().err

    launcher = _StubLauncher({"main": RuntimeError("nginx: [emerg] still could not bind()")})
    with pytest.raises(RuntimeError, match="could not bind"):
        launcher._start_level(level, workers=2)


def test_non_critical_specs_are_absorbed_either_way(capsys) -> None:
    """Unchanged behaviour: optional daemons never abort start-all, skip or fail."""
    launcher = _StubLauncher(
        {
            "krb5-kdc": pytest.skip.Exception("krb5-kdc: subsystem unavailable (rc=3)"),
            "compress": RuntimeError("failed rc=1"),
        }
    )
    for name in ("krb5-kdc", "compress", "plain"):
        launcher._start_guarded(_spec(name, critical=False))
    assert launcher.started == ["plain"]
    err = capsys.readouterr().err
    assert "non-critical spec 'krb5-kdc' did not start" in err
    assert "non-critical spec 'compress' did not start" in err


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
