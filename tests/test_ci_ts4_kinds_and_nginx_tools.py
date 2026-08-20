"""TS-4 pins: the six kind rows, and the de-triplicated nginx helpers.

testsuite-modernization-plan.md TS-4 items 2 and 3.

Item 2 introduces `brix_suite.kinds` — the six kinds this fleet runs, as
rows against `brixtest.fleet.kinds` instead of the four `if spec.kind ==`
ladders in the launcher.  Nothing reads the rows yet; item 5 flips the
ladders onto them one at a time.  Which makes THIS the load-bearing
test: it asserts the rows describe what the ladders already do, so a
later flip is a refactor and not a behavior change discovered in
production.

Item 3 collapses `_nginx_bin` and the two config injectors from four
byte-identical copies to one.  `check_duplication` never saw them —
its unit is the function, and four identical functions in four files
each look like exactly one.

  success   — every row passes the core's kind-contract kit; every
              `start_method` names a real launcher method; the four
              modules now share one function object per helper.
  error     — an unknown kind name, and an invalid quiescence mode, are
              both refused with a message naming the valid values.
  security  — `external` is NEVER reported quiescent, even with nothing
              listening and no pidfile on disk.  Quiescence is a licence
              to skip stopping, and an `external` instance is by
              definition one this lane did not start; guessing wrong
              there means walking away from another lane's process (§14).
"""

import os
from pathlib import Path

import pytest

import settings
from brixtest.fleet.kinds import known_kinds
from brixtest.testing.kind_contract import check_kind_contract

from brix_suite.kinds import KIND_PROFILES, LAUNCHER_KINDS, LauncherKind, launcher_kind

import server_launcher
from server_launcher import RegistryLauncher
from server_registry import InstanceSpec, clear_registry, endpoint_for, register_nginx

_PORT = 19870  # unused by the ladder; these specs are never started


@pytest.fixture
def launcher():
    return RegistryLauncher(settings.TESTS_DIR)


@pytest.fixture
def spec_for():
    """Register a throwaway spec of a given kind and yield it."""
    created = []

    def make(kind, name=None, port=_PORT):
        name = name or "kindparity-%s" % kind
        spec = register_nginx(InstanceSpec(
            name=name, template="nginx_registry_smoke.conf", port=port, kind=kind))
        created.append(spec)
        return spec

    clear_registry()
    yield make
    for spec in created:
        prefix = Path(endpoint_for(spec).prefix)
        for rel in ("logs/nginx.pid", "run/xrootd.pid", "logs/haproxy.pid"):
            try:
                (prefix / rel).unlink()
            except OSError:
                pass
    clear_registry()


# --- success ---------------------------------------------------------------


def test_every_row_satisfies_the_core_kind_contract():
    violations = {name: check_kind_contract(profile)
                  for name, profile in KIND_PROFILES.items()}
    assert {k: v for k, v in violations.items() if v} == {}


def test_the_six_kinds_are_registered_with_the_core():
    assert known_kinds() == ("external", "haproxy", "nginx", "proc",
                             "xrdhttp", "xrootd")
    assert set(LAUNCHER_KINDS) == set(KIND_PROFILES)


def test_every_start_method_names_a_real_launcher_method(launcher):
    for row in LAUNCHER_KINDS.values():
        if row.start_method is None:
            continue        # nginx: the render path, not a _start_* method
        assert callable(getattr(launcher, row.start_method, None)), row.name


def test_rows_agree_with_the_quiescence_ladder_when_nothing_is_running(
        launcher, spec_for):
    """The parity that makes item 5's flip a refactor."""
    for name, row in LAUNCHER_KINDS.items():
        spec = spec_for(name)
        observed = launcher._quiescent(spec, {})
        expected = row.quiescence != "never"
        assert observed is expected, "%s: ladder says %s, row says %s" % (
            name, observed, row.quiescence)


def test_rows_agree_with_the_ladder_when_the_pidfile_is_on_disk(
        launcher, spec_for):
    for name, row in LAUNCHER_KINDS.items():
        if row.pidfile is None:
            continue        # proc / external keep none; covered above
        spec = spec_for(name)
        pidfile = Path(endpoint_for(spec).prefix) / row.pidfile
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text("1\n")
        assert launcher._quiescent(spec, {}) is False, name


def test_a_listening_declared_port_defeats_quiescence(launcher, spec_for):
    spec = spec_for("nginx", name="kindparity-listening")
    assert launcher._quiescent(spec, {_PORT: {os.getpid()}}) is False


def test_the_nginx_helpers_are_one_function_not_four():
    import _server_launcher_part2_mixina as a
    import _server_launcher_part2_mixinb as b
    import _server_launcher_part2_mixinc as c

    for helper in ("_nginx_bin", "_inject_nginx_load_modules",
                   "_inject_nginx_runtime_paths"):
        objects = {getattr(module, helper)
                   for module in (server_launcher, a, b, c)}
        assert len(objects) == 1, "%s still has %d copies" % (helper, len(objects))


def test_patching_freeze_reaches_every_launcher_module(monkeypatch):
    """One copy means one patch point — the reason to de-triplicate."""
    from cmdscripts import live_common
    import _server_launcher_part2_mixinc as c

    monkeypatch.setattr(live_common, "freeze_nginx",
                        lambda src: Path("/tmp/one-copy-sentinel/nginx"))
    assert server_launcher._nginx_bin() == "/tmp/one-copy-sentinel/nginx"
    assert c._nginx_bin() == "/tmp/one-copy-sentinel/nginx"


# --- error -----------------------------------------------------------------


def test_unknown_kind_names_the_known_ones():
    with pytest.raises(KeyError) as excinfo:
        launcher_kind("kubernetes")
    message = str(excinfo.value)
    for name in KIND_PROFILES:
        assert name in message


def test_an_invalid_quiescence_mode_is_refused():
    with pytest.raises(ValueError) as excinfo:
        LauncherKind(KIND_PROFILES["nginx"], None, "probably")
    assert "pidfile, ports-only, never" in str(excinfo.value)


# --- security-negative -----------------------------------------------------


def test_external_is_never_quiescent(launcher, spec_for):
    """Nothing listening, no pidfile, no in-memory handle — still False."""
    spec = spec_for("external", name="kindparity-external-idle")
    assert launcher_kind("external").quiescence == "never"
    assert launcher._quiescent(spec, {}) is False


def test_an_owned_instance_is_never_quiescent(launcher, spec_for):
    """A spec this launcher started is stopped, never skipped."""
    spec = spec_for("proc", name="kindparity-owned")
    assert launcher._quiescent(spec, {}) is True
    launcher._external_stops[spec.name] = ([], {})
    assert launcher._quiescent(spec, {}) is False
    del launcher._external_stops[spec.name]
    launcher._xrootd_procs[spec.name] = None
    assert launcher._quiescent(spec, {}) is False


def test_no_snapshot_means_no_skipping(launcher, spec_for):
    """Hosts without `ss` produce no listener snapshot; absence of
    evidence must not read as evidence of absence."""
    spec = spec_for("proc", name="kindparity-nosnapshot")
    assert launcher._quiescent(spec, None) is False
