"""TS-3 pins: the settings shim, the configuration object, lane refusal.

testsuite-modernization-plan.md TS-3 ("Configuration object").  The body
of ``tests/settings.py`` moved to ``brix_suite.settings_values``; the flat
module is now a §10.2 self-replacement shim onto ``brix_suite.settings``.
~900 import sites were NOT touched, so the only thing standing between
that move and an AttributeError in whichever dependent runs first is a
machine check of the three properties below.

  success   — identity + completeness of the shim; ``from_env``/``derive``
              lane math against the TEST_ROOT/TEST_PORT_START matrix.
  error     — a malformed port base fails the same way it failed before.
  security  — the foreign-lane refusal text is byte-identical (an operator
              acting on a changed message is an operator acting on the
              wrong lane) and refusal still fires through the shim.

Lane-matrix cases run in a subprocess: settings reads the environment
once, at import, so a second lane cannot be observed in this process.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import settings

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "brixtest" / "src"
TESTS = REPO / "tests"
BASELINE = REPO / "docs/refactor/testsuite-shim-baseline.json"


def _in_lane(code, root, port_start, extra_env=None):
    """Run `code` in a child process holding a lane's environment."""
    env = dict(os.environ, TEST_ROOT=str(root), TEST_PORT_START=str(port_start))
    env["PYTHONPATH"] = os.pathsep.join([str(TESTS), str(SRC)])
    env.pop("TEST_SERVER_HOST", None)
    env.update(extra_env or {})
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, env=env)


# --- success ---------------------------------------------------------------


def test_shim_is_the_canonical_module_not_a_copy():
    """`import settings` and `import brix_suite.settings` are ONE object.

    Two module objects would mean two namespaces: a monkeypatch applied by
    one importer would be invisible to the other, which is precisely the
    failure aliasing is supposed to make impossible.
    """
    import brix_suite.settings as canonical

    assert settings is canonical
    assert sys.modules["settings"] is canonical


def test_shim_exports_every_name_it_exported_before_the_move():
    """Completeness against the frozen pre-move baseline (guard #3)."""
    baseline = json.loads(BASELINE.read_text())["settings"]
    missing = [name for name in baseline if not hasattr(settings, name)]
    assert not missing, "shim dropped %d name(s): %s" % (len(missing), missing[:10])
    assert len(baseline) >= 258, "baseline itself looks truncated"


def test_import_side_effects_survive_the_move():
    """The republish/pin the grown body did at import still happen.

    Launchers capture the environment, and every subprocess inherits
    TMPDIR; these are the side effects the move was most likely to lose
    silently, because nothing reads them until much later.
    """
    assert os.environ["TEST_ROOT"] == settings.TEST_ROOT
    assert os.path.isabs(settings.TEST_ROOT)
    assert os.environ["TMPDIR"] == settings.TMP_DIR
    import tempfile

    assert tempfile.tempdir == settings.TMP_DIR
    # the ladder republishes both spellings for non-Python consumers
    assert os.environ["NGINX_ANON_PORT"] == str(settings.NGINX_ANON_PORT)
    assert os.environ["TEST_NGINX_ANON_PORT"] == str(settings.NGINX_ANON_PORT)


def test_settings_object_agrees_with_the_module_attributes():
    """SETTINGS is a view over the computed values, never a re-parse."""
    s = settings.SETTINGS
    assert s.test_root == settings.TEST_ROOT
    assert s.port_start == settings.TEST_PORT_START
    assert s.host == settings.HOST and s.host6 == settings.HOST6
    assert s.registry_root == settings.REGISTRY_ROOT
    assert s.fleet_ready_marker == settings.FLEET_READY
    assert s.log_dir == settings.LOG_DIR
    assert s.tmp_dir == settings.TMP_DIR
    assert s.remote_server == settings.REMOTE_SERVER
    assert s.nginx_bin == settings.NGINX_BIN
    assert s.ports["NGINX_ANON_PORT"] == settings.NGINX_ANON_PORT
    assert s.ports.NGINX_ANON_PORT == settings.NGINX_ANON_PORT


def test_ledger_covers_every_named_port_and_keeps_the_alias():
    """One named attribute per constant (§9.2.1), alias included."""
    ledger = settings.SETTINGS.ports
    named = dict(ledger.iter_named_ports())
    for name, port in named.items():
        assert getattr(settings, name) == port, name
    def _assert_test_ledger_covers_every_named_port_and_keeps_the_alias_1():
        assert len(named) >= 178
        # one socket, two spellings — not two allocations
        assert named["XRDHTTP_HTTPS_PORT"] == named["XRDHTTP_HTTP_PORT"]

    _assert_test_ledger_covers_every_named_port_and_keeps_the_alias_1()
    # every ledger port is unique apart from that alias
    ports = [p for n, p in named.items() if n != "XRDHTTP_HTTPS_PORT"]
    assert len(set(ports)) == len(ports)


@pytest.mark.parametrize("port_start", [10000, 23000, 26000])
def test_lane_math_places_the_ladder_at_the_requested_base(port_start):
    """Each lane's ports are its own base + the same offsets (F8)."""
    probe = (
        "import json, settings\n"
        "print(json.dumps({'start': settings.TEST_PORT_START,"
        " 'anon': settings.NGINX_ANON_PORT,"
        " 'root': settings.TEST_ROOT,"
        " 'obj_anon': settings.SETTINGS.ports['NGINX_ANON_PORT']}))"
    )
    root = "/tmp/xrd-test-lane-%d" % port_start
    proc = _in_lane(probe, root, port_start)
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    assert got["start"] == port_start
    assert got["root"] == root
    # offset of NGINX_ANON_PORT within the ladder is lane-independent
    assert got["anon"] - port_start == settings.NGINX_ANON_PORT - settings.TEST_PORT_START
    assert got["obj_anon"] == got["anon"], "object and module disagree in-lane"


def test_derive_moves_a_lane_without_touching_the_original():
    """derive() is a copy: frozen dataclass, no in-place lane mutation."""
    base = settings.SETTINGS
    moved = base.derive(port_start=23000, test_root="/tmp/xrd-test-derived")
    assert moved.port_start == 23000
    assert moved.registry_root == "/tmp/xrd-test-derived/registry"
    assert moved.fleet_ready_marker == "/tmp/xrd-test-derived/registry/.fleet-ready"
    assert moved.ports["NGINX_ANON_PORT"] - 23000 == \
        base.ports["NGINX_ANON_PORT"] - base.port_start
    # the original is untouched
    assert base.port_start == settings.TEST_PORT_START
    assert base.test_root == settings.TEST_ROOT


def test_explicit_override_beats_a_derived_default():
    """C2 precedence: an explicit value always wins over derivation."""
    moved = settings.SETTINGS.derive(
        test_root="/tmp/xrd-test-c2", registry_root="/tmp/elsewhere/registry")
    assert moved.registry_root == "/tmp/elsewhere/registry"


def test_tier2_knob_defaults_match_their_read_sites():
    """§5.8's table is the completeness checklist; defaults must mirror it."""
    s = settings.SuiteSettings.from_env({"TEST_ROOT": "/tmp/x", "TEST_PORT_START": "10000"})
    assert (s.sentinel, s.sentinel_poll, s.sentinel_grace) == (True, 2.0, 8.0)
    assert (s.sentinel_fraction, s.sentinel_min_down, s.sentinel_abort) == (0.5, 8, False)
    assert s.fleet_prep_cache is True and s.fleet_start_workers is None
    assert s.fleet_stability_secs == 5.0 and s.fleet_start_timeout == 900.0
    assert s.ref_runas_user == "nobody" and s.large_file_seed == 42
    assert s.brix_test_user == "brixtest" and s.brix_test_tree == "/srv/brix-test"
    assert s.fwd_port_base == 21960 and s.nginx_conf_rel == "conf/nginx.conf"
    assert s.skip_server_setup is False and s.own_fleet is False


# --- error -----------------------------------------------------------------


def test_malformed_port_base_fails_exactly_as_before():
    """A non-int TEST_PORT_START is still an import-time ValueError.

    The grown module raised from `int(os.environ.get(...))`; a shim that
    turned that into a different exception type (or a silent default)
    would strand a typo'd lane on the default ports — i.e. on top of
    whatever fleet is already there.
    """
    proc = _in_lane("import settings", "/tmp/xrd-test-bad", "not-a-number")
    assert proc.returncode != 0
    assert "ValueError" in proc.stderr
    assert "invalid literal for int()" in proc.stderr
    assert "'not-a-number'" in proc.stderr


def test_malformed_port_base_fails_the_same_way_through_the_object():
    """from_env() reports the identical failure, not a wrapped one."""
    with pytest.raises(ValueError, match="invalid literal for int"):
        settings.SuiteSettings.from_env({"TEST_PORT_START": "not-a-number"})


def test_out_of_range_lane_warns_but_does_not_refuse():
    """TS-3 rule 6: validation is warn-only for one full phase.

    A refusal that does not fire today may only log — otherwise this phase
    would start rejecting lanes that have always worked.
    """
    with pytest.warns(UserWarning, match="sane lane range"):
        s = settings.SuiteSettings.from_env(
            {"TEST_ROOT": "/tmp/x", "TEST_PORT_START": "80"})
    assert s.port_start == 80          # accepted, not refused
    assert s.ports is None             # no ledger claimed below the floor


# --- security-negative -----------------------------------------------------


def test_foreign_lane_refusal_text_is_byte_identical():
    """Operators act on this string; ops docs quote it verbatim."""
    from brixtest.config.lanes import refuse_foreign_lane

    assert refuse_foreign_lane("/tmp/xrd-test", "127.0.0.1", 11094) == (  # net-literal-allow: the refusal formatter's own inputs
        "refusing to start TEST_ROOT=/tmp/xrd-test: 127.0.0.1:11094 "  # net-literal-allow: byte-identical expected message
        "is owned by another or incomplete test fleet. Choose a "
        "non-overlapping TEST_PORT_START; each lane reserves the complete "
        "central port ladder. The foreign listener was not modified."
    )


def test_refusal_promises_the_foreign_listener_was_left_alone():
    """The safety property, not just the wording: we refuse, never reap.

    A lane that 'cleaned up' a port it did not own is how one session
    kills another session's fleet.
    """
    from brixtest.config.lanes import refuse_foreign_lane

    msg = refuse_foreign_lane("/tmp/a", "127.0.0.1", 23005)  # net-literal-allow: refusal-formatter input
    assert msg.endswith("The foreign listener was not modified.")
    assert "refusing to start" in msg


def test_conftest_raises_the_shared_refusal_on_collision():
    """The refusal still fires through the shim + conftest path."""
    import importlib.util

    # Load tests/conftest.py by path: a bare ``import conftest`` resolves to
    # the repo-root compatibility shim, not this directory's conftest.
    spec = importlib.util.spec_from_file_location(
        "tests_conftest_ts3_probe", str(TESTS / "conftest.py"))
    conftest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(conftest)

    saved = conftest._foreign_fleet_collision
    try:
        conftest._foreign_fleet_collision = True
        with pytest.raises(pytest.UsageError,
                           match="foreign listener was not modified"):
            conftest._should_skip_local_lifecycle(None)
    finally:
        conftest._foreign_fleet_collision = saved


def test_lane_ownership_refuses_a_live_foreign_owner(tmp_path):
    """Lane.acquire() refuses when another live pid owns the root."""
    from brixtest.config.lanes import Lane
    from brixtest.errors import LaneOwnershipError

    lane = Lane(root=tmp_path / "lane", port_base=23000)
    lane.acquire(session="mine")
    record = lane._record_path
    forged = json.loads(record.read_text())
    forged["pid"] = 1              # pid 1 is always alive and never us
    record.write_text(json.dumps(forged))

    with pytest.raises(LaneOwnershipError):
        lane.acquire(session="other")


def test_lane_identity_is_exact_never_a_prefix(tmp_path):
    """`/tmp/xrd-test` must not own `/tmp/xrd-test-migration-lane`.

    A reaper once SIGTERMed every lane whose root merely started with its
    own; this is that incident as a contract.
    """
    from brixtest.config.lanes import Lane

    lane = Lane(root=tmp_path / "xrd-test", port_base=23000)
    assert lane.owns_root(tmp_path / "xrd-test")
    assert not lane.owns_root(tmp_path / "xrd-test-migration-lane")


def test_repo_root_brixtest_dir_never_shadows_the_real_package():
    """The project directory `brixtest/` sits at the repo root with the same
    name as the package it ships in `brixtest/src/`.  PEP 420 keeps the real
    package ahead of it — a directory with no `__init__.py` is only recorded
    as a namespace portion and the path scan continues — so `settings_model`
    reaches the true `brixtest.config.ports` even when a caller put the src
    root last.  An `__init__.py` at the repo root would make that directory a
    regular package and flip the precedence, silently substituting an empty
    namespace for the port ledger; assert it is absent and that resolution
    still lands inside src even in the worst path order."""
    assert not (REPO / "brixtest" / "__init__.py").exists(), (
        "brixtest/__init__.py at the repo root would shadow brixtest/src/brixtest")
    probe = (
        "import sys; sys.path.append(%r)\n"
        "import brixtest.config.ports as p; print(p.__file__)" % str(SRC)
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    proc = subprocess.run([sys.executable, "-c", probe], capture_output=True,
                          text=True, cwd=str(REPO), env=env)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().startswith(str(SRC)), proc.stdout


def test_tests_dir_names_the_real_flat_tree():
    """`TESTS_DIR` is the registry fixture's launch root, so a wrong value
    is not a cosmetic path bug — it points the launcher at a tree with no
    specs in it. It is also invisible under pytest, which already has
    `tests/` on `sys.path`, so nothing fails at import to reveal it. The
    package was relocated once mid-migration and a `parents[]` hop count
    silently began naming a directory that does not exist; assert the
    answer is the tree that actually holds the flat modules."""
    tests_dir = Path(settings.TESTS_DIR)
    assert tests_dir == TESTS, "%s != %s" % (tests_dir, TESTS)
    for anchor in ("port_ladder.py", "conftest.py", "server_registry.py"):
        assert (tests_dir / anchor).is_file(), "%s missing from %s" % (anchor, tests_dir)
