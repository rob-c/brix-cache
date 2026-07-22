"""
tests/test_conftest_fleet_lifecycle.py

Unit coverage for the conftest "own only the fleet we started" guard.

Background: in LOCAL mode the session teardown runs `manage_test_servers.sh
stop-all` then `rmtree(TEST_ROOT)`.  When an operator keeps a fleet up out of
band (`tests/manage_test_servers.sh start-all`) and runs a single test file for
a quick iteration, that teardown would tear the whole fleet down and wipe
/tmp/xrd-test -- orphaning every still-running server's export-root fd, so the
next manual `xrdcp`/TPC hangs.  `conftest._external_fleet_attached()` closes that
footgun: when a fleet is already listening it attaches WITHOUT taking lifecycle
ownership (no wipe / start-all / stop-all / rmtree), unless TEST_OWN_FLEET=1
forces a clean restart.  These tests pin that pure decision down hermetically --
no real server is started or stopped.
"""

import importlib.util
import os
import types

import pytest

# Load the *tests/* conftest by path: a bare ``import conftest`` resolves to the
# repo-root compatibility shim (./conftest.py), not this directory's lifecycle
# conftest, so address the file sitting next to this test explicitly.
_CONFTEST_PATH = os.path.join(os.path.dirname(__file__), "conftest.py")
_spec = importlib.util.spec_from_file_location("tests_conftest_under_test", _CONFTEST_PATH)
assert _spec is not None and _spec.loader is not None
conftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(conftest)


@pytest.fixture
def fleet_decision_env(monkeypatch):
    """Isolate `_external_fleet_attached()` from the real fleet and the ambient
    process: reset its memo, force LOCAL mode, and let the caller pick whether a
    fleet "appears" to be running and whether TEST_OWN_FLEET is set.  Restores the
    memo afterwards so the surrounding real session re-decides cleanly."""
    saved_memo = conftest._external_fleet
    monkeypatch.setattr(conftest, "REMOTE_SERVER", False, raising=False)
    monkeypatch.delenv("TEST_OWN_FLEET", raising=False)

    def configure(*, fleet_running: bool):
        conftest._external_fleet = None
        monkeypatch.setattr(
            conftest, "_check_server_reachable",
            lambda *a, **k: fleet_running,
        )

    yield configure
    conftest._external_fleet = saved_memo


def test_attaches_when_fleet_already_running(fleet_decision_env):
    fleet_decision_env(fleet_running=True)
    assert conftest._external_fleet_attached() is True


def test_owns_when_no_fleet_running(fleet_decision_env):
    fleet_decision_env(fleet_running=False)
    assert conftest._external_fleet_attached() is False


def test_own_override_forces_ownership_despite_running_fleet(
    fleet_decision_env, monkeypatch
):
    fleet_decision_env(fleet_running=True)
    monkeypatch.setenv("TEST_OWN_FLEET", "1")
    conftest._external_fleet = None  # re-decide after the env change
    assert conftest._external_fleet_attached() is False


def test_remote_mode_never_attaches(fleet_decision_env, monkeypatch):
    fleet_decision_env(fleet_running=True)
    monkeypatch.setattr(conftest, "REMOTE_SERVER", True, raising=False)
    conftest._external_fleet = None
    assert conftest._external_fleet_attached() is False


class _Options:
    def __init__(self, numprocesses=None, collectonly=False):
        self.numprocesses = numprocesses
        self.collectonly = collectonly


class _Config:
    """Minimal stand-in for pytest's Config as pytest_collection_finish sees it:
    no ``workerinput`` attribute (controller), an ``option`` namespace, and a
    positional ``args`` list."""

    def __init__(self, numprocesses=None, collectonly=False):
        self.option = _Options(numprocesses=numprocesses, collectonly=collectonly)
        self.args = ["test_read.py"]


class _Session:
    def __init__(self, config, items):
        self.config = config
        self.items = items


@pytest.fixture
def collection_finish_env(fleet_decision_env, monkeypatch):
    """Hermetic pytest_collection_finish harness: no fleet running (this session
    owns the lifecycle), env knobs cleared, subset computation and fleet start
    stubbed out.  Yields the recorder list of _start_all_resilient() calls."""
    fleet_decision_env(fleet_running=False)
    monkeypatch.delenv("TEST_SKIP_SERVER_SETUP", raising=False)
    monkeypatch.delenv("REGISTRY_SUBSET_BOOT", raising=False)
    monkeypatch.setattr(conftest, "REMOTE_SERVER", False, raising=False)
    started = []
    monkeypatch.setattr(conftest, "_start_all_resilient", started.append)
    monkeypatch.setattr(conftest, "_specs_to_boot", lambda items: ["subset-spec"])
    return started


def test_collection_finish_boots_the_declared_subset(collection_finish_env):
    """Owning controller, serial run: the post-collection hook computes the
    declared union, records it on config for teardown, and starts exactly it."""
    session = _Session(_Config(), items=[object()])
    conftest.pytest_collection_finish(session)
    assert collection_finish_env == [["subset-spec"]]
    assert session.config._nginx_xrootd_selected_registry_specs == ["subset-spec"]


def test_collection_finish_never_starts_when_attached(
    collection_finish_env, fleet_decision_env
):
    """Attach mode (an external fleet is up) must not start — or later stop —
    anything: lifecycle belongs to whoever launched the fleet."""
    fleet_decision_env(fleet_running=True)
    conftest.pytest_collection_finish(_Session(_Config(), items=[object()]))
    assert collection_finish_env == []


def test_collection_finish_defers_to_sessionstart_under_xdist(collection_finish_env):
    """With -n the controller never collects, so the hook must not double-start
    the fleet pytest_sessionstart already booted in full."""
    conftest.pytest_collection_finish(
        _Session(_Config(numprocesses=4), items=[object()])
    )
    assert collection_finish_env == []


def test_collection_finish_skips_collect_only_and_empty_sessions(
    collection_finish_env,
):
    conftest.pytest_collection_finish(
        _Session(_Config(collectonly=True), items=[object()])
    )
    conftest.pytest_collection_finish(_Session(_Config(), items=[]))
    assert collection_finish_env == []


def _named_spec(name):
    """A minimal stand-in for a registry spec: only ``.name`` is read by the
    boot-set closure filter."""
    spec = types.SimpleNamespace()
    spec.name = name
    return spec


def test_subset_boot_is_the_default(monkeypatch):
    """The default path boots the dependency closure of the collected *seed* —
    required/declared specs ∪ autouse specs ∪ conftest-fixture specs — filtered
    against the registered fleet, not the whole fleet."""
    monkeypatch.delenv("REGISTRY_SUBSET_BOOT", raising=False)
    monkeypatch.setattr(conftest, "_required_specs_for", lambda items: {"a"})
    monkeypatch.setattr(conftest, "_autouse_specs_for", lambda items: {"b"})
    monkeypatch.setattr(conftest, "_conftest_fixture_specs_for", lambda items: set())
    monkeypatch.setattr(conftest, "dependency_closure",
                        lambda seed: set(seed) | {"a-dep"})
    monkeypatch.setattr(
        conftest, "registered_specs",
        lambda: [_named_spec(n) for n in ("a", "b", "a-dep", "unrelated")])
    boot = conftest._specs_to_boot([])
    assert sorted(s.name for s in boot) == ["a", "a-dep", "b"]


def test_empty_seed_boots_nothing(monkeypatch):
    """Goal 5 (zero servers for tests that need none): a collected set that
    reaches no server yields an empty seed, so the fleet launches nothing and
    the registered fleet is never even scanned."""
    monkeypatch.delenv("REGISTRY_SUBSET_BOOT", raising=False)
    monkeypatch.setattr(conftest, "_required_specs_for", lambda items: set())
    monkeypatch.setattr(conftest, "_autouse_specs_for", lambda items: set())
    monkeypatch.setattr(conftest, "_conftest_fixture_specs_for", lambda items: set())
    monkeypatch.setattr(
        conftest, "registered_specs",
        lambda: pytest.fail("must not scan the fleet for an empty seed"))
    assert conftest._specs_to_boot([]) == []


def test_subset_boot_unions_module_autouse_specs(monkeypatch, tmp_path):
    """A module autouse fixture's server can't be declared by any test (nothing
    takes it as a parameter), so _specs_to_boot must union it in per collected
    module (REGISTRY_MIGRATION.md § blind spot)."""
    import fleet_declares
    import fleet_ports

    ded_spec = next(
        s for s in sorted(fleet_ports.CONST_TO_SPEC.values())
        if s not in fleet_declares.backbone_specs()
    )
    ded_const = next(
        c for c, s in sorted(fleet_ports.CONST_TO_SPEC.items()) if s == ded_spec
    )
    mod = tmp_path / "test_autouse_mod.py"
    mod.write_text(
        "import pytest\n"
        f"from settings import {ded_const}\n"
        '@pytest.fixture(scope="session", autouse=True)\n'
        "def module_env():\n"
        f"    wait_port({ded_const})\n"
    )

    class _Item:
        fspath = str(mod)

    monkeypatch.delenv("REGISTRY_SUBSET_BOOT", raising=False)
    # Isolate the autouse source: the other seed contributors return nothing, so
    # only the autouse fixture's spec can reach the boot set.
    monkeypatch.setattr(conftest, "_required_specs_for", lambda items: set())
    monkeypatch.setattr(conftest, "_conftest_fixture_specs_for", lambda items: set())
    monkeypatch.setattr(conftest, "dependency_closure", lambda seed: set(seed))
    monkeypatch.setattr(conftest, "registered_specs", lambda: [_named_spec(ded_spec)])
    boot = conftest._specs_to_boot([_Item()])
    assert ded_spec in {s.name for s in boot}


def test_decision_is_memoized(fleet_decision_env):
    """Only one probe per process: the first decision is cached so we neither
    re-probe nor re-print the attach notice on the teardown call."""
    fleet_decision_env(fleet_running=True)
    assert conftest._external_fleet_attached() is True

    calls = {"n": 0}

    def counting_probe(*a, **k):
        calls["n"] += 1
        return False  # would flip the answer if it were consulted

    conftest._check_server_reachable = counting_probe
    assert conftest._external_fleet_attached() is True  # cached True, not re-probed
    assert calls["n"] == 0
