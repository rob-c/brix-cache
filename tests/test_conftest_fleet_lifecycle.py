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
