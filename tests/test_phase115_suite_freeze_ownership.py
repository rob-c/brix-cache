"""
tests/test_phase115_suite_freeze_ownership.py — the run-wide frozen nginx
belongs to the multi-lane runner, not to whichever lane finishes first.

``operator_runtime._capture_suite_nginx()`` freezes ``objs/nginx`` ONCE before
any lane and publishes that path as ``NGINX_BIN``/``TEST_NGINX_BIN`` in the
environment every lane subprocess inherits.  Lane 1's ``pytest_sessionfinish``
then called ``cleanup_frozen_nginx()`` from ``_remove_test_root()`` and deleted
it.  Lanes 2..N inherited a path that no longer existed, ``freeze_nginx()`` took
its ``not src.exists()`` branch, found no copy to validate and handed the dead
path straight back, so every server exec failed with ENOENT:

    registered server 'main' failed to launch: [Errno 2] No such file or
    directory: '/tmp/brix-nginx-session-<tag>/nginx-<tag>'

A full four-lane ``suite`` run could therefore only ever report its FIRST lane;
the other three died in start-all before running a test.  Observed 2026-09-07:
lane 1 finished 41067 passed, lanes 2-4 ran nothing.

The first fix — an ownership marker plus a runner-side release — reproduced the
same ENOENT from the other side, because the release removed the freeze
DIRECTORY: a lane may call ``run_suite()`` in-process (tests/
test_cmd_operator_runtime.py does, eight times, with a throwaway nginx), and
that nested run froze into the SAME session directory and then deleted it out
from under the live run.  Observed the same day: lane 1 collapsed at 48% with
6508 FileNotFoundErrors and lanes 2-4 again ran nothing.  So the release takes
only the ONE binary its own capture froze, and clears the marker only when it
was the run that published it.

  success       — with the ownership marker set a lane's teardown leaves the
                  frozen binary in place, so a second lane sharing the TEST_ROOT
                  still resolves a working executable; the runner's release
                  drops it after the last lane; a nested in-process run takes
                  only its own throwaway copy; and a nested capture defers to
                  the marker an outer runner already published;
  error         — without the marker a lane still cleans up after itself (the
                  single-lane contract is unchanged), releasing a binary that is
                  already gone does not raise, and neither does releasing twice;
  security-neg  — the marker protects ONLY the binary: TEST_ROOT itself, which
                  holds the fleet's CA keys, proxies and data roots, is still
                  wiped by the lane that made it; the release never reaches the
                  freeze directory of a different TEST_ROOT; and a nested run
                  never disowns the live freeze by clearing an outer marker.

Run:
    PYTHONPATH=tests pytest tests/test_phase115_suite_freeze_ownership.py -v
"""
import os
import sys
from pathlib import Path

import pytest

import settings
from cmdscripts import fake_nginx, live_common
from cmdscripts import operator_runtime as runtime

MARKER = live_common.SUITE_OWNS_FROZEN_NGINX

# Both bodies under test are exec-composed CONTINUATIONS, not modules:
# conftest.py execs conftest_part5.py into its own globals, and
# operator_runtime.py does the same with operator_runtime_part2.py.  Importing
# either part directly hands it isolated globals in which `_ORIG_CWD` (and
# every other name the parent defines) is simply undefined, so a test that
# imports the part exercises a namespace the production run never has.  Reach
# them through the composed parent instead.
def _tests_conftest():
    """The composed ``tests/conftest.py`` module object.

    ``sys.modules["conftest"]`` is the REPO-ROOT conftest under pytest — a
    different file that never sees these names — so pick the loaded module by
    its path instead of by that ambiguous key.
    """
    for module in list(sys.modules.values()):
        path = getattr(module, "__file__", None)
        if path and Path(path).parts[-2:] == ("tests", "conftest.py"):
            return module
    raise AssertionError("tests/conftest.py is not loaded")


conftest = _tests_conftest()


@pytest.fixture
def lane(tmp_path, monkeypatch):
    """A private TEST_ROOT, a private freeze root, and a fake nginx to freeze.

    Nothing here touches the real /tmp freeze directory or the session fleet:
    ``_FREEZE_ROOT`` is module-level precisely so a test can redirect it.
    """
    test_root = tmp_path / "lane-root"
    (test_root / "registry").mkdir(parents=True)
    freeze_root = tmp_path / "freeze"
    freeze_root.mkdir()

    monkeypatch.setattr(live_common, "_FREEZE_ROOT", freeze_root)
    monkeypatch.setattr(live_common, "_FROZEN_NGINX", None)
    # _session_freeze_dir() keys off settings.TEST_ROOT and only falls back to
    # the environment, so patching the env alone leaves the real key in place.
    monkeypatch.setattr(settings, "TEST_ROOT", str(test_root))
    monkeypatch.setenv("TEST_ROOT", str(test_root))
    monkeypatch.setattr(conftest, "TEST_ROOT", str(test_root))
    monkeypatch.setattr(conftest, "REGISTRY_ROOT", str(test_root / "registry"))
    monkeypatch.setattr(conftest, "REGISTRY_KEEP_LOGS", False)
    monkeypatch.delenv(MARKER, raising=False)

    source = Path(fake_nginx.install(tmp_path, "nginx"))
    return {"test_root": test_root, "freeze_root": freeze_root, "source": source}


def _freeze(lane):
    """Freeze the fake binary the way _capture_suite_nginx does."""
    frozen = live_common.freeze_nginx(lane["source"])
    assert frozen != lane["source"], "the fake binary was not frozen at all"
    return Path(frozen)


# --------------------------------------------------------------------------
# success


def test_an_owned_freeze_survives_a_lanes_teardown(lane):
    frozen = _freeze(lane)
    os.environ[MARKER] = "1"
    try:
        conftest._remove_test_root()
    finally:
        os.environ.pop(MARKER, None)
    assert frozen.exists(), "lane teardown deleted the runner's frozen binary"


def test_a_second_lane_still_resolves_a_working_binary(lane):
    """The regression itself: freeze, tear a lane down, then re-resolve.

    This is what every lane after the first does — it inherits the frozen path
    as its NGINX_BIN and calls freeze_nginx() on it.  Before the ownership
    marker the path came back pointing at a file that had just been deleted.
    """
    frozen = _freeze(lane)
    os.environ[MARKER] = "1"
    try:
        conftest._remove_test_root()
        live_common._FROZEN_NGINX = None          # a fresh lane process
        again = Path(live_common.freeze_nginx(frozen))
    finally:
        os.environ.pop(MARKER, None)
    assert again.exists(), f"lane 2 resolved a nonexistent binary: {again}"
    assert os.access(again, os.X_OK)


def test_the_runner_releases_the_freeze_after_its_last_lane(lane):
    frozen = _freeze(lane)
    os.environ[MARKER] = str(frozen)
    try:
        runtime._release_suite_nginx(frozen)
    finally:
        os.environ.pop(MARKER, None)
    assert not frozen.exists(), "the runner never dropped its frozen binary"
    assert MARKER not in os.environ, "the ownership marker outlived the run"
    assert not frozen.parent.exists(), "the emptied freeze directory was left behind"


def test_a_nested_run_releases_only_the_binary_it_froze(lane):
    """The second half of the defect, and the one that actually collapsed a run.

    A lane may call run_suite() IN-PROCESS — tests/test_cmd_operator_runtime.py
    does it eight times — and that nested run freezes a throwaway binary into
    the SAME session directory as the live one.  A release that removed the
    DIRECTORY took the live run's binary with it: observed 2026-09-07, lane 1
    collapsed at 48% and lanes 2-4 ran nothing, every start-all reporting
    ENOENT on the frozen path.
    """
    live = _freeze(lane)
    nested = live.with_name("nginx-deadbeef")
    nested.write_bytes(live.read_bytes())
    os.environ[MARKER] = str(live)
    try:
        runtime._release_suite_nginx(nested)
    finally:
        os.environ.pop(MARKER, None)
    assert not nested.exists(), "the nested run kept its own throwaway binary"
    assert live.exists(), "a nested run deleted the live run's frozen binary"
    assert live.parent.is_dir(), "a nested run removed the live freeze directory"


def test_a_nested_capture_defers_to_an_outer_owner(lane, monkeypatch):
    """Capture must not re-label a freeze an outer runner already owns."""
    outer = "/tmp/some-other-run/nginx-outer"
    monkeypatch.setenv(MARKER, outer)
    monkeypatch.setenv("TEST_NGINX_BIN", str(lane["source"]))

    frozen = runtime._capture_suite_nginx()

    assert frozen is not None and frozen.exists()
    assert os.environ[MARKER] == outer, "a nested run seized the outer marker"
    assert os.environ["NGINX_BIN"] == str(frozen)


# --------------------------------------------------------------------------
# error


def test_an_unowned_lane_still_cleans_up_after_itself(lane):
    """A plain single-lane pytest run keeps its original contract."""
    frozen = _freeze(lane)
    assert MARKER not in os.environ
    conftest._remove_test_root()
    assert not frozen.exists(), "an unowned freeze leaked past session end"


def test_releasing_a_binary_that_is_already_gone_does_not_raise(lane):
    frozen = _freeze(lane)
    frozen.unlink()
    runtime._release_suite_nginx(frozen)


def test_releasing_twice_does_not_raise(lane):
    frozen = _freeze(lane)
    os.environ[MARKER] = str(frozen)
    try:
        runtime._release_suite_nginx(frozen)
        runtime._release_suite_nginx(frozen)
    finally:
        os.environ.pop(MARKER, None)


# --------------------------------------------------------------------------
# security-negative


def test_the_marker_does_not_spare_the_scratch_tree(lane):
    """TEST_ROOT holds the fleet's CA keys, proxies and data roots.

    The marker exempts the BINARY only.  If it were read as "skip teardown",
    one lane's credentials would survive into the next lane's tests.
    """
    secret = lane["test_root"] / "registry" / "ca.key"
    secret.write_text("PRIVATE KEY")
    _freeze(lane)
    os.environ[MARKER] = "1"
    try:
        conftest._remove_test_root()
    finally:
        os.environ.pop(MARKER, None)
    assert not secret.exists(), "a lane's credentials survived its own teardown"
    assert not lane["test_root"].exists()


def test_the_release_never_reaches_another_test_roots_freeze(lane, monkeypatch):
    """The release is keyed on TEST_ROOT, so a concurrent run is untouched."""
    frozen = _freeze(lane)
    monkeypatch.setattr(settings, "TEST_ROOT", str(lane["test_root"]) + "-other")
    live_common._FROZEN_NGINX = None
    other = Path(live_common.freeze_nginx(lane["source"]))
    assert other.parent != frozen.parent, "two TEST_ROOTs shared one freeze dir"

    monkeypatch.setattr(settings, "TEST_ROOT", str(lane["test_root"]))
    os.environ[MARKER] = str(frozen)
    try:
        runtime._release_suite_nginx(frozen)
    finally:
        os.environ.pop(MARKER, None)
    assert other.exists(), "the release deleted another run's frozen binary"


def test_a_nested_run_never_clears_an_outer_runners_marker(lane):
    """Clearing it would re-arm the very teardown the marker exists to stop."""
    live = _freeze(lane)
    nested = live.with_name("nginx-deadbeef")
    nested.write_bytes(live.read_bytes())
    os.environ[MARKER] = str(live)
    try:
        runtime._release_suite_nginx(nested)
        assert os.environ.get(MARKER) == str(live), (
            "a nested run disowned the live freeze; the next lane teardown "
            "would delete it and strand every remaining lane")
    finally:
        os.environ.pop(MARKER, None)


def test_the_release_is_wired_into_the_runs_teardown():
    """A correct helper nobody calls would leave the freeze behind forever.

    Pin the wiring as source, not behaviour: run_suite()'s `finally` is the one
    place guaranteed to run after the last lane whatever the lanes did.
    """
    body = Path(runtime.__file__).with_name("operator_runtime_part2.py").read_text()
    start = body.index("def run_suite(")
    finally_at = body.index("finally:", start)
    assert "_release_suite_nginx(frozen)" in body[finally_at:finally_at + 200], (
        "run_suite() no longer releases the run-wide frozen binary")
    assert "SUITE_OWNS_FROZEN_NGINX" in body[:start], (
        "the ownership marker is no longer published to the lanes")
    assert MARKER == "TEST_SUITE_OWNS_FROZEN_NGINX", (
        "the marker's WIRE name changed; lanes started before the change "
        "inherit the old one and would delete the freeze anyway")
