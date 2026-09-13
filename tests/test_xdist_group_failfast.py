"""Fail-fast must not drain thousands of queued fixed-port group cases."""

from types import SimpleNamespace
import os
import subprocess
import sys

import pytest

from brix_suite.harness.xdist_groups import GroupFailFast, configure_group_failfast


def _config(maxfail=1, workers=8, workerinput=None):
    config = SimpleNamespace(option=SimpleNamespace(
        maxfail=maxfail, numprocesses=workers))
    if workerinput is not None:
        config.workerinput = workerinput
    return config


@pytest.mark.parametrize("outcome", ["passed", "failed", "error", "xfail"])
def test_only_real_failures_publish_stop(tmp_path, outcome):
    controller = GroupFailFast(_config())
    controller.marker = tmp_path / "stop"
    report = SimpleNamespace(failed=outcome != "passed")
    if outcome == "xfail":
        report.wasxfail = "expected failure"
    controller.pytest_runtest_logreport(report)
    assert controller.marker.exists() == (outcome in ("failed", "error"))


def test_maxfail_threshold_is_respected(tmp_path):
    controller = GroupFailFast(_config(maxfail=2))
    controller.marker = tmp_path / "stop"
    report = SimpleNamespace(failed=True)
    controller.pytest_runtest_logreport(report)
    assert not controller.marker.exists()
    controller.pytest_runtest_logreport(report)
    assert controller.marker.exists()


@pytest.mark.parametrize("stop", [False, True])
def test_worker_stops_only_after_current_protocol_finishes(tmp_path, stop):
    marker = tmp_path / "stop"
    worker = GroupFailFast(_config(workerinput={"brix_failfast": str(marker)}))
    item = SimpleNamespace(session=SimpleNamespace(shouldstop=False))
    hook = worker.pytest_runtest_protocol(item, None)
    next(hook)
    if stop:
        marker.touch()
    assert not item.session.shouldstop
    with pytest.raises(StopIteration):
        next(hook)
    assert bool(item.session.shouldstop) == stop


def test_new_session_cannot_inherit_previous_stop(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))
    first = GroupFailFast(_config())
    second = GroupFailFast(_config())
    try:
        node = SimpleNamespace(workerinput={})
        first.pytest_configure_node(node)
        first.marker.touch()
        second.pytest_configure_node(node)
        assert first.marker != second.marker
        assert not second.marker.exists()
    finally:
        first.pytest_unconfigure(None)
        second.pytest_unconfigure(None)


@pytest.mark.parametrize("maxfail,workers,enabled", [(0, 8, False),
                                                    (1, 0, False),
                                                    (1, 8, True)])
def test_registration_preserves_normal_and_serial_runs(maxfail, workers, enabled):
    registered = []
    config = _config(maxfail, workers)
    config.pluginmanager = SimpleNamespace(register=lambda *args: registered.append(args))
    configure_group_failfast(config)
    assert bool(registered) == enabled


@pytest.mark.timeout(60)
def test_eight_workers_do_not_drain_queued_groups(tmp_path):
    """Exercise the real xdist queue: one failure leaves most cases unrun."""
    from settings import TESTS_DIR

    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "conftest.py").write_text(
        "import pytest\n"
        "from brix_suite.harness.xdist_groups import "
        "configure_group_failfast, materialize_xdist_group\n"
        "def pytest_configure(config):\n"
        "    configure_group_failfast(config)\n"
        "def pytest_collection_modifyitems(items):\n"
        "    for item in items:\n"
        "        item.add_marker(pytest.mark.xdist_group(str(item.callspec.params['group'])))\n"
        "        materialize_xdist_group(item)\n"
    )
    (tmp_path / "test_queue.py").write_text(
        "from pathlib import Path\n"
        "import time\n"
        "import pytest\n"
        "@pytest.mark.parametrize('case', range(30))\n"
        "@pytest.mark.parametrize('group', range(8))\n"
        "def test_queue(group, case):\n"
        "    root = Path(__file__).parent\n"
        "    (root / f'ran-{group}-{case}').touch()\n"
        "    if case == 0:\n"
        "        (root / f'ready-{group}').touch()\n"
        "        deadline = time.monotonic() + 20\n"
        "        while len(list(root.glob('ready-*'))) != 8:\n"
        "            assert time.monotonic() < deadline, 'workers did not start'\n"
        "            time.sleep(0.01)\n"
        "        assert group != 0, 'intentional fail-fast control'\n"
        "    time.sleep(0.04)\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-c", str(tmp_path / "pytest.ini"),
         "--confcutdir", str(tmp_path), "-x", "-n", "8", "--dist", "loadgroup",
         "-p", "no:rerunfailures", "-q", str(tmp_path / "test_queue.py")],
        cwd=tmp_path, env=dict(os.environ, PYTHONPATH=TESTS_DIR),
        capture_output=True, text=True, timeout=50,
    )
    assert result.returncode in (1, 2), result.stdout + result.stderr
    assert "intentional fail-fast control" in result.stdout
    assert "1 failed" in result.stdout
    assert len(list(tmp_path.glob("ready-*"))) == 8
    assert len(list(tmp_path.glob("ran-*"))) < 80, result.stdout
