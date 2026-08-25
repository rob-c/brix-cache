"""Heartbeat, cancellation, and helper reaping contracts."""

import json
import os
import subprocess
import sys
import time

import pytest

from brixtest import SpecError
from brixtest.helper_control import HelperHeartbeat
from brixtest.pytest_runtime import _heartbeat_timeout, _wait_helper


def _sleeper(seconds):
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(%s)" % seconds],
        start_new_session=True,
    )


def test_helper_heartbeat_publishes_liveness_and_cancellation(tmp_path):
    heartbeat_path = tmp_path / "heartbeat.json"
    cancel_path = tmp_path / "cancel.json"
    heartbeat = HelperHeartbeat(heartbeat_path, cancel_path, interval=0.02)
    heartbeat.start()
    first = heartbeat_path.stat().st_mtime_ns
    time.sleep(0.05)
    assert heartbeat_path.stat().st_mtime_ns > first
    cancel_path.write_text("{}")
    time.sleep(0.05)
    assert json.loads(heartbeat_path.read_text())["cancelled"] is True
    heartbeat.close()


def test_missing_heartbeat_reaps_process_tree_and_writes_cancellation(tmp_path, monkeypatch):
    heartbeat = tmp_path / "heartbeat.json"
    cancellation = tmp_path / "cancel.json"
    heartbeat.write_text("{}")
    old = time.time() - 60
    os.utime(heartbeat, (old, old))
    monkeypatch.setenv("BRIXTEST_HEARTBEAT_TIMEOUT", "0.05")
    process = _sleeper(30)
    assert _wait_helper(process, 10, heartbeat, cancellation) == "heartbeat"
    assert process.poll() is not None
    assert json.loads(cancellation.read_text())["reason"] == "heartbeat"


def test_live_heartbeat_allows_normal_helper_exit(tmp_path, monkeypatch):
    monkeypatch.setenv("BRIXTEST_HEARTBEAT_TIMEOUT", "1")
    heartbeat = HelperHeartbeat(
        tmp_path / "heartbeat.json", tmp_path / "cancel.json", interval=0.02,
    )
    heartbeat.start()
    process = _sleeper(0.1)
    try:
        assert _wait_helper(
            process, 2, heartbeat.heartbeat, heartbeat.cancellation,
        ) == ""
    finally:
        heartbeat.close()


def test_case_deadline_reaps_even_with_live_heartbeat(tmp_path, monkeypatch):
    monkeypatch.setenv("BRIXTEST_HEARTBEAT_TIMEOUT", "5")
    heartbeat = HelperHeartbeat(
        tmp_path / "heartbeat.json", tmp_path / "cancel.json", interval=0.02,
    )
    heartbeat.start()
    process = _sleeper(30)
    try:
        assert _wait_helper(
            process, 0.1, heartbeat.heartbeat, heartbeat.cancellation,
        ) == "deadline"
        assert json.loads(heartbeat.cancellation.read_text())["reason"] == "deadline"
    finally:
        heartbeat.close()


@pytest.mark.parametrize("value", ["zero", "0", "-1"])
def test_invalid_heartbeat_timeout_is_rejected(monkeypatch, value):
    monkeypatch.setenv("BRIXTEST_HEARTBEAT_TIMEOUT", value)
    with pytest.raises(SpecError, match="helper heartbeat timeout"):
        _heartbeat_timeout(30)
