"""Heartbeat, cancellation, and helper reaping contracts."""

import json
import os
import subprocess
import sys
import time

import pytest

from brixtest import SpecError
from brixtest.helper_control import HelperHeartbeat
from brixtest.pytest_runtime import _heartbeat_expired, _heartbeat_timeout, _wait_helper
from brixtest.testing import test_config


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
    try:
        first = heartbeat_path.stat().st_mtime_ns
        _wait_for_heartbeat(lambda: heartbeat_path.stat().st_mtime_ns > first)
        cancel_path.write_text("{}")
        _wait_for_heartbeat(lambda: json.loads(heartbeat_path.read_text())["cancelled"])
    finally:
        heartbeat.close()


def _wait_for_heartbeat(predicate):
    deadline = time.monotonic() + 3
    while not predicate():
        assert time.monotonic() < deadline, 'helper heartbeat did not advance'
        time.sleep(0.01)


def test_missing_heartbeat_reaps_process_tree_and_writes_cancellation(tmp_path):
    heartbeat = tmp_path / "heartbeat.json"
    cancellation = tmp_path / "cancel.json"
    heartbeat.write_text("{}")
    old = time.time() - 60
    os.utime(heartbeat, (old, old))
    config = test_config(heartbeat_timeout="0.05")
    process = _sleeper(30)
    assert _wait_helper(process, 10, heartbeat, cancellation, config=config) == "heartbeat"
    assert process.poll() is not None
    assert json.loads(cancellation.read_text())["reason"] == "heartbeat"


def test_live_heartbeat_allows_normal_helper_exit(tmp_path):
    config = test_config(heartbeat_timeout="1")
    heartbeat = HelperHeartbeat(
        tmp_path / "heartbeat.json", tmp_path / "cancel.json", interval=0.02,
    )
    heartbeat.start()
    process = _sleeper(0.1)
    try:
        assert _wait_helper(
            process, 2, heartbeat.heartbeat, heartbeat.cancellation, config=config,
        ) == ""
    finally:
        heartbeat.close()


def test_case_deadline_reaps_even_with_live_heartbeat(tmp_path):
    config = test_config(heartbeat_timeout="5")
    heartbeat = HelperHeartbeat(
        tmp_path / "heartbeat.json", tmp_path / "cancel.json", interval=0.02,
    )
    heartbeat.start()
    process = _sleeper(30)
    try:
        assert _wait_helper(
            process, 0.1, heartbeat.heartbeat, heartbeat.cancellation, config=config,
        ) == "deadline"
        assert json.loads(heartbeat.cancellation.read_text())["reason"] == "deadline"
    finally:
        heartbeat.close()


@pytest.mark.parametrize("value", ["zero", "0", "-1"])
def test_invalid_heartbeat_timeout_is_rejected(value):
    config = test_config(heartbeat_timeout=value)
    with pytest.raises(SpecError, match="helper heartbeat timeout"):
        _heartbeat_timeout(30, config=config)


def test_controller_marker_allows_bounded_cold_start(tmp_path):
    path = tmp_path / "heartbeat.json"
    path.write_text(json.dumps({"controller": os.getpid()}))
    old = time.time() - 60
    os.utime(path, (old, old))
    assert not _heartbeat_expired(path, 1, time.monotonic() + 30)
    assert _heartbeat_expired(path, 1, time.monotonic() - 1)


@pytest.mark.parametrize("payload", [{"pid": 123}, {"controller": -1}, []])
def test_startup_grace_never_masks_stale_helper_or_foreign_marker(tmp_path, payload):
    path = tmp_path / "heartbeat.json"
    path.write_text(json.dumps(payload))
    old = time.time() - 60
    os.utime(path, (old, old))
    assert _heartbeat_expired(path, 1, time.monotonic() + 30)


def test_startup_grace_cannot_extend_case_deadline(tmp_path):
    path = tmp_path / "heartbeat.json"
    cancellation = tmp_path / "cancel.json"
    path.write_text(json.dumps({"controller": os.getpid()}))
    process = _sleeper(30)
    assert _wait_helper(process, 0.1, path, cancellation) == "deadline"
    assert process.poll() is not None
