"""Fault schedules belong to the test that started them, even on failure."""

import threading

import pytest

import test_official_xrootd_resilience as resilience


def test_fault_schedule_finishes_before_read_result_is_returned(monkeypatch):
    started = threading.Event()
    commands = []
    expected = ("digest", 12, None)

    def read(path):
        assert path == "sample"
        started.set()
        return expected

    def control(command):
        assert started.wait(5), "read never started"
        commands.append(command)

    monkeypatch.setattr(resilience, "_read_md5", read)
    result = resilience._read_with_faults(
        "sample", control, [(0, "drop"), (0, "unblock")])
    assert result == expected
    assert commands == ["drop", "unblock"]


def test_control_error_is_reported_to_the_owning_test(monkeypatch):
    monkeypatch.setattr(resilience, "_read_md5", lambda path: ("digest", 12, None))

    def control(command):
        raise ConnectionRefusedError("control endpoint stopped")

    with pytest.raises(ConnectionRefusedError, match="control endpoint stopped"):
        resilience._read_with_faults("sample", control, [(0, "drop")])


def test_read_error_cannot_leave_faults_running_after_cleanup(monkeypatch):
    """Negative: a failed read must not leak commands into another test."""
    started = threading.Event()
    commands = []
    active = threading.Event()
    active.set()

    def read(path):
        started.set()
        raise OSError("read failed")

    def control(command):
        assert started.wait(5), "read never started"
        assert active.is_set(), "command escaped the owning test"
        commands.append(command)

    monkeypatch.setattr(resilience, "_read_md5", read)
    with pytest.raises(OSError, match="read failed"):
        resilience._read_with_faults(
            "sample", control, [(0, "block"), (0, "unblock")])
    active.clear()
    assert commands == ["block", "unblock"]
