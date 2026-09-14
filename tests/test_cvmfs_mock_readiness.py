"""Mock-origin startup must establish readiness before a live scenario proceeds."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def _subject():
    source = Path(__file__).parent / "cmdscripts" / "cvmfs_live.py"
    spec = importlib.util.spec_from_file_location("cvmfs_readiness_subject", source)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    return subject


def _mock_start(monkeypatch, subject, states, ready):
    events = []
    remaining = iter(states)

    def poll():
        events.append("poll")
        return next(remaining)

    process = SimpleNamespace(poll=poll)

    def spawn(command):
        events.append(("spawn", command))
        return process

    def wait(host, port, timeout):
        events.append(("ready", host, port, timeout))
        return ready

    monkeypatch.setattr(subject, "wait_tcp", wait)
    return SimpleNamespace(spawn=spawn), process, events


def test_live_child_is_not_returned_until_listener_is_ready(monkeypatch):
    subject = _subject()
    run, process, events = _mock_start(monkeypatch, subject, [None, None], True)
    assert subject._mock(run, subject.PORT_A, 6, 5, keepalive=True) is process
    assert events[0][0] == "spawn"
    assert events[0][1][-1] == "--keepalive"
    assert events[1:] == ["poll", ("ready", subject.BIND_HOST, subject.PORT_A, 10), "poll"]


@pytest.mark.parametrize("states,ready,checks", [
    ([1], True, ["poll"]),
    ([None], False, ["poll", "ready"]),
    ([None, 1], True, ["poll", "ready", "poll"]),
])
def test_exited_or_unready_child_is_rejected(monkeypatch, states, ready, checks):
    subject = _subject()
    run, _, events = _mock_start(monkeypatch, subject, states, ready)
    with pytest.raises(subject.LiveFailure, match="mock Stratum-1.*did not start"):
        subject._mock(run, subject.PORT_A, 6, 5)
    actual = [event if isinstance(event, str) else event[0] for event in events[1:]]
    assert actual == checks
