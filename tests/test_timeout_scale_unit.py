"""Unit cover for the per-test timeout scaler in ``conftest_part3``.

pytest.ini sizes the per-test timeout for the CI reference host. On a slower
or busier machine ``TEST_BUDGET_SCALE`` already stretches every other
wall-clock budget, and the timeout has to move with them or ordinary host load
reads as a test failure. These cells pin the three things that matter: it
lengthens when the operator asks, it never shortens, and a host that declares
nothing keeps the reference value byte-for-byte.
"""

import socket
import time

import pytest

import conftest_part3 as cp3
from lib_py.util import wait_tcp


class _Opt:
    def __init__(self, timeout=None):
        self.timeout = timeout


class _Config:
    """The two surfaces the scaler touches on a pytest config."""

    def __init__(self, timeout=None, ini="30", worker=False):
        self.option = _Opt(timeout)
        self._ini = ini
        if worker:
            self.workerinput = {}

    def getini(self, name):
        assert name == "timeout"
        return self._ini


def _scale(monkeypatch, value, **kwargs):
    if value is None:
        monkeypatch.delenv("TEST_BUDGET_SCALE", raising=False)
    else:
        monkeypatch.setenv("TEST_BUDGET_SCALE", value)
    config = _Config(**kwargs)
    cp3._scale_timeout(config)
    return config


def test_declared_scale_lengthens_the_ini_default(monkeypatch):
    """The documented path: 30 s at scale 5 becomes 150 s."""
    assert _scale(monkeypatch, "5").option.timeout == pytest.approx(150.0)


def test_command_line_timeout_scales_too(monkeypatch):
    """An explicit --timeout outranks the ini value and scales the same way."""
    config = _scale(monkeypatch, "4", timeout=10.0)
    assert config.option.timeout == pytest.approx(40.0)


def test_resolved_plugin_value_is_updated(monkeypatch):
    """The plugin caches the resolved timeout; a stale cache would win."""
    config = _Config()
    config._env_timeout = 30.0
    monkeypatch.setenv("TEST_BUDGET_SCALE", "3")
    cp3._scale_timeout(config)
    assert config._env_timeout == pytest.approx(90.0)


def test_unset_host_keeps_the_reference_timeout(monkeypatch):
    """No knob, no change — the CI reference must stay exactly 30 s."""
    assert _scale(monkeypatch, None).option.timeout is None


@pytest.mark.parametrize("value", ["1", "0", "-2", "", "not-a-number"])
def test_scale_never_shortens_a_timeout(monkeypatch, value):
    """A typo, a zero or a value below 1 must not shrink the budget."""
    assert _scale(monkeypatch, value).option.timeout is None


def test_missing_ini_value_is_left_alone(monkeypatch):
    """No configured timeout means nothing to scale, not a crash."""
    assert _scale(monkeypatch, "5", ini=None).option.timeout is None


def test_worker_process_scales_without_announcing(monkeypatch, capsys):
    """Only the controller prints the notice; N workers would print N times."""
    config = _scale(monkeypatch, "5", worker=True)
    assert config.option.timeout == pytest.approx(150.0)
    assert "per-test timeout" not in capsys.readouterr().err


def _closed_port():
    """A port nothing is listening on: bind one, read it back, release it."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_listener_wait_spends_the_scaled_budget(monkeypatch):
    """wait_tcp's timeout is a CI-reference budget: at scale 4 a 0.15 s wait
    must keep trying for about 0.6 s, not give up at 0.15 s."""
    monkeypatch.setenv("TEST_BUDGET_SCALE", "4")
    started = time.monotonic()
    assert wait_tcp("127.0.0.1", _closed_port(), 0.15) is False
    assert time.monotonic() - started >= 0.45


def test_listener_wait_keeps_the_reference_budget(monkeypatch):
    """With nothing declared it must not linger: a 0.15 s wait stays short."""
    monkeypatch.delenv("TEST_BUDGET_SCALE", raising=False)
    started = time.monotonic()
    assert wait_tcp("127.0.0.1", _closed_port(), 0.15) is False
    assert time.monotonic() - started < 0.45


# ---------------------------------------------------------------------------
# Kill tracer: a fatal signal aimed at the pytest session's own process group
# ends the run with no summary and no traceback, so the tracer has to see it.
# ---------------------------------------------------------------------------

def test_tracer_records_a_kill_aimed_at_our_own_group():
    """Our own group is always the wrong target, and the label must say so."""
    from brix_suite.harness import kill_tracer

    import os as _os
    target = kill_tracer._killpg_target(_os.getpgrp(), 9, (9, 15))
    assert target is not None and "OWN process group" in target


def test_tracer_ignores_a_harmless_signal_to_our_group():
    """A non-fatal signal (SIGHUP to reload, say) is not a lane death."""
    from brix_suite.harness import kill_tracer

    import os as _os
    assert kill_tracer._killpg_target(_os.getpgrp(), 1, (9, 15)) is None


# ---------------------------------------------------------------------------
# An explicit @pytest.mark.timeout(N) overrides the ini default outright, so it
# has to be scaled as well or 518 files keep a CI-reference budget.
# ---------------------------------------------------------------------------

class _Marker:
    def __init__(self, args=(), kwargs=None):
        self.args = args
        self.kwargs = kwargs or {}


def test_positional_marker_seconds_are_scaled():
    scaled = cp3._scaled_timeout_marker(_Marker((900,)), 5)
    assert scaled.args[0] == pytest.approx(4500.0)


def test_keyword_marker_seconds_are_scaled():
    scaled = cp3._scaled_timeout_marker(_Marker(kwargs={"timeout": 60}), 3)
    assert scaled.kwargs["timeout"] == pytest.approx(180.0)


def test_marker_method_is_preserved():
    """pytest.ini picks the signal method deliberately; scaling must keep it."""
    scaled = cp3._scaled_timeout_marker(
        _Marker((30,), {"method": "thread"}), 2)
    assert scaled.args[0] == pytest.approx(60.0)
    assert scaled.kwargs["method"] == "thread"


def test_disabled_timeout_stays_disabled():
    """timeout(0) means no limit; any multiple of zero is still no limit."""
    assert cp3._scaled_timeout_marker(_Marker((0,)), 5).args[0] == 0


def test_marker_without_a_number_is_left_alone():
    assert cp3._scaled_timeout_marker(_Marker(kwargs={"method": "signal"}), 5) is None
