"""Both launcher facades finish owned teardown without losing an interrupt."""
from types import SimpleNamespace

import pytest

import server_launcher
from brix_suite.launcher.harness import LifecycleHarness as PackagedHarness


@pytest.fixture(params=[server_launcher.LifecycleHarness, PackagedHarness])
def harness_case(request, monkeypatch):
    harness = object.__new__(request.param)
    harness._names = ["first", "second", "third"]
    retired, stopped = [], []
    monkeypatch.setitem(request.param.close.__globals__, "unregister", retired.append)
    return harness, stopped, retired


def _check_complete(harness, stopped, retired):
    assert stopped == retired == ["third", "second", "first"]
    assert harness._names == []


def test_normal_close_releases_every_owned_registration(harness_case):
    harness, stopped, retired = harness_case
    harness.launcher = SimpleNamespace(stop=stopped.append)
    harness.close()
    _check_complete(harness, stopped, retired)


def test_ordinary_stop_error_does_not_strand_later_instances(harness_case):
    harness, stopped, retired = harness_case

    def stop(name):
        stopped.append(name)
        if name == "third":
            raise RuntimeError("owned stop failed")

    harness.launcher = SimpleNamespace(stop=stop)
    harness.close()
    _check_complete(harness, stopped, retired)


def test_interrupt_is_reraised_after_all_owned_registrations_are_released(harness_case):
    harness, stopped, retired = harness_case
    interruption = KeyboardInterrupt("first verdict must survive cleanup")

    def stop(name):
        stopped.append(name)
        if name == "third":
            raise interruption
        if name == "second":
            raise SystemExit("later interruption must not replace the first")

    harness.launcher = SimpleNamespace(stop=stop)
    with pytest.raises(KeyboardInterrupt) as caught:
        harness.close()
    assert caught.value is interruption
    _check_complete(harness, stopped, retired)
