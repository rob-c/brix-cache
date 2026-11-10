"""Failover waits require explicit health from the intended HAProxy backend."""
import pytest

import _test_ha_health as health


def test_health_csv_preserves_up_and_down():
    states = health.backend_states(
        "# pxname,svname,status\nbrix_backends,nginx1,DOWN\n"
        "brix_backends,nginx2,UP\n")
    assert states == {"nginx1": "DOWN", "nginx2": "UP"}


def test_other_backend_cannot_satisfy_expected_health():
    assert health.backend_states("# pxname,svname,status\nother,nginx1,DOWN\n") == {}


def test_missing_backend_does_not_pass_wait(monkeypatch):
    monkeypatch.setattr(health, "_read_states", lambda: {"nginx2": "UP"})

    def one_attempt(predicate, **_kwargs):
        assert not predicate()
        raise AssertionError("backend did not become ready")

    monkeypatch.setattr(health, "wait_until", one_attempt)
    with pytest.raises(AssertionError, match="did not become ready"):
        health.wait_backend_states({"nginx1": "DOWN", "nginx2": "UP"})
