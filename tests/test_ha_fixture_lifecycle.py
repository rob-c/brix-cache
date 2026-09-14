"""Failover uses the registered member and restores it after transfer failure."""

from contextlib import nullcontext
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import test_ha_failover as subject


@pytest.mark.parametrize("failure_at, expected", [
    (None, ["stop", "restart"]),
    (0, []),
    (1, ["stop", "restart"]),
])
def test_failover_owns_only_its_registered_member(monkeypatch, tmp_path,
                                                failure_at, expected):
    """No member is touched before a good baseline; every stopped one returns."""
    calls, payloads, transfers = [], [], []

    def member_action(action, name):
        assert name == "ha-nginx1"
        calls.append(action)

    launcher = SimpleNamespace(
        stop=lambda name: member_action("stop", name),
        restart=lambda name: member_action("restart", name))
    monkeypatch.setattr(subject, "RegistryLauncher", lambda: launcher)
    monkeypatch.setattr(subject, "_write_shared", lambda name, data: payloads.append(data))
    monkeypatch.setattr(subject.time, "sleep", lambda duration: None)

    def transfer(source, destination, **kwargs):
        index = len(transfers)
        transfers.append(source)
        Path(destination).write_bytes(payloads[0])
        return subprocess.CompletedProcess([], int(index == failure_at), "", "fixture")

    monkeypatch.setattr(subject, "_xrdcp_get", transfer)
    expectation = nullcontext() if failure_at is None else pytest.raises(AssertionError)
    with expectation:
        subject.TestHAFailover().test_new_connections_handled_after_nginx1_stop(
            {"haproxy_url": "root://fixture.invalid/"}, tmp_path)
    assert calls == expected
