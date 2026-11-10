"""Short-lived Kubernetes probes retain output and clean up on every result."""
from subprocess import CompletedProcess

import pytest

from labtools import lab


@pytest.mark.parametrize("exit_code", ["0", "7", ""])
def test_probe_checks_exit_status_after_collecting_logs(monkeypatch, exit_code):
    """Success returns logs; failed or missing container status cannot pass."""
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        output = {"logs": "probe output\n", "get": exit_code}.get(argv[3], "")
        return CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(lab, "_sh", command)
    if exit_code == "0":
        assert lab._probe("private", "probe", "image:dev", "printf test") == "probe output"
    else:
        with pytest.raises(RuntimeError, match="exited"):
            lab._probe("private", "probe", "image:dev", "printf test")
    assert [call[3] for call in calls] == ["run", "logs", "wait", "get", "delete"]
    assert "--for=jsonpath={.status.containerStatuses[0].state.terminated}" in calls[2]
    assert all(call[:3] == ["kubectl", "-n", "private"] for call in calls)
    assert "--rm" not in calls[0]


def test_probe_timeout_retains_logs_and_cleans_up(monkeypatch):
    """Successful output alone cannot make an unobserved exit pass."""
    calls = []

    def command(argv, **kwargs):
        calls.append(argv[3])
        return CompletedProcess(argv, int(argv[3] == "wait"), "200", "")

    monkeypatch.setattr(lab, "_sh", command)
    with pytest.raises(RuntimeError, match="did not publish an exit status: 200"):
        lab._probe("private", "probe", "image:dev", "printf 200")
    assert calls == ["run", "logs", "wait", "delete"]
