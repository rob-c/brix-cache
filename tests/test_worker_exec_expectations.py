"""Unsupported worker execution is a rejection contract, not false success."""

import pytest

from lib_py import worker_exec


def test_supported_hosts_check_the_configured_program(monkeypatch):
    monkeypatch.setattr(worker_exec, "_worker_subprocess_supported", lambda: True)
    worker_exec.assert_worker_exec_config(0, "configuration is valid")
    worker_exec.assert_worker_exec_config(1, "world-writable", diagnostic="world-writable")


def test_unsupported_hosts_require_an_explicit_rejection(monkeypatch):
    monkeypatch.setattr(worker_exec, "_worker_subprocess_supported", lambda: False)
    worker_exec.assert_worker_exec_config(1, "hardened workers cannot execute subprocesses")
    with pytest.raises(pytest.skip.Exception):
        worker_exec.require_worker_exec()


@pytest.mark.parametrize("rc,output", [(0, "accepted"), (1, "unknown directive")])
def test_missing_host_enforcement_never_passes(monkeypatch, rc, output):
    monkeypatch.setattr(worker_exec, "_worker_subprocess_supported", lambda: False)
    with pytest.raises(AssertionError):
        worker_exec.assert_worker_exec_config(rc, output)
