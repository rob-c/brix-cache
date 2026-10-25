"""Optional kill diagnostics must never postpone or redirect owned cleanup."""

import os
import signal
import subprocess
from types import SimpleNamespace

from brix_suite.harness import kill_tracer


def _trace(monkeypatch, probe):
    """Record diagnostics and the real-call boundary without sending a signal."""
    calls, logs = [], []
    group = os.getpgrp() + 1
    monkeypatch.setattr(kill_tracer.subprocess, "run", probe)
    monkeypatch.setattr(kill_tracer, "_log", lambda *args: logs.append(args))
    kill_tracer._trace_killpg(group, signal.SIGKILL,
                             real_killpg=lambda *args: calls.append(args),
                             fatal=(signal.SIGKILL, signal.SIGTERM))
    assert calls == [(group, signal.SIGKILL)]
    return group, logs


def test_successful_group_discovery_is_bounded_and_logged(monkeypatch):
    """A verified server label is retained without changing the kill target."""
    probes = []

    def probe(args, **kwargs):
        probes.append((args, kwargs))
        return SimpleNamespace(stdout="704\n")

    monkeypatch.setattr(kill_tracer, "_server_name", lambda pid: "nginx:fixture" if pid == "704" else None)
    group, logs = _trace(monkeypatch, probe)
    assert probes == [(["pgrep", "-g", str(group)],
                       {"capture_output": True, "text": True, "timeout": 1})]
    assert logs == [(f"nginx:fixture(pg{group})", signal.SIGKILL, "os.killpg")]


def test_slow_diagnostic_cannot_prevent_the_real_kill(monkeypatch):
    """Expiry of the forensic budget still executes cleanup exactly once."""
    def probe(args, **kwargs):
        assert kwargs["timeout"] == 1
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    _group, logs = _trace(monkeypatch, probe)
    assert logs == []


def test_malformed_diagnostic_output_never_redirects_the_kill(monkeypatch):
    """Untrusted process-list text cannot substitute a target or signal."""
    _group, logs = _trace(monkeypatch, lambda *args, **kwargs:
                         SimpleNamespace(stdout="not-a-pid\n"))
    assert logs == []


def test_native_process_helper_labels_frozen_nginx(monkeypatch):
    """BSD has no procfs and its frozen executable retains a random suffix."""
    from lib_py import util

    monkeypatch.setattr(util, "process_cmdline", lambda pid:
        b"nginx-abcdef01: master process /tmp/nginx -p /tmp/lane/registry/main")
    assert kill_tracer._server_name(704) == "nginx:main"


def test_unreadable_native_process_has_no_diagnostic_label(monkeypatch):
    from lib_py import util

    monkeypatch.setattr(util, "process_cmdline", lambda pid: b"")
    assert kill_tracer._server_name(704) is None
    assert kill_tracer._process_command("not-a-pid") is None


def test_unrelated_command_cannot_impersonate_an_nginx_master(monkeypatch):
    from lib_py import util

    monkeypatch.setattr(util, "process_cmdline", lambda pid:
        b"python fake-nginx: master process /tmp/lane/registry/main")
    assert kill_tracer._server_name(704) is None
