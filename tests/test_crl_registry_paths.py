"""Check CRL fixture path and signal selection with private files only."""

from contextlib import closing
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import test_crl as subject


@pytest.fixture
def crl_case(monkeypatch, tmp_path):
    registry = tmp_path / "independently-selected-registry"
    endpoints = {}
    for name in ("crl", "crl-dir", "crl-reload"):
        prefix = registry / name
        logs = prefix / "logs"
        logs.mkdir(parents=True)
        pidfile = logs / "nginx.pid"
        pidfile.write_text("314159\n")
        endpoints[name] = SimpleNamespace(
            config=str(prefix / "conf/nginx.conf"), pidfile=str(pidfile))
    crl = tmp_path / "sample.crl"
    crl.write_text("inert copied fixture content")
    calls = []
    monkeypatch.setattr(subject, "get_server", lambda name: endpoints[name])
    monkeypatch.setattr(subject, "TEST_ROOT", str(tmp_path / "unrelated-test-root"))
    monkeypatch.setattr(subject, "CRL_DIR_CRLS", str(tmp_path / "directory-crls"))
    monkeypatch.setattr(subject, "CRL_RELOAD_CRLS", str(tmp_path / "reload-crls"))
    monkeypatch.setattr(subject, "_wait_for_port", lambda *args: True)
    monkeypatch.setattr(subject, "_wait_revoked_accepted", lambda *args: True)
    monkeypatch.setattr(subject.os, "kill", lambda pid, sig: calls.append((pid, sig)))
    return str(crl), endpoints, calls


@pytest.mark.parametrize("name,fixture", [
    ("crl", "crl_nginx"), ("crl-dir", "crl_dir_nginx"),
    ("crl-reload", "crl_reload_nginx"),
])
def test_fixtures_use_authoritative_registry_paths(crl_case, name, fixture):
    crl, endpoints, calls = crl_case
    with closing(getattr(subject, fixture).__wrapped__(crl)) as generator:
        info = next(generator)
    endpoint = endpoints[name]
    assert info["conf"] == endpoint.config
    assert info["pidfile"] == endpoint.pidfile
    assert info["log_dir"] == str(Path(endpoint.pidfile).parent)
    if name == "crl-reload":
        assert info["crl_src"] == crl
        assert calls == [(314159, subject.signal.SIGHUP)]
    else:
        assert calls == []


@pytest.mark.parametrize("content", [None, "invalid", "0", "-1", "1", "12 13"])
def test_missing_or_invalid_pid_never_signals(crl_case, content):
    _, endpoints, calls = crl_case
    path = Path(endpoints["crl-reload"].pidfile)
    if content is None:
        path.unlink()
    else:
        path.write_text(content)
    subject._reload_crl_server(subject._crl_server_info("crl-reload"))
    assert calls == []


def test_positive_pid_signal_error_keeps_best_effort_behavior(monkeypatch, crl_case):
    _, _, calls = crl_case

    def vanished(pid, sig):
        calls.append((pid, sig))
        raise ProcessLookupError("offline vanished fixture")

    monkeypatch.setattr(subject.os, "kill", vanished)
    subject._reload_crl_server(subject._crl_server_info("crl-reload"))
    assert calls == [(314159, subject.signal.SIGHUP)]


@pytest.mark.parametrize("content", [None, "unrelated log line", "CRL reload timer fired"])
def test_timer_evidence_is_required_and_keeps_exact_assertion(crl_case, content):
    info = subject._crl_server_info("crl-reload")
    path = Path(info["log_dir"]) / "error.log"
    if content is not None:
        path.write_text(content)
    call = subject.TestCRLReload().test_reload_timer_log_message
    if content == "CRL reload timer fired":
        call(info)
        return
    if content is None:
        with pytest.raises(pytest.fail.Exception, match="required CRL reload error.log"):
            call(info)
        return
    with pytest.raises(AssertionError, match="expected 'CRL reload timer fired'"):
        call(info)


def _readiness_case(monkeypatch, responses):
    clock, calls, sleeps = [0.0], [], []
    outcomes = iter(responses)

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    def run(command, **kwargs):
        limit = kwargs["timeout"]
        calls.append(limit)
        outcome = next(outcomes)
        if outcome == "timeout":
            clock[0] += limit
            raise subprocess.TimeoutExpired(command, limit)
        if isinstance(outcome, Exception):
            raise outcome
        clock[0] += 0.25
        return SimpleNamespace(returncode=outcome)

    monkeypatch.setattr(subject, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    monkeypatch.setattr(subject, "os", SimpleNamespace(environ={}, path=os.path))
    monkeypatch.setattr(subject, "subprocess", SimpleNamespace(
        run=run, TimeoutExpired=subprocess.TimeoutExpired))
    return clock, calls, sleeps


def test_reload_readiness_retries_transient_timeout_within_original_deadline(monkeypatch):
    clock, calls, sleeps = _readiness_case(monkeypatch, ["timeout", 0])
    assert subject._wait_revoked_accepted(subject.CRL_RELOAD_PORT) is True
    assert calls == [10, 1.5]
    assert sleeps == [0.5]
    assert clock[0] == 10.75


def test_reload_readiness_caps_commands_and_sleep_at_original_deadline(monkeypatch):
    clock, calls, sleeps = _readiness_case(monkeypatch, ["timeout", "timeout"])
    assert subject._wait_revoked_accepted(subject.CRL_RELOAD_PORT) is False
    assert calls == [10, 1.5]
    assert sleeps == [0.5]
    assert clock[0] == 12


def test_reload_readiness_propagates_unrelated_subprocess_error(monkeypatch):
    error = OSError("offline client executable unavailable")
    clock, calls, sleeps = _readiness_case(monkeypatch, [error])
    with pytest.raises(OSError) as raised:
        subject._wait_revoked_accepted(subject.CRL_RELOAD_PORT)
    assert raised.value is error
    assert calls == [10]
    assert sleeps == []
    assert clock[0] == 0


def test_failed_readiness_prevents_fixture_yield(monkeypatch, crl_case):
    crl, _, calls = crl_case
    monkeypatch.setattr(subject, "_wait_revoked_accepted", lambda _port: False)
    with pytest.raises(pytest.fail.Exception, match="CRL-free ready state"):
        with closing(subject.crl_reload_nginx.__wrapped__(crl)) as generator:
            next(generator)
    assert calls == [(314159, subject.signal.SIGHUP)]
