"""Exercise stock fixture control ownership without starting any process."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import official_interop_lib as subject
import test_official_interop as fixture_subject


@pytest.fixture
def stock_case(monkeypatch, tmp_path):
    base = tmp_path / ("deep-fixture-" * 8)
    data = base / "data"
    data.mkdir(parents=True)
    (data / "payload").write_bytes(b"unchanged fixture data")
    calls, reaped = [], []

    def spawn(command, **kwargs):
        config = Path(command[2])
        fields = dict(line.split(" ", 1) for line in config.read_text().splitlines())
        process = SimpleNamespace(admin=Path(fields["all.adminpath"]))
        process.wait = lambda timeout: 0
        calls.append((command, kwargs, fields, process))
        return process

    def reap(process):
        assert process.admin.is_dir(), "control state removed before process reap"
        reaped.append(process)

    monkeypatch.setenv("TMPDIR", str(base))
    monkeypatch.setattr(subject, "OFF_XROOTD", "/fixture/bin/stock-xrootd")
    monkeypatch.setattr(subject.subprocess, "Popen", spawn)
    monkeypatch.setattr(subject, "_wait", lambda port: True)
    monkeypatch.setattr(subject, "_kill_proc", reap)
    return base, data, calls, reaped


def _start(case):
    base, data, _, _ = case
    return subject.start_official_server(str(base), str(data), subject.OFF_PORT)


def _assert_control_config(call, base, data):
    command, kwargs, fields, process = call
    assert command == [subject.OFF_XROOTD, "-c", str(base / "xrootd.cfg"),
                       "-l", str(base / "xrd.log")]
    assert kwargs["start_new_session"] is True
    assert fields == {"xrd.port": str(subject.OFF_PORT), "all.export": "/",
                      "oss.localroot": str(data), "all.adminpath": str(process.admin),
                      "all.pidpath": str(process.admin), "xrootd.async": "off"}
    assert process.admin.parent == Path("/tmp")
    assert len(str(process.admin / ".xrd/admin").encode()) < 108
    assert process.admin.stat().st_mode & 0o777 == 0o700


def _assert_owned_isolation(case, first):
    base, data, calls, reaped = case
    first_admin, second_admin = calls[0][3].admin, calls[1][3].admin
    assert first_admin != second_admin
    for call in calls:
        _assert_control_config(call, base, data)
    subject.stop_pair([first])
    assert reaped == [calls[0][3]]
    assert not first_admin.exists()
    assert second_admin.is_dir()


def test_deep_fixture_uses_private_distinct_control_paths_until_stop(stock_case):
    _, data, calls, reaped = stock_case
    first, second = _start(stock_case), _start(stock_case)
    try:
        _assert_owned_isolation(stock_case, first)
    finally:
        subject.stop_pair([first, second])
    assert reaped == [call[3] for call in calls]
    assert not any(call[3].admin.exists() for call in calls)
    assert (data / "payload").read_bytes() == b"unchanged fixture data"


def _exercise_failed_start(monkeypatch, case, stage):
    def failure(*args, **kwargs):
        raise OSError("deliberate offline launch failure")

    if stage == "not-ready":
        monkeypatch.setattr(subject, "_wait", lambda port: False)
        assert _start(case) is None
        return
    target = subject.subprocess if stage == "spawn-error" else subject
    name = "Popen" if stage == "spawn-error" else "_wait"
    monkeypatch.setattr(target, name, failure)
    with pytest.raises(OSError, match="deliberate offline launch failure"):
        _start(case)


@pytest.mark.parametrize("stage", ["not-ready", "readiness-error", "spawn-error"])
def test_failed_start_never_retains_a_control_directory(monkeypatch, stock_case, stage):
    base, _, calls, reaped = stock_case
    _exercise_failed_start(monkeypatch, stock_case, stage)
    fields = dict(line.split(" ", 1) for line in (base / "xrootd.cfg").read_text().splitlines())
    assert not Path(fields["all.adminpath"]).exists()
    assert reaped == [call[3] for call in calls]


def _refuse_reap(monkeypatch, case, stage):
    def kill_failure(process):
        assert process.admin.is_dir()
        if getattr(process, "reap_recovered", False):
            return
        raise OSError("deliberate offline reap failure")

    def wait_failure(timeout):
        raise subject.subprocess.TimeoutExpired("fixture process", timeout)

    if stage == "kill-error":
        monkeypatch.setattr(subject, "_kill_proc", kill_failure)
    else:
        original = subject.subprocess.Popen

        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            process.wait = wait_failure
            return process

        monkeypatch.setattr(subject.subprocess, "Popen", spawn)
    if stage == "startup-wait-timeout":
        monkeypatch.setattr(subject, "_wait", lambda port: False)
        _start(case)
        pytest.fail("failed startup returned a handle despite an unreaped process")
    owner = _start(case)
    subject.stop_pair([owner])


@pytest.mark.parametrize("stage", ["kill-error", "wait-timeout", "startup-wait-timeout"])
def test_unreaped_process_retains_private_state_for_retry(monkeypatch, stock_case, stage):
    _, _, calls, _ = stock_case

    def forbidden_permission_change(*args, **kwargs):
        pytest.fail("control-path repair must not relax fixture permissions")

    monkeypatch.setattr(subject.os, "geteuid", lambda: 0)
    monkeypatch.setattr(subject.os, "chown", forbidden_permission_change)
    monkeypatch.setattr(subject.os, "chmod", forbidden_permission_change)
    errors = (OSError, subject.subprocess.TimeoutExpired)
    with pytest.raises(errors) as raised:
        _refuse_reap(monkeypatch, stock_case, stage)
    owner = raised.value.stock_server_owner
    assert "-R" not in calls[0][0]
    assert owner.process is calls[0][3]
    assert Path(owner.admin).stat().st_mode & 0o777 == 0o700
    owner.process.reap_recovered = True
    owner.process.wait = lambda timeout: 0
    subject.stop_pair([owner])
    assert not Path(owner.admin).exists()


@pytest.mark.parametrize("our_ready,off_ready,skip_message", [
    (False, True, "our nginx server did not start"),
    (True, False, "stock xrootd server did not start"),
    (True, True, None),
])
def test_pair_fixture_always_closes_started_handles(
        monkeypatch, tmp_path, our_ready, off_ready, skip_message):
    closed = []
    handles = {"ours": SimpleNamespace(close=lambda: closed.append("ours")),
               "off": SimpleNamespace(close=lambda: closed.append("off"))}
    readiness = {"ours": our_ready, "off": off_ready}
    started = {name: handle for name, handle in handles.items() if readiness[name]}
    monkeypatch.setattr(subject, "make_tree", lambda path: None)
    monkeypatch.setattr(subject, "start_our_server", lambda *a, **kw: started.get("ours"))
    monkeypatch.setattr(subject, "start_official_server", lambda *a, **kw: started.get("off"))
    factory = SimpleNamespace(mktemp=lambda name: tmp_path)
    generator = fixture_subject.srv.__wrapped__(factory)
    _exercise_pair_fixture(generator, skip_message)
    assert closed == list(started)


def _exercise_pair_fixture(generator, skip_message):
    if skip_message is not None:
        with pytest.raises(pytest.skip.Exception, match=skip_message):
            next(generator)
        return
    info = next(generator)
    assert set(info) == {"our", "off", "our_data", "off_data"}
    generator.close()


def test_stock_start_exception_closes_our_handle_without_replacing_error(monkeypatch, tmp_path):
    closed = []
    ours = SimpleNamespace(close=lambda: closed.append("ours"))
    error = OSError("deliberate offline stock startup error")

    def refuse(*args, **kwargs):
        raise error

    monkeypatch.setattr(subject, "make_tree", lambda path: None)
    monkeypatch.setattr(subject, "start_our_server", lambda *a, **kw: ours)
    monkeypatch.setattr(subject, "start_official_server", refuse)
    generator = fixture_subject.srv.__wrapped__(SimpleNamespace(mktemp=lambda name: tmp_path))
    with pytest.raises(OSError) as raised:
        next(generator)
    assert raised.value is error
    assert closed == ["ours"]
