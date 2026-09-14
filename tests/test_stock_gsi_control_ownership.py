"""Exercise three real fixture bodies with inert processes and PKI builders."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from settings import TEST_PORT_START
import stock_xrootd_owner
import test_native_gsi_interop as native
import test_tpc_delegation as delegation
import test_tpc_gsi_outbound as outbound


def _write_output(argv, option):
    if option in argv:
        path = Path(argv[argv.index(option) + 1])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("inert offline fixture material")


def _fake_run(argv, **kwargs):
    _write_output(argv, "-out")
    return SimpleNamespace(returncode=0, stdout="fixture-hash", stderr="")


def _fake_openssl(*args):
    _write_output(args, "-keyout")
    _write_output(args, "-out")


def _signed_cert(base, ca, common_name, key, cert):
    key.write_text("inert key fixture")
    cert.write_text("inert certificate fixture")


def _prepare_builders(monkeypatch, subject):
    if subject is native:
        monkeypatch.setattr(subject, "_guard_gsi_server_1", lambda: None)
        monkeypatch.setattr(subject, "_guard_gsi_server_2", lambda: None)
        monkeypatch.setattr(subject, "_openssl", _fake_openssl)
        monkeypatch.setattr(subject, "_signed_cert", _signed_cert)
        monkeypatch.setattr(subject, "_free_port", lambda port: None)
        return
    if subject is delegation:
        monkeypatch.setattr(subject, "_require_gate_tools", lambda: None)
        monkeypatch.setattr(subject, "_make_gate_pki", lambda *args: None)
        monkeypatch.setattr(subject, "_make_gate_proxies",
                            lambda paths: ({}, paths["usr"] / "proxy.pem"))
    else:
        monkeypatch.setattr(subject, "_require_gsi_tools", lambda: None)
        monkeypatch.setattr(subject, "_make_gsi_pki", lambda *args: None)
        monkeypatch.setattr(subject, "_make_gsi_proxies", lambda paths: {})
        monkeypatch.setattr(subject, "_free_port", lambda port: None)
    monkeypatch.setattr(subject, "free_port", lambda: TEST_PORT_START)


@pytest.fixture(params=[(delegation, "gate", "_wait"),
                       (outbound, "gsi_tpc", "_wait_listen"),
                       (native, "gsi_server", "_listener_ready")],
                ids=["delegation", "outbound", "native"])
def case(request, monkeypatch, tmp_path):
    subject, fixture, readiness = request.param
    base = tmp_path / ("deep-gsi-fixture-" * 8)
    base.mkdir()
    owners, processes, reaped, chowns, commands = [], [], [], [], []

    def reap(process):
        assert Path(owners[-1].admin).is_dir()
        reaped.append(process)

    def own():
        owner = stock_xrootd_owner.StockXrootdOwner(reap)
        owners.append(owner)
        return owner

    def spawn(argv, **kwargs):
        process = SimpleNamespace(wait=lambda timeout: 0)
        processes.append(process)
        commands.append((argv, kwargs))
        return process

    monkeypatch.setenv("TMPDIR", str(base))
    monkeypatch.setenv("REF_RUNAS_USER", "fixture-runas")
    monkeypatch.setattr(subject.os, "geteuid", lambda: 501)
    monkeypatch.setattr(subject.socket, "getfqdn", lambda: "gsi-fixture.invalid")
    monkeypatch.setattr(subject, "StockXrootdOwner", own)
    monkeypatch.setattr(subject, "_run", _fake_run)
    monkeypatch.setattr(subject, readiness, lambda *args: True)
    monkeypatch.setattr(subject.subprocess, "Popen", spawn)
    monkeypatch.setattr(subject.shutil, "chown", lambda path, user: chowns.append((str(path), user)))
    _prepare_builders(monkeypatch, subject)
    lifecycle = SimpleNamespace(start=lambda spec: SimpleNamespace(
        port=TEST_PORT_START, prefix=str(base / "destination")))
    factory = SimpleNamespace(mktemp=lambda name: base)
    function = getattr(subject, fixture).__wrapped__
    generator = function(factory) if subject is native else function(lifecycle, factory)
    return SimpleNamespace(subject=subject, ready=readiness, base=base, generator=generator,
                           owners=owners, processes=processes, reaped=reaped,
                           chowns=chowns, commands=commands, lifecycle=lifecycle)


def _read_config(path):
    return dict(line.split(" ", 1) for line in path.read_text().splitlines())


def _check_source_contract(case):
    owner = case.owners[0]
    fields = _read_config(case.base / "xrootd.cfg")
    assert fields["all.adminpath"] == fields["all.pidpath"] == owner.admin
    assert Path(owner.admin).parent == Path("/tmp")
    assert len(str(Path(owner.admin) / "tpcgsisrc/.xrd/admin").encode()) < 108
    assert Path(owner.admin).stat().st_mode & 0o777 == 0o700
    _assert_gsi_configuration(fields, case.base)
    argv, kwargs = case.commands[0]
    assert argv[0] == "xrootd"
    assert kwargs["start_new_session"] is True
    assert case.owners[0].process is case.processes[0]


def _assert_gsi_configuration(fields, base):
    assert fields["oss.localroot"] == str(base)
    assert fields["sec.protbind"] == "* only gsi"
    assert fields["xrootd.seclib"] == "libXrdSec.so"
    assert "-cert:" in fields["sec.protocol"] and "-key:" in fields["sec.protocol"]


def _assert_closed(case):
    assert not Path(case.owners[0].admin).exists()
    assert case.reaped == case.processes


def test_deep_gsi_fixture_reaps_before_removing_short_control(case):
    next(case.generator)
    try:
        _check_source_contract(case)
    finally:
        case.generator.close()
    _assert_closed(case)


def test_existing_root_runas_owns_control_without_widening_mode(monkeypatch, case):
    monkeypatch.setattr(case.subject.os, "geteuid", lambda: 0)
    next(case.generator)
    try:
        _check_source_contract(case)
        assert (case.owners[0].admin, "fixture-runas") in case.chowns
        assert case.commands[0][0][-2:] == ["-R", "fixture-runas"]
    finally:
        case.generator.close()
    _assert_closed(case)


@pytest.mark.parametrize("failure", ["not-ready", "readiness-error", "spawn-error"])
def test_gsi_startup_failure_cleans_only_owned_state(monkeypatch, case, failure):
    def refuse(*args, **kwargs):
        raise OSError("deliberate offline fixture failure")

    if failure == "not-ready":
        monkeypatch.setattr(case.subject, case.ready, lambda *args: False)
        error = pytest.skip.Exception
    else:
        target = case.subject.subprocess if failure == "spawn-error" else case.subject
        method = "Popen" if failure == "spawn-error" else case.ready
        monkeypatch.setattr(target, method, refuse)
        error = OSError
    with pytest.raises(error):
        next(case.generator)
    _assert_closed(case)


@pytest.mark.parametrize("case", [(delegation, "gate", "_wait"),
                                (outbound, "gsi_tpc", "_wait_listen")],
                         indirect=True, ids=["delegation", "outbound"])
def test_destination_start_failure_reaps_source_and_preserves_error(monkeypatch, case):
    failure = RuntimeError("deliberate offline destination startup failure")

    def refuse(spec):
        raise failure

    monkeypatch.setattr(case.lifecycle, "start", refuse)
    with pytest.raises(RuntimeError) as caught:
        next(case.generator)
    assert caught.value is failure
    assert len(case.processes) == 1
    _assert_closed(case)
