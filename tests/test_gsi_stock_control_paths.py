"""Stock GSI control state stays short and fixture-owned without live servers."""

from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

import _test_gsi_handshake_helpers as subject


@pytest.fixture
def stock_case(monkeypatch, tmp_path):
    base = tmp_path / ("long-runtime-" * 8) / "gsihs"
    data = base / "data"
    data.mkdir(parents=True)
    (data / "hello.txt").write_text("fixture payload")
    pki = {"base": str(base), "data": str(data)}
    calls = []
    process = SimpleNamespace(returncode=None)

    def popen(command, **kwargs):
        calls.append(command)
        return process

    monkeypatch.setattr(subject.os, "geteuid", lambda: 501)
    monkeypatch.setattr(subject, "_check_start_stock_gsi_1", lambda: None)
    monkeypatch.setattr(subject, "_free_port", lambda port: None)
    monkeypatch.setattr(subject, "_wait_listen", lambda *args: None)
    monkeypatch.setattr(subject.subprocess, "Popen", popen)
    monkeypatch.setenv("TMPDIR", str(base))
    return pki, calls, process


def _start(pki, port, filename, control):
    base = Path(pki["base"])
    result = subject._start_stock_gsi(
        pki, port, str(base / "hostcert.pem"), str(base / "hostkey.pem"),
        str(base / "certs"), filename, control)
    lines = (base / filename).read_text().splitlines()
    config = dict(line.split(" ", 1) for line in lines)
    return result, config


def _assert_control_config(config, pki, control, port):
    admin = Path(config["all.adminpath"])
    assert admin == Path(control) / str(port)
    assert config["all.pidpath"] == str(admin)
    assert len(str(admin / "gsihs/.xrd/admin").encode()) + 3 <= 108
    assert admin.stat().st_mode & 0o777 == 0o700
    assert config["oss.localroot"] == pki["base"]
    assert config["all.export"] == "/gsidata"
    assert f"-cert:{pki['base']}/hostcert.pem" in config["sec.protocol"]
    assert "-crl:0 -gmapopt:10 -dlgpxy:0" in config["sec.protocol"]
    assert config["sec.protbind"] == "* only gsi"


def test_stock_gsi_uses_short_distinct_paths_under_long_tmpdir(stock_case):
    pki, calls, process = stock_case
    with closing(subject.stock_control_root.__wrapped__()) as owner:
        control = next(owner)
        assert Path(control).parent == Path("/tmp")
        for port in (subject.P_STOCK_ROOT, subject.P_STOCK_ROOT_FCA):
            result, config = _start(pki, port, f"stock-{port}.cfg", control)
            assert result is process
            _assert_control_config(config, pki, control, port)
        assert len(list(Path(control).iterdir())) == 2
    assert not Path(control).exists()
    assert len(calls) == 2
    assert (Path(pki["base"]) / "gsidata/hello.txt").read_text() == "fixture payload"


def test_stock_gsi_startup_failure_remains_error_and_control_is_cleaned(
        monkeypatch, stock_case):
    pki, calls, _ = stock_case

    def failed_wait(*args):
        raise AssertionError("stock xrootd exited before binding")

    monkeypatch.setattr(subject, "_wait_listen", failed_wait)
    with closing(subject.stock_control_root.__wrapped__()) as owner:
        control = next(owner)
        with pytest.raises(AssertionError, match="exited before binding"):
            _start(pki, subject.P_STOCK_ROOT, "stock.cfg", control)
    assert not Path(control).exists()
    assert len(calls) == 1


def test_stock_control_instances_do_not_share_state(stock_case):
    with closing(subject.stock_control_root.__wrapped__()) as first:
        first_root = Path(next(first))
        with closing(subject.stock_control_root.__wrapped__()) as second:
            second_root = Path(next(second))
            assert first_root != second_root
            (first_root / "owner").write_text("first")
            assert not (second_root / "owner").exists()
        assert first_root.is_dir()
        assert not second_root.exists()
    assert not first_root.exists()


def test_root_control_directory_is_owned_by_reference_user(monkeypatch, stock_case):
    pki, _, _ = stock_case
    owners = []
    monkeypatch.setattr(subject.os, "geteuid", lambda: 0)
    monkeypatch.setattr(subject.shutil, "chown", lambda path, **kw: owners.append((path, kw)))
    with closing(subject.stock_control_root.__wrapped__()) as owner:
        control = next(owner)
        assert owners == [(control, {"user": "nobody"})]
        child = str(Path(control) / str(subject.P_STOCK_ROOT))
        subject._stock_control_directory(child)
        assert owners[-1] == (child, {"user": "nobody"})
        assert Path(control).stat().st_mode & 0o777 == 0o700
    assert not Path(control).exists()
    assert Path(pki["base"]).is_dir()
