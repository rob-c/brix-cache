"""Exercise the real smoke with owned files and a stubbed client process."""

from types import SimpleNamespace
import shutil

import pytest

import test_sanitizer_smoke as smoke


@pytest.fixture
def local_io(tmp_path, monkeypatch):
    export = tmp_path / "export"
    export.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    state = SimpleNamespace(export=export, reports=reports, mode="clean", calls=[])
    monkeypatch.setattr(smoke, "DATA_ROOT", str(export))
    monkeypatch.setattr(smoke, "SANITIZE_LOG_DIR", str(reports))
    monkeypatch.setattr(smoke, "_require_xrdcp", lambda: "fixture-xrdcp")

    def copy(command, **options):
        state.calls.append((command, options))
        assert command[:2] == ["fixture-xrdcp", "-f"]
        source = export / command[2].rsplit("/", 1)[-1]
        if state.mode == "transfer-failure":
            (reports / "asan.transfer").write_text("runtime error: fixture transfer failure\n")
            return SimpleNamespace(returncode=7, stdout="", stderr="fixture transfer failed")
        shutil.copyfile(source, command[3])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(smoke.subprocess, "run", copy)
    return state


def test_clean_smoke_transfers_owned_bytes(local_io, tmp_path):
    smoke.test_no_sanitizer_reports_after_basic_io(tmp_path)
    assert (tmp_path / "got.bin").read_bytes().startswith(b"xrootd-sanitizer-smoke\n")
    assert list(local_io.reports.iterdir()) == []
    _assert_transfer_cleanup(local_io)


def test_startup_report_fails_smoke_and_remains_available(local_io, tmp_path):
    startup = local_io.reports / "asan.startup"
    diagnostic = "ERROR: AddressSanitizer: fixture startup diagnostic\n"
    startup.write_text(diagnostic)
    with pytest.raises(AssertionError, match="reports written"):
        smoke.test_no_sanitizer_reports_after_basic_io(tmp_path)
    assert startup.read_text() == diagnostic
    assert list(local_io.reports.iterdir()) == [startup]
    _assert_transfer_cleanup(local_io)


def test_transfer_failure_retains_its_diagnostic(local_io, tmp_path):
    local_io.mode = "transfer-failure"
    with pytest.raises(AssertionError, match="xrdcp exited 7"):
        smoke.test_no_sanitizer_reports_after_basic_io(tmp_path)
    report = local_io.reports / "asan.transfer"
    assert report.read_text() == "runtime error: fixture transfer failure\n"
    assert list(local_io.reports.iterdir()) == [report]
    _assert_transfer_cleanup(local_io)


def _assert_transfer_cleanup(local_io):
    assert len(local_io.calls) == 1
    assert list(local_io.export.iterdir()) == []
