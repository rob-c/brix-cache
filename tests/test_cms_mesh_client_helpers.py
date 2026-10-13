"""Hermetic pins for CMS mesh client retry behaviour."""

import subprocess

import cms_mesh_lib as mesh


def _completed(returncode=0, stdout="located\n", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_xrdfs_locate_returns_first_success(monkeypatch):
    calls = []
    monkeypatch.setattr(mesh.subprocess, "run",
                        lambda *args, **kwargs: calls.append(args) or _completed())
    assert mesh.xrdfs_locate(1094, "/ok", retries=3) == (0, "located", "")
    assert len(calls) == 1


def test_xrdfs_locate_retries_a_timed_out_client(monkeypatch):
    outcomes = [subprocess.TimeoutExpired(["xrdfs"], 1, output=b"partial"),
                _completed(stdout="second\n")]
    monkeypatch.setattr(mesh.subprocess, "run", lambda *args, **kwargs: outcomes.pop(0))
    monkeypatch.setattr(mesh.time, "sleep", lambda _seconds: None)

    original = mesh.subprocess.run

    def run_or_raise(*args, **kwargs):
        result = original(*args, **kwargs)
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(mesh.subprocess, "run", run_or_raise)
    assert mesh.xrdfs_locate(1094, "/slow", timeout=1, retries=2) == (
        0, "second", "",
    )


def test_xrdfs_locate_reports_exhausted_timeouts(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(["xrdfs"], 2, stderr=b"stalled")

    monkeypatch.setattr(mesh.subprocess, "run", timeout)
    monkeypatch.setattr(mesh.time, "sleep", lambda _seconds: None)
    rc, _out, err = mesh.xrdfs_locate(1094, "/never", timeout=2, retries=2)
    assert rc == 124
    assert "stalled" in err and "timeout after 2s" in err
