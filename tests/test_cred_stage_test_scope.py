"""Credential-stage negative tests cannot mutate the live fleet's uid root."""

import subprocess

from cmdscripts import c_simple_units as units


def test_credential_harness_runs_only_in_its_private_directory(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(units, "compile_binary", lambda *a, **k:
                        subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(units, "run", lambda *a, **k:
                        calls.append(k["cwd"]) or subprocess.CompletedProcess([], 0, "ok", ""))
    assert all(ok for ok, _ in units.run_one("cred_stage", tmp_path))
    assert calls == [tmp_path]
    assert "tests/c/cred_stage_scope.h" in units.SPECS["cred_stage"].args


def test_failed_credential_build_does_not_run_an_old_executable(tmp_path, monkeypatch):
    monkeypatch.setattr(units, "compile_binary", lambda *a, **k:
                        subprocess.CompletedProcess([], 1, "", "bad compiler"))

    def forbidden(*args, **kwargs):
        raise AssertionError("failed build must never run a stale harness")

    monkeypatch.setattr(units, "run", forbidden)
    assert not all(ok for ok, _ in units.run_one("cred_stage", tmp_path))


def test_unrelated_unit_keeps_its_existing_fixture_directory(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(units, "compile_binary", lambda *a, **k:
                        subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(units, "run", lambda *a, **k:
                        calls.append(k["cwd"]) or subprocess.CompletedProcess([], 0, "ok", ""))
    assert all(ok for ok, _ in units.run_one("error_mapping", tmp_path))
    assert calls == [units.REPO_ROOT]
