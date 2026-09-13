"""GFAL workflows keep bounded commands, real failures and isolated TLS trust."""

import subprocess

import pytest

import test_gfal_interop as interop
from settings import HOST


def _assert_clean_client_policy(call, ca_dir):
    budget = next(mark.args[0] for mark in interop.pytestmark if mark.name == "timeout")
    assert 0 < call["timeout"] < budget
    assert "LD_LIBRARY_PATH" not in call["env"]
    assert call["env"]["X509_CERT_DIR"] == str(ca_dir)


@pytest.mark.parametrize("outcome,returncode", [("success", 0), ("error", 13), ("timeout", 124)])
def test_client_budget_and_failures_survive_environment_cleanup(
        tmp_path, monkeypatch, outcome, returncode):
    monkeypatch.setattr(interop, "CA_DIR", str(tmp_path))
    monkeypatch.setenv("LD_LIBRARY_PATH", "/untrusted/client/libraries")
    calls = []
    response = subprocess.CompletedProcess(["gfal-stat"], returncode)

    def invoke(args, **kwargs):
        calls.append(kwargs)
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        return response

    monkeypatch.setattr(interop.subprocess, "run", invoke)
    if outcome == "timeout":
        with pytest.raises(subprocess.TimeoutExpired):
            interop._gfal("gfal-stat", f"davs://{HOST}/object")
    else:
        assert interop._gfal("gfal-stat", f"davs://{HOST}/object") is response

    _assert_clean_client_policy(calls[0], tmp_path)
