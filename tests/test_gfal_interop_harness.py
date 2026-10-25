"""GFAL workflows keep bounded commands, real failures and isolated TLS trust."""

import os
import subprocess

import pytest

import test_gfal_interop as interop
import _test_conf_gfal_ops_helpers as conformance
from gfal_cli import clean_env
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


def _executable(path, content="#!/bin/sh\nexit 0\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o755)
    return path


def test_installed_python_is_selected_despite_virtualenv_path(tmp_path, monkeypatch):
    command = _executable(tmp_path / "distro" / "gfal-stat")
    python = _executable(command.parent / "python3")
    venv_python = _executable(tmp_path / "venv" / "python3")
    path = os.pathsep.join([str(venv_python.parent), str(command.parent)])
    monkeypatch.setenv("PATH", path)
    monkeypatch.delenv("GFAL_PYTHONBIN", raising=False)

    env = clean_env("gfal-stat")

    assert env["GFAL_PYTHONBIN"] == str(python)
    assert env["PATH"] == path
    assert "GFAL_PYTHONBIN" not in os.environ


def test_missing_command_remains_an_execution_error(tmp_path, monkeypatch):
    missing = str(tmp_path / "missing-gfal-stat")
    monkeypatch.delenv("GFAL_PYTHONBIN", raising=False)
    assert "GFAL_PYTHONBIN" not in clean_env(missing)
    with pytest.raises(FileNotFoundError):
        conformance._gfal(missing, "--version", timeout=2)


def test_explicit_interpreter_failure_is_not_hidden(tmp_path, monkeypatch):
    interpreter = _executable(
        tmp_path / "broken-python", "#!/bin/sh\necho missing-bindings >&2\nexit 23\n")
    command = _executable(
        tmp_path / "gfal-stat", '#!/bin/sh\nexec "$GFAL_PYTHONBIN" "$0" "$@"\n')
    monkeypatch.setenv("GFAL_PYTHONBIN", str(interpreter))

    rc, out, err = conformance._gfal(command, "--version", timeout=2)

    assert rc == 23
    assert out == ""
    assert err == "missing-bindings\n"


@pytest.mark.parametrize("name", ["LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME"])
def test_python_and_library_injection_are_isolated(tmp_path, monkeypatch, name):
    value = str(tmp_path / "unrelated-runtime")
    monkeypatch.setenv(name, value)
    monkeypatch.setenv("X509_USER_PROXY", str(tmp_path / "proxy.pem"))
    monkeypatch.setenv("X509_CERT_DIR", str(tmp_path / "ca"))

    env = clean_env()

    assert name not in env
    assert os.environ[name] == value
    assert env["X509_USER_PROXY"] == str(tmp_path / "proxy.pem")
    assert env["X509_CERT_DIR"] == str(tmp_path / "ca")


@pytest.mark.parametrize("answering", [True, False])
def test_listener_probe_checks_the_actual_gfal_endpoint(monkeypatch, answering):
    calls = []

    def probe(host, port):
        calls.append((host, port))
        return answering

    monkeypatch.setattr(interop, "tcp_answering", probe)
    assert interop._port_open(interop.NGINX_WEBDAV_PORT) is answering
    assert calls == [(interop.HOST, interop.NGINX_WEBDAV_PORT)]


def test_listener_probe_does_not_hide_invalid_endpoint_errors(monkeypatch):
    def probe(host, port):
        raise ValueError("invalid endpoint")

    monkeypatch.setattr(interop, "tcp_answering", probe)
    with pytest.raises(ValueError, match="invalid endpoint"):
        interop._port_open(interop.NGINX_ANON_PORT)


def _local_pair(tmp_path):
    return {side + '_data': str(tmp_path / side) for side in ('our', 'off')}


def test_namespace_fixture_seeds_both_exports_without_a_transfer(tmp_path, monkeypatch):
    def no_transfer(*args, **kwargs):
        pytest.fail('namespace fixture must not depend on a successful transfer')

    monkeypatch.setattr(conformance, '_gfal', no_transfer)
    paths = conformance._seed_scratch_file(_local_pair(tmp_path), 'seed', 'a/b', b'\x00exact')
    assert len(paths) == 2 and paths[0] != paths[1]
    assert all(conformance.fixture_read_bytes(path) == b'\x00exact' for path in paths)


def test_namespace_fixture_rejects_stale_or_wrong_seed_bytes(tmp_path):
    ctx = _local_pair(tmp_path)
    paths = conformance._seed_scratch_file(ctx, 'seed', 'file', b'first')
    with pytest.raises(AssertionError, match='scratch fixture bytes differ'):
        conformance._seed_scratch_file(ctx, 'seed', 'file', b'other')
    assert all(conformance.fixture_read_bytes(path) == b'first' for path in paths)


@pytest.mark.parametrize('name,relative', [('../outside', 'file'), ('seed', '../file'),
                                        ('seed', '/absolute'), ('seed', 'a//b')])
def test_namespace_fixture_refuses_escaping_or_ambiguous_names(tmp_path, name, relative):
    with pytest.raises(ValueError, match='confined path components'):
        conformance._seed_scratch_file(_local_pair(tmp_path), name, relative, b'bad')
    assert list(tmp_path.iterdir()) == []
