"""Token clients retain selected TLS trust without changing authentication."""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest


def _helpers(base, ca_dir, runner=None):
    path = Path(__file__).with_name("_test_native_xrdcp_xrdfs_helpers.py")
    tree = ast.parse(path.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in {"_token_env", "_run"}]
    assert len(functions) == 2
    namespace = {"_CLEAN_ENV": base, "CA_DIR": ca_dir, "TOKEN_FILE": "/fixture/upstream.jwt",
                 "subprocess": SimpleNamespace(run=runner)}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def test_token_environment_restores_only_selected_trust_and_bearer_file():
    base = {"PATH": "/fixture/bin", "X509_USER_PROXY": "/nonexistent/fixture-proxy"}
    helpers = _helpers(base, "/fixture/selected-fleet/ca")
    env = helpers["_token_env"]()
    assert env == {**base, "BEARER_TOKEN_FILE": "/fixture/upstream.jwt",
                   "X509_CERT_DIR": "/fixture/selected-fleet/ca"}
    assert base == {"PATH": "/fixture/bin", "X509_USER_PROXY": "/nonexistent/fixture-proxy"}


def test_token_environment_does_not_leak_trust_or_credentials_into_clean_clients():
    base = {"X509_USER_PROXY": "/nonexistent/fixture-proxy"}
    helpers = _helpers(base, "/fixture/selected-fleet/ca")
    first = helpers["_token_env"]()
    first["X509_CERT_DIR"] = "/fixture/decoy-ca"
    first["BEARER_TOKEN_FILE"] = "/fixture/decoy-token"
    second = helpers["_token_env"]()
    assert second["X509_CERT_DIR"] == "/fixture/selected-fleet/ca"
    assert second["BEARER_TOKEN_FILE"] == "/fixture/upstream.jwt"
    assert base == {"X509_USER_PROXY": "/nonexistent/fixture-proxy"}


def test_client_trust_failure_remains_a_failure_with_selected_ca():
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=53, stdout="", stderr="TLS verify failed")

    helpers = _helpers({}, "/fixture/selected-fleet/ca", run)
    env = helpers["_token_env"]()
    result = helpers["_run"]("fixture-xrdfs", "fixture-endpoint", "stat", "/fixture", env=env)
    assert result == (53, "", "TLS verify failed")
    assert calls == [(["fixture-xrdfs", "fixture-endpoint", "stat", "/fixture"],
                      {"capture_output": True, "text": True, "env": env, "timeout": 30})]


def test_client_launch_exception_propagates_unchanged():
    error = OSError("inert client launch failure")

    def refuse(*args, **kwargs):
        raise error

    helpers = _helpers({}, "/fixture/selected-fleet/ca", refuse)
    with pytest.raises(OSError) as caught:
        helpers["_run"]("fixture-xrdfs", "fixture-endpoint", env=helpers["_token_env"]())
    assert caught.value is error
