"""Offline stock-client health and credential isolation for the TLS token tier."""

import os
import subprocess
from types import SimpleNamespace

import pytest

from clientconf import endpoints
from config_templates import render_config
from settings import CA_DIR


@pytest.fixture
def client_calls(monkeypatch):
    calls = []
    outcomes = []

    def run(command, **options):
        calls.append((command, options))
        result = outcomes.pop(0)
        if isinstance(result, Exception):
            raise result
        return SimpleNamespace(returncode=result)

    monkeypatch.setattr(endpoints.subprocess, "run", run)
    return SimpleNamespace(calls=calls, outcomes=outcomes)


def _assert_secure_call(call, operation):
    command, options = call
    assert command == ["fixture-xrdfs", endpoints.TOKEN.url(), *operation]
    assert command[1].startswith("roots://")
    assert options["env"]["BEARER_TOKEN_FILE"] == endpoints.TOKEN_FILE
    assert options["env"]["X509_CERT_DIR"] == CA_DIR
    assert options["timeout"] == 3
    assert options["capture_output"] and options["text"]


def test_stock_health_uses_tls_and_the_managed_token_authority(client_calls):
    client_calls.outcomes[:] = [0]
    assert endpoints.TOKEN.healthy("fixture-xrdfs", probe="/clientconf")
    assert len(client_calls.calls) == 1
    _assert_secure_call(client_calls.calls[0], ["stat", "/clientconf"])
    assert endpoints.TOKEN.caps == frozenset({"token", "tls"})


def test_root_listing_fallback_keeps_the_same_tls_credentials(client_calls):
    client_calls.outcomes[:] = [1, 0]
    assert endpoints.TOKEN.healthy("fixture-xrdfs", probe="/clientconf")
    assert len(client_calls.calls) == 2
    _assert_secure_call(client_calls.calls[0], ["stat", "/clientconf"])
    _assert_secure_call(client_calls.calls[1], ["ls", "/"])


def test_refused_credentials_do_not_become_a_healthy_endpoint(client_calls):
    client_calls.outcomes[:] = [1, 1]
    assert not endpoints.TOKEN.healthy("fixture-xrdfs")
    assert len(client_calls.calls) == 2
    _assert_secure_call(client_calls.calls[1], ["ls", "/"])


def test_health_timeout_remains_unhealthy(client_calls):
    client_calls.outcomes[:] = [subprocess.TimeoutExpired("fixture-xrdfs", 3)]
    assert not endpoints.TOKEN.healthy("fixture-xrdfs")
    assert len(client_calls.calls) == 1


def test_ambient_credentials_cannot_replace_the_token_fixture(monkeypatch):
    for variable in endpoints.SCRUB_VARS:
        monkeypatch.setenv(variable, "ambient-credential-fixture")
    environment = endpoints.TOKEN.auth_env()
    assert environment["BEARER_TOKEN_FILE"] == endpoints.TOKEN_FILE
    assert environment["X509_CERT_DIR"] == CA_DIR
    retained = {"BEARER_TOKEN_FILE", "X509_CERT_DIR"}
    assert not (set(endpoints.SCRUB_VARS) - retained) & environment.keys()
    assert os.environ["BEARER_TOKEN_FILE"] == "ambient-credential-fixture"


def test_shared_token_listener_offers_tls_and_keeps_raw_fixture_opt_in():
    text = render_config("nginx_shared.conf", TOKEN_PORT="fixture-token-port")
    token_server = text.split("listen fixture-token-port;", 1)[1].split("\n    }", 1)[0]
    directives = {line.split("#", 1)[0].strip() for line in token_server.splitlines()}
    assert {
        "brix_auth token;", "brix_ztn_cleartext on;", "brix_tls on;",
        "brix_certificate     {SERVER_CERT};",
        "brix_certificate_key {SERVER_KEY};", "brix_trusted_ca      {CA_CERT};",
    } <= directives
    assert "brix_tls_require all;" not in directives
