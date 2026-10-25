"""Offline stock-client health and credential isolation for the TLS token tier."""

import os
import subprocess
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from clientconf import endpoints
from clientconf.fixtures import _client_credential_directory, _session_endpoints
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
    assert options["env"]["XrdSecPROTOCOL"] == 'ztn'
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
    retained = {"BEARER_TOKEN_FILE", "X509_CERT_DIR", "XrdSecPROTOCOL"}
    assert environment['XrdSecPROTOCOL'] == 'ztn'
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


def _token_fixture(tmp_path, monkeypatch):
    shared = tmp_path / "upstream.jwt"
    shared.write_bytes(b"test.header.signature")
    shared.chmod(0o644)
    monkeypatch.setattr(endpoints, "TOKEN_FILE", str(shared))
    return shared


def test_stock_token_copy_has_private_mode_and_identical_contents(tmp_path, monkeypatch):
    shared = _token_fixture(tmp_path, monkeypatch)
    selected = _session_endpoints(tmp_path)["token"]
    private = Path(selected.auth_env()["BEARER_TOKEN_FILE"])
    assert private != shared and private.read_bytes() == shared.read_bytes()
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert selected.scheme == "roots" and selected.port == endpoints.TOKEN.port


def test_missing_shared_token_is_not_replaced_with_a_fake_credential(tmp_path, monkeypatch):
    monkeypatch.setattr(endpoints, "TOKEN_FILE", str(tmp_path / "missing.jwt"))
    assert _session_endpoints(tmp_path)["token"] is endpoints.TOKEN
    assert list(tmp_path.iterdir()) == []


def test_client_copy_cannot_modify_server_or_ambient_credentials(tmp_path, monkeypatch):
    shared = _token_fixture(tmp_path, monkeypatch)
    monkeypatch.setenv("BEARER_TOKEN_FILE", "/untrusted/ambient.jwt")
    original_auth = dict(endpoints.TOKEN._auth)
    selected = _session_endpoints(tmp_path)
    assert selected["anon"] is endpoints.ANON
    assert endpoints.TOKEN._auth == original_auth
    assert stat.S_IMODE(shared.stat().st_mode) == 0o644
    assert selected["token"].auth_env()["BEARER_TOKEN_FILE"] != "/untrusted/ambient.jwt"
    assert selected["token"].auth_env()["X509_CERT_DIR"] == CA_DIR


def test_private_credentials_stay_in_the_fixture_namespace_and_are_retired(tmp_path, monkeypatch):
    shared = _token_fixture(tmp_path, monkeypatch)
    native_temp = tmp_path / 'native-temp'
    native_temp.mkdir()
    factory = SimpleNamespace(getbasetemp=lambda: native_temp)
    with _client_credential_directory(factory) as directory:
        path = Path(directory)
        selected = _session_endpoints(directory)['token']
        private = Path(selected.auth_env()['BEARER_TOKEN_FILE'])
        assert (path.parent, stat.S_IMODE(path.stat().st_mode)) == (shared.parent, 0o700)
        assert private.read_bytes() == shared.read_bytes()
        assert list(native_temp.iterdir()) == []
    assert not path.exists()
    assert shared.read_bytes() == b'test.header.signature'


def test_missing_fixture_token_directory_keeps_the_missing_credential_missing(tmp_path, monkeypatch):
    missing = tmp_path / 'absent-fixture' / 'upstream.jwt'
    monkeypatch.setattr(endpoints, 'TOKEN_FILE', str(missing))
    factory = SimpleNamespace(getbasetemp=lambda: tmp_path)
    with _client_credential_directory(factory) as directory:
        assert _session_endpoints(directory)['token'] is endpoints.TOKEN
        assert list(Path(directory).iterdir()) == []
    assert not missing.parent.exists()


def test_private_credential_cleanup_also_runs_after_a_client_error(tmp_path, monkeypatch):
    shared = _token_fixture(tmp_path, monkeypatch)
    factory = SimpleNamespace(getbasetemp=lambda: tmp_path)
    with pytest.raises(RuntimeError, match='client failed'):
        with _client_credential_directory(factory) as directory:
            selected = _session_endpoints(directory)['token']
            private = Path(selected.auth_env()['BEARER_TOKEN_FILE'])
            raise RuntimeError('client failed')
    assert not private.exists()
    assert stat.S_IMODE(shared.stat().st_mode) == 0o644


def test_remote_token_profile_cannot_borrow_the_operator_token_or_key(tmp_path):
    """A missing fixture bearer stays missing, without a host-key fallback."""
    from tools.ci.remote_reference_policy import oracle_environment

    values = dict(BEARER_TOKEN_FILE=str(tmp_path / 'missing-token'), XrdSecPROTOCOL='ztn')
    baseline = dict(X509_USER_CERT='/operator/cert', X509_USER_KEY='/operator/key',
                    BEARER_TOKEN_FILE='/operator/token', XRD_TLSNOCERTVERIFY='1')
    bundle = dict(values=values, files={}, directories=[])
    environment = oracle_environment(bundle, tmp_path, tmp_path / 'private', baseline)
    assert environment['XrdSecPROTOCOL'] == 'ztn'
    assert environment['BEARER_TOKEN_FILE'] == str(tmp_path / 'private/missing-token')
    assert not Path(environment['BEARER_TOKEN_FILE']).exists()
    assert not Path(environment['X509_USER_PROXY']).exists()
    assert not Path(environment['X509_USER_KEY']).exists()
    assert 'XRD_TLSNOCERTVERIFY' not in environment
    assert environment['HOME'] == str(tmp_path / 'private')
