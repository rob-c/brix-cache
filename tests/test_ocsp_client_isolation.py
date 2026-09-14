"""Check OCSP client addressing and verdict accounting without live listeners."""

from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest

import _test_audit16a_ocsp_flags_helpers as client


@pytest.mark.parametrize('plane,returncode,output,accepted', [
    ('PORT', 0, client.SEED.decode(), True),
    ('OFF_PORT', 1, client.SEED.decode(), False),
    ('PORT', 0, 'unrelated data', False),
], ids=['accepted-seed', 'denied-with-output', 'wrong-content'])
def test_ocsp_client_uses_one_configured_endpoint(
        monkeypatch, plane, returncode, output, accepted):
    """Keep address selection independent of certificate identity and verdict."""
    endpoint = SimpleNamespace(port=11000, extra_ports={'OFF_PORT': 11001})
    credentials = {'ca': '/fixture/ca', 'credential': '/fixture/proxy'}
    monkeypatch.setattr(client, 'HOST', 'fixture-address')
    monkeypatch.setattr(client, 'CONNECT_HOST', 'service-identity')
    monkeypatch.setattr(client, 'SYS_XRDFS', '/fixture/xrdfs')
    monkeypatch.setenv('KRB5CCNAME', 'FILE:/fixture/ambient-ticket')
    monkeypatch.setenv('XrdSecPROTOCOL', 'krb5')
    calls = []

    def run(arguments, **options):
        calls.append((arguments, options))
        return CompletedProcess(arguments, returncode, output, 'fixture result')

    monkeypatch.setattr(client.subprocess, 'run', run)
    verdict, result = client._accepted(endpoint, plane, credentials, 'credential')
    assert verdict is accepted
    assert result.returncode == returncode
    assert len(calls) == 1
    arguments, options = calls[0]
    port = client._port(endpoint, plane)
    assert arguments == ['/fixture/xrdfs', f'root://fixture-address:{port}',
                         'cat', client.SEED_PATH]
    assert options['timeout'] == 90
    environment = options['env']
    assert environment['XrdSecPROTOCOL'] == 'gsi'
    assert environment['X509_CERT_DIR'] == credentials['ca']
    assert environment['X509_USER_PROXY'] == credentials['credential']
    assert environment['XrdSecGSISRVNAMES'] == '*'
    assert 'KRB5CCNAME' not in environment
