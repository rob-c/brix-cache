"""Certificate diagnostics retain exact validity and bounded DNS SAN metadata."""

import ipaddress
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography import x509

from test_xrd_dispatch_native import compile_client_contract
from x509forge import make_ca, make_eec

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def certinfo(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('tls-certinfo'),
                                   'tests/c/tls_certinfo_native_test.c',
                                   ('SSL_get1_peer_certificate',))


def inspect(binary, tmp_path, certificate, hostname='source.example', transport='tls'):
    path = tmp_path / 'peer.pem'
    if certificate:
        path.write_bytes(certificate.pem)
    result = subprocess.run([str(binary), str(path) if certificate else '-', hostname, transport],
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.splitlines()


@pytest.mark.parametrize('before,after,expired,future', [(-1, 10, 0, 0), (-10, -1, 1, 0), (2, 10, 0, 1)])
@pytest.mark.parametrize('hostname,match', [('source.example', 1), ('wrong.example', 0), ('', 0)])
def test_peer_validity_and_hostname_facts_are_reported_exactly(certinfo, tmp_path,
                                                            before, after, expired, future, hostname, match):
    authority = make_ca('/CN=Diagnostic authority', key_type='ec')
    leaf = make_eec(authority, '/CN=Diagnostic peer', key_type='ec',
                    not_before_days=before, not_after_days=after,
                    extra_ext=[(x509.SubjectAlternativeName([
                        x509.DNSName('source.example'), x509.DNSName('mirror.example'),
                        x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)])  # net-literal-allow: certificate SAN bytes under test
    lines = inspect(certinfo, tmp_path, leaf, hostname)
    facts = list(map(int, lines[0].split()))
    assert facts[:4] == [0, match, expired, future]
    assert facts[4:6] == [int(leaf.cert.not_valid_before_utc.timestamp()),
                          int(leaf.cert.not_valid_after_utc.timestamp())]
    assert facts[6] < 0 if expired else facts[6] >= 0
    assert lines[1:] == ['/CN=Diagnostic peer', '/CN=Diagnostic authority',
                        'source.example,mirror.example']


def test_self_signed_without_sans_has_empty_san_list(certinfo, tmp_path):
    certificate = make_ca('/CN=Self-issued diagnostic peer', key_type='ec')
    lines = inspect(certinfo, tmp_path, certificate)
    assert list(map(int, lines[0].split()))[:4] == [1, 0, 0, 0]
    assert lines[1:] == ['/CN=Self-issued diagnostic peer', '/CN=Self-issued diagnostic peer', '']


def test_oversized_san_is_omitted_without_truncating_later_name(certinfo, tmp_path):
    authority = make_ca('/CN=SAN authority', key_type='ec')
    names = ['a' * 240 + '.example', 'b' * 240 + '.example', 'too-long.example', 'x.io']
    leaf = make_eec(authority, '/CN=SAN boundary peer', key_type='ec',
                    extra_ext=[(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), False)])
    lines = inspect(certinfo, tmp_path, leaf)
    assert lines[3] == ','.join([*names[:2], names[3]])


@pytest.mark.parametrize('transport', ['tls', 'cleartext'])
def test_absent_peer_clears_all_previous_diagnostic_fields(certinfo, tmp_path, transport):
    assert inspect(certinfo, tmp_path, None, transport=transport) == ['absent']
