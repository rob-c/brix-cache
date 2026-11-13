"""Real HTTPS OCSP exchanges require both TLS trust and a valid signed status."""

from contextlib import contextmanager
import http.server
import ipaddress
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.x509 import ocsp

from brix_suite.servers.ocsp_responder import _Handler
from settings import BIND_HOST
from test_nginx_native_contract import server_native_compile  # noqa: F401
from test_ocsp_native import (StapleResponder, authority, enroll, invoke,  # noqa: F401
                             ocsp_binary)
from x509forge import make_ca, make_eec


def tls_context(tmp_path, authority, policy, monkeypatch):
    """Prepare certificate identity and trust independently of server lifetime."""
    names = [x509.IPAddress(ipaddress.ip_address(BIND_HOST))]
    if policy == 'wrong-host':
        names = [x509.DNSName('other.invalid')]
    cert = make_eec(authority, '/CN=OCSP TLS responder', key_type='ec',
                    eku=[x509.ExtendedKeyUsageOID.SERVER_AUTH.dotted_string],
                    extra_ext=[(x509.SubjectAlternativeName(names), False)])
    certificate, key, trust = [tmp_path / name for name in ('server.pem', 'server.key', 'trust.pem')]
    certificate.write_bytes(cert.pem); key.write_bytes(cert.key_pem)
    trusted = make_ca('/CN=Unrelated TLS authority', key_type='ec') if policy == 'untrusted' else authority
    trust.write_bytes(trusted.pem)
    monkeypatch.setenv('SSL_CERT_FILE', str(trust))
    monkeypatch.setenv('SSL_CERT_DIR', str(tmp_path / 'no-system-roots'))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    return context


@contextmanager
def https_responder(tmp_path, authority, responder, policy, monkeypatch):
    context = tls_context(tmp_path, authority, policy, monkeypatch)
    handler = type('HTTPSOCSPHandler', (_Handler,), {'responder': responder})
    server = http.server.ThreadingHTTPServer((BIND_HOST, 0), handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
    thread.start()
    try:
        yield f'https://{BIND_HOST}:{server.server_port}/ocsp'
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize('mode', ['check', 'staple'])
@pytest.mark.parametrize('verdict', ['good', 'revoked', 'unknown'])
def test_https_status_requires_real_signed_response(ocsp_binary, authority, tmp_path,
                                                   monkeypatch, mode, verdict):
    responder = StapleResponder(authority.cert, authority.key, {})
    with https_responder(tmp_path, authority, responder, 'trusted', monkeypatch) as url:
        leaf = enroll(responder, authority, url, verdict)
        status, body = invoke(ocsp_binary, tmp_path, leaf, authority, mode=mode)
    assert status == (0 if verdict == 'good' else -1)
    assert responder.log == [{'serial': leaf.cert.serial_number, 'verdict': verdict}]
    if mode == 'staple' and verdict == 'good':
        decoded = ocsp.load_der_ocsp_response(body)
        assert decoded.serial_number == leaf.cert.serial_number
        assert decoded.certificate_status == ocsp.OCSPCertStatus.GOOD
    else:
        assert body == b''


@pytest.mark.parametrize('mode', ['check', 'staple'])
@pytest.mark.parametrize('policy', ['untrusted', 'wrong-host'])
def test_https_rejects_untrusted_or_misnamed_peer_before_ocsp_request(ocsp_binary,
                                         authority, tmp_path, monkeypatch, mode, policy):
    responder = StapleResponder(authority.cert, authority.key, {})
    with https_responder(tmp_path, authority, responder, policy, monkeypatch) as url:
        leaf = enroll(responder, authority, url)
        assert invoke(ocsp_binary, tmp_path, leaf, authority, mode=mode) == (-1, b'')
    assert responder.log == []
