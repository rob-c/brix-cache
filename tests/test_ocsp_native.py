"""Public OCSP checks and staples use real signed HTTP responder exchanges."""

from contextlib import contextmanager
import http.server
import subprocess
import threading

import pytest
from cryptography import x509
from cryptography.x509 import ocsp

from brix_suite.servers.ocsp_responder import _Handler, _Responder
from settings import BIND_HOST
from test_nginx_native_contract import server_native_compile  # noqa: F401
from x509forge import make_ca, make_eec


class StapleResponder(_Responder):
    """Carry the signer certificate needed by OpenSSL's OCSP_basic_verify."""

    def _response_builder(self, entry):
        return super()._response_builder(entry).certificates([self.signer_cert])


@pytest.fixture(scope='module')
def ocsp_binary(server_native_compile):
    return server_native_compile('ocsp-native', 'tests/c/ocsp_native_test.c',
                                 ['-Wl,--wrap=ngx_alloc'])


@pytest.fixture(scope='module')
def authority():
    return make_ca('/CN=Native OCSP fixture CA', key_type='ec')


@contextmanager
def responder_server(responder):
    """Keep each HTTP responder local, private, and fully joined at teardown."""
    handler = type('FixtureOCSPHandler', (_Handler,), {'responder': responder})
    server = http.server.ThreadingHTTPServer((BIND_HOST, 0), handler)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={'poll_interval': 0.01})
    thread.start()
    try:
        yield f'http://{BIND_HOST}:{server.server_port}/ocsp'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def leaf_for(authority, urls):
    extensions = []
    if urls:
        descriptions = [x509.AccessDescription(x509.AuthorityInformationAccessOID.OCSP,
                         x509.UniformResourceIdentifier(url)) for url in urls]
        extensions = [(x509.AuthorityInformationAccess(descriptions), False)]
    return make_eec(authority, '/CN=Native OCSP client', key_type='ec',
                    extra_ext=extensions)


def invoke(binary, tmp_path, leaf, issuer, *, mode='check', soft=0, nonce=1,
           repeats=1, fault=''):
    paths = []
    for name, cert in [('leaf', leaf), ('issuer', issuer)]:
        path = tmp_path / (name + '.pem')
        if cert is not None:
            path.write_bytes(cert.pem)
        paths.append(str(path) if cert is not None else '-')
    result = subprocess.run([str(binary), mode, *paths, str(soft), str(nonce),
                             str(repeats), fault], capture_output=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    status, body = result.stdout.split(b'\n', 1)
    return int(status), body


def enroll(responder, authority, url, status='good', prefix=()):
    leaf = leaf_for(authority, [*prefix, url])
    responder.entries[leaf.cert.serial_number] = (leaf.cert, authority.cert, status)
    return leaf


@pytest.mark.parametrize('status', ['good', 'revoked', 'unknown'])
@pytest.mark.parametrize('soft', [0, 1])
def test_check_signed_status_applies_soft_fail_only_to_unknown(ocsp_binary,
                                                authority, tmp_path, status, soft):
    responder = StapleResponder(authority.cert, authority.key, {})
    with responder_server(responder) as url:
        leaf = enroll(responder, authority, url, status)
        expected = {'good': 0, 'revoked': -1, 'unknown': -1 + soft}[status]
        assert invoke(ocsp_binary, tmp_path, leaf, authority, soft=soft) == (expected, b'')
    assert responder.log == [{'serial': leaf.cert.serial_number, 'verdict': status}]


@pytest.mark.parametrize('options,nonce,expected', [
    ({'omit_nonce': True}, 0, 0), ({'omit_nonce': True}, 1, -1),
    ({'wrong_nonce': True}, 0, -1), ({'wrong_nonce': True}, 1, -1),
])
def test_check_nonce_replay_policy_cannot_be_softened(ocsp_binary, authority,
                                               tmp_path, options, nonce, expected):
    responder = _Responder(authority.cert, authority.key, {}, **options)
    with responder_server(responder) as url:
        leaf = enroll(responder, authority, url)
        assert invoke(ocsp_binary, tmp_path, leaf, authority, soft=1,
                      nonce=nonce) == (expected, b'')
    assert len(responder.log) == 1


@pytest.mark.parametrize('status', ['good', 'revoked'])
@pytest.mark.parametrize('soft', [0, 1])
def test_stale_revocation_still_denies(ocsp_binary, authority, tmp_path, status, soft):
    responder = _Responder(authority.cert, authority.key, {}, stale=True)
    with responder_server(responder) as url:
        leaf = enroll(responder, authority, url, status)
        expected = -1 if status == 'revoked' else -1 + soft
        assert invoke(ocsp_binary, tmp_path, leaf, authority, soft=soft) == (expected, b'')


@pytest.mark.parametrize('missing', ['leaf', 'issuer', 'aia'])
@pytest.mark.parametrize('soft', [0, 1])
def test_missing_check_identity_uses_explicit_policy(ocsp_binary, authority,
                                                   tmp_path, missing, soft):
    leaf = leaf_for(authority, [])
    issuer = authority
    if missing == 'leaf':
        leaf = None
    if missing == 'issuer':
        issuer = None
    assert invoke(ocsp_binary, tmp_path, leaf, issuer, soft=soft) == (-1 + soft, b'')


@pytest.mark.parametrize('mode', ['check', 'staple'])
def test_unusable_first_aia_url_preserves_certificate_id_for_next(ocsp_binary,
                                                   authority, tmp_path, mode):
    responder = StapleResponder(authority.cert, authority.key, {})
    with responder_server(responder) as url:
        leaf = enroll(responder, authority, url, prefix=('unsupported://invalid',))
        status, body = invoke(ocsp_binary, tmp_path, leaf, authority, mode=mode)
    assert status == 0
    assert bool(body) == (mode == 'staple')
    assert len(responder.log) == 1


@pytest.mark.parametrize('repeats', [1, 2])
@pytest.mark.parametrize('omit_nonce', [False, True])
def test_staple_verifies_and_replaces_owned_der(ocsp_binary, authority, tmp_path,
                                             repeats, omit_nonce):
    responder = StapleResponder(authority.cert, authority.key, {}, omit_nonce=omit_nonce)
    with responder_server(responder) as url:
        leaf = enroll(responder, authority, url)
        status, body = invoke(ocsp_binary, tmp_path, leaf, authority,
                              mode='staple', repeats=repeats)
    assert status == 0
    response = ocsp.load_der_ocsp_response(body)
    assert response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert response.certificate_status == ocsp.OCSPCertStatus.GOOD
    assert response.serial_number == leaf.cert.serial_number
    assert len(responder.log) == repeats


@pytest.mark.parametrize('verdict,options', [
    ('revoked', {}), ('unknown', {}), ('good', {'wrong_nonce': True}),
    ('good', {'stale': True}),
])
def test_unusable_staple_is_never_published(ocsp_binary, authority, tmp_path,
                                         verdict, options):
    responder = StapleResponder(authority.cert, authority.key, {}, **options)
    with responder_server(responder) as url:
        leaf = enroll(responder, authority, url, verdict)
        assert invoke(ocsp_binary, tmp_path, leaf, authority, mode='staple') == (-1, b'')
    assert len(responder.log) == 1


def test_staple_rejects_untrusted_responder_signature(ocsp_binary, authority, tmp_path):
    other = make_ca('/CN=Untrusted OCSP fixture CA', key_type='ec')
    responder = StapleResponder(other.cert, other.key, {})
    with responder_server(responder) as url:
        leaf = enroll(responder, authority, url)
        assert invoke(ocsp_binary, tmp_path, leaf, authority, mode='staple') == (-1, b'')
    assert len(responder.log) == 1


@pytest.mark.parametrize('missing,with_aia', [('leaf', True), ('issuer', True),
                                            ('aia', False), ('no-store', True)])
def test_staple_requires_complete_identity_and_trust(ocsp_binary, authority,
                                                   tmp_path, missing, with_aia):
    urls = ['unsupported://invalid'] * with_aia
    leaf = None if missing == 'leaf' else leaf_for(authority, urls)
    issuer = None if missing == 'issuer' else authority
    assert invoke(ocsp_binary, tmp_path, leaf, issuer, mode='staple',
                  fault=missing) == (-1, b'')


def test_failed_staple_allocation_retains_previous_response(ocsp_binary, authority,
                                                         tmp_path):
    responder = StapleResponder(authority.cert, authority.key, {})
    with responder_server(responder) as url:
        leaf = enroll(responder, authority, url)
        assert invoke(ocsp_binary, tmp_path, leaf, authority, mode='staple',
                      fault='allocation') == (-1, b'OLD')
    assert len(responder.log) == 1
