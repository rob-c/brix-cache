"""TLS setup retains verification policy and releases failed provider state."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_gftp_gsi_native import credential
from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def handshake_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    wrappers = ('SSL_CTX_new', 'SSL_CTX_free', 'SSL_new', 'SSL_free', 'SSL_CTX_load_verify_locations',
        'SSL_CTX_use_certificate_chain_file', 'SSL_CTX_use_PrivateKey_file', 'SSL_CTX_check_private_key',
        'X509_VERIFY_PARAM_set1_host', 'SSL_connect', 'SSL_get_error', 'SSL_get_verify_result', 'poll',
        'SSL_set_session', 'SSL_session_reused', 'SSL_shutdown', 'SSL_version', 'SSL_renegotiate',
        'SSL_do_handshake', 'SSL_get1_session')
    return compile_client_contract(root, tmp_path_factory.mktemp('tls-handshake'),
                                   'tests/c/tls_handshake_native_test.c', wrappers)


@pytest.fixture(scope='module')
def handshake(handshake_binary, tmp_path_factory):
    root = tmp_path_factory.mktemp('tls-handshake-credentials')
    cert, key = credential()
    identity = root / 'identity.pem'
    identity.write_bytes(cert + key)
    identity.chmod(0o600)
    def invoke(operation='upgrade', mode='normal', peer=True, host=True, use_ca=True, use_identity=False):
        result = subprocess.run([str(handshake_binary), operation, mode, str(int(peer)), str(int(host)),
            str(root) if use_ca else '-', str(identity) if use_identity else '-'],
            capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return tuple(map(int, result.stdout.split()))
    return invoke


@pytest.mark.parametrize('operation', ['upgrade', 'client'])
@pytest.mark.parametrize('peer,host', [(True, True), (True, False), (False, False)])
@pytest.mark.parametrize('use_ca', [True, False])
def test_success_keeps_verification_and_protocol_floor(handshake, operation, peer, host, use_ca):
    assert handshake(operation=operation, peer=peer, host=host, use_ca=use_ca)[:2] == (0, 0)


@pytest.mark.parametrize('operation', ['upgrade', 'client'])
@pytest.mark.parametrize('mode', ['context-oom', 'session-oom', 'ca-error', 'hostname-error',
                                 'connect-error', 'verify-connect-error', 'verify-error'])
def test_tls_failure_cannot_leave_a_live_or_unverified_session(handshake, operation, mode):
    assert handshake(operation=operation, mode=mode)[0] == -1


@pytest.mark.parametrize('operation', ['upgrade', 'client'])
@pytest.mark.parametrize('mode,polls', [('want-read', 1), ('want-write', 1), ('poll-interrupt', 2)])
def test_handshake_retry_polls_exact_requested_direction(handshake, operation, mode, polls):
    result = handshake(operation=operation, mode=mode)
    assert result[0] == 0 and result[3:5] == (2, polls)


@pytest.mark.parametrize('operation', ['upgrade', 'client'])
@pytest.mark.parametrize('mode', ['timeout', 'poll-error'])
def test_handshake_wait_failure_stops_before_second_connect(handshake, operation, mode):
    result = handshake(operation=operation, mode=mode)
    assert result[0] == -1 and result[3:5] == (1, 1)


@pytest.mark.parametrize('mode,expected', [('normal', 0), ('certificate-error', -1),
    ('key-error', -1), ('mismatch', -1)])
def test_http_client_identity_is_complete_or_setup_is_refused(handshake, mode, expected):
    assert handshake(operation='client', mode=mode, use_identity=True)[0] == expected


@pytest.mark.parametrize('mode,expected', [('legacy', 0), ('resumed', 0), ('resume-error', -1)])
def test_explicit_legacy_version_and_session_resumption_are_observed(handshake, mode, expected):
    assert handshake(mode=mode)[0] == expected


def test_http_client_without_host_keeps_peer_verification(handshake):
    assert handshake(operation='client', mode='no-host')[0] == 0


@pytest.mark.parametrize('mode,expected,attempts', [('normal', 1, 1), ('want-read', 1, 2),
    ('want-write', 1, 2), ('renegotiate-error', -1, 0), ('wrong-version', -1, 0),
    ('null-connection', -1, 0), ('refused', 0, 1), ('timeout', -1, 1), ('runaway', -1, 32)])
def test_renegotiation_outcome_is_bounded_and_keeps_session_ownership(handshake, mode, expected, attempts):
    result = handshake(operation='renegotiate', mode=mode)
    assert result[0] == expected and result[5] == attempts
