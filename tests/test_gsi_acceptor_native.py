"""GSI acceptor trust, record failures and resource ownership at finite boundaries."""

import subprocess

import pytest

from test_gftp_gsi_native import proxy_files
from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def acceptor_binary(server_native_compile):
    names = ('SSL_new', 'SSL_free', 'BIO_new', 'ngx_pcalloc', 'ngx_palloc', 'ngx_pnalloc',
        'ngx_pool_cleanup_add', 'SSL_accept', 'SSL_get_error', 'SSL_get1_peer_certificate',
        'SSL_get_peer_cert_chain', 'SSL_read', 'SSL_write', 'BIO_write', 'BIO_read', 'PEM_write_bio_X509')
    return server_native_compile('gsi-acceptor', 'tests/c/gsi_acceptor_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


@pytest.fixture
def acceptor(acceptor_binary, proxy_files):
    def run(operation, mode='normal', expected=0):
        result = subprocess.run([str(acceptor_binary), operation, mode, str(proxy_files / 'valid'),
            str(expected)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return tuple(map(int, result.stdout.split()))
    return run


def test_context_owns_both_bios_and_repeated_teardown_is_safe(acceptor):
    assert acceptor('create', expected=1) == (1, 0, 0)


@pytest.mark.parametrize('mode', ['context-oom', 'session-oom', 'bio-oom',
                                 'second-bio-oom', 'cleanup-oom'])
def test_partial_context_acquisition_releases_every_ssl_and_bio(acceptor, mode):
    assert acceptor('create', mode) == (0, 0, 0)


@pytest.mark.parametrize('mode,expected', [('normal', 1), ('want-read', 0), ('want-write', 0),
    ('handshake-error', 2), ('no-peer', 2), ('untrusted', 2), ('identity-oom', 2),
    ('output-oom', 2), ('input-error', 2), ('drain-error', 2)])
def test_handshake_checks_real_chain_before_granting_identity(acceptor, mode, expected):
    acceptor('handshake', mode, expected)


def test_delegation_marker_emits_a_self_verified_real_certificate_request(acceptor):
    assert acceptor('marker') == (0, 1, 1)


@pytest.mark.parametrize('mode', ['empty', 'bad-marker', 'output-oom', 'no-peer',
                                 'bio-oom', 'pem-error', 'empty-pem', 'write-error', 'drain-error'])
def test_delegation_request_failure_cannot_complete_authentication(acceptor, mode):
    acceptor('marker', mode, 2)


def test_exported_leaf_matches_the_verified_peer(acceptor):
    acceptor('peer')


@pytest.mark.parametrize('mode', ['freed', 'no-peer', 'bio-oom', 'pem-error', 'empty-pem', 'output-oom'])
def test_failed_peer_export_leaves_no_credential_output(acceptor, mode):
    acceptor('peer', mode, -1)


@pytest.mark.parametrize('operation', ['wrap', 'unwrap'])
def test_application_records_are_byte_exact(acceptor, operation):
    acceptor(operation)


@pytest.mark.parametrize('operation,mode', [('wrap', 'write-error'), ('wrap', 'output-oom'),
    ('wrap', 'drain-error'), ('unwrap', 'input-error'), ('unwrap', 'output-oom')])
def test_record_provider_failure_cannot_claim_success(acceptor, operation, mode):
    acceptor(operation, mode, -1)


def test_empty_nonblocking_application_read_is_observable(acceptor):
    acceptor('unwrap', 'empty')
