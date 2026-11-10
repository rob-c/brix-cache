"""Client GridFTP GSI must preserve verification, delegation and failure state."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_gftp_gsi_native import proxy_files
from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def client_gsi_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    names = ('malloc', 'calloc', 'realloc', 'SSL_CTX_new', 'SSL_new', 'SSL_CTX_ctrl',
        'SSL_CTX_load_verify_locations', 'SSL_CTX_use_certificate', 'SSL_CTX_use_PrivateKey',
        'fdopen', 'BIO_new_fp', 'BIO_new', 'SSL_connect', 'SSL_get_error', 'SSL_write', 'SSL_read', 'BIO_write')
    return compile_client_contract(root, tmp_path_factory.mktemp('ftp-client-gsi'),
                                   'tests/c/ftp_client_gsi_native_test.c', names)


@pytest.fixture
def client_gsi(client_gsi_binary, proxy_files):
    def run(operation, mode='normal', proxy='valid', expected=0, length=4):
        path = proxy_files / proxy
        result = subprocess.run([str(client_gsi_binary), operation, mode, str(path), str(proxy_files),
            str(expected), str(length)], env=dict(os.environ, X509_CERT_DIR=str(proxy_files),
            X509_USER_PROXY=str(path)), capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        return tuple(map(int, result.stdout.split()))
    return run


@pytest.mark.parametrize('proxy', ['valid', 'chain'])
@pytest.mark.parametrize('mode', ['normal', 'default-ca', 'environment-proxy', 'insecure'])
def test_credential_chain_and_explicit_tls_policy(client_gsi, proxy, mode):
    assert client_gsi('create', mode, proxy, expected=1) == (1, 0, 0, 0)


@pytest.mark.parametrize('proxy', ['certificate', 'key', 'mismatch', 'empty', 'writable',
                                 'symlink', 'directory', 'missing'])
def test_unsafe_or_incomplete_identity_never_starts_handshake(client_gsi, proxy):
    assert client_gsi('create', proxy=proxy) == (0, 0, 0, 0)


@pytest.mark.parametrize('mode', ['context-allocation', 'chain-allocation', 'context-error',
    'session-error', 'version-error', 'ca-error', 'certificate-error', 'key-error',
    'file-stream-error', 'file-bio-error', 'credential-bio-error'])
def test_credential_provider_failure_leaves_no_context_or_open_credential(client_gsi, mode):
    assert client_gsi('create', mode) == (0, 0, 0, 0)


@pytest.mark.parametrize('mode,expected', [('normal', 1), ('want-read', 1), ('want-write', 1),
    ('handshake-error', -1), ('write-error', -1), ('input-error', -1), ('drain-allocation', -1)])
def test_handshake_transitions_and_failed_context_stickiness(client_gsi, mode, expected):
    client_gsi('handshake', mode, expected=expected)


@pytest.mark.parametrize('mode,expected', [('normal', 1), ('empty', -1), ('bad-request', -1),
                                        ('payload-allocation', -1), ('issue-write-error', -1)])
def test_delegation_requires_valid_request_and_returns_a_real_signed_proxy(client_gsi, mode, expected):
    result = client_gsi('delegate', mode, expected=expected)
    assert result[3] == int(expected == 1)


@pytest.mark.parametrize('length', [1, 4, 16384, 20000, 1048576])
def test_protected_reply_growth_is_byte_exact(client_gsi, length):
    client_gsi('application', length=length)


@pytest.mark.parametrize('mode,length', [('normal', 0), ('payload-allocation', 4),
    ('payload-growth', 20000), ('input-error', 4), ('write-error', 4), ('drain-allocation', 4)])
def test_empty_or_failed_application_io_never_claims_success(client_gsi, mode, length):
    client_gsi('application', mode, expected=-1, length=length)


def test_command_wrap_returns_owned_record(client_gsi):
    client_gsi('application', 'wrap')
