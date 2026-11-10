"""GridFTP delegation uses real certificates while record-layer faults stay finite."""

from datetime import datetime, timedelta, timezone
import os
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def gsi_binary(server_native_compile):
    names = ('malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc',
             'SSL_connect', 'SSL_get_error', 'SSL_write', 'SSL_read', 'BIO_write')
    return server_native_compile('gftp-gsi', 'tests/c/gftp_gsi_native_test.c',
        ['-Wl,--wrap=' + name for name in names])


def credential():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'finite-gsi-signer')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(12345)
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
        .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())


@pytest.fixture(scope='module')
def proxy_files(tmp_path_factory):
    root = tmp_path_factory.mktemp('gsi-native-credentials')
    cert, key = credential()
    _, other = credential()
    variants = {'valid': cert + key, 'chain': cert + cert + key, 'certificate': cert,
                'key': key, 'mismatch': cert + other, 'empty': b'', 'writable': cert + key}
    for name, content in variants.items():
        path = root / name
        path.write_bytes(content)
        path.chmod(0o600)
    (root / 'writable').chmod(0o666)
    (root / 'symlink').symlink_to(root / 'valid')
    (root / 'directory').mkdir()
    return root


@pytest.fixture
def gsi(gsi_binary, proxy_files):
    def run(action, mode='normal', proxy='valid', expected=0, length=4):
        result = subprocess.run([str(gsi_binary), action, mode, str(proxy_files / proxy),
            str(proxy_files), str(expected), str(length)],
            env=dict(os.environ, X509_CERT_DIR=str(proxy_files)),
            capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('proxy', ['valid', 'chain'])
@pytest.mark.parametrize('mode', ['normal', 'default-ca'])
def test_real_credential_and_chain_load(gsi, proxy, mode):
    gsi('create', mode=mode, proxy=proxy, expected=1)


@pytest.mark.parametrize('proxy', ['certificate', 'key', 'mismatch', 'empty',
                                 'writable', 'symlink', 'directory', 'missing'])
def test_invalid_or_unsafe_proxy_cannot_create_context(gsi, proxy):
    output = gsi('create', proxy=proxy)
    assert 'connects=0 writes=0' in output


@pytest.mark.parametrize('mode', ['context-allocation', 'chain-allocation'])
def test_credential_allocation_failure_is_terminal(gsi, mode):
    gsi('create', mode=mode)


@pytest.mark.parametrize('mode,expected', [('normal', 1), ('want-read', 1), ('want-write', 1),
    ('handshake-error', -1), ('write-error', -1), ('input-error', -1), ('drain-allocation', -1)])
def test_handshake_states_and_output_token_ownership(gsi, mode, expected):
    gsi('handshake', mode=mode, expected=expected)


@pytest.mark.parametrize('mode,expected', [('normal', 1), ('empty', -1), ('bad-request', -1),
                                        ('payload-allocation', -1), ('issue-write-error', -1)])
def test_delegation_validates_real_request_and_issued_proxy(gsi, mode, expected):
    output = gsi('delegate', mode=mode, expected=expected)
    if expected == 1:
        assert 'issued=1' in output


@pytest.mark.parametrize('length', [1, 4, 16384, 20000, 1048576])
def test_protected_reply_growth_preserves_bytes(gsi, length):
    gsi('application', length=length)


@pytest.mark.parametrize('mode,length', [('normal', 0), ('payload-allocation', 4),
                                      ('payload-growth', 20000), ('input-error', 4)])
def test_empty_or_failed_protected_reply_is_rejected(gsi, mode, length):
    gsi('application', mode=mode, length=length, expected=-1)


@pytest.mark.parametrize('mode,expected', [('wrap', 0), ('write-error', -1), ('drain-allocation', -1)])
def test_protected_command_output_or_failure(gsi, mode, expected):
    gsi('application', mode=mode, expected=expected)


@pytest.mark.parametrize('mode', ['normal', 'openssl-detail'])
def test_openssl_diagnostic_drains_error_queue(gsi, mode):
    gsi('diagnostic', mode=mode)
