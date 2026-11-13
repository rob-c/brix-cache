"""GSI crypto preserves real round trips and refuses provider/allocation failures."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def crypto(server_native_compile):
    seams = ('malloc', 'EVP_PKEY_CTX_new', 'EVP_PKEY_CTX_new_from_name',
        'EVP_PKEY_keygen_init', 'EVP_PKEY_keygen', 'EVP_PKEY_CTX_set_params',
        'EVP_PKEY_get_bn_param', 'BN_bn2hex', 'BN_hex2bn', 'EVP_PKEY_derive_init',
        'EVP_PKEY_derive_set_peer', 'EVP_PKEY_derive', 'BIO_new_mem_buf', 'BIO_new',
        'PEM_read_bio_Parameters', 'PEM_write_bio_Parameters', 'EVP_CIPHER_CTX_new',
        'RAND_bytes', 'EVP_CipherInit_ex', 'EVP_CipherUpdate', 'EVP_CipherFinal_ex')
    return server_native_compile('gsi-crypto-fault', 'tests/c/gsi_crypto_fault_native_test.c',
                                 ['-Wl,--wrap=' + name for name in seams])


def invoke(binary, action, fault='normal', padded=1, value='normal'):
    result = subprocess.run([str(binary), action, fault, str(padded), value],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout == 'accepted=1\n'


@pytest.mark.parametrize('action', ['keygen', 'fixed-keygen', 'derive', 'session',
                                    'encode', 'decode', 'public', 'parse'])
def test_real_key_generation_derivation_and_public_encoding(crypto, action):
    assert invoke(crypto, action)


@pytest.mark.parametrize('action,fault', [
    ('keygen', 'ctx-name'), ('keygen', 'keygen-init'), ('keygen', 'params'), ('keygen', 'keygen'),
    ('fixed-keygen', 'bio-memory'), ('fixed-keygen', 'read-parameters'),
    ('fixed-keygen', 'ctx'), ('fixed-keygen', 'keygen-init'), ('fixed-keygen', 'keygen'),
    ('encode', 'public'), ('encode', 'hex-print'), ('encode', 'malloc'),
    ('decode', 'malloc'), ('decode', 'hex-parse'),
    ('public', 'public'), ('public', 'hex-print'), ('public', 'bio'),
    ('public', 'write-parameters'), ('public', 'malloc'),
    ('parse', 'malloc'), ('parse', 'hex-parse'), ('parse', 'bio-memory'),
    ('parse', 'read-parameters')])
def test_provider_failure_cannot_publish_a_partial_key(crypto, action, fault):
    assert not invoke(crypto, action, fault)


@pytest.mark.parametrize('action', ['derive', 'session'])
@pytest.mark.parametrize('fault', ['ctx', 'derive-init', 'peer', 'derive-size', 'derive-output', 'malloc'])
def test_failed_derivation_leaves_session_output_unmodified(crypto, action, fault):
    assert not invoke(crypto, action, fault)


def test_short_secret_cannot_be_used_as_full_session_key(crypto):
    assert not invoke(crypto, 'session', 'short-secret')


@pytest.mark.parametrize('action', ['decode', 'parse'])
@pytest.mark.parametrize('value', ['', 'garbage', '---BPUB------EPUB--',
    '---EPUB-----BPUB---12', '---BPUB---invalid---EPUB--'])
def test_malformed_peer_public_material_is_refused(crypto, action, value):
    assert not invoke(crypto, action, value=value)


@pytest.mark.parametrize('name', ['aes-128-cbc', 'aes-256-cbc'])
@pytest.mark.parametrize('padded', [0, 1])
def test_binary_payload_round_trips_with_and_without_explicit_iv(crypto, name, padded):
    assert invoke(crypto, 'cipher', padded=padded, value=name)


@pytest.mark.parametrize('name', ['aes-128-cbc', 'aes-256-cbc'])
@pytest.mark.parametrize('fault', ['cipher-ctx', 'rng', 'malloc', 'cipher-init', 'cipher-update', 'cipher-final'])
def test_cipher_or_rng_failure_never_publishes_ciphertext(crypto, name, fault):
    assert not invoke(crypto, 'cipher', fault, value=name)
