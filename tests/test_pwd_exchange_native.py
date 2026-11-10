"""Password authentication wire contracts and cryptographic refusal behavior."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def password_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    wrappers = ['brix_gsi_cipher_' + name for name in
                ('keygen', 'public', 'session_key', 'lookup', 'apply')]
    return compile_client_contract(root, tmp_path_factory.mktemp('pwd-exchange'),
        'tests/c/pwd_exchange_native_test.c', [*wrappers, 'realloc'])


@pytest.fixture
def password(password_binary):
    def invoke(mode='success', injection='', literal='fixture-password', blob=None,
               user='alice', fallback=None, expected='fixture-password', have=1, skip=0):
        environment = password_environment(literal, blob, user, fallback)
        username = environment.get('XRDC_PWD_USER') or environment.get('USER', '')
        result = subprocess.run([str(password_binary), mode, injection, expected,
            username, str(have), str(skip)], env=environment,
            capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'fixture-password' not in result.stdout + result.stderr
        return result.stdout
    return invoke


def password_environment(literal, blob, user, fallback):
    environment = dict(os.environ)
    for key in ('XRDC_PWD', 'XrdSecCREDS', 'XRDC_PWD_USER', 'USER'):
        environment.pop(key, None)
    values = dict(XRDC_PWD=literal, XrdSecCREDS=blob, XRDC_PWD_USER=user, USER=fallback)
    environment.update({key: value for key, value in values.items() if value is not None})
    return environment


@pytest.mark.parametrize('mode', ['success', 'repeat'])
@pytest.mark.parametrize('length', [16, 256, 300])
def test_real_dh_exchange_encrypts_exact_bounded_password(password, mode, length):
    secret = 's' * length
    assert 'VERIFIED' in password(mode=mode, literal=secret, expected=secret)


@pytest.mark.parametrize('prefix', [b'', b'prefix-data'])
@pytest.mark.parametrize('length', [16, 300])
def test_legacy_hex_credentials_use_same_encrypted_exchange(password, prefix, length):
    secret = 's' * length
    blob = prefix + b'&pwd\0' + b'1234' + secret.encode()
    assert 'VERIFIED' in password(literal=None, blob=blob.hex(), expected=secret)


def test_literal_wins_over_legacy_credential_and_user_falls_back(password):
    output = password(blob='not-hex', user=None, fallback='legacy-user')
    assert 'VERIFIED' in output


@pytest.mark.parametrize('blob', [None, '', 'f', 'zz' * 12, '00' * 513, '00' * 12,
                                 b'123456789&pwd'.hex(), b'&pwd\0abcd'.hex()])
def test_missing_or_malformed_credentials_emit_no_payload(password, blob):
    output = password(mode='first-error', literal=None, blob=blob, have=int(bool(blob)))
    assert 'no password' in output


def test_missing_username_is_refused_before_key_generation(password):
    assert 'no username' in password(mode='first-error', user=None)


@pytest.mark.parametrize('fault,hint', [('keygen', 'DH keygen failed'),
                                      ('public', 'cannot encode key'), ('allocation', 'out of memory')])
def test_first_round_primitive_failures_return_no_partial_payload(password, fault, hint):
    assert hint in password(mode='first-error', injection=fault)


@pytest.mark.parametrize('mode,hint', [('missing', 'server key missing'),
                                    ('invalid', 'bad server key'), ('no-session', 'server key missing')])
def test_invalid_challenges_cannot_release_credentials(password, mode, hint):
    assert hint in password(mode=mode)


@pytest.mark.parametrize('fault,hint', [('agreement', 'key agreement failed'),
                                      ('cipher', 'key agreement failed'),
                                      ('encrypt', 'credential encrypt failed')])
def test_second_round_crypto_refusals_emit_no_payload(password, fault, hint):
    assert hint in password(mode='error', injection=fault)


@pytest.mark.parametrize('skip', [0, 1])
def test_inner_and_outer_allocation_failures_emit_no_credentials(password, skip):
    assert 'out of memory' in password(mode='error', injection='allocation', skip=skip)
