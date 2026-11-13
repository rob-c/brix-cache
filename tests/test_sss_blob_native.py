"""SSS blob verification: independent encryption, replay and malformed inputs."""

import subprocess

import pytest

from _test_sss_helpers import SSS_BASE_TIME, sss_credential
from test_nginx_native_contract import server_native_compile  # noqa: F401


KEY = b'0123456789abcdef'
NOW = 1800000000 - SSS_BASE_TIME


@pytest.fixture(scope='module')
def sss_blob_binary(server_native_compile):
    return server_native_compile('sss-blob', 'tests/c/sss_blob_native_test.c')


def mint(**options):
    arguments = dict(key_id=7, username='alice', gen_time=NOW,
                     nonce=bytes(range(32)))
    return sss_credential(KEY, **(arguments | options))


def verify(binary, blob, mode='valid', lifetime=60):
    result = subprocess.run([str(binary), mode, str(lifetime)], input=blob,
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    lines = result.stdout.decode().splitlines()
    status, selected = map(int, lines[0].split())
    return status, selected, lines[1], lines[2]


@pytest.mark.parametrize('mode', ['valid', 'live-expiry', 'no-identity', 'no-key-out'])
@pytest.mark.parametrize('name', ['alice', 'user-with-dashes', 'x' * 255])
def test_valid_blob_and_optional_outputs(sss_blob_binary, mode, name):
    status, selected, encoded, error = verify(sss_blob_binary, mint(username=name), mode)
    assert status == 0 and selected == 1 and not error
    assert encoded == ('' if mode == 'no-identity' else name.encode().hex())


@pytest.mark.parametrize('length', [0, 1, 3, 4, 7, 8, 15, 16, 32, 55, 59])
def test_truncated_blob_is_refused(sss_blob_binary, length):
    status, selected, _name, error = verify(sss_blob_binary, mint()[:length])
    assert status == -1 and selected == 0 and 'too short' in error


@pytest.mark.parametrize('offset,value,reason', [(0, 0, 'magic'), (1, 0, 'magic'),
    (2, 0, 'magic'), (3, 1, 'magic'), (7, 1, 'magic'),
    (6, 1, 'key-name size'), (6, 200, 'key-name size'),
    (6, 192, 'malformed header'), (6, 8, 'malformed header')])
def test_invalid_outer_framing(sss_blob_binary, offset, value, reason):
    blob = bytearray(mint())
    blob[offset] = value
    status, selected, _name, error = verify(sss_blob_binary, bytes(blob))
    assert status == -1 and selected == 0 and reason in error


def test_padded_key_name_header_is_accepted(sss_blob_binary):
    blob = bytearray(mint())
    blob[6] = 8
    blob[16:16] = b'name\0\0\0\0'
    assert verify(sss_blob_binary, bytes(blob))[:3] == (0, 1, b'alice'.hex())


@pytest.mark.parametrize('mode,reason', [('expired', 'not in keytab'),
    ('null-keytab', 'not in keytab'), ('zero-key', 'decrypt failed'),
    ('wrong-key', 'CRC mismatch'), ('null-blob', 'too short')])
def test_key_and_pointer_failures_do_not_publish_key(sss_blob_binary, mode, reason):
    status, selected, _name, error = verify(sss_blob_binary, mint(), mode)
    assert status == -1 and selected == 0 and reason in error


@pytest.mark.parametrize('options,reason', [({'key_id': 8}, 'not in keytab'),
    ({'corrupt_crc': True}, 'CRC mismatch'),
    ({'gen_time': NOW - 60}, 'replay window'),
    ({'gen_time': 0}, 'replay window'),
    ({'username': 'x' * 256}, 'identity parse failed'),
    ({'username': None}, 'identity parse failed'),
    ({'trailer': b'\x01'}, 'identity parse failed'),
    ({'trailer': b'\x01\x00'}, 'identity parse failed'),
    ({'trailer': b'\x01\xff\xffx'}, 'identity parse failed'),
    ({'tlvs': [(6, b'x' * 4097)]}, 'identity parse failed'),
    ({'trailer': b'x' * 8200}, 'ciphertext length out of range')])
def test_tamper_expiry_and_identity_limits(sss_blob_binary, options, reason):
    status, selected, _name, error = verify(sss_blob_binary, mint(**options))
    assert status == -1 and selected == 0 and reason in error


def test_last_second_inside_replay_window_is_valid(sss_blob_binary):
    assert verify(sss_blob_binary, mint(gen_time=NOW - 59))[:2] == (0, 1)


def test_interactive_blob_is_declined(sss_blob_binary):
    status, selected, _name, error = verify(sss_blob_binary, mint(opt=1))
    assert status == -5 and selected == 0 and 'SNDLID' in error
