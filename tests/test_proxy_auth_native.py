"""Upstream auth preserves credential precedence and refuses anonymous forwarding."""

import struct
import subprocess
import zlib

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher

from _test_sss_helpers import Blowfish, CFB
from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def authentication(server_native_compile):
    return server_native_compile('proxy-auth', 'tests/c/proxy_auth_native_test.c',
        ['-Wl,--wrap=' + name for name in ('ngx_palloc', 'RAND_bytes', 'brix_proxy_abort',
                                         'brix_proxy_flush', 'ngx_handle_write_event')])


@pytest.fixture
def auth(authentication, tmp_path):
    path = tmp_path / 'token'
    path.write_text('service-token\n')
    path.chmod(0o600)
    def invoke(source='bearer', mode='normal', action='auth', contents=None):
        if contents is not None:
            path.write_text(contents)
        result = subprocess.run([str(authentication), action, source, mode, str(path)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        lines = result.stdout.splitlines()
        counts = tuple(map(int, lines[0].split()[1:]))
        frame = bytes.fromhex(lines[1].split()[1]) if len(lines) > 1 else b''
        return counts, frame
    return invoke


def body_of(frame, protocol):
    assert frame[:4] == struct.pack('!HH', 0, 3000)
    assert frame[4:16] == bytes(12) and frame[16:20] == protocol + b'\0'
    assert struct.unpack('!I', frame[20:24])[0] == len(frame) - 24
    return frame[24:]


def sss_fields(frame):
    blob = body_of(frame, b'sss')
    clear = Cipher(Blowfish(b'0123456789abcdef'), CFB(bytes(8))).decryptor().update(blob[16 + blob[6]:])
    assert zlib.crc32(clear[:-4]) == struct.unpack('!I', clear[-4:])[0]
    fields, offset = {}, 40
    while offset < len(clear) - 4:
        tag, length = clear[offset], struct.unpack('!H', clear[offset + 1:offset + 3])[0]
        fields[tag] = clear[offset + 3:offset + 3 + length]
        offset += 3 + length
    return struct.unpack('!Q', blob[8:16])[0], fields


@pytest.mark.parametrize('action', ['auth', 'hint'])
@pytest.mark.parametrize('source,token', [('bearer', b'caller-token'), ('file', b'service-token'),
                                       ('both', b'caller-token')])
def test_bearer_precedes_file_and_wire_length_is_exact(auth, action, source, token):
    counts, frame = auth(source=source, action=action)
    assert counts == (1, 0, 1, 0, 0, 0, 0)
    assert body_of(frame, b'ztn') == b'ztn\0' + token


@pytest.mark.parametrize('action', ['auth', 'hint'])
@pytest.mark.parametrize('mode,key,name', [('normal', 8, b'second-service\0'),
                                         ('unknown-key', 7, b'first-service\0')])
def test_sss_named_key_selection_and_explicit_fallback_are_exact(auth, action, mode, key, name):
    counts, frame = auth(source='sss', mode=mode, action=action)
    actual_key, fields = sss_fields(frame)
    assert counts == (1, 0, 1, 0, 0, 0, 0)
    assert actual_key == key and fields[1] == name


@pytest.mark.parametrize('mode,name', [('normal', b'mapped-client\0'), ('unmapped', b'client-dn\0'),
                                    ('empty-map', b'client-dn\0'), ('asserted', b'mapped-client\0')])
def test_sss_client_identity_carries_only_asserted_vo_and_role(auth, mode, name):
    counts, frame = auth(source='entity', mode=mode)
    key, fields = sss_fields(frame)
    assert counts == (1, 0, 1, 0, 0, 0, 0) and key == 8
    assert fields[1] == name and b'group-a\0' in fields.values()
    assert (b'asserted-vo\0' in fields.values()) == (mode == 'asserted')
    assert (b'asserted-role\0' in fields.values()) == (mode == 'asserted')


@pytest.mark.parametrize('action', ['auth', 'hint'])
@pytest.mark.parametrize('mode', ['no-identity', 'no-client', 'anonymous', 'empty-dn'])
def test_sss_forwarding_never_launders_anonymous_client_into_keytab_identity(auth, action, mode):
    counts, frame = auth(source='entity', action=action, mode=mode)
    metric = int(mode != 'no-client')
    assert counts == (1, 1, 0, 0, 1, metric, metric) and frame == b''


@pytest.mark.parametrize('action', ['auth', 'hint'])
@pytest.mark.parametrize('source', ['bearer', 'file', 'sss', 'entity'])
@pytest.mark.parametrize('mode,flushes,events', [('allocation', 0, 0), ('flush-error', 1, 0),
                                             ('event-error', 1, 1)])
def test_failed_send_aborts_once_and_counts_the_correct_scope(auth, action, source, mode, flushes, events):
    counts, _ = auth(source=source, action=action, mode=mode)
    upstream = int(source in ('sss', 'entity') or (source == 'bearer' and action == 'auth'))
    assert counts == (1, 1, flushes, events, 0, 1, upstream)


@pytest.mark.parametrize('action', ['auth', 'hint'])
@pytest.mark.parametrize('source', ['bearer', 'file', 'sss'])
def test_partial_write_arms_event_without_losing_auth_frame(auth, action, source):
    counts, frame = auth(source=source, action=action, mode='partial')
    assert counts == (1, 0, 1, 1, 0, 0, 0) and len(frame) > 28


@pytest.mark.parametrize('action', ['auth', 'hint'])
@pytest.mark.parametrize('contents', ['', '\n'])
def test_unusable_service_token_sends_no_credential(auth, action, contents):
    counts, frame = auth(source='file', action=action, contents=contents)
    expected = (1, 1, 0, 0, 0, 1, 1) if action == 'auth' else (0, 0, 0, 0, 0, 0, 0)
    assert counts == expected and frame == b''


@pytest.mark.parametrize('action', ['auth', 'hint'])
def test_service_token_reader_retains_its_documented_bounded_prefix(auth, action):
    counts, frame = auth(source='file', action=action, contents='x' * 65537)
    assert counts == (1, 0, 1, 0, 0, 0, 0)
    assert body_of(frame, b'ztn') == b'ztn\0' + b'x' * 65535


@pytest.mark.parametrize('source', ['sss', 'entity'])
@pytest.mark.parametrize('mode', ['random-error', 'invalid-key'])
def test_failed_credential_crypto_never_reaches_transport(auth, source, mode):
    counts, frame = auth(source=source, mode=mode)
    assert counts == (1, 1, 0, 0, 0, 1, 1) and frame == b''


@pytest.mark.parametrize('mode', ['override-anonymous', 'no-conf', 'no-keys'])
def test_missing_auth_policy_or_key_refuses_required_authentication(auth, mode):
    counts, frame = auth(source='sss', mode=mode)
    assert counts == (1, 1, 0, 0, 0, 1, 1) and frame == b''


def test_upstream_forward_override_wins_over_global_sss(auth):
    counts, frame = auth(source='sss', mode='override-forward')
    assert counts == (1, 0, 1, 0, 0, 0, 0)
    assert body_of(frame, b'ztn') == b'ztn\0caller-token'


@pytest.mark.parametrize('mode', ['short-hint', 'unknown-hint', 'no-keys', 'override-anonymous'])
def test_unmatched_login_hint_does_not_manufacture_authentication(auth, mode):
    counts, frame = auth(source='sss', action='hint', mode=mode)
    assert counts == (0, 0, 0, 0, 0, 0, 0) and frame == b''
