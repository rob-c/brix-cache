"""Cache-origin auth framing, caller identity, and fail-closed key selection."""

from contextlib import contextmanager
import os
import socket
import struct
import subprocess
import zlib

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher

from _test_sss_helpers import Blowfish, CFB, sss_write_keytab
from test_nginx_native_contract import server_native_compile  # noqa: F401

KEY = b'0123456789abcdef'


@pytest.fixture(scope='module')
def origin_auth_binary(server_native_compile):
    return server_native_compile('origin-auth', 'tests/c/cache_origin_auth_native_test.c',
                                  ['-Wl,--wrap=malloc', '-Wl,--wrap=fdopen'])


@pytest.fixture
def keytab(tmp_path):
    return sss_write_keytab(tmp_path / 'keytab', KEY, key_id=7, user='service')


@contextmanager
def origin_child(binary, protocol, keytab, identity, fault=''):
    """Give the native connector one socket and bound all fixture process cleanup."""
    child_socket, peer = socket.socketpair()
    peer.settimeout(5)
    environment = {**os.environ, 'BRIX_ORIGIN_AUTH_FAULT': fault}
    process = subprocess.Popen([str(binary), protocol, str(child_socket.fileno()),
        str(keytab), identity], pass_fds=[child_socket.fileno()], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    child_socket.close()
    try:
        yield process, peer
    finally:
        peer.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise
        finally:
            process.stdout.close()
            process.stderr.close()


def result(process):
    output, error = process.communicate(timeout=10)
    assert process.returncode == 0, output + error
    status, message = output.split('\n', 1)
    return tuple(map(int, status.split())), message


def receive_exact(peer, length):
    data = bytearray()
    while len(data) < length:
        chunk = peer.recv(length - len(data))
        assert chunk, f'credential ended after {len(data)} of {length} bytes'
        data.extend(chunk)
    return bytes(data)


def credential(peer, protocol):
    header = receive_exact(peer, 24)
    assert header[:4] == struct.pack('!HH', 1, 3000)
    assert header[4:16] == bytes(12)
    assert header[16:20] == protocol.encode() + b'\0'
    return receive_exact(peer, struct.unpack('!I', header[20:24])[0])


def reply(peer, status=0, body=b''):
    peer.sendall(struct.pack('!HHI', 1, status, len(body)) + body)


def sss_name(blob):
    """Independently decrypt and checksum the real connector's identity TLV."""
    assert blob[:4] == b'sss\0' and blob[7] == ord('0')
    assert struct.unpack('!Q', blob[8:16])[0] == 7
    clear = Cipher(Blowfish(KEY), CFB(bytes(8))).decryptor().update(blob[16 + blob[6]:])
    assert zlib.crc32(clear[:-4]) == struct.unpack('!I', clear[-4:])[0]
    assert clear[40] == 1
    length = struct.unpack('!H', clear[41:43])[0]
    assert clear[43 + length - 1] == 0
    return clear[43:43 + length - 1].decode()


@pytest.mark.parametrize('identity,expected', [('-', 'service'), ('alice', 'alice'),
                                              ('u' * 63, 'u' * 63)])
def test_sss_auth_keeps_service_or_explicit_caller(origin_auth_binary, keytab,
                                                identity, expected):
    with origin_child(origin_auth_binary, 'sss', keytab, identity) as (process, peer):
        assert sss_name(credential(peer, 'sss')) == expected
        reply(peer)
        assert result(process) == ((0, 0, 0), '')


@pytest.mark.parametrize('length', [1, 16, 4096, 65534])
def test_ztn_auth_encodes_length_and_terminating_nul(origin_auth_binary, keytab, length):
    token = 't' * length
    with origin_child(origin_auth_binary, 'ztn', keytab, token) as (process, peer):
        blob = credential(peer, 'ztn')
        assert blob[:8] == b'ztn\0\0T\0\0'
        assert struct.unpack('!H', blob[8:10])[0] == length + 1
        assert blob[10:] == token.encode() + b'\0'
        reply(peer, body=b'optional-success-data')
        assert result(process) == ((0, 0, 0), '')


@pytest.mark.parametrize('protocol', ['ztn', 'sss'])
@pytest.mark.parametrize('status,body,error,fragment', [
    (4003, struct.pack('!I', 3010) + b'origin denied', 3010, 'origin denied'),
    (4003, b'xx', 3012, 'auth rejected'),
    (4002, b'next round', 3030, 'auth incomplete'),
    (4004, b'redirect', 3030, 'auth incomplete'),
])
def test_auth_response_refusals_preserve_error_contract(origin_auth_binary, keytab,
                                                       protocol, status, body,
                                                       error, fragment):
    with origin_child(origin_auth_binary, protocol, keytab, 'alice') as (process, peer):
        credential(peer, protocol)
        reply(peer, status, body)
        actual, message = result(process)
        assert actual[:2] == (-1, error) and fragment in message


@pytest.mark.parametrize('protocol', ['ztn', 'sss'])
@pytest.mark.parametrize('frame', [b'\0', struct.pack('!HHI', 1, 0, 4) + b'x',
                                 struct.pack('!HHI', 1, 0, 0xffffffff)])
def test_truncated_or_oversized_response_cannot_authenticate(origin_auth_binary,
                                                          keytab, protocol, frame):
    with origin_child(origin_auth_binary, protocol, keytab, 'alice') as (process, peer):
        credential(peer, protocol)
        peer.sendall(frame)
        peer.shutdown(socket.SHUT_WR)
        status, message = result(process)
        assert status[:2] == (-1, 3012) and 'response' in message


@pytest.mark.parametrize('identity', ['', 'u' * 64])
def test_invalid_sss_caller_is_refused_before_any_wire_bytes(origin_auth_binary,
                                                           keytab, identity):
    with origin_child(origin_auth_binary, 'sss', keytab, identity) as (process, peer):
        assert peer.recv(1) == b''
        status, message = result(process)
        assert status[:2] == (-1, 3030) and 'identity injection' in message


def selected_keytab(keytab, tmp_path, kind):
    """Prepare exactly one invalid key source without touching operator files."""
    if kind == 'missing':
        return tmp_path / 'missing'
    if kind in ('empty', 'malformed'):
        keytab.write_text('' if kind == 'empty' else 'wrong keytab format\n')
    if kind == 'symlink':
        selected = tmp_path / 'linked'
        selected.symlink_to(keytab)
        return selected
    return keytab


@pytest.mark.parametrize('kind', ['missing', 'empty', 'malformed', 'symlink', 'fdopen'])
def test_invalid_sss_keytab_cannot_start_auth(origin_auth_binary, keytab, tmp_path, kind):
    selected = selected_keytab(keytab, tmp_path, kind)
    fault = 'fdopen' if kind == 'fdopen' else ''
    with origin_child(origin_auth_binary, 'sss', selected, 'alice', fault) as (process, peer):
        assert peer.recv(1) == b''
        status, message = result(process)
        assert status[:2] == (-1, 3030) and 'keytab' in message


def test_ztn_allocation_refusal_sends_nothing(origin_auth_binary, keytab):
    with origin_child(origin_auth_binary, 'ztn', keytab, 'token', 'allocation') as (process, peer):
        assert peer.recv(1) == b''
        assert result(process)[0][:2] == (-1, 3008)


def test_zero_payload_auth_header_is_complete(origin_auth_binary, keytab):
    with origin_child(origin_auth_binary, 'empty', keytab, '') as (process, peer):
        assert credential(peer, 'ztn') == b''
        assert result(process) == ((0, 0, 0), '')
