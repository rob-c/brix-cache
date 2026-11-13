"""TPC verification hashes the actual destination and rejects absent or malformed digests."""

import hashlib
import subprocess
import zlib

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def verify_binary(server_native_compile):
    names = ('tpc_send_all', 'tpc_recv_response', 'brix_vfs_writer_fd', 'brix_vfs_open_fd')
    return server_native_compile('tpc-verify', 'tests/c/tpc_verify_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, tmp_path, operation, reply, mode='normal'):
    path = tmp_path / 'destination'
    path.write_bytes(b'verified object bytes\x00\xff')
    result = subprocess.run([str(binary), operation, mode, reply, str(tmp_path), str(path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert path.read_bytes() == b'verified object bytes\x00\xff'
    return tuple(map(int, result.stdout.split()))


@pytest.mark.parametrize('reply,size', [('1 0 0 0', 0), ('  id   12345 0 0', 12345),
    ('id 18446744073709551615 0 0', 2**64 - 1)])
def test_stat_records_authoritative_unsigned_size(verify_binary, tmp_path, reply, size):
    assert invoke(verify_binary, tmp_path, 'stat', reply)[:4] == (0, 0, 1, size)


@pytest.mark.parametrize('reply', ['', 'id', 'id nope 0 0', 'id -1 0 0',
    'id 18446744073709551616 0 0'])
def test_unparseable_stat_never_claims_an_authoritative_size(verify_binary, tmp_path, reply):
    assert invoke(verify_binary, tmp_path, 'stat', reply)[:4] == (0, 0, 0, 0)


@pytest.mark.parametrize('mode', ['refused', 'no-body'])
def test_unavailable_stat_retains_unknown_size(verify_binary, tmp_path, mode):
    assert invoke(verify_binary, tmp_path, 'stat', 'id 12 0 0', mode)[:4] == (0, 0, 0, 0)


@pytest.mark.parametrize('operation', ['stat', 'checksum'])
@pytest.mark.parametrize('mode,sends,receives', [('send-error', 1, 0), ('recv-error', 1, 1)])
def test_transport_failure_is_a_protocol_io_failure(verify_binary, tmp_path, operation, mode, sends, receives):
    counts = invoke(verify_binary, tmp_path, operation, '', mode)
    assert counts[:2] == (-1, 3007) and counts[4:6] == (sends, receives)


@pytest.mark.parametrize('mode', ['normal', 'writer', 'object'])
@pytest.mark.parametrize('algorithm', ['sha256', 'md5', 'adler32'])
def test_checksum_uses_the_actual_file_or_still_owned_writer_bytes(verify_binary, tmp_path, mode, algorithm):
    data = b'verified object bytes\x00\xff'
    checksum = f'{zlib.adler32(data):08x}' if algorithm == 'adler32' else hashlib.new(algorithm, data).hexdigest()
    counts = invoke(verify_binary, tmp_path, 'checksum', algorithm + '   ' + checksum.upper() + '\r\n', mode)
    assert counts[:2] == (0, 0)
    assert counts[6] == int(mode == 'normal')


@pytest.mark.parametrize('mode', ['normal', 'writer', 'object'])
@pytest.mark.parametrize('reply', ['', 'sha256', ' abc', 'a' * 32 + ' abc',
    'sha256 ', 'sha256 ' + 'a' * 129, 'unknown abcd', 'sha256 deadbeef'])
def test_missing_invalid_or_mismatched_checksum_cannot_verify(verify_binary, tmp_path, mode, reply):
    counts = invoke(verify_binary, tmp_path, 'checksum', reply, mode)
    assert counts[0] == -1 and counts[1] != 0


@pytest.mark.parametrize('mode', ['refused', 'no-body', 'open-error'])
def test_missing_source_digest_or_unreadable_destination_fails_closed(verify_binary, tmp_path, mode):
    counts = invoke(verify_binary, tmp_path, 'checksum', 'sha256 deadbeef', mode)
    assert counts[0] == -1 and counts[1] != 0
