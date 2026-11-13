"""Pool-thread pgread preserves CRC frames and token ownership under backpressure."""

import errno
import struct
import subprocess

import pytest

from _test_phase115_pgread_verify_helpers import crc32c
from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def pool_reader(server_native_compile):
    return server_native_compile('pgread-pool', 'tests/c/pgread_pool_native_test.c',
        ['-Wl,--wrap=' + name for name in ('send', 'poll', 'brix_vfs_io_execute')])


@pytest.fixture
def read(pool_reader, tmp_path):
    def invoke(operation='single', mode='normal', offset=3, length=5000, available=None):
        source, image, sent = (tmp_path / name for name in ('source', 'image', 'sent'))
        count = offset + length if available is None else available
        payload = (bytes(range(251)) * (count // 251 + 1))[:count]
        source.write_bytes(payload)
        result = subprocess.run([str(pool_reader), operation, mode, str(source), str(image),
            str(sent), str(offset), str(length)], capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        keys = ('handled', 'read', 'size', 'token', 'all', 'held', 'chunked', 'frames',
                'chunk_error', 'socket_errno', 'io_errno', 'polls')
        return dict(zip(keys, map(int, result.stdout.split()))), image.read_bytes(), sent.read_bytes(), payload[offset:]
    return invoke


def decode_pages(body, offset):
    plain = bytearray()
    while body:
        checksum = struct.unpack('!I', body[:4])[0]
        size = min(4096 - offset % 4096, len(body) - 4)
        page = body[4:4 + size]
        assert size > 0 and crc32c(page) == checksum
        plain.extend(page)
        offset += size
        body = body[4 + size:]
    return bytes(plain)


def decode_frames(image, offset):
    payload, kinds = bytearray(), []
    while image:
        header = image[:32]
        assert header[:8] == struct.pack('!HHI', 0x3192, 4007, 24)
        assert header[12:14] == b'\x31\x92' and header[16:20] == bytes(4)
        assert struct.unpack('!I', header[8:12])[0] == crc32c(header[12:])
        assert struct.unpack('!Q', header[24:32])[0] == offset
        length = struct.unpack('!I', header[20:24])[0]
        decoded = decode_pages(image[32:32 + length], offset)
        payload.extend(decoded)
        offset += len(decoded)
        kinds.append(header[15])
        image = image[32 + length:]
    return bytes(payload), kinds


@pytest.mark.parametrize('operation', ['single', 'stream'])
@pytest.mark.parametrize('mode', ['normal', 'short', 'interrupt', 'progress'])
def test_progress_and_short_writes_preserve_exact_status_crc_and_page_bytes(read, operation, mode):
    result, image, sent, expected = read(operation, mode)
    assert result['read'] == 5000 and result['all'] == 1 and result['token'] == result['held'] == 0
    assert sent == image and decode_frames(image, 3) == (expected, [0])


@pytest.mark.parametrize('operation', ['single', 'stream'])
@pytest.mark.parametrize('mode,sent_length', [('stall', 7), ('blocked', 0)])
def test_stalled_reader_keeps_token_and_complete_unsent_tail_for_event_loop(read, operation, mode, sent_length):
    result, image, sent, expected = read(operation, mode)
    assert (result['all'], result['token'], result['held'], result['polls']) == (0, 1, 1, 12)
    assert sent == image[:sent_length] and decode_frames(image, 3) == (expected, [0])


@pytest.mark.parametrize('operation', ['single', 'stream'])
@pytest.mark.parametrize('mode,error', [('socket-error', errno.ECONNRESET), ('zero', errno.EPIPE),
                                     ('errno-zero', errno.EPIPE)])
def test_dead_socket_releases_token_without_marking_frame_sent(read, operation, mode, error):
    result, _, sent, _ = read(operation, mode)
    assert (result['all'], result['held'], result['token'], result['socket_errno']) == (0, 0, 0, error)
    assert sent == b''


@pytest.mark.parametrize('operation', ['single', 'stream'])
@pytest.mark.parametrize('mode,token', [('token-owned', 1), ('busy-ring', 0), ('read-error', 0)])
def test_existing_owner_or_read_failure_never_interleaves_wire_bytes(read, operation, mode, token):
    result, image, sent, _ = read(operation, mode)
    assert result['token'] == token and result['frames'] == 0 and image == sent == b''


@pytest.mark.parametrize('mode', ['normal', 'stall', 'blocked'])
@pytest.mark.parametrize('offset', [0, 4093])
def test_chunk_train_aligns_absolute_page_grid_and_retains_complete_tail(read, mode, offset):
    result, image, sent, expected = read('stream', mode, offset, 1100000)
    assert result['frames'] == 2 and result['read'] == len(expected)
    assert decode_frames(image, offset) == (expected, [1, 0])
    assert sent == image[:len(sent)] and result['all'] == int(mode == 'normal')


@pytest.mark.parametrize('available', [0, 103])
def test_stream_eof_finishes_without_fabricating_remaining_bytes(read, available):
    result, image, sent, expected = read('stream', offset=3, length=1100000, available=available)
    assert result['read'] == len(expected) and result['all'] == 1 and sent == image
    assert decode_frames(image, 3) == (expected, [0])


def test_later_read_failure_preserves_committed_partial_and_releases_socket(read):
    result, image, sent, expected = read('stream', 'late-read-error', 0, 1100000)
    assert (result['chunk_error'], result['io_errno'], result['all'], result['token']) == (1, errno.EIO, 0, 0)
    assert sent == image and decode_frames(image, 0) == (expected[:1048576], [1])
