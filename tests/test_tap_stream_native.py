"""Byte relay decoding stays aligned across streamed checkpoint/writev bodies."""

import struct
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def tap_stream(server_native_compile):
    return server_native_compile('tap-stream', 'tests/c/tap_stream_native_test.c')


def request(opcode, payload=b'', declared=None, checkpoint=0, sid=7):
    body = bytearray(16)
    body[15] = checkpoint
    length = len(payload) if declared is None else declared
    return struct.pack('!HH', sid, opcode) + body + struct.pack('!I', length) + payload


def descriptor(length):
    return struct.pack('!IIQ', 1, length, 0)


def invoke(binary, tmp_path, wire, chunk, count, direction=0, remaining=0):
    path = tmp_path / 'wire'
    path.write_bytes(wire)
    result = subprocess.run([str(binary), str(path), str(direction), str(chunk),
        str(count), str(remaining)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return [line.split() for line in result.stdout.splitlines()]


@pytest.mark.parametrize('chunk', [1, 7, 16, 23, 24, 31, 4096])
@pytest.mark.parametrize('embedded', [False, True])
def test_writev_trailing_data_does_not_become_spurious_headers(tap_stream, tmp_path, chunk, embedded):
    vectors = descriptor(3) + descriptor(5)
    frame = request(3031, vectors, declared=32)
    if embedded:
        frame = request(3012, frame[:24], checkpoint=4) + vectors
    wire = b'\0' * 20 + frame + b'abcdefgh' + request(3011, sid=9)
    rows = invoke(tap_stream, tmp_path, wire, chunk, 2)
    assert rows[0] == ['7', str(3012 if embedded else 3031), '0', str(24 if embedded else 32), '0', '-']
    assert rows[1] == ['9', '3011', '0', '0', '0', '-']


@pytest.mark.parametrize('opcode', [3019, 3026])
@pytest.mark.parametrize('chunk', [1, 19, 24, 4096])
def test_checkpoint_write_body_is_consumed_before_next_frame(tap_stream, tmp_path, opcode, chunk):
    inner = request(opcode, declared=13)
    frame = request(3012, inner, checkpoint=4) + b'payload bytes'
    rows = invoke(tap_stream, tmp_path, b'\0' * 20 + frame + request(3011, sid=9), chunk, 2)
    assert [row[1] for row in rows] == ['3012', '3011']


@pytest.mark.parametrize('opcode,length', [(3019, 0), (3026, 0), (3019, 16 * 1024 * 1024 + 1),
    (3026, 16 * 1024 * 1024 + 1), (3031, 15), (3031, 0x100000), (3011, 12)])
@pytest.mark.parametrize('chunk', [1, 4096])
def test_malformed_checkpoint_embedding_does_not_arm_unbounded_body(tap_stream, tmp_path, opcode, length, chunk):
    inner = request(opcode, declared=length)
    frame = request(3012, inner, checkpoint=4)
    rows = invoke(tap_stream, tmp_path, b'\0' * 20 + frame + request(3011, sid=9), chunk, 2)
    assert [row[0] for row in rows] == ['7', '9']


@pytest.mark.parametrize('payload', [b'', descriptor(0), b'x' * 15])
def test_empty_or_misaligned_vector_descriptors_have_no_trailing_body(tap_stream, tmp_path, payload):
    wire = b'\0' * 20 + request(3031, payload) + request(3011, sid=9)
    rows = invoke(tap_stream, tmp_path, wire, 1, 2)
    assert [row[1] for row in rows] == ['3031', '3011']


def test_vector_byte_total_uses_full_width_without_buffering(tap_stream, tmp_path):
    wire = b'\0' * 20 + request(3031, descriptor(0xffffffff) * 2)
    rows = invoke(tap_stream, tmp_path, wire, 7, 1, remaining=2 * 0xffffffff)
    assert rows == [['7', '3031', '0', '32', '0', '-']]


@pytest.mark.parametrize('length', [1, 1024, 1500])
@pytest.mark.parametrize('chunk', [1, 37, 4096])
def test_paths_are_captured_once_with_bounded_prefix(tap_stream, tmp_path, length, chunk):
    path = b'/' + b'p' * (length - 1)
    wire = b'\0' * 20 + request(3010, path) + request(3011, sid=9)
    rows = invoke(tap_stream, tmp_path, wire, chunk, 2)
    assert rows[0][5] == path[:1024].hex()
    assert rows[1][0] == '9'


@pytest.mark.parametrize('payload,error', [(b'x', 0), (b'xyz', 0), (struct.pack('!I', 3011) + b'gone', 3011)])
@pytest.mark.parametrize('chunk', [1, 4096])
def test_error_capture_preserves_response_alignment(tap_stream, tmp_path, payload, error, chunk):
    wire = struct.pack('!HHI', 7, 4003, len(payload)) + payload + struct.pack('!HHI', 9, 0, 0)
    rows = invoke(tap_stream, tmp_path, wire, chunk, 2, direction=1)
    assert rows[0] == ['7', '0', '4003', str(len(payload)), str(error), '-']
    assert rows[1] == ['9', '0', '0', '0', '0', '-']
