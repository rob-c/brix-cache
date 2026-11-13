"""Origin write and namespace requests preserve real wire and error contracts."""

import errno
import socket
import struct
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def origin_wire(server_native_compile):
    return server_native_compile('cache-origin-wire', 'tests/c/cache_origin_wire_native_test.c',
        ['-Wl,--wrap=malloc,--wrap=calloc,--wrap=send,--wrap=recv'])


def invoke(binary, op, *, body=b'', status=0, path='/source', fault='', allocation=0, raw=None):
    client, peer = socket.socketpair()
    namespace = op in ('rename', 'rm', 'rmdir', 'mkdir', 'chmod', 'stage', 'evict')
    with client, peer:
        peer.settimeout(10)
        send_response(peer, raw, status, body)
        peer.shutdown(socket.SHUT_WR)
        result = subprocess.run([str(binary), str(client.fileno()), op, path, fault,
            str(allocation), 'namespace' if namespace else 'write'], pass_fds=(client.fileno(),),
            capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        client.close()
        request = read_request(peer)
    return dict(line.split('=', 1) for line in result.stdout.splitlines()), bytes(request)


def send_response(peer, raw, status, body):
    frame = struct.pack('!2sHI', b'\0\1', status, len(body)) + body if raw is None else raw
    peer.sendall(frame)


def read_request(peer):
    """Early refusal may close with the preloaded response still unread."""
    request = bytearray()
    while True:
        try:
            data = peer.recv(4096)
        except ConnectionResetError:
            return request
        if not data:
            return request
        request.extend(data)


@pytest.mark.parametrize('op,opcode,payload', [
    ('open', 3010, b'/source'), ('read-open', 3010, b'/source'),
    ('write', 3019, b'payload'), ('write-empty', 3019, b''),
    ('truncate', 3028, b''), ('truncate-path', 3028, b'/source'),
    ('sync', 3016, b''), ('close', 3003, b''),
    ('rename', 3009, b'/source /destination'), ('rm', 3014, b'/source'),
    ('rmdir', 3015, b'/source'), ('mkdir', 3008, b'/source'),
    ('chmod', 3002, b'/source'), ('stage', 3021, b'/source'), ('evict', 3021, b'/source'),
])
@pytest.mark.parametrize('fault', ['', 'send-eintr', 'recv-eintr'])
def test_successful_exchange_retains_opcode_payload_and_handle(origin_wire, op, opcode, payload, fault):
    body = {'open': b'ABCD', 'read-open': b'ABCD' + bytes(8) + b'0 123 0 456'}.get(op, b'')
    result, request = invoke(origin_wire, op, body=body, fault=fault)
    assert result['rc'] == '0'
    assert struct.unpack_from('!H', request, 2)[0] == opcode
    assert struct.unpack_from('!I', request, 20)[0] == len(payload)
    assert request[24:] == payload
    assert result['handle'] == ('41424344' if op in ('open', 'read-open') else '12345678')
    assert result['size'] == ('123' if op == 'read-open' else '0')
    check_request_offset(op, request)


def check_request_offset(op, request):
    if op in ('write', 'write-empty', 'truncate'):
        assert request[4:8] == b'\x12\x34\x56\x78'
        assert request[8:16] == bytes(range(1, 9))
    if op == 'truncate-path':
        assert request[4:8] == bytes(4) and request[8:16] == bytes(range(1, 9))


@pytest.mark.parametrize('op', ['open', 'read-open', 'write', 'truncate', 'truncate-path', 'sync'])
@pytest.mark.parametrize('error', [3010, 3011, 3012])
def test_origin_write_errors_preserve_exact_protocol_reason(origin_wire, op, error):
    result, _request = invoke(origin_wire, op, status=4003, body=struct.pack('!I', error) + b'refused')
    assert result['rc'] == '-1' and result['xrd_error'] == str(error)
    assert result['handle'] == '12345678'


@pytest.mark.parametrize('op', ['rename', 'rm', 'rmdir', 'mkdir', 'chmod', 'stage', 'evict'])
@pytest.mark.parametrize('error,mapped', [(3010, errno.EACCES), (3011, errno.ENOENT),
                                        (3016, errno.EISDIR), (3018, errno.ENOTEMPTY), (3012, errno.EIO)])
def test_namespace_errors_preserve_caller_actionable_errno(origin_wire, op, error, mapped):
    result, _request = invoke(origin_wire, op, status=4003, body=struct.pack('!I', error) + b'refused')
    if op == 'mkdir' and error == 3018:
        mapped = errno.EEXIST
    assert result['rc'] == '-1' and result['errno'] == str(mapped)


@pytest.mark.parametrize('op', ['open', 'read-open', 'write', 'truncate', 'truncate-path', 'sync', 'rm'])
@pytest.mark.parametrize('raw', [b'', b'\0\1\0', struct.pack('!2sHI', b'\0\1', 0, 4) + b'ab',
                                struct.pack('!2sHI', b'\0\1', 0, 100000)])
def test_truncated_and_oversized_responses_never_report_success(origin_wire, op, raw):
    result, _request = invoke(origin_wire, op, raw=raw)
    assert result['rc'] == '-1' and result['xrd_error'] == '3012'


@pytest.mark.parametrize('op', ['open', 'read-open', 'write', 'truncate', 'truncate-path', 'sync', 'rm'])
@pytest.mark.parametrize('fault', ['send-error', 'send-zero'])
def test_failed_request_send_is_visible_before_response(origin_wire, op, fault):
    result, request = invoke(origin_wire, op, fault=fault)
    assert result['rc'] == '-1' and request == b''


def test_write_payload_failure_is_not_mistaken_for_header_success(origin_wire):
    result, request = invoke(origin_wire, 'write', fault='payload-error')
    assert result['rc'] == '-1' and len(request) == 24


@pytest.mark.parametrize('op', ['open', 'read-open', 'truncate-path', 'rename', 'rm'])
def test_request_allocation_failure_emits_no_frame(origin_wire, op):
    result, request = invoke(origin_wire, op, allocation=1)
    assert result['rc'] == '-1' and request == b''


@pytest.mark.parametrize('op,allocation', [('open', 2), ('read-open', 2), ('write', 1),
                                        ('truncate', 1), ('truncate-path', 2), ('sync', 1)])
def test_response_allocation_failure_is_explicit(origin_wire, op, allocation):
    result, _request = invoke(origin_wire, op, allocation=allocation, body=b'ABCD')
    assert result['rc'] == '-1' and result['xrd_error'] == '3008'


@pytest.mark.parametrize('op', ['open', 'truncate-path', 'rm', 'stage'])
@pytest.mark.parametrize('path', ['', '<null>'])
def test_missing_paths_are_refused_before_network_io(origin_wire, op, path):
    result, request = invoke(origin_wire, op, path=path)
    assert result['rc'] == '-1' and request == b''


@pytest.mark.parametrize('op', ['rename', 'rm', 'mkdir', 'chmod', 'stage'])
def test_namespace_path_cannot_overflow_wire_length(origin_wire, op):
    result, request = invoke(origin_wire, op, path='x' * 32768)
    assert result['rc'] == '-1' and result['errno'] == str(errno.EINVAL) and request == b''


@pytest.mark.parametrize('op', ['open', 'read-open', 'write', 'truncate', 'truncate-path', 'sync', 'rm'])
def test_unexpected_status_cannot_be_accepted_as_success(origin_wire, op):
    result, _request = invoke(origin_wire, op, status=4001)
    assert result['rc'] == '-1'


@pytest.mark.parametrize('body', [b'', b'a', b'abc'])
@pytest.mark.parametrize('op', ['open', 'read-open'])
def test_short_open_reply_cannot_publish_a_handle(origin_wire, op, body):
    result, _request = invoke(origin_wire, op, body=body)
    assert result['rc'] == '-1' and result['handle'] == '12345678'


def test_nonempty_write_reply_is_rejected(origin_wire):
    result, _request = invoke(origin_wire, 'write', body=b'extra')
    assert result['rc'] == '-1'


def test_large_write_is_rejected_before_reading_its_buffer(origin_wire):
    result, request = invoke(origin_wire, 'write-large')
    assert result['rc'] == '-1' and request == b''


@pytest.mark.parametrize('length', [0, 12, 39, 40, 100])
def test_prepare_request_identifier_is_bounded_and_terminated(origin_wire, length):
    result, _request = invoke(origin_wire, 'stage', body=b'a' * length)
    assert result['rc'] == '0' and result['request'] == 'a' * min(length, 39)
