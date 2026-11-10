"""TPC source-open async replies are bounded and preserve capability and error bytes."""

import socket
import struct
import subprocess

import pytest

from test_cache_origin_wire_native import read_request
from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def source_open(server_native_compile):
    return server_native_compile('tpc-source-open', 'tests/c/tpc_source_open_native_test.c',
        ['-Wl,--wrap=' + name for name in ('tpc_send_all', 'sleep', 'time', 'malloc')])


def frame(status=0, body=b'ABCD'):
    return struct.pack('!HHI', 2, status, len(body)) + body


def attention(status=0, body=b'ABCD', action=5008, declared=None):
    embedded = struct.pack('!HHI', 2, status, len(body) if declared is None else declared)
    return frame(4001, struct.pack('!II', action, 0) + embedded + body)


def invoke(binary, replies, selection='', mode='', path='/source'):
    client, peer = socket.socketpair()
    with client, peer:
        peer.settimeout(10); peer.sendall(replies); peer.shutdown(socket.SHUT_WR)
        result = subprocess.run([str(binary), str(client.fileno()), selection, mode, path],
            pass_fds=(client.fileno(),), capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        client.close(); wire = bytes(read_request(peer))
    return dict(line.split('=', 1) for line in result.stdout.splitlines()), wire


@pytest.mark.parametrize('selection,payload', [('', b'/source'), ('key', b'/source?tpc.key=grant'),
    ('key-org', b'/source?tpc.key=grant&tpc.org=alice@origin'),
    ('deleg-key-org', b'/source'), ('cap', b'/source?cap.sym=opaque&cap.msg=proof'),
    ('key-cap', b'/source?tpc.key=grant&cap.sym=opaque&cap.msg=proof')])
def test_source_open_renders_only_authorized_rendezvous_fields(source_open, selection, payload):
    result, wire = invoke(source_open, frame(), selection)
    assert result['rc'] == '0' and result['handle'] == '41424344'
    assert struct.unpack_from('!HH', wire) == (2, 3010)
    assert struct.unpack_from('!I', wire, 20)[0] == len(payload) and wire[24:] == payload


@pytest.mark.parametrize('replies,sends,sleeps', [
    (frame(4005, struct.pack('!I', 1000)) + frame(), 2, 1),
    (frame(4006, bytes(4)) + attention(), 1, 0),
    (attention(4005, bytes(4)) + frame(), 2, 1),
    (attention(4006, b'') + frame(), 1, 0),
    (attention(action=5001) + frame(), 1, 0),
    (attention(declared=4096), 1, 0),
])
def test_async_resolution_preserves_handle_and_restores_timeout(source_open, replies, sends, sleeps):
    result, wire = invoke(source_open, replies)
    assert result['rc'] == '0' and result['handle'] == '41424344'
    assert result['sends'] == str(sends) and result['sleeps'] == str(sleeps)
    assert int(result['timeout']) > 0 and len(wire) == sends * 31


@pytest.mark.parametrize('replies,mode,fragment', [
    (frame(4001, b'short'), '', 'too short'),
    (frame(4006, b'') * 16, '', '16 async rounds'),
    (frame(), 'deadline', 'deadline exceeded'),
    (b'\0', '', 'recv failed'),
    (frame(), 'send', 'send failed'),
    (frame(4005, bytes(4)), 'resend', 'resend'),
    (attention(4005, bytes(4)), 'resend', 'resend'),
    (frame(4003, struct.pack('!I', 3010) + b'authorization denied'), '', 'authorization denied'),
    (frame(0, b'abc'), '', 'rejected'),
    (frame(4003, b'x'), '', 'rejected'),
])
def test_failed_resolution_never_returns_a_remote_handle(source_open, replies, mode, fragment):
    result, _wire = invoke(source_open, replies, mode=mode)
    assert result['rc'] == '-1' and result['handle'] == '00000000'
    assert fragment in result['message']


def test_embedded_body_allocation_failure_preserves_no_memory(source_open):
    result, _wire = invoke(source_open, attention(), mode='allocation')
    assert result['rc'] == '-1' and result['error'] == '3008'


def test_oversized_remote_path_sends_no_partial_request(source_open):
    result, wire = invoke(source_open, frame(), selection='remote', path='/' + 'a' * 8192)
    assert result['rc'] == '-1' and result['error'] == '3002' and wire == b''


@pytest.mark.parametrize('body,accepted', [(struct.pack('!I', 1094) + b'data.invalid?cap.sym=next', True),
    (b'x', False), (struct.pack('!i', -1) + b'data.invalid', False)])
def test_redirect_is_recorded_for_later_policy_check_without_dialing(source_open, body, accepted):
    result, _wire = invoke(source_open, frame(4004, body))
    if accepted:
        assert int(result['rc']) > 0 and result['pending'] == '1'
        assert result['host'] == 'data.invalid' and result['opaque'] == 'cap.sym=next'
    else:
        assert result['rc'] == '-1' and result['pending'] == '0'
