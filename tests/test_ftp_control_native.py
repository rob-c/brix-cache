"""FTP reply framing and I/O errors exercise real control-channel code."""

import base64
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def ftp_control_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('ftp-control-native')
    return compile_client_contract(root, output, 'tests/c/ftp_control_native_test.c',
        ('poll', 'recv', 'send', 'malloc', 'brix_tcp_connect',
         'brix_ftp_gss_wrap', 'brix_ftp_gss_unwrap'))


@pytest.fixture
def control_run(ftp_control_binary, tmp_path):
    def run(reply='200 ready\r\n', operation='read', command='NOOP', secure=False,
            fault='', expected=0, code=200):
        path = tmp_path / 'reply'
        path.write_bytes(reply.encode())
        result = subprocess.run([str(ftp_control_binary), operation, str(path), command,
            str(int(secure)), fault, str(expected), str(code)],
            capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


def protected(reply, code=631):
    return str(code) + ' ' + base64.b64encode(reply.encode()).decode() + '\r\n'


@pytest.mark.parametrize('fault', ['', 'fragment', 'poll-eintr', 'recv-eintr', 'recv-eagain'])
def test_incremental_multiline_reply_and_buffered_successor(control_run, fault):
    output = control_run('200-first line\r\ncontinuation\r\n200 finished\r\n550 later\r\n', fault=fault)
    assert 'TEXT finished\n' in output and 'code=200' in output


@pytest.mark.parametrize('fault,message', [
    ('poll-error', 'poll:'), ('poll-timeout', 'control timeout'), ('recv-error', 'read:'),
])
def test_read_system_errors_are_reported(control_run, fault, message):
    assert message in control_run(fault=fault, expected=-1)


@pytest.mark.parametrize('reply,message', [
    ('', 'closed by peer'), ('not a reply\r\n', 'malformed reply'),
    ('200 incomplete', 'closed by peer'), ('200-' + 'a' * 32768, 'reply too long'),
])
def test_invalid_or_truncated_reply_never_succeeds(control_run, reply, message):
    assert message in control_run(reply, expected=-1)


@pytest.mark.parametrize('fault', ['', 'short-send', 'send-eintr', 'send-eagain'])
def test_command_wire_bytes_survive_short_writes(control_run, fault):
    output = control_run(operation='command', command='SIZE /nested/file', fault=fault)
    assert output.endswith('SENT SIZE /nested/file\n')


@pytest.mark.parametrize('fault', ['send-error', 'send-zero', 'poll-error', 'poll-timeout'])
def test_failed_send_never_consumes_reply(control_run, fault):
    output = control_run(operation='command', fault=fault, expected=-1)
    assert 'code=0' in output


def test_oversized_command_never_writes(control_run):
    output = control_run(operation='command', command='A' * 4096, expected=-1)
    assert 'command too long' in output and output.endswith('SENT ')


@pytest.mark.parametrize('reply,status', [('550 absent\r\n', -10), ('150 early\r\n', -2)])
def test_expected_reply_class_is_enforced(control_run, reply, status):
    output = control_run(reply, operation='expect', expected=-1)
    assert f'RESULT -1 {status} ' in output


@pytest.mark.parametrize('code', [631, 632, 633])
def test_protected_reply_is_decoded_and_parsed(control_run, code):
    output = control_run(protected('200-first\r\n200 protected\r\n', code), secure=True)
    assert 'TEXT protected\n' in output


@pytest.mark.parametrize('reply,message', [
    ('200 cleartext\r\n', 'unprotected reply'), ('631 !!!!\r\n', 'not base64'),
    (protected('garbage\r\n'), 'malformed reply inside'),
])
def test_secure_session_rejects_downgrade_and_bad_frames(control_run, reply, message):
    assert message in control_run(reply, secure=True, expected=-1)


@pytest.mark.parametrize('operation', ['read', 'command'])
def test_security_engine_refusal_propagates(control_run, operation):
    output = control_run(protected('200 ready\r\n'), operation=operation,
                         secure=True, fault='gss-error', expected=-1)
    assert 'protection refused' in output


def test_secure_command_uses_one_encoded_frame(control_run):
    output = control_run(protected('200 ready\r\n'), operation='command', secure=True)
    assert output.endswith('SENT ENC ' + base64.b64encode(b'NOOP\r\n').decode() + '\n')


@pytest.mark.parametrize('fault', ['malloc-first', 'malloc-second'])
def test_protected_command_allocation_failure_sends_nothing(control_run, fault):
    output = control_run(protected('200 ready\r\n'), operation='command', secure=True,
                         fault=fault, expected=-1)
    assert 'out of memory' in output and output.endswith('SENT ')


@pytest.mark.parametrize('reply', ['220 welcome\r\n', '199 rejected\r\n221 bye\r\n',
                                   'malformed\r\n221 bye\r\n'])
def test_connect_validates_greeting_and_closes_failures(control_run, reply):
    expected = 0 if reply.startswith('220') else -1
    output = control_run(reply, operation='connect', expected=expected, code=220)
    assert ('SENT QUIT\n' in output) == (expected == -1)


def test_connect_failure_has_no_control_io(control_run):
    output = control_run(operation='connect', fault='connect-error', expected=-1)
    assert 'connect refused' in output and output.endswith('SENT ')
