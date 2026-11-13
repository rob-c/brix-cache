"""GridFTP control framing retains protection, bounded replies and ownership."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def control_binary(server_native_compile):
    names = ('poll', 'recv', 'send', 'socket', 'close', 'getpeername',
        'fcntl64', 'connect', 'brix_dns_resolve_sync', 'gftp_authenticate',
        'gftp_gsi_free', 'malloc', 'gftp_gsi_wrap', 'gftp_gsi_unwrap',
        'gftp_base64_encode')
    return server_native_compile('gftp-control', 'tests/c/gftp_control_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, operation, mode='normal', reply='220 Ready\r\n'):
    result = subprocess.run([str(binary), operation, mode, reply],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return tuple(map(int, result.stdout.split()))


@pytest.mark.parametrize('operation', ['reply', 'command', 'expect'])
@pytest.mark.parametrize('mode', ['normal', 'poll-interrupt', 'read-interrupt',
    'read-again', 'fragmented', 'secure'])
def test_reply_transport_retries_and_protected_framing(control_binary, operation, mode):
    assert invoke(control_binary, operation, mode)[:3] == (0, 0, 220)


@pytest.mark.parametrize('mode', ['short-write', 'write-interrupt', 'write-again'])
def test_command_retries_deliver_each_byte_once(control_binary, mode):
    assert invoke(control_binary, 'command', mode)[:4] == (0, 0, 220, 6)


@pytest.mark.parametrize('operation', ['reply', 'command', 'expect'])
@pytest.mark.parametrize('mode,error', [('timeout', errno.ETIMEDOUT),
    ('poll-error', errno.EIO), ('poll-hangup', errno.EIO),
    ('read-error', errno.ECONNABORTED), ('eof', errno.ECONNRESET),
    ('unprotected', errno.EPROTO), ('bad-base64', errno.EPROTO),
    ('secure-malformed', errno.EPROTO), ('unwrap-error', errno.EACCES),
    ('overflow', errno.EOVERFLOW)])
def test_failed_or_unprotected_replies_cannot_complete_commands(control_binary, operation, mode, error):
    assert invoke(control_binary, operation, mode)[:2] == (-1, error)


@pytest.mark.parametrize('mode,error', [('write-zero', errno.EIO),
    ('write-error', errno.EPIPE), ('wrap-error', errno.EACCES),
    ('encode-error', errno.ENOMEM), ('frame-alloc', errno.ENOMEM),
    ('long-command', errno.EOVERFLOW)])
def test_command_publication_failure_has_specific_errno(control_binary, mode, error):
    assert invoke(control_binary, 'command', mode)[:2] == (-1, error)


@pytest.mark.parametrize('reply,error', [('550 Absent\r\n', errno.ENOENT),
                                      ('530 Denied\r\n', errno.EIO)])
def test_expect_maps_refusal_without_losing_reply(control_binary, reply, error):
    assert invoke(control_binary, 'expect', reply=reply)[:3] == (-1, error, int(reply[:3]))


@pytest.mark.parametrize('length', [0, 10, 2046, 2047, 4096])
def test_multiline_capability_text_is_bounded_and_marks_truncation(control_binary, length):
    result = invoke(control_binary, 'reply', reply='211-Features\r\n' + 'x' * length + '\r\n211 End\r\n')
    assert result[:3] == (0, 0, 211)
    assert result[4:6] == (min(length + 2, 2047), int(length + 2 >= 2048))


@pytest.mark.parametrize('mode,closes', [('normal', 1), ('ipv6', 1),
    ('peer-error', 1), ('peer-short', 1), ('peer-other', 1),
    ('socket-retry', 1), ('connect-retry', 2)])
def test_session_carries_dns_and_data_policy_and_releases_auth_once(control_binary, mode, closes):
    result = invoke(control_binary, 'open', mode)
    assert result[:3] == (0, 0, 220)
    assert result[6:] == (closes, 1, 1)


@pytest.mark.parametrize('mode,error,closes', [('dns-error', errno.EHOSTUNREACH, 0),
    ('socket-error', errno.ECONNREFUSED, 0), ('connect-error', errno.ECONNREFUSED, 2),
    ('eof', errno.ECONNRESET, 1), ('read-error', errno.ECONNABORTED, 1)])
def test_failed_connection_never_authenticates_and_closes_every_socket(control_binary, mode, error, closes):
    result = invoke(control_binary, 'open', mode)
    assert result[:2] == (-1, error)
    assert result[6:] == (closes, 0, 0)


def test_bad_greeting_and_auth_failure_release_owned_resources(control_binary):
    greeting = invoke(control_binary, 'open', reply='500 Refused\r\n')
    assert greeting[0] == -1 and greeting[6:] == (1, 0, 0)
    authentication = invoke(control_binary, 'open', 'auth-error')
    assert authentication[0] == -1 and authentication[6:] == (1, 1, 1)
