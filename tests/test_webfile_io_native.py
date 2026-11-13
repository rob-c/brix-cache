"""HTTP range reads preserve partial progress and reject unusable responses."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def webfile_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('webfile-io-native')
    return compile_client_contract(root, output, 'tests/c/webfile_io_native_test.c',
        ('read', 'poll', 'brix_write_full', 'brix_tcp_connect', 'brix_tls_client',
         'brix_tls_client_free', 'brix_tls_read_some'))


@pytest.fixture
def range_run(webfile_binary, tmp_path):
    def run(response, offset=0, length=4, expected=4, data='data', fault='', tls=False, fragment=0):
        path = tmp_path / 'response'
        path.write_bytes(response.encode())
        result = subprocess.run([str(webfile_binary), str(path), str(offset), str(length),
            fault, str(expected), str(int(tls)), data],
            env=dict(os.environ, BRIX_WEB_FRAGMENT=str(fragment)),
            capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


def reply(body='data', status=206, length=None):
    return f'HTTP/1.1 {status} response\r\nContent-Length: {len(body) if length is None else length}\r\n\r\n{body}'


@pytest.mark.parametrize('tls', [False, True])
@pytest.mark.parametrize('fragment', [0, 1, 7])
def test_range_read_assembles_fragmented_header_and_body(range_run, tls, fragment):
    output = range_run(reply(), offset=7, tls=tls, fragment=fragment)
    assert 'Range: bytes=7-10\n' in output and 'connected=1' in output


@pytest.mark.parametrize('fault', ['poll-eintr', 'read-eintr', 'empty-path'])
def test_interrupted_reads_and_root_path(range_run, fault):
    output = range_run(reply(), fault=fault)
    assert 'RESULT 4' in output
    if fault == 'empty-path':
        assert 'GET / HTTP/1.1' in output


@pytest.mark.parametrize('fault,message', [('poll-error', 'web read'), ('timeout', 'web read'),
    ('read-error', 'web read:'), ('write', 'write failed')])
def test_transport_failure_disconnects(range_run, fault, message):
    output = range_run(reply(), expected=-1, fault=fault)
    assert 'connected=0' in output and message in output


@pytest.mark.parametrize('fault,message', [('connect', 'connect failed'),
    ('tls-connect', 'TLS refused'), ('tls-read', 'TLS read failed')])
def test_tls_setup_and_read_failure_release_socket(range_run, fault, message):
    output = range_run(reply(), expected=-1, fault=fault, tls=True)
    assert 'connected=0' in output and message in output


@pytest.mark.parametrize('status', [301, 400, 401, 403, 404, 500])
def test_unsuccessful_http_status_is_not_file_content(range_run, status):
    output = range_run(reply(status=status), expected=-1)
    assert 'connected=0' in output


@pytest.mark.parametrize('response,message', [
    ('not HTTP\r\n\r\ndata', 'HTTP 0'), ('HTTP/1.1\r\n\r\n', 'HTTP 0'),
    ('HTTP/1.1 206 ok\r\n\r\ndata', 'no Content-Length'),
    ('HTTP/1.1 206 ok\r\nContent-Length: -1\r\n\r\ndata', 'no Content-Length'),
    ('HTTP/1.1 206 unfinished', 'peer closed'), ('x' * 16384, 'header too large'),
])
def test_malformed_headers_disconnect(range_run, response, message):
    output = range_run(response, expected=-1)
    assert message in output and 'connected=0' in output


def test_oversized_request_has_no_wire_output(range_run):
    output = range_run(reply(), fault='long-request', expected=-1)
    assert 'request too long' in output and 'REQUEST ' not in output


@pytest.mark.parametrize('fragment', [0, 1, 11])
def test_short_body_returns_progress_and_disconnects(range_run, fragment):
    output = range_run(reply('da', length=4), expected=2, data='da', fragment=fragment)
    assert 'connected=0' in output


def test_empty_truncated_body_is_an_error(range_run):
    output = range_run(reply('', length=4), expected=-1)
    assert 'peer closed mid-body' in output and 'connected=0' in output


def test_excess_body_is_drained_before_reusing_connection(range_run):
    output = range_run(reply('data' + 'x' * 20000), fragment=1)
    assert 'connected=1' in output


def test_drain_failure_keeps_wanted_bytes_but_disconnects(range_run):
    output = range_run(reply('data', length=20000), fragment=1)
    assert 'connected=0' in output


@pytest.mark.parametrize('body', ['', 'range error body'])
def test_range_past_end_returns_no_bytes_and_discards_connection(range_run, body):
    output = range_run(reply(body, status=416), expected=0, data='')
    assert 'connected=0' in output


@pytest.mark.parametrize('offset', [0, 3, 8, 10, 12])
@pytest.mark.parametrize('fragment', [0, 1, 7])
def test_server_ignoring_range_must_deliver_requested_offset(range_run, offset, fragment):
    data = 'abcdefghij'[offset:offset + 4]
    range_run(reply('abcdefghij', status=200), offset=offset, expected=len(data),
              data=data, fragment=fragment)


def test_truncated_prefix_cannot_be_returned_as_requested_data(range_run):
    output = range_run(reply('ab', status=200, length=10), offset=5, expected=-1, fragment=1)
    assert 'connected=0' in output


@pytest.mark.parametrize('offset', [-1, 2**63 - 2])
def test_invalid_range_never_sends_a_request(range_run, offset):
    output = range_run(reply(), offset=offset, expected=-1)
    assert 'invalid range' in output and 'REQUEST ' not in output


def test_empty_read_does_not_send_request(range_run):
    output = range_run(reply(), length=0, expected=0, data='')
    assert 'REQUEST ' not in output
