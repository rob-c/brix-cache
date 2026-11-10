"""Real keep-alive PROPFIND requests, response bounds and reconnect contracts."""

from contextlib import contextmanager
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import threading

import pytest

from test_xrd_dispatch_native import compile_client_contract
from settings import BIND_HOST

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


class MetadataPeer(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        self.server.connections += 1
        try:
            self.exchange()
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    def exchange(self):
        while True:
            request = self.read_request()
            if not request:
                return
            self.server.requests.append(request)
            response, close = next(self.server.responses, (b'', True))
            self.wfile.write(response)
            self.wfile.flush()
            if close:
                return

    def read_request(self):
        parts = []
        while True:
            line = self.rfile.readline()
            if not line:
                return b''
            parts.append(line)
            if line == b'\r\n':
                return b''.join(parts)


@contextmanager
def peer(responses):
    with socketserver.TCPServer((BIND_HOST, 0), MetadataPeer) as server:
        server.responses = iter(responses)
        server.requests = []
        server.connections = 0
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()


@pytest.fixture(scope='module')
def webmeta_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('webmeta-native'),
        'tests/c/webmeta_native_test.c', ('poll', 'read', 'malloc', 'brix_write_full'))


@pytest.fixture
def exchange(webmeta_binary):
    def run(responses, mode='normal', depth=0, expected='<ok/>', error=0,
            chunk=0, repeat=1, window='0'):
        with peer(responses) as server:
            port = 0 if mode == 'connect-error' else server.server_address[1]
            result = subprocess.run([str(webmeta_binary), mode, str(port), str(depth),
                str(-1 if error else 0), str(error), expected, str(repeat)],
                env=dict(os.environ, BRIX_KA_CHUNK=str(chunk), XRDC_MAX_STALL_MS=window),
                capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr
        return server, result.stdout
    return run


def response(body='<ok/>', status=207, length=None):
    size = len(body) if length is None else length
    return f'HTTP/1.1 {status} response\r\nContent-Length: {size}\r\n\r\n{body}'.encode()


@pytest.mark.parametrize('status', [200, 207])
@pytest.mark.parametrize('chunk', [0, 1, 7])
@pytest.mark.parametrize('depth', [0, 1, 7])
def test_two_exchanges_reuse_connection_and_preserve_headers(exchange, status, chunk, depth):
    server, _ = exchange([(response(status=status), False)] * 2, repeat=2, chunk=chunk, depth=depth)
    assert server.connections == 1 and len(server.requests) == 2
    for request in server.requests:
        assert request.startswith(b'PROPFIND /tree HTTP/1.1\r\n')
        assert f'Depth: {int(bool(depth))}\r\n'.encode() in request
        assert b'Authorization: Bearer fixture-token\r\n' in request


@pytest.mark.parametrize('mode', ['root-path', 'anonymous', 'poll-eintr', 'read-eintr'])
def test_optional_auth_root_path_and_interrupts(exchange, mode):
    server, _ = exchange([(response(), False)], mode=mode)
    request = server.requests[0]
    assert (b'Authorization:' in request) == (mode != 'anonymous')
    if mode == 'root-path':
        assert request.startswith(b'PROPFIND / HTTP/1.1\r\n')


@pytest.mark.parametrize('mode,error', [('poll-error', -1), ('poll-timeout', -1),
    ('read-error', -1), ('write-error', -1), ('connect-error', -1), ('allocation', -2)])
def test_transport_and_allocation_errors_drop_connection(exchange, mode, error):
    _, output = exchange([(response(), True)], mode=mode, error=error)
    assert 'connected=0' in output


def test_oversize_path_never_sends_request(exchange):
    server, output = exchange([], mode='long-path', error=-3)
    assert not server.requests and 'request too long' in output


@pytest.mark.parametrize('status,error', [(404, 3011), (401, 3010), (403, 3010),
                                       (301, -2), (500, -2), (201, -2)])
def test_http_errors_cannot_be_returned_as_metadata(exchange, status, error):
    server, output = exchange([(response(status=status), True)], error=error, window='1000')
    assert len(server.requests) == 1 and 'connected=0' in output


@pytest.mark.parametrize('wire,error,message', [
    (b'', -1, 'peer closed'), (b'HTTP/1.1 207 partial', -1, 'peer closed'),
    (b'x' * 17000, -2, 'header too large'),
    (response(length=4194305), -2, 'body too large'),
    (b'HTTP/1.1 207 ok\r\n\r\nbody', -2, 'no Content-Length'),
    (response(length=-1), -2, 'no Content-Length'),
    (b'HTTP/1.1\r\nContent-Length: 0\r\n\r\n', -2, 'HTTP 0'),
    (b'Content-Length: 0\r\n\r\n', -2, 'HTTP 0'),
])
def test_malformed_or_unbounded_response_disconnects(exchange, wire, error, message):
    _, output = exchange([(wire, True)], error=error)
    assert message in output and 'connected=0' in output


@pytest.mark.parametrize('body', ['', 'x' * 50000])
def test_empty_and_spanning_response_bodies(exchange, body):
    exchange([(response(body), False)], expected=body, chunk=7)


def test_midbody_disconnect_returns_no_partial_metadata(exchange):
    _, output = exchange([(response('short', length=50000), True)], error=-1, chunk=1)
    assert 'connected=0' in output


@pytest.mark.parametrize('first', [b'', response('short', length=50000)])
def test_transport_retry_reissues_whole_metadata_request(exchange, first):
    server, _ = exchange([(first, True), (response(), False)], window='1000')
    assert server.connections == 2 and server.requests[0] == server.requests[1]
