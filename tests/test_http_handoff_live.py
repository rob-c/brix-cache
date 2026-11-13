"""Single-port HTTP/TLS handoff preserves bytes, closes failures and isolates root."""

from contextlib import contextmanager
import socket
import socketserver
import threading
import time

import pytest

from _test_brix_fault_proxy_helpers import _free_port
import _test_session_bind_helpers as root_wire
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.uses_lifecycle_harness, pytest.mark.timeout(40),
              pytest.mark.xdist_group('lc-http-handoff')]


@pytest.fixture(autouse=True)
def worker_survives(lifecycle):
    """A respawn must never turn a crashing relay into an apparently passing test."""
    yield
    for path in lifecycle.error_log_paths().values():
        assert 'exited on signal' not in path.read_text(errors='replace')


class EchoHandler(socketserver.BaseRequestHandler):
    """Independent byte oracle; the proxy sees only the socket protocol."""

    def handle(self):
        self.server.accepted.append(self.client_address)
        self.request.settimeout(5)
        try:
            while data := self.request.recv(32768):
                self.request.sendall(data)
        except OSError:
            return


@pytest.fixture
def handoff_target():
    with socketserver.ThreadingTCPServer((BIND_HOST, 0), EchoHandler) as server:
        server.daemon_threads = True
        server.accepted = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(3)


def start_handoff(lifecycle, target):
    directive = f'brix_http_handoff {target};' if target else ''
    endpoint = lifecycle.start(NginxInstanceSpec(
        name='lc-http-handoff', template='nginx_lc_handoff.conf',
        template_values={'BIND_HOST': BIND_HOST, 'HANDOFF_DIRECTIVE': directive},
        reason='raw handoff byte integrity and connection ownership'))
    return endpoint.port


def receive_exact(peer, size):
    output = bytearray()
    while len(output) < size:
        part = peer.recv(min(65536, size - len(output)))
        assert part, f'early EOF after {len(output)} of {size} bytes'
        output.extend(part)
    return bytes(output)


def send_payload(peer, payload, failures):
    try:
        peer.sendall(payload)
    except OSError as error:
        failures.append(error)


@contextmanager
def sending(peer, payload):
    failures = []
    writer = threading.Thread(target=send_payload, args=(peer, payload, failures), daemon=True)
    writer.start()
    try:
        yield
    finally:
        writer.join(10)
        assert not writer.is_alive() and not failures, failures


@pytest.mark.parametrize('prefix', [b'GET / HTTP/1.1\r\n\r\n', b'\x16\x03\x03\x00\x05hello'])
@pytest.mark.parametrize('size', [0, 65517, 65536, 3 * 1024 * 1024 + 17])
def test_handoff_replays_prefix_and_full_duplex_bytes(lifecycle, handoff_target, prefix, size):
    target = f'{HOST}:{handoff_target.server_address[1]}'
    port = start_handoff(lifecycle, target)
    payload = (bytes(range(251)) * (size // 251 + 1))[:size]
    with socket.create_connection((HOST, port), timeout=10) as peer:
        # One byte triggers the protocol decision before the rest is available.
        peer.sendall(prefix[:1])
        assert receive_exact(peer, 1) == prefix[:1]
        tail = prefix[1:] + payload
        with sending(peer, tail):
            if size > 65536:
                time.sleep(0.1)
            assert receive_exact(peer, len(tail)) == tail


def assert_closed(peer):
    try:
        assert peer.recv(64) == b''
    except ConnectionResetError:
        pass


def test_handoff_idle_timeout_releases_only_idle_connection(lifecycle, handoff_target):
    port = start_handoff(lifecycle, f'{HOST}:{handoff_target.server_address[1]}')
    with socket.create_connection((HOST, port), timeout=3) as peer:
        peer.sendall(b'GET')
        assert receive_exact(peer, 3) == b'GET'
        assert_closed(peer)
    with socket.create_connection((HOST, port), timeout=3) as peer:
        peer.sendall(b'GET again')
        assert receive_exact(peer, 9) == b'GET again'


@pytest.mark.parametrize('target', ['refused', 'unresolved', 'disabled'])
def test_unavailable_handoff_fails_closed_without_hanging_startup(lifecycle, target):
    targets = {'refused': f'{HOST}:{_free_port()}',
               'unresolved': 'no-such-handoff.invalid:12345', 'disabled': ''}
    port = start_handoff(lifecycle, targets[target])
    with socket.create_connection((HOST, port), timeout=3) as peer:
        peer.sendall(b'GET /private HTTP/1.1\r\nHost: example\r\n\r\n')
        assert_closed(peer)


def test_root_handshake_never_leaks_into_http_target(lifecycle, handoff_target, monkeypatch):
    port = start_handoff(lifecycle, f'{HOST}:{handoff_target.server_address[1]}')
    monkeypatch.setattr(root_wire, 'ANON_HOST', HOST)
    peer, _session, _stream = root_wire._establish_primary(port)
    peer.close()
    assert handoff_target.accepted == []
