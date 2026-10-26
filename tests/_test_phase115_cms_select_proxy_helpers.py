"""Wire helpers and scripted upstream for the Phase-115 CMS proxy tests.

The public test module owns fixtures and assertions.  This support module owns
only reusable wire construction and the deliberately small fake data server so
the test narrative stays below the repository's file-size ceiling.
"""

import os
import socket
import struct
import threading

from ephemeral_port import free_port
from settings import SERVER_HOST
from test_pgwrite_checksum import _read_response


H = SERVER_HOST

kXR_ok = 0
kXR_error = 4003
kXR_redirect = 4004
kXR_close = 3003
kXR_protocol = 3006
kXR_login = 3007
kXR_open = 3010
kXR_read = 3013
kXR_rm = 3014
kXR_bind = 3024
kXR_locate = 3027
kXR_mv = 3009

kXR_NotAuthorized = 3010

kXR_new = 0x0008
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_mkpath = 0x0100
WRITE_CREATE = kXR_new | kXR_open_updt | kXR_mkpath


def _open(sock, path: bytes, options: int, mode: int = 0):
    """Send a ROOT OPEN request and return its decoded response."""
    sock.sendall(struct.pack("!2sHHH2s6s4sI", b"\x00\x04", kXR_open, mode,
                             options, b"\x00\x00", b"\x00" * 6,
                             b"\x00" * 4, len(path)) + path)
    return _read_response(sock)


def _close(sock, fh: bytes):
    """Send a ROOT CLOSE request and return its decoded response."""
    sock.sendall(struct.pack("!2sH4sq4sI", b"\x00\x06", kXR_close, fh, 0,
                             b"\x00" * 4, 0))
    return _read_response(sock)


def _locate(sock, path: bytes):
    """Send a ROOT LOCATE request and return its decoded response."""
    payload = path + b"\x00"
    sock.sendall(struct.pack("!2sHH14sI", b"\x00\x07", kXR_locate, 0,
                             b"\x00" * 14, len(payload)) + payload)
    return _read_response(sock)


def _namespace_mutation(sock, opcode: int, source: bytes, destination=b""):
    """Send one path-form manager mutation used by pinned-proxy checks."""
    sid = b"\x00\x19"
    if opcode == kXR_mv:
        payload = source + b" " + destination
        frame = struct.pack("!2sH14sHI", sid, opcode, b"\x00" * 14,
                            len(source), len(payload)) + payload
    else:
        frame = struct.pack("!2sH16sI", sid, opcode, b"\x00" * 16,
                            len(source)) + source
    sock.sendall(frame)
    return _read_response(sock)


def _login_with_session(port: int):
    """Perform an anonymous ROOT login and return its socket and session ID."""
    sock = socket.create_connection((H, port), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    assert _read_response(sock)[0] == kXR_ok
    sock.sendall(struct.pack("!2sHI2s10xI", b"\x00\x01", kXR_protocol,
                             0x00000520, b"\x02\x03", 0))
    assert _read_response(sock)[0] == kXR_ok
    sock.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                             os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00",
                             0, 0, 5, 0, 0))
    status, body = _read_response(sock)
    assert status == kXR_ok and len(body) >= 16, (status, body)
    return sock, body[:16]


def _bind_secondary(port: int, sessid: bytes):
    """Attach a fresh connection as a restricted data secondary."""
    sock = socket.create_connection((H, port), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    assert _read_response(sock)[0] == kXR_ok
    sock.sendall(struct.pack("!2sH16sI", b"\x00\x18", kXR_bind, sessid, 0))
    status, body = _read_response(sock)
    assert status == kXR_ok and len(body) == 1, (status, body)
    return sock


def _response_or_eof(sock):
    """Read one response, treating an upstream-induced close as a result."""
    response_header = b""
    while len(response_header) < 8:
        chunk = sock.recv(8 - len(response_header))
        if not chunk:
            return "eof", b""
        response_header += chunk
    _sid, status, body_length = struct.unpack("!2sHI", response_header)
    body = b""
    while len(body) < body_length:
        chunk = sock.recv(body_length - len(body))
        if not chunk:
            return "eof", body
        body += chunk
    return status, body


def _redirect_port(body: bytes) -> int:
    """Decode the network-order port at the start of a redirect response."""
    return struct.unpack(">I", body[:4])[0]


def _settle(*nodes):
    """Wait until every scripted node has entered the manager registry."""
    for node in nodes:
        assert node.wait_ready(8.0), "CMS node never entered the registry"


def _closed_port() -> int:
    """Return a session-owned loopback port on which nothing listens."""
    return free_port(H)


class _FakeDataServer:
    """Minimal ROOT upstream with connection counting and a read-failure arm."""

    PAYLOAD = b"fake-node-bytes!"

    def __init__(self, mode="serve"):
        self.mode = mode
        self.accepted = 0
        self._lock = threading.Lock()
        self._closing = False
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port = free_port(H)
        self._srv.bind((H, self.port))
        self._srv.listen(8)
        self._srv.settimeout(0.2)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def connections(self) -> int:
        """Return the number of accepted proxy connections."""
        with self._lock:
            return self.accepted

    def _accept_loop(self):
        while not self._closing:
            try:
                conn, _peer = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self.accepted += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _exact(conn, byte_count):
        body = b""
        while len(body) < byte_count:
            chunk = conn.recv(byte_count - len(body))
            if not chunk:
                raise ConnectionError("peer closed")
            body += chunk
        return body

    def _reply_for(self, request_id, conn):
        if request_id == kXR_protocol:
            return struct.pack(">II", 0x00000310, 0)
        if request_id == kXR_login:
            return b"\x00" * 16
        if request_id == kXR_open:
            return struct.pack(">I", 7) + b"\x00" * 8
        if request_id == kXR_read:
            if self.mode == "die_on_read":
                conn.close()
                return None
            return self.PAYLOAD
        return b""

    def _serve(self, conn):
        conn.settimeout(5)
        try:
            self._exact(conn, 20)
            hello = struct.pack(">HHI", 0, 0, 8)
            conn.sendall(hello + struct.pack(">II", 0x00000310, 1))
            while not self._closing:
                header = self._exact(conn, 24)
                sid = header[:2]
                request_id = struct.unpack(">H", header[2:4])[0]
                body_length = struct.unpack(">I", header[20:24])[0]
                if body_length:
                    self._exact(conn, body_length)
                body = self._reply_for(request_id, conn)
                if body is None:
                    return
                response = sid + struct.pack(">HI", kXR_ok, len(body)) + body
                conn.sendall(response)
        except (OSError, ConnectionError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        """Stop accepting connections and close the listener."""
        self._closing = True
        try:
            self._srv.close()
        except OSError:
            pass
        self._thread.join(timeout=2)
