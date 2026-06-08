"""
Tests for upstream XRootD redirector support (kXR_redirect, kXR_wait,
kXR_waitresp, kXR_authmore / kXR_gotoTLS).

Architecture
------------
Two tests use real pre-started infrastructure (no Python mock):

  test_locate_redirected       — nginx at REAL_REDIRECT_NGINX_PORT (11137)
                                 proxies to the cluster-redir (11160); the
                                 real redirector returns kXR_redirect to the
                                 cluster-ds (CLUSTER_DS_PORT 11162).

  test_upstream_error_forwarded — nginx at UPSTREAM_ERROR_NGINX_PORT (11123)
                                  proxies to a real anonymous xrootd (12123);
                                  a missing-path request produces kXR_error.

Four scenarios require Python MockUpstream / MockAuthUpstream because the
response behaviour cannot be driven from a real xrootd:

  test_locate_wait_then_redirect    — kXR_wait → kXR_redirect sequence
  test_locate_waitresp_then_redirect — kXR_waitresp → kXR_redirect sequence
  TestUpstreamAuth.*                — kXR_authmore / kXR_gotoTLS wire inspection

For mock-based tests the nginx instance (11131–11136) points to a mock-only
backend port (13121–13126).  MockUpstream / MockAuthUpstream bind SO_REUSEADDR
so ports are reclaimed without TIME_WAIT stalls between tests.
"""

import os
import socket
import struct
import threading
import time

import pytest

from settings import (
    CLUSTER_DS_PORT,
    MOCK_AUTH_BACKEND_PORT,
    MOCK_AUTH_NGINX_PORT,
    MOCK_AUTH_NOFILE_BACKEND_PORT,
    MOCK_AUTH_NOFILE_NGINX_PORT,
    MOCK_GOTORLS_BACKEND_PORT,
    MOCK_GOTORLS_NGINX_PORT,
    MOCK_WAIT_BACKEND_PORT,
    MOCK_WAIT_NGINX_PORT,
    MOCK_WAITRESP_BACKEND_PORT,
    MOCK_WAITRESP_NGINX_PORT,
    REAL_REDIRECT_NGINX_PORT,
    TOKENS_DIR,
    UPSTREAM_ERROR_NGINX_PORT,
)

pytestmark = pytest.mark.timeout(60)

# ------------------------------------------------------------------ #
# XRootD wire constants                                                #
# ------------------------------------------------------------------ #

kXR_ok       = 0
kXR_error    = 4003
kXR_redirect = 4004
kXR_wait     = 4005
kXR_waitresp = 4006
kXR_authmore = 4002

kXR_protocol = 3006
kXR_login    = 3007
kXR_auth     = 3000
kXR_locate   = 3027

kXR_gotoTLS  = 0x40000000

# ------------------------------------------------------------------ #
# Wire helpers                                                         #
# ------------------------------------------------------------------ #

def _build_resp_hdr(streamid: bytes, status: int, dlen: int) -> bytes:
    return struct.pack(">2sHI", streamid, status, dlen)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(
                f"connection closed expecting {n} bytes, got {len(buf)}")
        buf += chunk
    return buf


def _read_response(sock: socket.socket):
    hdr    = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen   = struct.unpack(">I", hdr[4:8])[0]
    body   = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _xrd_handshake_login(host: str, port: int) -> socket.socket:
    """Full XRootD bootstrap: handshake + kXR_protocol + kXR_login."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((host, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, kXR_protocol, 0x00000520, 0x02, 0x03, 0))
    _recv_exact(sock, 16)
    _read_response(sock)
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, kXR_login, 0,
                             b"test\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))
    _read_response(sock)
    return sock


def _send_locate(sock: socket.socket, path: str):
    payload = path.encode() + b"\x00"
    hdr = struct.pack(">BB H H 14x I",
                      0, 1, kXR_locate, 0, len(payload))
    sock.sendall(hdr + payload)


def _make_redirect_body(host: str, port: int) -> bytes:
    return struct.pack(">I", port) + host.encode()


# ------------------------------------------------------------------ #
# Mock upstream redirector                                             #
# ------------------------------------------------------------------ #

class MockUpstream:
    """
    Binds to `port`, accepts one connection, completes the XRootD
    bootstrap, reads one request, then sends the list of (status, body)
    tuples returned by `handler`.  Daemon thread; exits after one exchange.
    """

    def __init__(self, handler, port: int):
        self._handler = handler
        self._sock    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._port  = self._sock.getsockname()[1]
        self._errors = []
        self._sock.listen(5)
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def port(self):
        return self._port

    def _bootstrap(self, conn):
        _recv_exact(conn, 20)
        conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
        conn.sendall(struct.pack(">II", 0x00000520, 1))
        hdr = _recv_exact(conn, 24)
        sid = hdr[:2]
        conn.sendall(_build_resp_hdr(sid, kXR_ok, 8))
        conn.sendall(struct.pack(">II", 0x00000520, 1))
        hdr  = _recv_exact(conn, 24)
        sid  = hdr[:2]
        dlen = struct.unpack(">I", hdr[20:24])[0]
        if dlen:
            _recv_exact(conn, dlen)
        conn.sendall(_build_resp_hdr(sid, kXR_ok, 16))
        conn.sendall(b"\x01" * 16)

    def _read_one_request(self, conn):
        hdr        = _recv_exact(conn, 24)
        req_sid    = hdr[:2]
        req_opcode = struct.unpack(">H", hdr[2:4])[0]
        req_dlen   = struct.unpack(">I", hdr[20:24])[0]
        payload    = _recv_exact(conn, req_dlen) if req_dlen else b""
        path       = payload.rstrip(b"\x00").decode(errors="replace")
        return req_sid, req_opcode, path

    def _serve(self):
        conn = None
        try:
            conn, _ = self._sock.accept()
            conn.settimeout(60)
            self._bootstrap(conn)
            req_sid, opcode, path = self._read_one_request(conn)
            responses = self._handler(opcode, path)
            for status, body in responses:
                conn.sendall(_build_resp_hdr(req_sid, status, len(body)))
                if body:
                    conn.sendall(body)
        except Exception as exc:
            self._errors.append(str(exc))
        finally:
            for obj in (conn, self._sock):
                if obj is not None:
                    try:
                        obj.close()
                    except Exception:
                        pass


# ------------------------------------------------------------------ #
# Mock auth upstream                                                   #
# ------------------------------------------------------------------ #

class MockAuthUpstream:
    """
    Mock upstream that drives the kXR_authmore / kXR_gotoTLS path.

    auth_mode:
      "authmore_then_ok"  — kXR_login → kXR_authmore challenge →
                            read kXR_auth credential → accept → redirect
      "authmore_no_auth"  — kXR_login → kXR_authmore → close (no kXR_auth read)
      "gotorls"           — kXR_protocol → kXR_gotoTLS flag → close
    """

    def __init__(self, port: int, auth_mode: str, redirect_body: bytes = b""):
        self._mode          = auth_mode
        self._redirect_body = redirect_body
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._port = self._sock.getsockname()[1]
        self._sock.listen(5)
        self.errors         = []
        self.received_token = None
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def port(self):
        return self._port

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            conn.settimeout(30)

            # Handshake
            _recv_exact(conn, 20)
            conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
            conn.sendall(struct.pack(">II", 0x00000520, 1))

            # kXR_protocol
            hdr = _recv_exact(conn, 24)
            sid = hdr[:2]

            if self._mode == "gotorls":
                flags = kXR_gotoTLS | 0x00000520
                conn.sendall(struct.pack(">2sHI", sid, kXR_ok, 8))
                conn.sendall(struct.pack(">II", flags, 1))
                conn.close()
                return

            conn.sendall(struct.pack(">2sHI", sid, kXR_ok, 8))
            conn.sendall(struct.pack(">II", 0x00000520, 1))

            # kXR_login
            hdr  = _recv_exact(conn, 24)
            sid  = hdr[:2]
            dlen = struct.unpack(">I", hdr[20:24])[0]
            if dlen:
                _recv_exact(conn, dlen)

            if self._mode == "authmore_no_auth":
                authmore_body = b"&P=ztn,test"
                conn.sendall(struct.pack(">2sHI", sid, kXR_authmore,
                                         len(authmore_body)))
                conn.sendall(authmore_body)
                time.sleep(0.5)
                conn.close()
                return

            # authmore_then_ok: issue challenge, read kXR_auth
            authmore_body = b"&P=ztn,test"
            conn.sendall(struct.pack(">2sHI", sid, kXR_authmore,
                                     len(authmore_body)))
            conn.sendall(authmore_body)

            auth_hdr  = _recv_exact(conn, 24)
            auth_sid  = auth_hdr[:2]
            auth_op   = struct.unpack(">H", auth_hdr[2:4])[0]
            auth_dlen = struct.unpack(">I", auth_hdr[20:24])[0]
            cred_payload = _recv_exact(conn, auth_dlen) if auth_dlen else b""
            self.received_token = cred_payload

            if auth_op != kXR_auth:
                self.errors.append(f"expected kXR_auth (3000), got {auth_op}")
                conn.close()
                return

            conn.sendall(struct.pack(">2sHI", auth_sid, kXR_ok, 16))
            conn.sendall(b"\x02" * 16)

            req_hdr  = _recv_exact(conn, 24)
            req_sid  = req_hdr[:2]
            req_dlen = struct.unpack(">I", req_hdr[20:24])[0]
            if req_dlen:
                _recv_exact(conn, req_dlen)

            conn.sendall(struct.pack(">2sHI", req_sid, kXR_redirect,
                                     len(self._redirect_body)))
            if self._redirect_body:
                conn.sendall(self._redirect_body)
            conn.close()

        except Exception as exc:
            self.errors.append(str(exc))
        finally:
            try:
                self._sock.close()
            except Exception:
                pass


# ------------------------------------------------------------------ #
# Fixtures — readiness checks on pre-started dedicated nginx           #
# ------------------------------------------------------------------ #

def _require_mock_nginx(port: int, label: str) -> dict:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return {"port": port}
        except OSError:
            time.sleep(0.1)
    pytest.skip(f"{label} nginx not running on port {port}")


@pytest.fixture(scope="session")
def real_redirect_nginx():
    return _require_mock_nginx(REAL_REDIRECT_NGINX_PORT, "real-upstream-redirect")


@pytest.fixture(scope="session")
def mock_wait_nginx():
    return _require_mock_nginx(MOCK_WAIT_NGINX_PORT, "mock-wait")


@pytest.fixture(scope="session")
def mock_waitresp_nginx():
    return _require_mock_nginx(MOCK_WAITRESP_NGINX_PORT, "mock-waitresp")


@pytest.fixture(scope="session")
def upstream_error_nginx():
    return _require_mock_nginx(UPSTREAM_ERROR_NGINX_PORT, "upstream-error")


@pytest.fixture(scope="session")
def mock_auth_nginx():
    return _require_mock_nginx(MOCK_AUTH_NGINX_PORT, "mock-auth")


@pytest.fixture(scope="session")
def mock_auth_nofile_nginx():
    return _require_mock_nginx(MOCK_AUTH_NOFILE_NGINX_PORT, "mock-auth-nofile")


@pytest.fixture(scope="session")
def mock_gotorls_nginx():
    return _require_mock_nginx(MOCK_GOTORLS_NGINX_PORT, "mock-gotorls")


# ------------------------------------------------------------------ #
# Tests — upstream response forwarding                                 #
# ------------------------------------------------------------------ #

class TestUpstreamRedirect:
    """nginx correctly forwards kXR_redirect / kXR_wait / kXR_waitresp /
    kXR_error responses from an upstream XRootD redirector to the client."""

    def test_locate_redirected(self, real_redirect_nginx):
        """Upstream cluster-redir returns kXR_redirect → client receives it.

        The real-upstream-redirect nginx at REAL_REDIRECT_NGINX_PORT proxies to
        the pre-started cluster-redir (CLUSTER_REDIR_PORT).  The cluster-redir
        has the cluster-ds registered for "/" so any kXR_locate is answered with
        kXR_redirect pointing at CLUSTER_DS_PORT.
        """
        sock = _xrd_handshake_login("127.0.0.1", real_redirect_nginx["port"])
        _send_locate(sock, "/data/file.root")
        status, body = _read_response(sock)
        sock.close()

        assert status == kXR_redirect, f"expected kXR_redirect, got {status}"
        assert len(body) >= 4
        assert struct.unpack(">I", body[:4])[0] == CLUSTER_DS_PORT

    def test_locate_wait_then_redirect(self, mock_wait_nginx):
        """Upstream returns kXR_wait(1) then kXR_redirect on the same
        connection; nginx keeps the upstream read event armed during the wait
        so it picks up the redirect without the client retrying."""
        target_host = "retry.example.org"
        target_port = 2094

        mock = MockUpstream(
            lambda opcode, path: [
                (kXR_wait,     struct.pack(">I", 1)),
                (kXR_redirect, _make_redirect_body(target_host, target_port)),
            ],
            MOCK_WAIT_BACKEND_PORT,
        )

        sock = _xrd_handshake_login("127.0.0.1", mock_wait_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(15)
        status, body = _read_response(sock)
        sock.close()

        assert not mock._errors, f"mock upstream error: {mock._errors}"
        assert status == kXR_redirect, \
            f"expected kXR_redirect after kXR_wait, got {status}"
        assert struct.unpack(">I", body[:4])[0] == target_port
        assert body[4:].decode() == target_host

    def test_locate_waitresp_then_redirect(self, mock_waitresp_nginx):
        """Upstream returns kXR_waitresp (async hold) then kXR_redirect;
        client receives both frames in order."""
        target_host = "async.example.org"
        target_port = 3094

        mock = MockUpstream(
            lambda opcode, path: [
                (kXR_waitresp, b""),
                (kXR_redirect, _make_redirect_body(target_host, target_port)),
            ],
            MOCK_WAITRESP_BACKEND_PORT,
        )

        sock = _xrd_handshake_login("127.0.0.1", mock_waitresp_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(5)
        status1, _    = _read_response(sock)
        status2, body = _read_response(sock)
        sock.close()

        assert not mock._errors, f"mock upstream error: {mock._errors}"
        assert status1 == kXR_waitresp, \
            f"expected kXR_waitresp first, got {status1}"
        assert status2 == kXR_redirect, \
            f"expected kXR_redirect second, got {status2}"
        assert struct.unpack(">I", body[:4])[0] == target_port
        assert body[4:].decode() == target_host

    def test_upstream_error_forwarded(self, upstream_error_nginx):
        """Upstream kXR_error is forwarded to the client.

        The upstream-error nginx at UPSTREAM_ERROR_NGINX_PORT proxies to a real
        anonymous xrootd.  Requesting a non-existent path causes the xrootd to
        return kXR_error, which nginx must forward to the client.
        """
        sock = _xrd_handshake_login("127.0.0.1", upstream_error_nginx["port"])
        _send_locate(sock, "/nonexistent/missing.root")
        status, body = _read_response(sock)
        sock.close()

        assert status == kXR_error, f"expected kXR_error, got {status}"
        assert len(body) >= 4


# ------------------------------------------------------------------ #
# Tests — upstream auth (kXR_authmore / kXR_gotoTLS)                  #
# ------------------------------------------------------------------ #

class TestUpstreamAuth:
    """nginx correctly handles token-auth challenges and gotoTLS on the
    outbound upstream connection."""

    def test_upstream_token_auth_success(self, mock_auth_nginx):
        """Upstream issues kXR_authmore; nginx sends the ztn JWT from
        xrootd_upstream_token_file; upstream accepts; redirect forwarded."""
        token_content = "eyJhbGciOiJSUzI1NiJ9.test.sig"
        token_path = os.path.join(TOKENS_DIR, "mock_auth.jwt")
        os.makedirs(TOKENS_DIR, exist_ok=True)
        with open(token_path, "w") as fh:
            fh.write(token_content + "\n")

        redirect_body = _make_redirect_body("storage.example.org", 1094)
        mock = MockAuthUpstream(
            MOCK_AUTH_BACKEND_PORT,
            auth_mode="authmore_then_ok",
            redirect_body=redirect_body,
        )

        sock = _xrd_handshake_login("127.0.0.1", mock_auth_nginx["port"])
        _send_locate(sock, "/data/file.root")
        status, body = _read_response(sock)
        sock.close()

        assert not mock.errors, f"mock upstream error: {mock.errors}"
        assert status == kXR_redirect, \
            f"expected kXR_redirect after token auth, got {status}"
        assert struct.unpack(">I", body[:4])[0] == 1094
        assert body[4:].decode() == "storage.example.org"

        assert mock.received_token is not None, "nginx never sent kXR_auth"
        # Credential payload is "ztn\0<jwt>" — skip 4-byte credtype prefix
        sent_token = mock.received_token[4:].decode()
        assert sent_token == token_content, \
            f"sent token mismatch: {sent_token!r} != {token_content!r}"

    def test_upstream_token_auth_no_file_aborts(self, mock_auth_nofile_nginx):
        """Upstream issues kXR_authmore but nginx has no token file
        configured; nginx must abort and return kXR_error to the client."""
        mock = MockAuthUpstream(
            MOCK_AUTH_NOFILE_BACKEND_PORT,
            auth_mode="authmore_no_auth",
        )

        sock = _xrd_handshake_login("127.0.0.1", mock_auth_nofile_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(5)
        status, _ = _read_response(sock)
        sock.close()

        assert status == kXR_error, \
            f"expected kXR_error when token_file not set, got {status}"

    def test_upstream_gotorls_no_tls_configured_aborts(self, mock_gotorls_nginx):
        """Upstream signals kXR_gotoTLS but nginx has xrootd_upstream_tls off;
        nginx must abort — no credentials may travel over a cleartext channel."""
        mock = MockAuthUpstream(
            MOCK_GOTORLS_BACKEND_PORT,
            auth_mode="gotorls",
        )

        sock = _xrd_handshake_login("127.0.0.1", mock_gotorls_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(5)
        status, _ = _read_response(sock)
        sock.close()

        assert status == kXR_error, \
            f"expected kXR_error when gotoTLS but upstream_tls=off, got {status}"
