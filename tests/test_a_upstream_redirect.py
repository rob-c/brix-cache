"""
Tests for upstream XRootD redirector support (kXR_redirect, kXR_wait,
kXR_waitresp).

nginx-xrootd can be configured with `xrootd_upstream host:port` so that
when a client requests a file that does not exist locally, nginx connects
to the upstream redirector, relays the request, and forwards the response
back to the client.

A lightweight Python mock redirector handles the upstream side of each
test scenario so no real XRootD installation is needed.
"""

import os
import socket
import struct
import threading
import time
import pytest

from settings import (
    NGINX_BIN,
    UPSTREAM_ERROR_BACKEND_PORT,
    UPSTREAM_ERROR_NGINX_PORT,
    UPSTREAM_REDIRECT_BACKEND_PORT,
    UPSTREAM_REDIRECT_NGINX_PORT,
    UPSTREAM_WAIT_BACKEND_PORT,
    UPSTREAM_WAIT_NGINX_PORT,
    UPSTREAM_WAITRESP_BACKEND_PORT,
    UPSTREAM_WAITRESP_NGINX_PORT,
    UPSTREAM_AUTH_NGINX_PORT,
    UPSTREAM_AUTH_BACKEND_PORT,
    UPSTREAM_AUTH_NOFILE_NGINX_PORT,
    UPSTREAM_AUTH_NOFILE_BACKEND_PORT,
    UPSTREAM_GOTORLS_NOTLS_NGINX_PORT,
    UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT,
)

pytestmark = pytest.mark.timeout(60)

import server_control

# ------------------------------------------------------------------ #
# XRootD wire constants                                                #
# ------------------------------------------------------------------ #

kXR_ok       = 0
kXR_error    = 4003
kXR_redirect = 4004
kXR_wait     = 4005
kXR_waitresp = 4006
kXR_authmore = 4002   # server wants more credentials; body has &P=ztn,...

kXR_protocol = 3006
kXR_login    = 3007
kXR_auth     = 3000   # client sends credential in response to kXR_authmore
kXR_locate   = 3027

kXR_gotoTLS  = 0x40000000  # bit in protocol-response flags: require TLS

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
    # Handshake
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    # kXR_protocol
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, kXR_protocol, 0x00000520, 0x02, 0x03, 0))
    _recv_exact(sock, 16)         # handshake response
    _read_response(sock)          # protocol response
    # kXR_login
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, kXR_login, 0,
                             b"test\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))
    _read_response(sock)          # login response
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
    Listens on a random port, accepts one connection, completes the
    XRootD bootstrap, reads one client request, then runs ``handler``
    which returns a list of (status, body) tuples to send back.

    For multi-response scenarios (kXR_wait retry, kXR_waitresp), pass
    a ``handler`` that returns multiple tuples — they are all sent in
    sequence on the same connection.
    """

    def __init__(self, handler, port: int):
        self._handler  = handler
        self._sock     = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._port     = self._sock.getsockname()[1]
        self._errors   = []
        self._sock.listen(5)
        t = threading.Thread(target=self._serve, daemon=True)
        t.start()

    @property
    def port(self):
        return self._port

    def _bootstrap(self, conn):
        # Handshake (20 bytes)
        _recv_exact(conn, 20)
        conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
        conn.sendall(struct.pack(">II", 0x00000520, 1))
        # kXR_protocol (24 bytes)
        hdr = _recv_exact(conn, 24)
        sid = hdr[:2]
        conn.sendall(_build_resp_hdr(sid, kXR_ok, 8))
        conn.sendall(struct.pack(">II", 0x00000520, 1))
        # kXR_login (24 bytes + optional payload)
        hdr  = _recv_exact(conn, 24)
        sid  = hdr[:2]
        dlen = struct.unpack(">I", hdr[20:24])[0]
        if dlen:
            _recv_exact(conn, dlen)
        conn.sendall(_build_resp_hdr(sid, kXR_ok, 16))
        conn.sendall(b"\x01" * 16)

    def _read_one_request(self, conn):
        hdr    = _recv_exact(conn, 24)
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
            conn.close()
        except Exception as exc:
            self._errors.append(str(exc))
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        finally:
            try:
                self._sock.close()
            except Exception:
                pass


# ------------------------------------------------------------------ #
# nginx config template used by all upstream tests                    #
# ------------------------------------------------------------------ #

UPSTREAM_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log info;
pid       {LOG_DIR}/nginx.pid;

events { worker_connections 1024; }

stream {
    server {
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_upstream 127.0.0.1:{UPSTREAM_PORT};
    }
}
"""


def _start_upstream_nginx(listen_port: int, upstream_port: int) -> dict:
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    # Brief pause to let any prior test-suite connections settle.
    time.sleep(0.5)
    # Retry up to 3 times in case of port conflict from prior tests.
    for attempt in range(3):
        try:
            return server_control.start_nginx_instance(
                port=listen_port,
                conf_text=UPSTREAM_CONF,
                template_kwargs={"UPSTREAM_PORT": upstream_port},
            )
        except RuntimeError:
            if attempt < 2:
                time.sleep(1.0)
            else:
                raise


@pytest.fixture(scope="session")
def upstream_redirect_nginx():
    info = _start_upstream_nginx(
        UPSTREAM_REDIRECT_NGINX_PORT, UPSTREAM_REDIRECT_BACKEND_PORT
    )
    yield info
    info["stop"]()


@pytest.fixture(scope="function")
def upstream_wait_nginx():
    info = _start_upstream_nginx(
        UPSTREAM_WAIT_NGINX_PORT, UPSTREAM_WAIT_BACKEND_PORT
    )
    yield info
    info["stop"]()


@pytest.fixture(scope="session")
def upstream_waitresp_nginx():
    info = _start_upstream_nginx(
        UPSTREAM_WAITRESP_NGINX_PORT, UPSTREAM_WAITRESP_BACKEND_PORT
    )
    yield info
    info["stop"]()


@pytest.fixture(scope="session")
def upstream_error_nginx():
    info = _start_upstream_nginx(
        UPSTREAM_ERROR_NGINX_PORT, UPSTREAM_ERROR_BACKEND_PORT
    )
    yield info
    info["stop"]()


# ------------------------------------------------------------------ #
# Tests                                                                #
# ------------------------------------------------------------------ #

class TestUpstreamRedirect:

    def test_locate_redirected(self, upstream_redirect_nginx):
        """Upstream returns kXR_redirect → client receives the redirect."""
        target_host = "storage.example.org"
        target_port = 1094

        mock = MockUpstream(
            lambda opcode, path: [
                (kXR_redirect, _make_redirect_body(target_host, target_port))
            ],
            UPSTREAM_REDIRECT_BACKEND_PORT,
        )

        sock = _xrd_handshake_login("127.0.0.1", upstream_redirect_nginx["port"])
        _send_locate(sock, "/data/file.root")
        status, body = _read_response(sock)
        sock.close()

        assert not mock._errors, f"mock upstream error: {mock._errors}"
        assert status == kXR_redirect, f"expected kXR_redirect, got {status}"
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        got_host = body[4:].decode()
        assert got_port == target_port
        assert got_host == target_host

    def test_locate_wait_then_redirect(self, upstream_wait_nginx):
        """Upstream returns kXR_wait(1), then kXR_redirect on retry."""
        target_host = "retry.example.org"
        target_port = 2094

        # Send kXR_wait then kXR_redirect on the same connection.
        # nginx keeps the upstream read event armed during kXR_wait so it reads
        # the buffered kXR_redirect before the 1-second retry timer fires.
        mock = MockUpstream(
            lambda opcode, path: [
                (kXR_wait, struct.pack(">I", 1)),
                (kXR_redirect, _make_redirect_body(target_host, target_port)),
            ],
            UPSTREAM_WAIT_BACKEND_PORT,
        )

        sock = _xrd_handshake_login("127.0.0.1", upstream_wait_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(15)   # nginx waits 1 s internally before retry
        status, body = _read_response(sock)
        sock.close()

        assert not mock._errors, f"mock upstream error: {mock._errors}"
        assert status == kXR_redirect, \
            f"expected kXR_redirect after kXR_wait, got {status}"
        got_port = struct.unpack(">I", body[:4])[0]
        got_host = body[4:].decode()
        assert got_port == target_port
        assert got_host == target_host

    def test_locate_waitresp_then_redirect(self, upstream_waitresp_nginx):
        """Upstream returns kXR_waitresp then kXR_redirect → client gets both."""
        target_host = "async.example.org"
        target_port = 3094

        # Serve kXR_waitresp immediately, then a brief pause, then redirect
        class WaitRespMock:
            def __init__(self, port: int):
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind(("127.0.0.1", port))
                self._port = self._sock.getsockname()[1]
                self._sock.listen(5)
                self.errors = []
                t = threading.Thread(target=self._serve, daemon=True)
                t.start()

            @property
            def port(self):
                return self._port

            def _serve(self):
                conn = None
                try:
                    conn, _ = self._sock.accept()
                    conn.settimeout(30)
                    # bootstrap
                    _recv_exact(conn, 20)
                    conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
                    conn.sendall(struct.pack(">II", 0x00000520, 1))
                    hdr = _recv_exact(conn, 24)
                    sid = hdr[:2]
                    conn.sendall(_build_resp_hdr(sid, kXR_ok, 8))
                    conn.sendall(struct.pack(">II", 0x00000520, 1))
                    hdr = _recv_exact(conn, 24)
                    sid = hdr[:2]
                    dlen = struct.unpack(">I", hdr[20:24])[0]
                    if dlen:
                        _recv_exact(conn, dlen)
                    conn.sendall(_build_resp_hdr(sid, kXR_ok, 16))
                    conn.sendall(b"\x01" * 16)
                    # Read request
                    hdr = _recv_exact(conn, 24)
                    req_sid = hdr[:2]
                    dlen = struct.unpack(">I", hdr[20:24])[0]
                    if dlen:
                        _recv_exact(conn, dlen)
                    # kXR_waitresp (dlen=0)
                    conn.sendall(_build_resp_hdr(req_sid, kXR_waitresp, 0))
                    # Brief async delay, then the actual redirect
                    time.sleep(0.1)
                    body = _make_redirect_body(target_host, target_port)
                    conn.sendall(_build_resp_hdr(req_sid, kXR_redirect, len(body)))
                    conn.sendall(body)
                    conn.close()
                except Exception as exc:
                    self.errors.append(str(exc))
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
                finally:
                    try:
                        self._sock.close()
                    except Exception:
                        pass

        mock = WaitRespMock(UPSTREAM_WAITRESP_BACKEND_PORT)
        sock = _xrd_handshake_login("127.0.0.1", upstream_waitresp_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(5)
        status1, _body1 = _read_response(sock)
        status2, body2  = _read_response(sock)
        sock.close()

        assert not mock.errors, f"mock upstream error: {mock.errors}"
        assert status1 == kXR_waitresp, \
            f"expected kXR_waitresp first, got {status1}"
        assert status2 == kXR_redirect, \
            f"expected kXR_redirect second, got {status2}"
        got_port = struct.unpack(">I", body2[:4])[0]
        got_host = body2[4:].decode()
        assert got_port == target_port
        assert got_host == target_host

    def test_upstream_error_forwarded(self, upstream_error_nginx):
        """Upstream kXR_error is forwarded verbatim to the client."""
        err_code = 3011  # kXR_NotFound

        mock = MockUpstream(
            lambda opcode, path: [
                (kXR_error,
                 struct.pack(">I", err_code) + b"file not found\x00")
            ],
            UPSTREAM_ERROR_BACKEND_PORT,
        )

        sock = _xrd_handshake_login("127.0.0.1", upstream_error_nginx["port"])
        _send_locate(sock, "/data/missing.root")
        status, body = _read_response(sock)
        sock.close()

        assert not mock._errors, f"mock upstream error: {mock._errors}"
        assert status == kXR_error, f"expected kXR_error, got {status}"
        assert len(body) >= 4
        assert struct.unpack(">I", body[:4])[0] == err_code


# ------------------------------------------------------------------ #
# Phase 2 tests: kXR_authmore (token auth) and kXR_gotoTLS           #
# ------------------------------------------------------------------ #

# Nginx config with upstream_token_file configured
UPSTREAM_AUTH_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log info;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_upstream 127.0.0.1:{UPSTREAM_PORT};
        xrootd_upstream_token_file {TOKEN_FILE};
    }}
}}
"""

# Nginx config without upstream_token_file (to test abort on authmore)
UPSTREAM_AUTH_NOFILE_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log info;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_upstream 127.0.0.1:{UPSTREAM_PORT};
        # No xrootd_upstream_token_file -- should abort on kXR_authmore
    }}
}}
"""

# Nginx config without upstream_tls (to test abort on kXR_gotoTLS)
UPSTREAM_GOTORLS_NOTLS_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log info;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_upstream 127.0.0.1:{UPSTREAM_PORT};
        # xrootd_upstream_tls is deliberately OFF (default)
    }}
}}
"""


class MockAuthUpstream:
    """
    Mock upstream that handles kXR_authmore / kXR_auth in the bootstrap phase.

    ``auth_mode`` controls the bootstrap behaviour:
      "authmore_then_ok"  -- respond to kXR_login with kXR_authmore, then accept
                            the kXR_auth credential, then redirect.
      "authmore_no_auth"  -- respond to kXR_login with kXR_authmore only;
                            never reads a kXR_auth frame.
      "gotorls"           -- respond to kXR_protocol with kXR_gotoTLS flag set;
                            then closes without doing TLS.
    """

    def __init__(self, port: int, auth_mode: str, redirect_body: bytes = b""):
        self._mode          = auth_mode
        self._redirect_body = redirect_body
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._port = self._sock.getsockname()[1]
        self._sock.listen(5)
        self.errors = []
        self.received_token = None

        t = threading.Thread(target=self._serve, daemon=True)
        t.start()

    @property
    def port(self):
        return self._port

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            conn.settimeout(30)

            # Handshake (20 bytes in, 8+8 out)
            _recv_exact(conn, 20)
            conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
            conn.sendall(struct.pack(">II", 0x00000520, 1))

            # kXR_protocol
            hdr = _recv_exact(conn, 24)
            sid = hdr[:2]

            if self._mode == "gotorls":
                # Signal kXR_gotoTLS -- nginx must abort (upstream_tls is off)
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

            # authmore_then_ok: issue challenge, then read kXR_auth
            authmore_body = b"&P=ztn,test"
            conn.sendall(struct.pack(">2sHI", sid, kXR_authmore,
                                     len(authmore_body)))
            conn.sendall(authmore_body)

            # kXR_auth from nginx
            auth_hdr  = _recv_exact(conn, 24)
            auth_sid  = auth_hdr[:2]
            auth_op   = struct.unpack(">H", auth_hdr[2:4])[0]
            auth_dlen = struct.unpack(">I", auth_hdr[20:24])[0]
            cred_payload = b""
            if auth_dlen:
                cred_payload = _recv_exact(conn, auth_dlen)
            self.received_token = cred_payload

            if auth_op != kXR_auth:
                self.errors.append(
                    f"expected kXR_auth (3000), got {auth_op}")
                conn.close()
                return

            # Accept credential (sessid reply)
            conn.sendall(struct.pack(">2sHI", auth_sid, kXR_ok, 16))
            conn.sendall(b"\x02" * 16)

            # Read locate request, reply with redirect
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


def _start_custom_upstream_nginx(listen_port: int, upstream_port: int,
                                  conf_text: str, extra_kwargs: dict) -> dict:
    """Start an nginx instance with a custom config template."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    time.sleep(1.0)
    for attempt in range(3):
        try:
            return server_control.start_nginx_instance(
                port=listen_port,
                conf_text=conf_text,
                template_kwargs={"UPSTREAM_PORT": upstream_port,
                                 **extra_kwargs},
            )
        except RuntimeError:
            if attempt < 2:
                time.sleep(1.0)
            else:
                raise


class TestUpstreamAuth:
    """
    Phase 1 & 2 feature tests: kXR_authmore bearer-token auth and kXR_gotoTLS
    handling on the outbound upstream redirector connection.
    """

    def test_upstream_token_auth_success(self, tmp_path):
        """
        Success path: upstream issues kXR_authmore, nginx sends ztn JWT token
        from the configured token file, upstream accepts, nginx completes the
        redirect and forwards it to the client.
        """
        token_file = tmp_path / "token.jwt"
        token_content = "eyJhbGciOiJSUzI1NiJ9.test.sig"
        token_file.write_text(token_content + "\n")

        redirect_body = _make_redirect_body("storage.example.org", 1094)
        mock = MockAuthUpstream(
            UPSTREAM_AUTH_BACKEND_PORT,
            auth_mode="authmore_then_ok",
            redirect_body=redirect_body,
        )

        nginx_info = _start_custom_upstream_nginx(
            UPSTREAM_AUTH_NGINX_PORT,
            UPSTREAM_AUTH_BACKEND_PORT,
            UPSTREAM_AUTH_CONF,
            {"TOKEN_FILE": str(token_file)},
        )
        try:
            sock = _xrd_handshake_login("127.0.0.1", nginx_info["port"])
            _send_locate(sock, "/data/file.root")
            status, body = _read_response(sock)
            sock.close()
        finally:
            nginx_info["stop"]()

        assert not mock.errors, f"mock upstream error: {mock.errors}"
        assert status == kXR_redirect, \
            f"expected kXR_redirect after token auth, got {status}"
        got_port = struct.unpack(">I", body[:4])[0]
        got_host = body[4:].decode()
        assert got_port == 1094
        assert got_host == "storage.example.org"

        # Verify the correct token was forwarded (payload after "ztn\0" prefix)
        assert mock.received_token is not None, "nginx never sent kXR_auth"
        sent_token = mock.received_token[4:].decode()   # skip "ztn\0" credtype
        assert sent_token == token_content, \
            f"sent token mismatch: {sent_token!r} != {token_content!r}"

    def test_upstream_token_auth_no_file_aborts(self, tmp_path):
        """
        Security negative: upstream issues kXR_authmore but nginx has no
        xrootd_upstream_token_file configured.  The upstream connection must
        be aborted cleanly; the client receives kXR_error (not a hang).
        """
        mock = MockAuthUpstream(
            UPSTREAM_AUTH_NOFILE_BACKEND_PORT,
            auth_mode="authmore_no_auth",
        )

        nginx_info = _start_custom_upstream_nginx(
            UPSTREAM_AUTH_NOFILE_NGINX_PORT,
            UPSTREAM_AUTH_NOFILE_BACKEND_PORT,
            UPSTREAM_AUTH_NOFILE_CONF,
            {},
        )
        try:
            sock = _xrd_handshake_login("127.0.0.1", nginx_info["port"])
            _send_locate(sock, "/data/file.root")
            sock.settimeout(5)
            status, _body = _read_response(sock)
            sock.close()
        finally:
            nginx_info["stop"]()

        assert status == kXR_error, \
            f"expected kXR_error when token_file not set, got {status}"

    def test_upstream_gotorls_no_tls_configured_aborts(self, tmp_path):
        """
        Security negative: upstream signals kXR_gotoTLS in protocol response
        but nginx has xrootd_upstream_tls off (default).  Nginx must abort the
        connection -- no credentials may be sent over a cleartext channel.
        """
        mock = MockAuthUpstream(
            UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT,
            auth_mode="gotorls",
        )

        nginx_info = _start_custom_upstream_nginx(
            UPSTREAM_GOTORLS_NOTLS_NGINX_PORT,
            UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT,
            UPSTREAM_GOTORLS_NOTLS_CONF,
            {},
        )
        try:
            sock = _xrd_handshake_login("127.0.0.1", nginx_info["port"])
            _send_locate(sock, "/data/file.root")
            sock.settimeout(5)
            status, _body = _read_response(sock)
            sock.close()
        finally:
            nginx_info["stop"]()

        assert status == kXR_error, \
            f"expected kXR_error when gotoTLS but upstream_tls=off, got {status}"
