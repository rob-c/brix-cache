"""
Tests for upstream XRootD redirector support (kXR_redirect, kXR_wait,
kXR_waitresp, kXR_authmore / kXR_gotoTLS).

Architecture
------------
All tests connect to pre-started nginx instances that proxy to protocol stub
backends started by manage_test_servers.sh via upstream_protocol_stubs.py.
No Python server objects are created inside tests.

  test_locate_redirected         nginx:11137 → cluster-redir:11160 (real XRootD)
  test_upstream_error_forwarded  nginx:11123 → upstream-error xrootd:12123
  test_locate_wait_then_redirect      nginx:11131 → stub:13121 (wait→redirect)
  test_locate_waitresp_then_redirect  nginx:11132 → stub:13122 (waitresp→redirect)
  TestUpstreamAuth.*                  nginx:11134–11136 → stubs:13124–13126
"""

import os
import socket
import struct
import time

import pytest

from settings import (
    HOST,
    CLUSTER_DS_PORT,
    REAL_REDIRECT_NGINX_PORT,
    STUB_AUTH_NGINX_PORT,
    STUB_AUTH_NOFILE_NGINX_PORT,
    STUB_GOTORLS_NGINX_PORT,
    STUB_WAIT_NGINX_PORT,
    STUB_WAITRESP_NGINX_PORT,
    TOKENS_DIR,
    TMP_DIR,
    UPSTREAM_ERROR_NGINX_PORT,
)

pytestmark = pytest.mark.timeout(60)

# Stub daemon writes received auth credentials here so tests can verify
# nginx forwarded the right token from its brix_upstream_token_file.
_RECEIVED_CRED_PATH = os.path.join(TMP_DIR, "received-auth-cred.bin")

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


# ------------------------------------------------------------------ #
# Fixtures — readiness checks on pre-started nginx instances           #
# ------------------------------------------------------------------ #

def _require_nginx(port: int, label: str) -> dict:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=1):
                return {"port": port}
        except OSError:
            time.sleep(0.1)
    pytest.skip(f"{label} nginx not running on port {port}")


@pytest.fixture(scope="session")
def real_redirect_nginx():
    return _require_nginx(REAL_REDIRECT_NGINX_PORT, "real-upstream-redirect")


@pytest.fixture(scope="session")
def upstream_wait_nginx():
    return _require_nginx(STUB_WAIT_NGINX_PORT, "upstream-wait")


@pytest.fixture(scope="session")
def upstream_waitresp_nginx():
    return _require_nginx(STUB_WAITRESP_NGINX_PORT, "upstream-waitresp")


@pytest.fixture(scope="session")
def upstream_error_nginx():
    return _require_nginx(UPSTREAM_ERROR_NGINX_PORT, "upstream-error")


@pytest.fixture(scope="session")
def upstream_auth_nginx():
    return _require_nginx(STUB_AUTH_NGINX_PORT, "upstream-auth")


@pytest.fixture(scope="session")
def upstream_auth_nofile_nginx():
    return _require_nginx(STUB_AUTH_NOFILE_NGINX_PORT, "upstream-auth-nofile")


@pytest.fixture(scope="session")
def upstream_gotorls_nginx():
    return _require_nginx(STUB_GOTORLS_NGINX_PORT, "upstream-gotorls")


# ------------------------------------------------------------------ #
# Tests — upstream response forwarding                                 #
# ------------------------------------------------------------------ #

class TestUpstreamRedirect:
    """nginx correctly forwards kXR_redirect / kXR_wait / kXR_waitresp /
    kXR_error responses from an upstream XRootD redirector to the client."""

    @pytest.mark.registry_servers("cluster-ds", "real-upstream-redirect")
    def test_locate_redirected(self, real_redirect_nginx):
        """Upstream cluster-redir returns kXR_redirect → client receives it.

        The real-upstream-redirect nginx at REAL_REDIRECT_NGINX_PORT proxies to
        the pre-started cluster-redir (CLUSTER_REDIR_PORT).  The cluster-redir
        has the cluster-ds registered for "/".

        manager_mode locate returns kXR_redirect to the best registered DS.

        Retry with backoff: under parallel test load, cluster-ds may not have
        finished its CMS registration when this test fires.  The redirector
        returns kXR_error (no servers available) until at least one DS is
        registered; retrying for up to 20 s covers normal startup variance.
        """
        deadline = time.monotonic() + 20.0
        status, body = None, b""
        while time.monotonic() < deadline:
            sock = _xrd_handshake_login(HOST, real_redirect_nginx["port"])
            _send_locate(sock, "/data/file.root")
            status, body = _read_response(sock)
            sock.close()
            if status == kXR_redirect:
                break
            time.sleep(0.3)

        assert status == kXR_redirect, \
            f"expected kXR_redirect from manager_mode, got {status:#x}"
        redir_port = struct.unpack(">I", body[:4])[0]
        assert redir_port == CLUSTER_DS_PORT, \
            f"expected redirect to port {CLUSTER_DS_PORT}, got {redir_port}"

    @pytest.mark.registry_server("stub-upstream-wait")
    def test_locate_wait_then_redirect(self, upstream_wait_nginx):
        """Upstream returns kXR_wait(1) then kXR_redirect on the same
        connection; nginx keeps the upstream read event armed during the wait
        so it picks up the redirect without the client retrying."""
        sock = _xrd_handshake_login(HOST, upstream_wait_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(15)
        status, body = _read_response(sock)
        sock.close()

        assert status == kXR_redirect, \
            f"expected kXR_redirect after kXR_wait, got {status}"
        assert struct.unpack(">I", body[:4])[0] == 2094
        assert body[4:].decode() == "retry.example.org"

    @pytest.mark.registry_server("stub-upstream-waitresp")
    def test_locate_waitresp_then_redirect(self, upstream_waitresp_nginx):
        """Upstream returns kXR_waitresp (async hold) then kXR_redirect;
        client receives both frames in order."""
        sock = _xrd_handshake_login(HOST, upstream_waitresp_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(5)
        status1, _    = _read_response(sock)
        status2, body = _read_response(sock)
        sock.close()

        assert status1 == kXR_waitresp, \
            f"expected kXR_waitresp first, got {status1}"
        assert status2 == kXR_redirect, \
            f"expected kXR_redirect second, got {status2}"
        assert struct.unpack(">I", body[:4])[0] == 3094
        assert body[4:].decode() == "async.example.org"

    @pytest.mark.registry_server("upstream-error")
    def test_upstream_error_forwarded(self, upstream_error_nginx):
        """Upstream kXR_error is forwarded to the client.

        The upstream-error nginx at UPSTREAM_ERROR_NGINX_PORT proxies to a real
        anonymous xrootd.  Requesting a non-existent path causes the xrootd to
        return kXR_error, which nginx must forward to the client.
        """
        sock = _xrd_handshake_login(HOST, upstream_error_nginx["port"])
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

    @pytest.mark.registry_server("stub-upstream-auth")
    def test_upstream_token_auth_success(self, upstream_auth_nginx):
        """Upstream issues kXR_authmore; nginx sends the ztn JWT from
        brix_upstream_token_file; upstream accepts; redirect forwarded."""
        token_content = "eyJhbGciOiJSUzI1NiJ9.test.sig"
        token_path = os.path.join(TOKENS_DIR, "stub_auth.jwt")
        os.makedirs(TOKENS_DIR, exist_ok=True)
        with open(token_path, "w") as fh:
            fh.write(token_content + "\n")

        # Remove stale credential record from a previous run.
        try:
            os.unlink(_RECEIVED_CRED_PATH)
        except FileNotFoundError:
            pass

        sock = _xrd_handshake_login(HOST, upstream_auth_nginx["port"])
        _send_locate(sock, "/data/file.root")
        status, body = _read_response(sock)
        sock.close()

        assert status == kXR_redirect, \
            f"expected kXR_redirect after token auth, got {status}"
        assert struct.unpack(">I", body[:4])[0] == 1094
        assert body[4:].decode() == "storage.example.org"

        # Verify nginx forwarded the token written above.  The stub daemon
        # wrote the raw kXR_auth credential payload to _RECEIVED_CRED_PATH.
        # The payload is "ztn\0<jwt>"; skip the 4-byte credential-type prefix.
        assert os.path.exists(_RECEIVED_CRED_PATH), \
            "stub never wrote received-auth-cred — nginx never sent kXR_auth"
        with open(_RECEIVED_CRED_PATH, "rb") as fh:
            cred = fh.read()
        sent_token = cred[4:].decode()
        assert sent_token == token_content, \
            f"sent token mismatch: {sent_token!r} != {token_content!r}"

    @pytest.mark.registry_server("stub-upstream-auth-nofile")
    def test_upstream_token_auth_no_file_aborts(self, upstream_auth_nofile_nginx):
        """Upstream issues kXR_authmore but nginx has no token file
        configured; nginx must abort and return kXR_error to the client."""
        sock = _xrd_handshake_login(HOST, upstream_auth_nofile_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(5)
        status, _ = _read_response(sock)
        sock.close()

        assert status == kXR_error, \
            f"expected kXR_error when token_file not set, got {status}"

    @pytest.mark.registry_server("stub-upstream-gotorls")
    def test_upstream_gotorls_no_tls_configured_aborts(self, upstream_gotorls_nginx):
        """Upstream signals kXR_gotoTLS but nginx has brix_upstream_tls off;
        nginx must abort — no credentials may travel over a cleartext channel."""
        sock = _xrd_handshake_login(HOST, upstream_gotorls_nginx["port"])
        _send_locate(sock, "/data/file.root")
        sock.settimeout(5)
        status, _ = _read_response(sock)
        sock.close()

        assert status == kXR_error, \
            f"expected kXR_error when gotoTLS but upstream_tls=off, got {status}"
