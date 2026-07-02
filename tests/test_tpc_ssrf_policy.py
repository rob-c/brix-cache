"""
tests/test_tpc_ssrf_policy.py

Tests for the xrootd_tpc_allow_local and xrootd_tpc_allow_private
SSRF-guard directives on the XRootD stream module.

The SSRF guard lives in src/tpc/outbound/connect.c: tpc_addr_is_prohibited().
These tests verify that the per-server directives control which
destination addresses are allowed for TPC pulls:

  xrootd_tpc_allow_local   on|off  — loopback + link-local (default: off)
  xrootd_tpc_allow_private on|off  — RFC-1918 ranges (default: on)

Run:
    pytest tests/test_tpc_ssrf_policy.py -v
"""

import os
import socket
import struct
import time

import pytest

from settings import (
    HOST,
    TPC_SSRF_DEFAULT_PORT,
    TPC_SSRF_ALLOW_LOCAL_PORT,
    TPC_SSRF_DENY_PRIVATE_PORT,
)

pytestmark = pytest.mark.timeout(60)

# ---------------------------------------------------------------------------
# Wire protocol constants
# ---------------------------------------------------------------------------

kXR_protocol   = 0x0bbe
kXR_login      = 0x0bbf
kXR_open       = 0x0bca   # 3018 — wait, let me check

# kXR_open = 3010 = 0x0BC2
kXR_open       = 0x0bc2
kXR_sync       = 3016
kXR_OK         = 0
kXR_error      = 4003

kXR_open_updt  = 0x0020   # open for read+write
kXR_new        = 0x0008   # create new file

# ---------------------------------------------------------------------------
# Raw socket helpers
# ---------------------------------------------------------------------------

_TIMEOUT = 20.0


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed reading %d bytes" % n)
        data += chunk
    return data


def _read_response(sock):
    header = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_session(host, port):
    """Connect, send XRootD handshake, return (sock, status)."""
    sock = socket.create_connection((host, port), timeout=_TIMEOUT)
    sock.settimeout(_TIMEOUT)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    return sock, status


def _login(sock):
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sHI8sBBBBI",
        b"\x00\x01", kXR_login,
        os.getpid() & 0xFFFFFFFF,
        username, 0, 0, 5, 0, 0,
    )
    sock.sendall(req)
    status, body = _read_response(sock)
    return status


def _sync_tpc_pull(sock, streamid, fhandle0):
    """Arm then run native TPC pull (matches src/protocols/root/write/sync.c two-step)."""
    fh = bytes([fhandle0 & 0xFF, 0, 0, 0])
    req = struct.pack("!2sH4s12sI", streamid, kXR_sync, fh, b"\x00" * 12, 0)
    sock.sendall(req)
    status_arm, _body_arm = _read_response(sock)
    if status_arm != kXR_OK:
        return status_arm, b""

    sock.sendall(req)
    return _read_response(sock)


def _open_tpc_pull(sock, dst_path, src_url, streamid=b"\x00\x02"):
    """Send kXR_open for a TPC-destination pull from src_url."""
    # Body: NUL-terminated path followed by opaque query string
    # For TPC, a key is required: tpc.key=<some_token>
    opaque = "tpc.src=%s&tpc.key=testkey&tpc.dst=root://localhost//%s" % (
        src_url, dst_path.lstrip("/"),
    )
    path_with_opaque = ("%s?%s" % (dst_path, opaque)).encode() + b"\x00"
    dlen = len(path_with_opaque)

    # ClientOpenRequest: streamid(2) requestid(2) mode(2) options(2)
    #                    optiont(2) reserved(6) fhtemplt(4) dlen(4) = 24 bytes
    header = struct.pack(
        "!2sHHHH6s4sI",
        streamid,
        kXR_open,
        0o644,                        # mode
        kXR_open_updt | kXR_new,      # options: create+write (is_write=1)
        0,                            # optiont
        b"\x00" * 6,                  # reserved
        b"\x00" * 4,                  # fhtemplt
        dlen,
    )
    sock.sendall(header + path_with_opaque)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# Module-level fixtures: one dedicated server per policy config
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def nginx_default():
    """Verify the default SSRF-policy dedicated server is reachable."""
    try:
        with socket.create_connection((HOST, TPC_SSRF_DEFAULT_PORT), timeout=5):
            pass
    except OSError:
        pytest.skip(f"TPC SSRF default server not reachable at port {TPC_SSRF_DEFAULT_PORT}")
    return {"port": TPC_SSRF_DEFAULT_PORT}


@pytest.fixture(scope="module")
def nginx_allow_local():
    """Verify the allow-local SSRF-policy dedicated server is reachable."""
    try:
        with socket.create_connection((HOST, TPC_SSRF_ALLOW_LOCAL_PORT), timeout=5):
            pass
    except OSError:
        pytest.skip(f"TPC SSRF allow-local server not reachable at port {TPC_SSRF_ALLOW_LOCAL_PORT}")
    return {"port": TPC_SSRF_ALLOW_LOCAL_PORT}


@pytest.fixture(scope="module")
def nginx_deny_private():
    """Verify the deny-private SSRF-policy dedicated server is reachable."""
    try:
        with socket.create_connection((HOST, TPC_SSRF_DENY_PRIVATE_PORT), timeout=5):
            pass
    except OSError:
        pytest.skip(f"TPC SSRF deny-private server not reachable at port {TPC_SSRF_DENY_PRIVATE_PORT}")
    return {"port": TPC_SSRF_DENY_PRIVATE_PORT}


# ---------------------------------------------------------------------------
# Helper: connect + login + open TPC pull, return (status, body, err_text)
# ---------------------------------------------------------------------------

def _tpc_attempt(port, src_url, dst_filename="/tpc_dst_test.dat"):
    sock, hs_status = _raw_session(HOST, port)
    assert hs_status == kXR_OK, "handshake failed: %d" % hs_status
    login_status = _login(sock)
    assert login_status == kXR_OK, "login failed: %d" % login_status
    status, body = _open_tpc_pull(sock, dst_filename, src_url)
    err_text = ""
    if status == kXR_OK and len(body) >= 1:
        fh0 = body[0]
        status, body = _sync_tpc_pull(sock, b"\x00\x02", fh0)
    sock.close()
    if len(body) >= 4:
        err_text = body[4:].rstrip(b"\x00").decode("utf-8", errors="replace")
    return status, err_text


# ---------------------------------------------------------------------------
# Tests: default policy (loopback blocked, private allowed)
# ---------------------------------------------------------------------------

class TestSSRFDefaultPolicy:
    """Default: tpc_allow_local=off, tpc_allow_private=on."""

    def test_loopback_ipv4_rejected(self, nginx_default):
        port = nginx_default["port"]
        status, err = _tpc_attempt(port, "root://127.0.0.1//test.txt")
        assert status == kXR_error, "expected kXR_error, got %d" % status
        assert "prohibited" in err, "error should mention 'prohibited': %r" % err

    def test_loopback_localhost_name_rejected(self, nginx_default):
        # 'localhost' resolves to 127.0.0.1 (or ::1) — both are blocked by default
        port = nginx_default["port"]
        status, err = _tpc_attempt(port, "root://localhost//test.txt")
        assert status == kXR_error, "expected kXR_error, got %d" % status
        assert "prohibited" in err or "refused" in err, (
            "expected SSRF or connection-refused: %r" % err
        )

    def test_link_local_ipv4_rejected(self, nginx_default):
        port = nginx_default["port"]
        # 169.254.0.1 is link-local — blocked by default
        status, err = _tpc_attempt(port, "root://169.254.0.1//test.txt")
        assert status == kXR_error, "expected kXR_error, got %d" % status
        assert "prohibited" in err, "expected prohibited: %r" % err

    def test_rfc1918_10_allowed_by_default(self, nginx_default):
        # 10.x.x.x is RFC-1918 private — allowed by default
        # Since there's no actual server, we expect connection error (not SSRF rejection)
        port = nginx_default["port"]
        status, err = _tpc_attempt(port, "root://10.255.255.1//test.txt")
        assert status == kXR_error, "expected kXR_error, got %d" % status
        # The error should NOT be a prohibited-address rejection
        assert "prohibited" not in err, (
            "RFC-1918 10/8 should be allowed by default, got: %r" % err
        )

    def test_rfc1918_192168_allowed_by_default(self, nginx_default):
        port = nginx_default["port"]
        status, err = _tpc_attempt(port, "root://192.168.255.1//test.txt")
        assert status == kXR_error
        assert "prohibited" not in err, "192.168/16 should be allowed: %r" % err

    def test_rfc1918_172_allowed_by_default(self, nginx_default):
        port = nginx_default["port"]
        status, err = _tpc_attempt(port, "root://172.31.0.1//test.txt")
        assert status == kXR_error
        assert "prohibited" not in err, "172.16/12 should be allowed: %r" % err


# ---------------------------------------------------------------------------
# Tests: xrootd_tpc_allow_local on
# ---------------------------------------------------------------------------

class TestSSRFAllowLocalPolicy:
    """With tpc_allow_local on, loopback is no longer SSRF-blocked."""

    def test_loopback_not_ssrf_blocked_when_allow_local(self, nginx_allow_local):
        port = nginx_allow_local["port"]
        status, err = _tpc_attempt(port, "root://127.0.0.1//test.txt")
        assert status == kXR_error, "expected some error, got %d" % status
        # The error should be a connection failure, NOT a SSRF rejection
        assert "prohibited" not in err, (
            "loopback should not be prohibited with allow_local on: %r" % err
        )

    def test_link_local_not_ssrf_blocked_when_allow_local(self, nginx_allow_local):
        port = nginx_allow_local["port"]
        status, err = _tpc_attempt(port, "root://169.254.1.1//test.txt")
        assert status == kXR_error
        assert "prohibited" not in err, "link-local should pass SSRF with allow_local: %r" % err

    def test_private_still_allowed(self, nginx_allow_local):
        port = nginx_allow_local["port"]
        status, err = _tpc_attempt(port, "root://10.0.0.1//test.txt")
        assert status == kXR_error
        assert "prohibited" not in err, "RFC-1918 should still be allowed: %r" % err


# ---------------------------------------------------------------------------
# Tests: xrootd_tpc_allow_private off
# ---------------------------------------------------------------------------

class TestSSRFDenyPrivatePolicy:
    """With tpc_allow_private off, RFC-1918 addresses are blocked."""

    def test_rfc1918_10_rejected(self, nginx_deny_private):
        port = nginx_deny_private["port"]
        status, err = _tpc_attempt(port, "root://10.0.0.1//test.txt")
        assert status == kXR_error
        assert "prohibited" in err, "10/8 should be prohibited with allow_private off: %r" % err

    def test_rfc1918_192168_rejected(self, nginx_deny_private):
        port = nginx_deny_private["port"]
        status, err = _tpc_attempt(port, "root://192.168.1.1//test.txt")
        assert status == kXR_error
        assert "prohibited" in err, "192.168/16 should be prohibited: %r" % err

    def test_rfc1918_172_rejected(self, nginx_deny_private):
        port = nginx_deny_private["port"]
        status, err = _tpc_attempt(port, "root://172.16.0.1//test.txt")
        assert status == kXR_error
        assert "prohibited" in err, "172.16/12 should be prohibited: %r" % err

    def test_loopback_still_rejected(self, nginx_deny_private):
        # loopback is governed by allow_local (off by default), not allow_private
        port = nginx_deny_private["port"]
        status, err = _tpc_attempt(port, "root://127.0.0.1//test.txt")
        assert status == kXR_error
        assert "prohibited" in err, "loopback should still be prohibited: %r" % err

    def test_public_ip_not_ssrf_blocked(self, nginx_deny_private):
        # A non-private, non-loopback address: should NOT be SSRF-rejected
        # (will fail with DNS/connect error, but not "prohibited")
        port = nginx_deny_private["port"]
        status, err = _tpc_attempt(port, "root://203.0.113.1//test.txt")
        assert status == kXR_error
        assert "prohibited" not in err, (
            "public address should not be SSRF-blocked: %r" % err
        )
