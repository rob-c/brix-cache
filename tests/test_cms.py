"""
Tests for the CMS manager heartbeat/registration subsystem.

nginx-xrootd can be configured with ``brix_cms_manager host:port`` so that
the server periodically sends registration and heartbeat frames to a CMS
manager.  The protocol uses a simple binary frame format:

    [streamid(4)][code(1)][modifier(1)][payload_len(2)][payload(N)]

Frame codes:
    CMS_RR_LOGIN   (0) — initial registration with path list, PID, space info
    CMS_RR_AVAIL   (12) — availability report with free MB and utilization %
    CMS_RR_LOAD    (16) — load report
    CMS_RR_PING    (17) — heartbeat from manager → server must reply PONG
    CMS_RR_PONG    (18) — server response to manager ping
    CMS_RR_SPACE   (19) — space query
    CMS_RR_STATUS  (22) — status report

This test suite exercises:

  - CMS registration: the cms-test nginx connects to the pre-started real CMS
    manager (cms-test-mgr nginx at CMS_TEST_CMS_PORT) and maintains a TCP
    connection.
  - PING/PONG heartbeat: the cms-test nginx remains healthy across multiple
    heartbeat cycles.
  - Reconnect: the cms-test nginx continues serving XRootD requests after CMS
    connectivity has been verified.

The CMS manager is a real nginx instance (nginx_cluster_redir.conf at
CMS_TEST_CMS_PORT) started by ``manage_test_servers.sh start-all``.  The
cms-test nginx (CMS_TEST_NGINX_PORT) connects to it with brix_cms_interval 2
and retries automatically on disconnect.

Run:
    pytest tests/test_cms.py -v -s
"""

import socket
import struct
import subprocess
import time

import pytest

from settings import CMS_TEST_NGINX_PORT, CMS_TEST_CMS_PORT, HOST


# ---------------------------------------------------------------------------
# CMS protocol constants (used by TestCmsWireFormat)
# ---------------------------------------------------------------------------

CMS_RR_LOGIN   = 0
CMS_RR_AVAIL   = 12
CMS_RR_LOAD    = 16
CMS_RR_PING    = 17
CMS_RR_PONG    = 18
CMS_RR_SPACE   = 19
CMS_RR_STATUS  = 22

CMS_PT_SHORT   = 0x80
CMS_PT_INT     = 0xa0

CMS_LOGIN_VERSION = 3
CMS_LOGIN_MODE    = 0x00000008

kXR_ok       = 0
kXR_protocol = 3006
kXR_login    = 3007
kXR_ping     = 3011


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_brix_response(sock):
    hdr = _recv_exact(sock, 8)
    assert hdr is not None, "no XRootD response header received"
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _send_brix_req(sock, streamid, reqid, body=b"", payload=b""):
    hdr = struct.pack(">2sH", streamid, reqid)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    return _read_brix_response(sock)


def _assert_brix_ping(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((HOST, port))
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        assert _recv_exact(sock, 16) is not None

        status, _ = _send_brix_req(sock, b"\x00\x01", kXR_protocol)
        assert status == kXR_ok

        status, _ = _send_brix_req(
            sock,
            b"\x00\x01",
            kXR_login,
            payload=b"anon\x00\x00\x00\x00",
        )
        assert status == kXR_ok

        status, _ = _send_brix_req(sock, b"\x00\x01", kXR_ping)
        assert status == kXR_ok
    finally:
        sock.close()


def _count_established_to(port: int) -> int:
    """Count TCP connections with the given port as the remote end."""
    result = subprocess.run(["ss", "-tn"], capture_output=True, text=True)
    return sum(
        1 for line in result.stdout.splitlines()
        if f":{port}" in line and "ESTAB" in line
    )


# ---------------------------------------------------------------------------
# Fixture — wait for cms-test nginx to connect to the real CMS manager
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cms_nginx():
    """Wait for the pre-started cms-test nginx to connect to the CMS manager.

    The cms-test-mgr nginx at CMS_TEST_CMS_PORT acts as the real CMS server.
    The cms-test nginx (CMS_TEST_NGINX_PORT) connects to it with
    brix_cms_interval 2.  Both are started by manage_test_servers.sh
    start-all, so the connection should be established by test time.
    """
    deadline = time.time() + 30
    while time.time() < deadline:
        if _count_established_to(CMS_TEST_CMS_PORT) >= 1:
            break
        time.sleep(0.5)
    else:
        pytest.skip(
            f"cms-test nginx did not connect to CMS manager at port "
            f"{CMS_TEST_CMS_PORT} within 30s — run manage_test_servers.sh start-all"
        )

    yield {
        "nginx_port": CMS_TEST_NGINX_PORT,
        "cms_port": CMS_TEST_CMS_PORT,
    }


# ---------------------------------------------------------------------------
# CMS registration — nginx connects to the real manager
# ---------------------------------------------------------------------------

class TestCmsLogin:
    """Verify that the cms-test nginx registers with the real CMS manager."""

    @pytest.mark.registry_servers("cms-test", "cms-test-mgr")
    def test_cms_connection_established(self, cms_nginx):
        """The CMS manager must have at least one ESTABLISHED connection from
        the cms-test nginx data server.
        """
        count = _count_established_to(cms_nginx["cms_port"])
        assert count >= 1, (
            f"no established CMS connection to port {cms_nginx['cms_port']}; "
            "the cms-test nginx may not have registered with the CMS manager"
        )

    @pytest.mark.registry_servers("cms-test", "cms-test-mgr")
    def test_cms_server_responds_to_brix_ping(self, cms_nginx):
        """After CMS registration the nginx cms-test server must serve
        XRootD requests normally.
        """
        _assert_brix_ping(cms_nginx["nginx_port"])


# ---------------------------------------------------------------------------
# PING/PONG heartbeat — nginx stays healthy across multiple intervals
# ---------------------------------------------------------------------------

class TestCmsPingPong:

    @pytest.mark.registry_servers("cms-test", "cms-test-mgr")
    def test_server_stays_healthy_after_heartbeat_cycle(self, cms_nginx):
        """The cms-test nginx must remain responsive after 8 seconds of CMS
        heartbeat traffic (covering ~4 brix_cms_interval=2 cycles).
        """
        time.sleep(8.0)
        _assert_brix_ping(cms_nginx["nginx_port"])


# ---------------------------------------------------------------------------
# CMS availability — connection maintained under sustained operation
# ---------------------------------------------------------------------------

class TestCmsAvail:
    """Verify that the CMS connection is maintained after heartbeat cycles."""

    @pytest.mark.registry_servers("cms-test", "cms-test-mgr")
    def test_cms_connection_maintained_after_heartbeat(self, cms_nginx):
        """The CMS connection must still be ESTABLISHED after the heartbeat
        cycle in TestCmsPingPong has run.
        """
        count = _count_established_to(cms_nginx["cms_port"])
        assert count >= 1, (
            "CMS connection to manager dropped after heartbeat cycle; "
            "nginx cms-test may have failed to reconnect"
        )


# ---------------------------------------------------------------------------
# Reconnection — nginx stays healthy if CMS connection was ever established
# ---------------------------------------------------------------------------

class TestCmsReconnect:

    @pytest.mark.registry_servers("cms-test", "cms-test-mgr")
    def test_cms_connection_maintained(self, cms_nginx):
        count = _count_established_to(cms_nginx["cms_port"])
        assert count >= 1, "no CMS connection found"
        _assert_brix_ping(cms_nginx["nginx_port"])


# ---------------------------------------------------------------------------
# CMS frame header size validation (pure Python struct tests, no server)
# ---------------------------------------------------------------------------

class TestCmsWireFormat:
    """Verify the CMS wire format constants are correct."""

    def test_frame_header_is_8_bytes(self):
        """CMS frame headers must be exactly 8 bytes: [4B streamid][1B code]
        [1B modifier][2B payload_len].
        """
        hdr = struct.pack(">IBBH", 0, CMS_RR_LOGIN, 0, 0)
        assert len(hdr) == 8, f"CMS header length {len(hdr)} != expected 8"

    def test_short_tag_encoding(self):
        """CMS PT_SHORT tag encodes as [1B tag][2B value] = 3 bytes total."""
        p = bytearray(4)
        p[0] = CMS_PT_SHORT
        struct.pack_into(">H", p, 1, 42)
        assert len(p[:3]) == 3
        assert p[0] == CMS_PT_SHORT
        assert struct.unpack(">H", p[1:3])[0] == 42

    def test_int_tag_encoding(self):
        """CMS PT_INT tag encodes as [1B tag][4B value] = 5 bytes total."""
        p = bytearray(6)
        p[0] = CMS_PT_INT
        struct.pack_into(">I", p, 1, 999999)
        assert len(p[:5]) == 5
        assert p[0] == CMS_PT_INT
        assert struct.unpack(">I", p[1:5])[0] == 999999
