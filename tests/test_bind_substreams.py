"""
brix_data_substreams knob — kXR_bind acceptance/refusal.

BriX accepts kXR_bind by default (secondary connections for parallel data), which
a bound reader uses.  A deployment fronting a client that streams WRITE payloads
on a substream (BriX has no cross-connection write data-path yet) sets
`brix_data_substreams off`; BriX then refuses bind with kXR_Unsupported so the
client falls back to sending everything inline on the primary (pathid 0) — the
now-streaming inline write path.

These raw-socket tests target a substreams-OFF server (BRIX_SUBSTREAMS_OFF_PORT):

  * success (refusal) — kXR_bind is answered with kXR_error/kXR_Unsupported
  * framing           — the connection survives the refusal (a following ping ok)
  * negative          — a primary kXR_write tagged with a non-zero pathid is
                        refused WITHOUT desyncing (a following ping still answers)

The default (substreams on) acceptance path is exercised by test_session_bind.py.
"""

import os
import socket
import struct

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, SERVER_HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("bind-substreams-off")]

kXR_login    = 3007
kXR_ping     = 3011
kXR_write    = 3019
kXR_bind     = 3024

kXR_ok          = 0
kXR_error       = 4003
kXR_Unsupported = 3013


def _recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data.extend(chunk)
    return bytes(data)


def _resp(sock):
    sid, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    body = _recv_exact(sock, dlen) if dlen else b""
    return sid, status, body


def _session(port):
    s = socket.create_connection((SERVER_HOST, port), timeout=10)
    s.settimeout(10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "handshake"
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00",
                          0, 0, 5, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "login"
    return s


def _bind(sock, sessid=b"\x00" * 16, streamid=b"\x00\x03"):
    # ClientBindRequest: streamid[2] reqid sessid[16] dlen
    sock.sendall(struct.pack("!2sH16sI", streamid, kXR_bind, sessid, 0))
    return _resp(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    sock.sendall(struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0))
    return _resp(sock)


@pytest.fixture(scope="module")
def substreams_off_port():
    harness = LifecycleHarness()
    try:
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-bind-substreams-off",
            template="nginx_bind_substreams_off.conf",
            protocol="root",
            template_values={"BIND_HOST": BIND_HOST},
            reason="kXR_bind refusal when data substreams are disabled",
        ))
        yield endpoint.port
    finally:
        harness.close()


@pytest.mark.requires_local_server
class TestBindSubstreamsOff:

    def test_bind_refused_when_substreams_off(self, substreams_off_port):
        """success: kXR_bind is refused with kXR_error/kXR_Unsupported."""
        s = _session(substreams_off_port)
        try:
            _, st, body = _bind(s)
            assert st == kXR_error, f"bind must be refused, got status={st}"
            code = struct.unpack("!i", body[:4])[0] if len(body) >= 4 else -1
            assert code == kXR_Unsupported, (
                f"refusal code must be kXR_Unsupported, got {code}")
        finally:
            s.close()

    def test_connection_survives_bind_refusal(self, substreams_off_port):
        """framing: a following request is answered normally after the refusal."""
        s = _session(substreams_off_port)
        try:
            _, st, _ = _bind(s)
            assert st == kXR_error
            _, st, _ = _ping(s)
            assert st == kXR_ok, f"connection desynced after refusal (ping={st})"
        finally:
            s.close()

    def test_pathid_tagged_write_refused_without_desync(self, substreams_off_port):
        """negative: a kXR_write with a non-zero pathid (data would be on a
        secondary) is refused with no payload read, so framing stays intact."""
        s = _session(substreams_off_port)
        try:
            # kXR_write body: fhandle[4] offset(i64) pathid(1) reserved[3]; set
            # pathid=7 and dlen=8192, but send NO payload (as a real client does
            # for a data-path write — the data would travel on the substream).
            fhandle = b"\x00\x00\x00\x00"
            req = struct.pack("!2sH4sqB3sI", b"\x00\x09", kXR_write, fhandle,
                              0, 7, b"\x00\x00\x00", 8192)
            s.sendall(req)  # header only — no 8192 payload bytes
            _, st, body = _resp(s)
            assert st == kXR_error, f"pathid write must be refused, got {st}"

            # No payload was consumed, so the next request is framed correctly.
            _, st, _ = _ping(s)
            assert st == kXR_ok, (
                f"connection desynced after pathid-write refusal (ping={st})")
        finally:
            s.close()
