"""
test_audit15b_substreams_tls.py — the substreams × TLS pair (audit §B1.3,
testsuite-combinatorial-coverage-audit 2026-08-15: "a bound data path arriving
on a TLS listener ... should work for free — no test proves it").

src/protocols/root/session/bind.c contains no TLS handling because the in-band
upgrade completes at the connection edge, before any request dispatch — so a
secondary connection that upgrades to TLS and then sends kXR_bind should behave
exactly like the cleartext bind suite (test_session_bind.py).  This file proves
that on a `brix_tls on` server:

  * a TLS secondary binds to a TLS primary's session and reads the primary's
    handle byte-exact (the xrdcp -S N data-channel shape, now over TLS)
  * a bound TLS secondary still cannot open files of its own (the bound-stream
    privilege reduction survives the transport change)
  * the TLS primary keeps serving after its secondary disconnects (no
    cross-connection teardown leak through the TLS record layer)

Write/pgwrite over a bound path is not driven here: BriX refuses substream
writes by design (test_bind_substreams.py), so there is no TLS twin to test.
"""

import os
import socket
import ssl
import struct

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, SERVER_CERT, SERVER_KEY

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15b-subs-tls")]

kXR_close = 3003
kXR_open  = 3010
kXR_read  = 3013
kXR_bind  = 3024
kXR_login = 3007

KXR_OK    = 0
KXR_ERROR = 4003

SEED = bytes(range(256)) * 8   # 2 KiB, non-trivial pattern


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def _send_req(s, streamid, reqid, body=b"", payload=b""):
    hdr = streamid[:2] + struct.pack(">H", reqid)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    s.sendall(hdr + payload)
    rsp_hdr = _recv_exact(s, 8)
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen = struct.unpack(">I", rsp_hdr[4:8])[0]
    return status, (_recv_exact(s, dlen) if dlen else b"")


def _tls_connection(port):
    """Handshake + kXR_protocol(ableTLS) in cleartext, then the in-band
    upgrade: the server now expects a ClientHello, which we complete."""
    raw = socket.create_connection((HOST, port), timeout=10)
    raw.settimeout(10)
    raw.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(raw, 16)
    raw.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006,
                            0x00000520, 0x02, 0x03, 0))
    hdr = _recv_exact(raw, 8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        _recv_exact(raw, dlen)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=HOST)


def _tls_primary(port):
    """TLS connection + anonymous login; returns (sock, sessid)."""
    s = _tls_connection(port)
    status, body = _send_req(s, b"\x00\x01", kXR_login,
                             payload=b"anonymous\x00")
    assert status == KXR_OK, (status, body)
    assert len(body) >= 16, body
    return s, body[:16]


def _tls_bound_secondary(port, sessid, streamid=b"\x00\x03"):
    """TLS connection (no login) bound to the primary's session."""
    s = _tls_connection(port)
    status, pathid = _send_req(s, streamid, kXR_bind, body=sessid)
    assert status == KXR_OK, f"bind over TLS refused: {status} {pathid}"
    assert len(pathid) == 1 and 1 <= pathid[0] <= 253, pathid
    return s


def _open_read(s, streamid, path):
    body = struct.pack(">HH12s", 0o644, 0x0010, b"\x00" * 12)
    return _send_req(s, streamid, kXR_open, body=body,
                     payload=path.encode() + b"\x00")


def _read(s, streamid, fhandle, length, offset=0):
    body = fhandle + struct.pack(">q", offset) + struct.pack(">i", length)
    return _send_req(s, streamid, kXR_read, body=body)


@pytest.fixture()
def tls_port(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    data = tmp_path / "data"
    data.mkdir()
    (data / "bound.bin").write_bytes(SEED)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15b-subs-tls",
        template="nginx_resilience_tls_anon.conf",
        data_root=str(data),
        template_values={"SERVER_CERT": SERVER_CERT,
                         "SERVER_KEY": SERVER_KEY},
        reason="audit-15b substreams x TLS pair"))
    return ep.port


def test_bound_tls_secondary_reads_primary_handle(tls_port):
    primary, sessid = _tls_primary(tls_port)
    try:
        status, body = _open_read(primary, b"\x00\x01", "/bound.bin")
        assert status == KXR_OK, (status, body)
        fhandle = body[:4]

        secondary = _tls_bound_secondary(tls_port, sessid)
        try:
            status, data = _read(secondary, b"\x00\x03", fhandle, len(SEED))
            assert status == KXR_OK, status
            assert data == SEED, "bound TLS read is not byte-exact"
        finally:
            secondary.close()
    finally:
        primary.close()


def test_bound_tls_secondary_cannot_open(tls_port):
    # Security-negative: the transport change must not widen a bound stream's
    # privileges — it stays a data channel, not an independent session.
    primary, sessid = _tls_primary(tls_port)
    try:
        secondary = _tls_bound_secondary(tls_port, sessid, b"\x00\x04")
        try:
            status, _ = _open_read(secondary, b"\x00\x04", "/bound.bin")
            assert status == KXR_ERROR, \
                f"bound TLS secondary opened a file on its own: {status}"
        finally:
            secondary.close()
    finally:
        primary.close()


def test_primary_survives_secondary_disconnect(tls_port):
    primary, sessid = _tls_primary(tls_port)
    try:
        status, body = _open_read(primary, b"\x00\x01", "/bound.bin")
        assert status == KXR_OK, (status, body)
        fhandle = body[:4]

        secondary = _tls_bound_secondary(tls_port, sessid)
        status, data = _read(secondary, b"\x00\x03", fhandle, 64)
        assert status == KXR_OK and data == SEED[:64]
        secondary.close()

        # The primary's session and handle must survive the bound teardown.
        status, data = _read(primary, b"\x00\x01", fhandle, 64, offset=64)
        assert status == KXR_OK and data == SEED[64:128], (status, data)
    finally:
        primary.close()
