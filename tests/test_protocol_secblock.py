"""
kXR_protocol security-requirements block (ServerResponseReqs_Protocol) tests.

Regression coverage for the wire-layout fix in
src/protocols/root/session/protocol.c: when a client sets kXR_secreqs, the
6-byte ServerResponseReqs_Protocol ('S') block must sit IMMEDIATELY after the
8-byte ServerProtocolBody — the wire layout is

    ServerResponseBody_Protocol = { pval(4), flags(4), secreq(6) }

with nothing in between.  A previous implementation prepended a 4-byte
"SecurityInfo header" plus N*8 binary auth-protocol entries, shifting the 'S'
tag downfield; strict clients (go-hep, XrdRust) then misread the block (XrdRust
saw tag 0x00 at offset 8; go-hep read the 'S' char as an enormous seclvl and
demanded signing on every request).  These tests pin the conformant layout.

Uses raw sockets — no PyXRootD dependency.  Target is the plain anonymous data
server (auth=none, security_level defaults to 0).

Three cases, per the coding standard (success + error/regression + security-neg):
  * success        — secreqs requested -> exactly one 6-byte 'S' block at off 8
  * regression     — 'S' tag is at byte 8 (guards the old shifted layout) and
                     seclvl is 0 under no-auth (no spurious signing demand)
  * security-neg   — secreqs NOT requested -> no trailer leaks (body == 8)
"""

import socket
import struct

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST

# ClientProtocolRequest.flags bits (XProtocol.hh RequestFlags)
_kXR_secreqs = 0x01
_kXR_ableTLS = 0x02

# ServerProtocolBody is pval(4) + flags(4)
_PROTO_BODY_LEN = 8
# ServerResponseReqs_Protocol: theTag, rsvd, secver, secopt, seclvl, secvsz
_SECREQ_LEN = 6


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _protocol_exchange(host: str, port: int, flags: int):
    """Do the handshake + one kXR_protocol request with `flags`; return body."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        # XRootD initial handshake (20 bytes) + 16-byte server handshake reply.
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        # kXR_protocol (3006): streamid[2], requestid, clientpv, flags, expect,
        # reserved[10], dlen. clientpv 0x520 mirrors the other wire tests.
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, flags, 0x03, 0))
        _recv_exact(sock, 16)
        # kXR_protocol response: 8-byte response header + body.
        hdr = _recv_exact(sock, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen = struct.unpack(">I", hdr[4:8])[0]
        body = _recv_exact(sock, dlen) if dlen else b""
        assert status == 0, f"kXR_protocol returned status {status:#06x}"
        return body
    finally:
        sock.close()


@pytest.mark.requires_local_server
class TestProtocolSecBlock:
    """The kXR_protocol secreq block must match the wire layout exactly."""

    def test_secblock_present_and_sized_when_requested(self):
        """success: secreqs -> body is exactly 8-byte body + 6-byte 'S' block."""
        body = _protocol_exchange(SERVER_HOST, NGINX_ANON_PORT,
                                  _kXR_secreqs | _kXR_ableTLS)
        assert len(body) == _PROTO_BODY_LEN + _SECREQ_LEN, (
            "secreq body must be body(8)+secreq(6)=14 with no SecurityInfo "
            f"header or binary auth entries; got {len(body)} bytes"
        )

    def test_secblock_tag_at_offset_eight_and_no_signing_under_noauth(self):
        """regression: 'S' tag sits at byte 8, seclvl=0 (old bug: shifted/0x00)."""
        body = _protocol_exchange(SERVER_HOST, NGINX_ANON_PORT,
                                  _kXR_secreqs | _kXR_ableTLS)
        tag = body[_PROTO_BODY_LEN]
        assert tag == ord("S"), (
            f"secreq theTag must be 'S' (0x53) at offset 8, got {tag:#04x}; "
            "a non-'S' byte here is the old shifted-layout regression"
        )
        # theTag, rsvd, secver, secopt, seclvl, secvsz
        _tag, rsvd, secver, secopt, seclvl, secvsz = body[8:14]
        assert seclvl == 0, (
            f"auth=none server must demand no signing (seclvl 0), got {seclvl}"
        )
        assert rsvd == 0 and secver == 0 and secopt == 0 and secvsz == 0, (
            "rsvd/secver/secopt/secvsz must be zero under no-auth; got "
            f"rsvd={rsvd} secver={secver} secopt={secopt} secvsz={secvsz}"
        )

    def test_no_secblock_when_not_requested(self):
        """security-neg: without secreqs, no security info is emitted at all."""
        body = _protocol_exchange(SERVER_HOST, NGINX_ANON_PORT, _kXR_ableTLS)
        assert len(body) == _PROTO_BODY_LEN, (
            "a client that did not set kXR_secreqs must receive only the "
            f"8-byte ServerProtocolBody, no trailer; got {len(body)} bytes"
        )
