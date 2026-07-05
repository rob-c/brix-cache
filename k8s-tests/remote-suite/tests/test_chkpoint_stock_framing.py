# brix-remote-skip
"""tests/test_chkpoint_stock_framing.py — kXR_ckpXeq stock wire-framing parity.

Stock contract (XrdXrootdProtocol::do_ChkPntXeq, mirrored by the reference
client — XrdCl::MessageUtils marks ckpXeq write/pgwrite/writev as raw-body
requests): the chkpoint request's dlen covers ONLY the embedded 24-byte
sub-request header (which must carry the outer streamid); the sub-request
body streams immediately after the frame — write/pgwrite data, or writev
descriptors followed by their segment data (the same descriptors-only dlen
contract as a standalone kXR_writev, see test_writev_stock_framing.py).
A stock server rejects any other outer dlen with kXR_ArgInvalid
"Request length invalid" followed by a link drop — this suite pins our
server to the same behaviour (src/protocols/root/write/chkpoint_xeq.c +
the two-stage recv-framing extension in
src/protocols/root/connection/recv.c).

Run:
    PYTHONPATH=tests pytest tests/test_chkpoint_stock_framing.py -v
"""

import os
import socket
import struct
import uuid
from pathlib import Path

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

kXR_ok       = 0
kXR_error    = 4003
kXR_protocol = 3006
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_chkpoint = 3012
kXR_read     = 3013
kXR_write    = 3019
kXR_truncate = 3028
kXR_writev   = 3031
kXR_close    = 3003

kXR_ArgInvalid   = 3000
kXR_Unsupported  = 3013

kXR_ckpBegin  = 0
kXR_ckpCommit = 1
kXR_ckpXeq    = 4

kXR_open_updt = 0x0020
kXR_new       = 0x0008
kXR_delete    = 0x0002

# ---------------------------------------------------------------------------
# Raw-socket helpers (same pattern as test_writev_stock_framing.py)
# ---------------------------------------------------------------------------


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (ConnectionResetError, socket.timeout):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_response(sock):
    """Read one 8-byte response header (+ body). Returns (status, body) or
    (None, None) if the connection was closed."""
    rsp_hdr = _recv_exact(sock, 8)
    if rsp_hdr is None:
        return None, None
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen = struct.unpack(">I", rsp_hdr[4:8])[0]
    body = b""
    if dlen > 0:
        body = _recv_exact(sock, dlen) or b""
    return status, body


def _send_req(sock, streamid, reqid, body=b"", payload=b""):
    hdr = bytes(streamid[:2]) + struct.pack(">H", reqid)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    return _read_response(sock)


def _connect_anon():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((SERVER_HOST, NGINX_ANON_PORT))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    assert _recv_exact(sock, 16) is not None            # handshake response
    status, _ = _send_req(sock, b"\x00\x01", kXR_protocol)
    assert status == kXR_ok
    status, _ = _send_req(sock, b"\x00\x01", kXR_login, payload=b"anonymous\x00")
    assert status == kXR_ok
    return sock


def _open_write(sock, xrd_path):
    flags = kXR_open_updt | kXR_new | kXR_delete
    open_body = struct.pack(">HH", 0o644, flags) + b"\x00" * 12
    status, body = _send_req(sock, b"\x00\x01", kXR_open, body=open_body,
                             payload=xrd_path.encode() + b"\x00")
    assert status == kXR_ok, f"open failed: {status}"
    return body[:4]


def _chkpoint_body(fh, opcode):
    """16-byte kXR_chkpoint body: fhandle[4] reserved[11] opcode[1]."""
    return fh + b"\x00" * 11 + bytes([opcode])


def _ckp_simple(sock, sid, fh, opcode):
    """begin/commit/query/rollback — dlen 0."""
    return _send_req(sock, sid, kXR_chkpoint, body=_chkpoint_body(fh, opcode))


def _ckpxeq_hdr(sid, fh):
    """kXR_chkpoint/ckpXeq request header with dlen == 24 (stock framing)."""
    return bytes(sid[:2]) + struct.pack(">H", kXR_chkpoint) \
        + _chkpoint_body(fh, kXR_ckpXeq) + struct.pack(">I", 24)


def _sub_write_hdr(sid, fh, offset, dlen):
    """Embedded kXR_write sub-header (24 bytes)."""
    return bytes(sid[:2]) + struct.pack(">H", kXR_write) \
        + fh + struct.pack(">q", offset) + b"\x00" * 4 \
        + struct.pack(">I", dlen)


def _sub_writev_hdr(sid, dlen):
    """Embedded kXR_writev sub-header (24 bytes); dlen frames descriptors."""
    return bytes(sid[:2]) + struct.pack(">H", kXR_writev) + b"\x00" * 16 \
        + struct.pack(">I", dlen)


def _desc(fh, offset, wlen):
    return fh + struct.pack(">I", wlen) + struct.pack(">q", offset)


def _err_code(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


# ---------------------------------------------------------------------------
# Success — stock framing accepted, byte-exact, connection stays aligned
# ---------------------------------------------------------------------------


class TestStockFramingAccepted:

    def test_ckpxeq_write_split_sends_roundtrip(self):
        """chkpoint dlen = 24 (embedded write sub-header only); the write
        data streams after the frame, split mid-buffer — exercises the
        recv-framing extension continuation.  Bytes must land exactly and
        the connection must stay request-aligned (ping + close succeed)."""
        name = f"ckpstock_{uuid.uuid4().hex[:8]}.bin"
        sock = _connect_anon()
        fh = _open_write(sock, f"/{name}")

        status, _ = _ckp_simple(sock, b"\x00\x02", fh, kXR_ckpBegin)
        assert status == kXR_ok, f"ckpBegin failed: {status}"

        data = b"CHECKPOINTED"
        sid = b"\x00\x03"
        sock.sendall(_ckpxeq_hdr(sid, fh)
                     + _sub_write_hdr(sid, fh, 0, len(data)))
        sock.sendall(data[:5])                  # streamed data, split
        sock.sendall(data[5:])

        status, _ = _read_response(sock)
        assert status == kXR_ok, f"stock-framed ckpXeq write rejected: {status}"

        status, _ = _ckp_simple(sock, b"\x00\x04", fh, kXR_ckpCommit)
        assert status == kXR_ok, f"ckpCommit failed: {status}"

        # Connection still aligned: ping then close must work.
        status, _ = _send_req(sock, b"\x00\x05", kXR_ping)
        assert status == kXR_ok
        status, _ = _send_req(sock, b"\x00\x06", kXR_close,
                              body=fh + b"\x00" * 12)
        assert status == kXR_ok
        sock.close()

        with open(os.path.join(DATA_ROOT, name), "rb") as f:
            assert f.read() == data

    def test_ckpxeq_writev_two_stage_roundtrip(self):
        """Embedded writev: the sub-header's dlen frames only the descriptor
        block; sum(wlen) data bytes stream after it — the recv framing must
        extend TWICE (embedded header -> descriptors -> data)."""
        name = f"ckpwv_{uuid.uuid4().hex[:8]}.bin"
        sock = _connect_anon()
        fh = _open_write(sock, f"/{name}")

        status, _ = _ckp_simple(sock, b"\x00\x02", fh, kXR_ckpBegin)
        assert status == kXR_ok, f"ckpBegin failed: {status}"

        seg1, seg2 = b"HELLO", b"WORLD"
        descs = _desc(fh, 0, len(seg1)) + _desc(fh, 10, len(seg2))
        sid = b"\x00\x03"
        sock.sendall(_ckpxeq_hdr(sid, fh) + _sub_writev_hdr(sid, len(descs)))
        sock.sendall(descs)                     # stage-1 extension bytes
        sock.sendall(seg1 + seg2[:2])           # stage-2, split mid-segment
        sock.sendall(seg2[2:])

        status, _ = _read_response(sock)
        assert status == kXR_ok, f"stock-framed ckpXeq writev rejected: {status}"

        status, _ = _ckp_simple(sock, b"\x00\x04", fh, kXR_ckpCommit)
        assert status == kXR_ok

        status, _ = _send_req(sock, b"\x00\x05", kXR_ping)
        assert status == kXR_ok
        status, _ = _send_req(sock, b"\x00\x06", kXR_close,
                              body=fh + b"\x00" * 12)
        assert status == kXR_ok
        sock.close()

        with open(os.path.join(DATA_ROOT, name), "rb") as f:
            data = f.read()
        assert data[:5] == seg1
        assert data[10:15] == seg2


# ---------------------------------------------------------------------------
# Error — legacy layout / malformed embeds rejected like stock
# ---------------------------------------------------------------------------


class TestLegacyAndMalformedRejected:

    def test_legacy_all_in_one_layout_rejected_then_drop(self):
        """The old private layout (sub-header AND data counted inside the
        chkpoint dlen) must be rejected with kXR_ArgInvalid 'Request length
        invalid' and a link drop, exactly like a stock server."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/ckpleg_{uuid.uuid4().hex[:8]}.bin")

        status, _ = _ckp_simple(sock, b"\x00\x02", fh, kXR_ckpBegin)
        assert status == kXR_ok

        data = b"LEGACY"
        sid = b"\x00\x03"
        sub = _sub_write_hdr(sid, fh, 0, len(data))
        legacy = bytes(sid) + struct.pack(">H", kXR_chkpoint) \
            + _chkpoint_body(fh, kXR_ckpXeq) \
            + struct.pack(">I", len(sub) + len(data)) + sub + data
        sock.sendall(legacy)

        status, body = _read_response(sock)
        assert status == kXR_error
        assert _err_code(body) == kXR_ArgInvalid
        assert b"Request length invalid" in body

        # Stock parity: the link is dropped after the error.
        assert _recv_exact(sock, 1) is None
        sock.close()

    def test_streamid_mismatch_rejected_then_drop(self):
        """The embedded sub-header must carry the outer streamid (XrdCl
        copies it in); a mismatch is kXR_ArgInvalid + link drop."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/ckpsid_{uuid.uuid4().hex[:8]}.bin")

        status, _ = _ckp_simple(sock, b"\x00\x02", fh, kXR_ckpBegin)
        assert status == kXR_ok

        # Embedded write with 0 data bytes but a foreign streamid.
        sock.sendall(_ckpxeq_hdr(b"\x00\x03", fh)
                     + _sub_write_hdr(b"\x00\x77", fh, 0, 0))

        status, body = _read_response(sock)
        assert status == kXR_error
        assert _err_code(body) == kXR_ArgInvalid
        assert b"streamid mismatch" in body
        assert _recv_exact(sock, 1) is None
        sock.close()

    def test_embedded_chkpoint_rejected_then_drop(self):
        """A chkpoint may not embed another chkpoint ('chkpoint request is
        invalid' + drop, stock first-pass check)."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/ckpnest_{uuid.uuid4().hex[:8]}.bin")

        sid = b"\x00\x02"
        sub = bytes(sid) + struct.pack(">H", kXR_chkpoint) \
            + _chkpoint_body(fh, kXR_ckpBegin) + struct.pack(">I", 0)
        sock.sendall(_ckpxeq_hdr(sid, fh) + sub)

        status, body = _read_response(sock)
        assert status == kXR_error
        assert _err_code(body) == kXR_ArgInvalid
        assert b"chkpoint request is invalid" in body
        assert _recv_exact(sock, 1) is None
        sock.close()

    def test_embedded_truncate_with_data_rejected_then_drop(self):
        """Stock first-pass check: an embedded truncate carries NO data (its
        length rides in the offset field) — a truncate sub-header declaring a
        payload is 'chkpoint request is invalid' + drop, and the framing must
        not wait for the declared bytes."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/ckptrd_{uuid.uuid4().hex[:8]}.bin")

        status, _ = _ckp_simple(sock, b"\x00\x02", fh, kXR_ckpBegin)
        assert status == kXR_ok

        sid = b"\x00\x03"
        sub = bytes(sid) + struct.pack(">H", kXR_truncate) \
            + fh + struct.pack(">q", 0) + b"\x00" * 4 \
            + struct.pack(">I", 5)                 # declares 5 payload bytes
        sock.sendall(_ckpxeq_hdr(sid, fh) + sub)
        # No payload sent — the reply must still arrive promptly.

        status, body = _read_response(sock)
        assert status == kXR_error, "server hung waiting for truncate data"
        assert _err_code(body) == kXR_ArgInvalid
        assert b"chkpoint request is invalid" in body
        assert _recv_exact(sock, 1) is None
        sock.close()

    def test_multifile_embedded_writev_unsupported_then_drop(self):
        """Stock parity: a ckpXeq writev whose data-bearing segments name more
        than one handle is kXR_Unsupported 'multi-file chkpoint writev not
        supported' + link drop (the rollback anchor covers exactly one file)."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/ckpmf_{uuid.uuid4().hex[:8]}.bin")

        status, _ = _ckp_simple(sock, b"\x00\x02", fh, kXR_ckpBegin)
        assert status == kXR_ok

        sid = b"\x00\x03"
        foreign = b"\x63\x00\x00\x00"              # a handle we never opened
        descs = _desc(fh, 0, 5) + _desc(foreign, 10, 5)
        sock.sendall(_ckpxeq_hdr(sid, fh) + _sub_writev_hdr(sid, len(descs))
                     + descs + b"AAAAABBBBB")

        status, body = _read_response(sock)
        assert status == kXR_error
        assert _err_code(body) == kXR_Unsupported
        assert b"multi-file chkpoint writev not supported" in body
        assert _recv_exact(sock, 1) is None
        sock.close()

    def test_zero_length_foreign_segment_is_exempt(self):
        """Stock parity nuance: zero-length segments are dropped when the
        vector is collected, BEFORE the multi-file check — so a zero-wlen
        descriptor naming a foreign handle must not fail the request."""
        name = f"ckpz_{uuid.uuid4().hex[:8]}.bin"
        sock = _connect_anon()
        fh = _open_write(sock, f"/{name}")

        status, _ = _ckp_simple(sock, b"\x00\x02", fh, kXR_ckpBegin)
        assert status == kXR_ok

        sid = b"\x00\x03"
        foreign = b"\x63\x00\x00\x00"
        descs = _desc(fh, 0, 5) + _desc(foreign, 100, 0)   # foreign but empty
        sock.sendall(_ckpxeq_hdr(sid, fh) + _sub_writev_hdr(sid, len(descs))
                     + descs + b"AAAAA")

        status, _ = _read_response(sock)
        assert status == kXR_ok, \
            f"zero-wlen foreign segment must be exempt, got {status}"

        status, _ = _ckp_simple(sock, b"\x00\x04", fh, kXR_ckpCommit)
        assert status == kXR_ok
        status, _ = _send_req(sock, b"\x00\x05", kXR_close,
                              body=fh + b"\x00" * 12)
        assert status == kXR_ok
        sock.close()

        with open(os.path.join(DATA_ROOT, name), "rb") as f:
            assert f.read() == b"AAAAA"


# ---------------------------------------------------------------------------
# Security-negative — hostile embedded lengths never buffer or hang
# ---------------------------------------------------------------------------


class TestHostileEmbeddedLengths:

    def test_huge_embedded_write_rejected_promptly_without_data(self):
        """An embedded write declaring a 1 GiB sub_dlen busts the payload
        cap.  The framing must NOT extend the read obligation (no 1 GiB
        allocation, no waiting for bytes that never come): the error must
        arrive promptly with only the sub-header on the wire, then the link
        is dropped."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/ckphuge_{uuid.uuid4().hex[:8]}.bin")

        sid = b"\x00\x02"
        sock.sendall(_ckpxeq_hdr(sid, fh)
                     + _sub_write_hdr(sid, fh, 0, 0x40000000))
        # No data sent — the reply must still arrive within the socket timeout.

        status, body = _read_response(sock)
        assert status == kXR_error, "server hung waiting for hostile data"
        assert _err_code(body) == kXR_ArgInvalid
        assert _recv_exact(sock, 1) is None
        sock.close()

    def test_embedded_writev_huge_wlen_rejected_promptly(self):
        """An embedded writev whose single descriptor declares 1 GiB of
        segment data: the stage-2 extension must decline (no buffering, no
        hang) and the handler rejects + drops with only the descriptors on
        the wire."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/ckpwvhuge_{uuid.uuid4().hex[:8]}.bin")

        status, _ = _ckp_simple(sock, b"\x00\x02", fh, kXR_ckpBegin)
        assert status == kXR_ok

        sid = b"\x00\x03"
        descs = _desc(fh, 0, 0x40000000)         # declares 1 GiB of data
        sock.sendall(_ckpxeq_hdr(sid, fh) + _sub_writev_hdr(sid, len(descs))
                     + descs)
        # No segment data sent.

        status, body = _read_response(sock)
        assert status == kXR_error, "server hung waiting for hostile data"
        assert _err_code(body) == kXR_ArgInvalid
        assert _recv_exact(sock, 1) is None
        sock.close()


# ---------------------------------------------------------------------------
# Source contracts — pin the documented framing/classification wiring so the
# divergences this suite exists for cannot silently reopen (same no-nginx
# marker idiom as test_cross_protocol_shared_helpers_b.py).
# ---------------------------------------------------------------------------


def _src(relpath):
    path = REPO_ROOT / relpath
    assert path.exists(), f"missing expected file: {relpath}"
    return path.read_text(encoding="utf-8")


class TestSourceContracts:

    def test_writev_and_ckpxeq_cross_reference_each_other(self):
        """The audit foot-gun this suite closed: standalone kXR_writev and
        the ckpXeq-embedded form share ONE wire contract (dlen frames only
        the descriptors; data streams behind).  Each side must keep the
        cross-reference note pointing at the other, so the next person who
        touches write_list framing sees both consumers."""
        writev = _src("src/protocols/root/write/writev.c")
        ckpxeq = _src("src/protocols/root/write/chkpoint_xeq.c")
        assert "chkpoint_xeq.c" in writev, \
            "writev.c lost its cross-reference to the checkpoint-embedded form"
        assert "ckp_xeq_writev" in writev
        assert "brix_writev_body_extra" in ckpxeq, \
            "chkpoint_xeq.c no longer delegates/references the shared " \
            "writev descriptor contract"

    def test_recv_framing_runs_the_two_stage_ckpxeq_extension(self):
        """The recv state machine must extend the read obligation for ckpXeq
        (embedded header -> sub-body; embedded writev -> descriptors ->
        data).  Without this hook a stock client's streamed sub-body would be
        parsed as the next request header."""
        recv = _src("src/protocols/root/connection/recv.c")
        assert "brix_ckpxeq_body_extra" in recv
        assert "kXR_ckpXeq" in recv

    def test_tap_stream_consumes_the_ckpxeq_sub_body(self):
        """The relay's streaming decoder must consume the ckpXeq trailing
        sub-body (and re-arm the writev descriptor fold for an embedded
        writev) or the byte relay's frame view desyncs."""
        tap = _src("src/net/tap/tap_stream.c")
        assert "ckp_active" in tap
        assert "kXR_chkpoint" in tap

    def test_relay_guard_classifies_chkpoint_as_write(self):
        """kXR_chkpoint mutates files; the guard must classify it in the
        WRITE group, not fall through to the INFO housekeeping default.
        Ordering check: the case label sits inside the group that returns
        GUARD_OP_WRITE."""
        guard = _src("src/protocols/root/relay/relay_guard.c")
        chk = guard.find("case kXR_chkpoint:")
        assert chk != -1, "relay_guard.c lost the kXR_chkpoint classification"
        write_ret = guard.find("return GUARD_OP_WRITE;")
        group_start = guard.find("case kXR_write:")
        assert group_start != -1 and write_ret != -1
        assert group_start < chk < write_ret, \
            "kXR_chkpoint is no longer classified in the GUARD_OP_WRITE group"

    def test_proxy_translates_the_embedded_fhandle(self):
        """The terminating proxy rewrites file handles between the client and
        upstream sessions; a ckpXeq frame names the handle THREE ways (outer
        chkpoint body, embedded sub-header, embedded writev descriptors) and
        all of them must be translated."""
        fwd = _src("src/net/proxy/forward_request.c")
        assert "kXR_ckpXeq" in fwd, \
            "forward_request.c no longer translates the ckpXeq embedded fhandle"
