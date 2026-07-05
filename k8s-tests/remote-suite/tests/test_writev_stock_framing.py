# brix-remote-adapted
"""tests/test_writev_stock_framing.py — kXR_writev stock wire-framing parity.

Stock contract (XrdXrootdProtocol::do_WriteV + do_WriteVec, mirrored by the
reference client XrdCl::FileStateHandler::VectorWrite): the request header's
dlen covers ONLY the N*16-byte write_list descriptor block; the concatenated
segment data streams immediately after the frame, its length recovered by the
server as sum(wlen).  The legacy private layout (data counted inside dlen) is
rejected by stock servers with kXR_ArgInvalid "Write vector is invalid"
followed by a link drop — this suite pins our server to the same behaviour
(src/protocols/root/write/writev.c + the recv-framing body extension in
src/protocols/root/connection/recv.c).

Run:
    PYTHONPATH=tests pytest tests/test_writev_stock_framing.py -v
"""

import os
import socket
import struct
import uuid

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST
import klib  # remote: read written file from the SERVER
SERVER_SVC="mega"; SERVER_DATA="/data/xrootd"

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

kXR_ok       = 0
kXR_error    = 4003
kXR_protocol = 3006
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_writev   = 3031
kXR_close    = 3003

kXR_ArgInvalid = 3000
kXR_ArgTooLong = 3002
kXR_NoMemory   = 3008

kXR_open_updt = 0x0020
kXR_new       = 0x0008
kXR_delete    = 0x0002

# ---------------------------------------------------------------------------
# Raw-socket helpers (same pattern as test_recover_wrts.py)
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


def _writev_hdr(n_desc_bytes, sid=b"\x00\x02"):
    return sid + struct.pack(">H", kXR_writev) + b"\x00" * 16 \
        + struct.pack(">I", n_desc_bytes)


def _desc(fh, offset, wlen):
    return fh + struct.pack(">I", wlen) + struct.pack(">q", offset)


def _err_code(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


# ---------------------------------------------------------------------------
# Success — stock framing accepted, byte-exact, connection stays aligned
# ---------------------------------------------------------------------------


class TestStockFramingAccepted:

    def test_two_segments_split_sends_roundtrip(self):
        """dlen = 2*16; descriptor block and data sent in separate TCP pushes
        (data even split mid-segment) — exercises the recv-framing extension
        continuation.  Bytes must land exactly and the connection must stay
        request-aligned afterwards (ping + close succeed)."""
        name = f"wvstock_{uuid.uuid4().hex[:8]}.bin"
        sock = _connect_anon()
        fh = _open_write(sock, f"/{name}")

        seg1, seg2 = b"HELLO", b"WORLD"
        descs = _desc(fh, 0, len(seg1)) + _desc(fh, 10, len(seg2))
        sock.sendall(_writev_hdr(len(descs)) + descs)
        sock.sendall(seg1 + seg2[:2])           # trailing data, split mid-segment
        sock.sendall(seg2[2:])

        status, _ = _read_response(sock)
        assert status == kXR_ok, f"stock-framed writev rejected: {status}"

        # Connection still aligned: ping then close must work.
        status, _ = _send_req(sock, b"\x00\x03", kXR_ping)
        assert status == kXR_ok
        status, _ = _send_req(sock, b"\x00\x04", kXR_close,
                              body=fh + b"\x00" * 12)
        assert status == kXR_ok
        sock.close()

        data = klib.svc_read(SERVER_SVC, os.path.join(SERVER_DATA, name))
        assert data[:5] == seg1
        assert data[10:15] == seg2

    def test_all_zero_length_vector_succeeds(self):
        """Stock parity: a vector whose wlen are all zero succeeds immediately
        (do_WriteV replies before any handle validation)."""
        sock = _connect_anon()
        descs = _desc(b"\x00\x00\x00\x00", 0, 0)
        sock.sendall(_writev_hdr(len(descs)) + descs)
        status, _ = _read_response(sock)
        sock.close()
        assert status == kXR_ok


# ---------------------------------------------------------------------------
# Error — the legacy layout (data counted in dlen) is rejected like stock
# ---------------------------------------------------------------------------


class TestLegacyFramingRejected:

    def test_legacy_layout_arginvalid_then_drop(self):
        """dlen = 16 + len(data) (the old private layout) is not a whole
        number of descriptors → kXR_ArgInvalid 'Write vector is invalid',
        then the server drops the link (stock do_WriteV returns -1)."""
        name = f"wvlegacy_{uuid.uuid4().hex[:8]}.bin"
        sock = _connect_anon()
        fh = _open_write(sock, f"/{name}")

        data = b"HELLO"                          # 5 bytes → dlen 21, not 16-aligned
        payload = _desc(fh, 0, len(data)) + data
        sock.sendall(_writev_hdr(len(payload)) + payload)

        status, body = _read_response(sock)
        assert status == kXR_error
        assert _err_code(body) == kXR_ArgInvalid
        assert b"Write vector is invalid" in body

        # Stock parity: the link is dropped after the error.
        assert _recv_exact(sock, 1) is None
        sock.close()

    def test_vector_too_long_argtoolong_then_drop(self):
        """1025 descriptors exceeds the 1024 cap (stock maxWvecsz) →
        kXR_ArgTooLong 'Write vector is too long' + link drop."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/wvlong_{uuid.uuid4().hex[:8]}.bin")

        descs = _desc(fh, 0, 0) * 1025
        sock.sendall(_writev_hdr(len(descs)) + descs)

        status, body = _read_response(sock)
        assert status == kXR_error
        assert _err_code(body) == kXR_ArgTooLong
        assert _recv_exact(sock, 1) is None
        sock.close()


# ---------------------------------------------------------------------------
# Security-negative — hostile descriptor totals never buffer the data
# ---------------------------------------------------------------------------


class TestHostileDescriptorTotals:

    def test_huge_wlen_rejected_promptly_without_data(self):
        """A single descriptor declaring a 1 GiB wlen busts the aggregate
        transfer cap.  The framing must NOT extend the read obligation (no
        1 GiB allocation, no waiting for bytes that never come): the error
        (kXR_NoMemory) must arrive promptly with only the descriptor block on
        the wire, and the link is dropped."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/wvhuge_{uuid.uuid4().hex[:8]}.bin")

        descs = _desc(fh, 0, 0x40000000)         # declares 1 GiB of data
        sock.sendall(_writev_hdr(len(descs)) + descs)
        # No data sent — the reply must still arrive within the socket timeout.

        status, body = _read_response(sock)
        assert status == kXR_error, "server hung waiting for hostile data"
        assert _err_code(body) == kXR_NoMemory
        assert _recv_exact(sock, 1) is None
        sock.close()

    def test_wlen_sum_overflow_rejected(self):
        """Descriptors whose wlen sum overflows 32 bits must be rejected, not
        wrapped into a small extension."""
        sock = _connect_anon()
        fh = _open_write(sock, f"/wvovf_{uuid.uuid4().hex[:8]}.bin")

        descs = _desc(fh, 0, 0xFFFFFFFF) * 4     # sum ≈ 16 GiB
        sock.sendall(_writev_hdr(len(descs)) + descs)

        status, body = _read_response(sock)
        assert status == kXR_error
        assert _err_code(body) == kXR_NoMemory
        assert _recv_exact(sock, 1) is None
        sock.close()
