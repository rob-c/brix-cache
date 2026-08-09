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

def _src(relpath):
    path = REPO_ROOT / relpath
    assert path.exists(), f"missing expected file: {relpath}"
    return path.read_text(encoding="utf-8")
