# brix-remote-skip
"""tests/test_recover_wrts.py — kXR_recoverWrts write-recovery journal tests.

Verifies the per-handle write journal (src/protocols/root/write/wrts_journal.c):
  1. A duplicate kXR_write at the same (offset, length) is treated as a replay —
     server returns kXR_ok but does not re-issue the pwrite, preserving the original data.
  2. A write at a DIFFERENT offset on the same handle is not a replay — it lands normally.
  3. kXR_close flushes the journal; a subsequent open + same offset writes fresh data.
  4. kXR_writev segments are journalled the same way; replays are skipped there too.

Run:
    PYTHONPATH=tests pytest tests/test_recover_wrts.py -v
"""

import os
import socket
import struct
import uuid

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

kXR_ok       = 0
kXR_protocol = 3006
kXR_login    = 3007
kXR_open     = 3010
kXR_write    = 3019
kXR_writev   = 3031
kXR_close    = 3003

# kXR_open option flags
kXR_open_updt = 0x0020   # open for read/write
kXR_new       = 0x0008   # O_CREAT
kXR_delete    = 0x0002   # O_TRUNC (overwrite existing)

# ---------------------------------------------------------------------------
# Module-level defaults
# ---------------------------------------------------------------------------

_HOST = SERVER_HOST
_PORT = NGINX_ANON_PORT
_DATA = DATA_ROOT


# ---------------------------------------------------------------------------
# Raw-socket helpers (same pattern as test_session_bind.py)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _send_req(sock, streamid, reqid, body=b"", payload=b""):
    hdr = bytes(streamid[:2]) + struct.pack(">H", reqid)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    rsp_hdr = _recv_exact(sock, 8)
    assert rsp_hdr is not None, "connection closed unexpectedly"
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen   = struct.unpack(">I", rsp_hdr[4:8])[0]
    body_data = b""
    if dlen > 0:
        body_data = _recv_exact(sock, dlen)
    return status, body_data


def _connect_anon(port):
    """Handshake + kXR_protocol + kXR_login (anonymous). Returns (sock, streamid)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((_HOST, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)                                    # handshake response
    status, _ = _send_req(sock, b"\x00\x01", kXR_protocol)
    assert status == kXR_ok, f"kXR_protocol failed: {status}"
    status, _ = _send_req(sock, b"\x00\x01", kXR_login, payload=b"anonymous\x00")
    assert status == kXR_ok, f"kXR_login failed: {status}"
    return sock, b"\x00\x01"


def _open_write(sock, sid, xrd_path):
    """Open a file for write (create or overwrite). Returns the 4-byte fhandle."""
    flags = kXR_open_updt | kXR_new | kXR_delete
    open_body = struct.pack(">HH", 0o644, flags) + b"\x00" * 12
    status, body = _send_req(sock, sid, kXR_open, body=open_body,
                             payload=xrd_path.encode() + b"\x00")
    assert status == kXR_ok, f"kXR_open (write) failed: status={status}"
    return body[:4]


def _write(sock, sid, fhandle, offset, data):
    """Send kXR_write at (offset, len(data)) and assert kXR_ok."""
    write_body = fhandle + struct.pack(">q", offset) + b"\x00" * 4
    status, _ = _send_req(sock, sid, kXR_write, body=write_body, payload=data)
    assert status == kXR_ok, f"kXR_write failed: status={status}"


def _writev_one(sock, sid, fhandle, offset, data):
    """Send kXR_writev with a single segment and assert kXR_ok.

    Segment descriptor (write_list): fhandle[4] + wlen[4be] + offset[8be] = 16 bytes.
    Stock wire framing: dlen covers ONLY the descriptor block; the segment
    data streams after the frame (server recovers its length as sum(wlen)).
    """
    seg = fhandle + struct.pack(">I", len(data)) + struct.pack(">q", offset)
    hdr = bytes(sid[:2]) + struct.pack(">H", kXR_writev)
    hdr += b"\x00" * 16
    hdr += struct.pack(">I", len(seg))
    sock.sendall(hdr + seg + data)
    rsp_hdr = _recv_exact(sock, 8)
    assert rsp_hdr is not None, "connection closed unexpectedly"
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen = struct.unpack(">I", rsp_hdr[4:8])[0]
    if dlen > 0:
        _recv_exact(sock, dlen)
    assert status == kXR_ok, f"kXR_writev failed: status={status}"


def _close(sock, sid, fhandle):
    close_body = fhandle + b"\x00" * 12
    status, _ = _send_req(sock, sid, kXR_close, body=close_body)
    assert status == kXR_ok, f"kXR_close failed: status={status}"


def _disk_contents(name):
    """Read file bytes directly from the server's data root."""
    with open(os.path.join(_DATA, name), "rb") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def fname():
    """Unique filename (no directory component) for each test."""
    return f"_test_wrts_{uuid.uuid4().hex}.bin"


@pytest.fixture(autouse=True)
def _cleanup(fname):
    yield
    try:
        os.unlink(os.path.join(_DATA, fname))
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWriteJournal:

    def test_replay_of_same_offset_length_is_skipped(self, fname):
        """A second kXR_write with identical (offset, length) is a recovery replay.

        The server must return kXR_ok but skip the pwrite, so the file retains
        the data from the first write.  This is the core kXR_recoverWrts guarantee.
        """
        sock, sid = _connect_anon(_PORT)
        try:
            fh = _open_write(sock, sid, f"/{fname}")
            _write(sock, sid, fh, 0, b"AAAAAAAA")   # committed, recorded in journal
            _write(sock, sid, fh, 0, b"BBBBBBBB")   # same offset+len → replay, skipped
            _close(sock, sid, fh)
        finally:
            sock.close()

        assert _disk_contents(fname) == b"AAAAAAAA"

    def test_different_offset_is_not_treated_as_replay(self, fname):
        """A write at a different offset than the journalled entry lands normally.

        Replay detection must not accidentally suppress writes to fresh offsets.
        """
        sock, sid = _connect_anon(_PORT)
        try:
            fh = _open_write(sock, sid, f"/{fname}")
            _write(sock, sid, fh, 0, b"AAAAAAAA")   # offset 0 recorded
            _write(sock, sid, fh, 8, b"BBBBBBBB")   # offset 8 — different range, not a replay
            _close(sock, sid, fh)
        finally:
            sock.close()

        assert _disk_contents(fname) == b"AAAAAAAABBBBBBBB"

    def test_close_flushes_journal_so_reopen_writes_fresh(self, fname):
        """kXR_close flushes the write journal.

        After close + reopen, a write at the same (offset, length) as a previous
        write must NOT be treated as a replay — it must land and overwrite.
        """
        sock, sid = _connect_anon(_PORT)
        try:
            fh = _open_write(sock, sid, f"/{fname}")
            _write(sock, sid, fh, 0, b"AAAAAAAA")
            _close(sock, sid, fh)                    # close flushes journal
        finally:
            sock.close()

        # Second connection, same offset — fresh write, NOT a replay
        sock, sid = _connect_anon(_PORT)
        try:
            fh = _open_write(sock, sid, f"/{fname}")
            _write(sock, sid, fh, 0, b"BBBBBBBB")
            _close(sock, sid, fh)
        finally:
            sock.close()

        assert _disk_contents(fname) == b"BBBBBBBB"

    def test_writev_replay_is_skipped(self, fname):
        """kXR_writev writes are entered into the journal and replays are skipped.

        The same (offset, length) sent via kXR_writev twice must produce one write,
        not two, preserving the original segment data.
        """
        sock, sid = _connect_anon(_PORT)
        try:
            fh = _open_write(sock, sid, f"/{fname}")
            _writev_one(sock, sid, fh, 0, b"CCCCCCCC")   # committed, journalled
            _writev_one(sock, sid, fh, 0, b"DDDDDDDD")   # replay → skipped
            _close(sock, sid, fh)
        finally:
            sock.close()

        assert _disk_contents(fname) == b"CCCCCCCC"
