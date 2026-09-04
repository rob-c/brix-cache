"""
Windowed primary-path pgread — kXR_PartialResult frame trains on the
PRIMARY channel (pathid 0).

A pgread larger than one streaming window (BRIX_READ_WINDOW, 2 MiB) that is
NOT offload-eligible (no bound secondary — the everyday xrdcp shape) is
served by the shared windowed-read pump as a train of kXR_status frames on
the requesting connection itself: every frame but the last carries
resptype=kXR_PartialResult, the last kXR_FinalResult, window cuts land on
the absolute 4 KiB page grid, and each frame's page units carry their own
CRC32c.  This suite proves that shape on the wire, byte-exactness of the
reassembled train (which exercises both the warm inline window path and the
thread-pool window path — the server picks per window), the single-frame
shape of sub-window replies, early Final termination at EOF, the bogus-handle
refusal, and the negative-rlen refusal (the unsigned-wrap guard: -1 read
unsigned would be a ~4 GiB allocation request).

Run:
    PYTHONPATH=tests pytest tests/test_pgread_primary_stream.py -v
"""

import os
import socket
import struct

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

from _test_pgread_wire_conformance_helpers import (
    _CRC32C_OK,
    PG_PAGESZ,
    _decode_pages,
    crc32c,
)
from _test_data_substreams_parallel_helpers import (
    _det,
    _establish_primary,
    _open_read,
    _recv_exact,
)

pytestmark = pytest.mark.xdist_group("pgread-primary-shared-data")

# Hand-validation overrides: point the suite at a bespoke server (e.g. the
# bench fleet) without touching the shared fleet.
HOST = os.environ.get("BRIX_PGSTREAM_HOST", SERVER_HOST)
PORT = int(os.environ.get("BRIX_PGSTREAM_PORT", NGINX_ANON_PORT))
EXPORT_DIR = os.environ.get("BRIX_PGSTREAM_EXPORT_DIR", DATA_ROOT)

kXR_pgread     = 3030
kXR_status     = 4007
kXR_error      = 4003
kXR_ArgInvalid = 3000

kXR_FinalResult   = 0
kXR_PartialResult = 1

# > BRIX_READ_WINDOW (2 MiB), so the reply takes the windowed primary path;
# ~3 window frames at the 2 MiB window.
FILE_NAME = "pgstream_primary.bin"
FILE_SIZE = 6 * 1024 * 1024 + 12345      # off-grid tail: last page partial
CONTENT = _det(FILE_SIZE)


def _send_pgread(sock, fhandle, offset, rlen, streamid):
    """ClientPgReadRequest on the primary channel (no optional args ext)."""
    sock.sendall(struct.pack("!2sH4sqiI", streamid, kXR_pgread, fhandle,
                             offset, rlen, 0))


def _recv_or_empty(sock, nbytes):
    """_recv_exact that treats a non-positive length as an empty payload and
    hard-fails on truncation."""
    if nbytes <= 0:
        return b""
    data = _recv_exact(sock, nbytes)
    assert data is not None and len(data) == nbytes, "truncated frame payload"
    return data


def _parse_status_body(body):
    """Verify a 24-byte pgread status body (CRC32c over streamID..pgr.offset,
    20 bytes) and return (resptype, bdy_dlen, pgr_off)."""
    assert len(body) == 24, f"pgread status body must be 24 bytes, got {len(body)}"
    if _CRC32C_OK:
        body_crc = struct.unpack("!I", body[0:4])[0]
        assert body_crc == crc32c(body[4:24]), "status body CRC32c mismatch"
    return body[7], struct.unpack("!i", body[12:16])[0], \
        struct.unpack("!q", body[16:24])[0]


def _read_frame(sock):
    """Read ONE kXR_status pgread frame: (sid, resptype, pgr_offset, pages)."""
    hdr = _recv_exact(sock, 8)
    assert hdr is not None, "connection closed mid-train"
    status = struct.unpack("!H", hdr[2:4])[0]
    assert status == kXR_status, f"expected kXR_status frame, got {status}"
    dlen = struct.unpack("!I", hdr[4:8])[0]
    resptype, bdy_dlen, pgr_off = _parse_status_body(_recv_or_empty(sock, dlen))
    return hdr[0:2], resptype, pgr_off, _recv_or_empty(sock, bdy_dlen)


def _drain_train(sock, streamid):
    """Read frames until kXR_FinalResult; return [(resptype, pgr_off, pages)].

    Every frame of the train must echo the ORIGINAL request's streamid —
    the windowed path snapshots it (rd.win_streamid) because cur_streamid is
    overwritten by the next inbound header.
    """
    frames = []
    while True:
        sid, resptype, pgr_off, pages = _read_frame(sock)
        assert sid == streamid, f"stream id mismatch: {sid!r}"
        frames.append((resptype, pgr_off, pages))
        if resptype == kXR_FinalResult:
            return frames
        assert resptype == kXR_PartialResult, f"bad resptype {resptype}"


def _assert_train_shape(frames):
    """Every frame but the last is kXR_PartialResult; the last is Final."""
    for resptype, _, _ in frames[:-1]:
        assert resptype == kXR_PartialResult
    assert frames[-1][0] == kXR_FinalResult


def _reassemble_train(frames, base_offset):
    """Concatenate a train's decoded pages, asserting contiguous offsets and
    (for partial frames) window cuts on the absolute 4 KiB page grid.  A
    partial page is legal ONLY in the Final frame (XProtocol pgread framing):
    the stock client rejects a short page mid-train as corrupt, so a Partial
    frame ending off the grid is a wire bug even when an empty Final
    follows."""
    out = b""
    for resptype, pgr_off, pages in frames:
        assert pgr_off == base_offset + len(out), (
            f"frame offset {pgr_off} != running offset {base_offset + len(out)}")
        decoded = _decode_pages(pages, first_offset=pgr_off)
        if resptype == kXR_PartialResult:
            assert (pgr_off + len(decoded)) % PG_PAGESZ == 0, \
                "partial frame ended off the page grid"
        out += decoded
    return out


def _drain_error(sock):
    """Read one frame expecting kXR_error; return (errnum, message)."""
    hdr = _recv_exact(sock, 8)
    assert hdr is not None, "connection closed"
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    assert status == kXR_error, f"expected kXR_error, got {status}"
    errnum = struct.unpack("!i", body[0:4])[0]
    return errnum, body[4:].rstrip(b"\x00").decode(errors="replace")


def _ping_ok(sock, streamid=b"\x00\x7f"):
    """kXR_ping round-trip — proves the connection did not desync."""
    sock.sendall(struct.pack("!2sH16sI", streamid, 3011, b"\x00" * 16, 0))
    hdr = _recv_exact(sock, 8)
    if hdr is None:
        return False
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    if dlen:
        _recv_exact(sock, dlen)
    return status == 0


@pytest.fixture(scope="module", autouse=True)
def _require_server():
    try:
        s = socket.create_connection((HOST, PORT), timeout=3)
        s.close()
    except OSError as exc:
        pytest.skip(f"anon stream server {HOST}:{PORT} unreachable: {exc}")


@pytest.fixture(scope="module")
def data_file():
    try:
        os.makedirs(EXPORT_DIR, exist_ok=True)
        full = os.path.join(EXPORT_DIR, FILE_NAME)
        with open(full, "wb") as f:
            f.write(CONTENT)
    except OSError as exc:
        pytest.skip(f"export dir {EXPORT_DIR!r} not locally writable: {exc}")
    yield "/" + FILE_NAME
    try:
        os.remove(full)
    except OSError:
        pass


@pytest.fixture()
def open_handle(data_file):
    """A fresh primary connection with the data file open for read."""
    primary, _sessid = _establish_primary(HOST, PORT)
    fh = _open_read(primary, b"\x00\x51", data_file)
    yield primary, fh
    primary.close()


class TestPgreadPrimaryStream:
    """kXR_PartialResult trains for large pgreads on the primary channel."""

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_primary_train_reassembles_byte_exact(self, open_handle):
        """success: a whole-file pgread arrives inline as ≥2 window frames —
        every frame but the last kXR_PartialResult, the last kXR_FinalResult,
        window cuts on the absolute 4 KiB page grid, and the concatenated
        decoded pages are byte-identical to the file."""
        primary, fh = open_handle
        _send_pgread(primary, fh, 0, FILE_SIZE, b"\x00\x52")
        frames = _drain_train(primary, b"\x00\x52")
        assert len(frames) >= 2, (
            f"large pgread must stream as a multi-frame train, got "
            f"{len(frames)} frame(s)")
        _assert_train_shape(frames)
        out = _reassemble_train(frames, 0)
        assert out == CONTENT, "reassembled train differs from the file"

    def test_sub_window_read_stays_single_final_frame(self, open_handle):
        """success (regression guard): a reply that fits one streaming window
        must remain ONE kXR_FinalResult frame — the classic single-frame path
        still owns small reads."""
        primary, fh = open_handle
        want = 64 * 1024
        _send_pgread(primary, fh, 0, want, b"\x00\x53")
        frames = _drain_train(primary, b"\x00\x53")
        assert len(frames) == 1, f"sub-window read split into {len(frames)} frames"
        assert frames[0][0] == kXR_FinalResult
        decoded = _decode_pages(frames[0][2], first_offset=0)
        assert decoded == CONTENT[:want]

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_eof_terminates_train_early_with_final(self, open_handle):
        """success/EOF: a pgread whose windows extend past EOF streams the
        available tail (including the partial last page) and terminates with
        kXR_FinalResult at the short read — no error frame, no padding."""
        primary, fh = open_handle
        offset = FILE_SIZE - (2 * 1024 * 1024 + 512 * 1024)
        tail = FILE_SIZE - offset
        rlen = 4 * 1024 * 1024                    # asks well past EOF
        _send_pgread(primary, fh, offset, rlen, b"\x00\x54")
        frames = _drain_train(primary, b"\x00\x54")
        assert frames[-1][0] == kXR_FinalResult
        out = _reassemble_train(frames, offset)
        assert out == CONTENT[offset:], "EOF train differs from the file tail"
        assert len(out) == tail, f"expected {tail} tail bytes, got {len(out)}"

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_eof_short_window_is_final_not_partial(self, open_handle):
        """success/EOF regression: a windowed pgread whose FIRST window comes
        up short (the file tail is smaller than the window) must arrive as
        ONE kXR_FinalResult frame carrying the partial last page — never as
        kXR_PartialResult + an empty Final.  A short page is only legal in
        the final frame; the stock client flags the mid-train shape as a
        corrupted page and its retry silently truncates the tail (xrdfs cat
        returned size-4 bytes for every unaligned file)."""
        primary, fh = open_handle
        offset = FILE_SIZE - 11                   # unaligned 11-byte tail
        _send_pgread(primary, fh, offset, 4 * 1024 * 1024, b"\x00\x58")
        frames = _drain_train(primary, b"\x00\x58")
        assert len(frames) == 1, (
            f"EOF-short window must be a single Final frame, got "
            f"{len(frames)} frames (resptypes {[f[0] for f in frames]})")
        assert frames[0][0] == kXR_FinalResult
        decoded = _decode_pages(frames[0][2], first_offset=offset)
        assert decoded == CONTENT[-11:], "EOF tail bytes differ"

    def test_bogus_fhandle_yields_error_no_desync(self, open_handle):
        """error: a large pgread on an invalid file handle is refused with
        kXR_error before any window is produced, and the connection remains
        usable afterwards."""
        primary, fh = open_handle
        _send_pgread(primary, b"\xde\xad\xbe\xef", 0, FILE_SIZE, b"\x00\x55")
        errnum, _msg = _drain_error(primary)
        assert errnum != 0
        assert _ping_ok(primary), "connection desynced after handle refusal"
        # the real handle must still stream a valid train
        _send_pgread(primary, fh, 0, FILE_SIZE, b"\x00\x56")
        frames = _drain_train(primary, b"\x00\x56")
        assert frames[-1][0] == kXR_FinalResult

    def test_negative_rlen_refused(self, open_handle):
        """security-negative: rlen is a signed 32-bit wire field; -1 read
        unsigned would become a ~4 GiB scratch demand.  A negative length must
        be refused with kXR_ArgInvalid and must not desync the connection."""
        primary, fh = open_handle
        _send_pgread(primary, fh, 0, -1, b"\x00\x57")
        errnum, msg = _drain_error(primary)
        assert errnum == kXR_ArgInvalid, (
            f"negative rlen must be kXR_ArgInvalid, got {errnum} ({msg})")
        assert _ping_ok(primary), "connection desynced after refusal"
