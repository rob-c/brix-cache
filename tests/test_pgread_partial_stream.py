"""
§1.3 chunked pgread streaming — kXR_PartialResult frame trains on a bound
secondary data channel.

A pgread whose encoded reply exceeds one streaming window and whose response
is routed over a bound secondary (nonzero pathid, same-worker) is streamed by
the thread pool as a TRAIN of kXR_status frames: every frame but the last
carries resptype=kXR_PartialResult, the last kXR_FinalResult, and chunk cuts
land on the absolute 4 KiB page grid so every non-final frame's page units
are whole pages.  This suite proves that shape on the wire, byte-exactness of
the reassembled train, the single-frame shape of sub-window replies, early
Final termination at EOF, and the two refusal legs (bogus handle, unbound
pathid).

The offload only engages when the secondary lands on the SAME worker as the
primary; against a multi-worker (reuseport) server the fixture retries with
fresh connection pairs until it does, so the suite is topology-independent.

Run:
    PYTHONPATH=tests pytest tests/test_pgread_partial_stream.py -v
"""

import os
import select
import socket
import struct
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

from _test_pgread_wire_conformance_helpers import (
    _CRC32C_OK,
    PG_PAGESZ,
    _decode_pages,
    crc32c,
)
from _test_data_substreams_parallel_helpers import (
    _bind_secondary,
    _det,
    _establish_primary,
    _open_read,
    _recv_exact,
)

pytestmark = pytest.mark.xdist_group("pgread-partial-shared-data")

# Hand-validation overrides (mirror BRIX_SUBS_EXPORT_DIR in the substreams
# helpers): point the suite at a bespoke server without touching the fleet.
HOST = os.environ.get("BRIX_PGSTREAM_HOST", SERVER_HOST)
PORT = int(os.environ.get("BRIX_PGSTREAM_PORT", NGINX_ANON_PORT))
EXPORT_DIR = os.environ.get("BRIX_PGSTREAM_EXPORT_DIR", DATA_ROOT)

kXR_pgread  = 3030
kXR_status  = 4007
kXR_error   = 4003
kXR_ArgInvalid = 3000

kXR_FinalResult   = 0
kXR_PartialResult = 1

# > BRIX_READ_WINDOW (2 MiB) encoded, so the reply takes the thread-pool
# streaming path; ~6 chunk frames at the 1 MiB BRIX_PGREAD_STREAM_CHUNK.
FILE_NAME = "pgstream_train.bin"
FILE_SIZE = 6 * 1024 * 1024
CONTENT = _det(FILE_SIZE)

SAME_WORKER_ATTEMPTS = 24


def _send_pgread(sock, fhandle, offset, rlen, pathid, streamid):
    """ClientPgReadRequest with the optional 4-byte args payload
    (pathid, reqflags, reserved[2])."""
    req = struct.pack("!2sH4sqiI", streamid, kXR_pgread, fhandle,
                      offset, rlen, 4)
    sock.sendall(req + bytes([pathid, 0, 0, 0]))


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
    """Read frames until kXR_FinalResult; return [(resptype, pgr_off, pages)]."""
    frames = []
    while True:
        sid, resptype, pgr_off, pages = _read_frame(sock)
        assert sid == streamid, f"stream id mismatch: {sid!r}"
        frames.append((resptype, pgr_off, pages))
        if resptype == kXR_FinalResult:
            return frames
        assert resptype == kXR_PartialResult, f"bad resptype {resptype}"


def _bind_tiny_secondary(sessid):
    """Bind a secondary whose receive window is deliberately tiny (SO_RCVBUF
    must be set BEFORE connect to cap the negotiated window); return
    (sec, pathid)."""
    sec = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sec.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024)
    sec.connect((HOST, PORT))
    sec.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sec, 16)
    sec.sendall(struct.pack("!2sH16sI", b"\x00\x70", 3024, sessid, 0))
    hdr = _recv_exact(sec, 8)
    st = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    body = _recv_or_empty(sec, dlen)
    assert st == 0 and len(body) == 1, f"bind failed: {st}"
    return sec, body[0]


def _engage_tiny_rcvbuf_secondary(primary, sessid, data_file):
    """Retry fresh tiny-rcvbuf secondaries until a whole-file pgread's reply
    actually rides one (same-worker requirement); return the engaged
    secondary with the probe train unread, or skip."""
    for _ in range(SAME_WORKER_ATTEMPTS):
        sec, pathid = _bind_tiny_secondary(sessid)
        fh = _open_read(primary, b"\x00\x71", data_file)
        _send_pgread(primary, fh, 0, FILE_SIZE, pathid, b"\x00\x72")
        ready, _, _ = select.select([primary, sec], [], [], 30)
        assert ready, "no pgread response within 30s"
        if sec in ready:
            return sec
        _drain_train(primary, b"\x00\x72")   # cross-worker fallback
        sec.close()
    pytest.skip("offload never engaged (cross-worker every try)")


def _assert_train_shape(frames):
    """≥2 frames, every one but the last kXR_PartialResult, the last final."""
    assert len(frames) >= 2, (
        f"large pgread must stream as a multi-frame train, got "
        f"{len(frames)} frame(s)")
    for resptype, _, _ in frames[:-1]:
        assert resptype == kXR_PartialResult
    assert frames[-1][0] == kXR_FinalResult


def _reassemble_train(frames, base_offset):
    """Concatenate a train's decoded pages, asserting per-frame contiguity
    (each frame's pgr_off continues exactly where the previous ended)."""
    out = b""
    for _resptype, pgr_off, pages in frames:
        assert pgr_off == base_offset + len(out), (
            f"frame offset {pgr_off} != running position "
            f"{base_offset + len(out)}")
        out += _decode_pages(pages, first_offset=pgr_off)
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
def offload_pair(data_file):
    """A (primary, secondary, fhandle, pathid) tuple whose pgread responses
    actually ride the secondary.

    Response offloading needs the secondary on the SAME worker as the
    primary; on a multi-worker reuseport listener each fresh connection pair
    has an independent chance, so probe with a large pgread and retry until
    the reply lands on the secondary.  A single-worker server engages on the
    first attempt.
    """
    for _ in range(SAME_WORKER_ATTEMPTS):
        primary, sessid = _establish_primary(HOST, PORT)
        sec, pathid = _bind_secondary(HOST, PORT, sessid, b"\x00\x60")
        fh = _open_read(primary, b"\x00\x61", data_file)
        _send_pgread(primary, fh, 0, FILE_SIZE, pathid, b"\x00\x62")
        ready, _, _ = select.select([primary, sec], [], [], 30)
        assert ready, "no pgread response within 30s"
        if sec in ready:
            # drain the probe train so the fixture hands over a quiet pair
            _drain_train(sec, b"\x00\x62")
            yield primary, sec, fh, pathid
            primary.close()
            sec.close()
            return
        # cross-worker fallback: reply came inline on the primary — drain
        # the single frame and retry with a fresh pair
        _drain_train(primary, b"\x00\x62")
        primary.close()
        sec.close()
    pytest.skip(f"offload never engaged in {SAME_WORKER_ATTEMPTS} attempts "
                "(secondary kept landing on another worker)")


class TestPgreadPartialStream:
    """kXR_PartialResult trains for large pgreads on a bound secondary."""

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_partial_train_reassembles_byte_exact(self, offload_pair):
        """success: a whole-file pgread arrives as ≥2 chunk frames — every
        frame but the last kXR_PartialResult, the last kXR_FinalResult, chunk
        cuts on the absolute 4 KiB page grid, and the concatenated decoded
        pages are byte-identical to the file."""
        primary, sec, fh, pathid = offload_pair
        _send_pgread(primary, fh, 0, FILE_SIZE, pathid, b"\x00\x63")
        frames = _drain_train(sec, b"\x00\x63")
        _assert_train_shape(frames)
        for _resptype, pgr_off, _pages in frames[1:]:
            assert pgr_off % PG_PAGESZ == 0, "chunk cut off the page grid"
        out = _reassemble_train(frames, 0)
        assert out == CONTENT, "reassembled train differs from the file"

    def test_sub_window_read_stays_single_final_frame(self, offload_pair):
        """success (regression guard): a reply that fits one streaming window
        must remain ONE kXR_FinalResult frame — small reads never become
        partial trains."""
        primary, sec, fh, pathid = offload_pair
        want = 64 * 1024
        _send_pgread(primary, fh, 0, want, pathid, b"\x00\x64")
        frames = _drain_train(sec, b"\x00\x64")
        assert len(frames) == 1, f"sub-window read split into {len(frames)} frames"
        assert frames[0][0] == kXR_FinalResult
        decoded = _decode_pages(frames[0][2], first_offset=0)
        assert decoded == CONTENT[:want]

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_eof_terminates_train_early_with_final(self, offload_pair):
        """success/EOF: a pgread whose window extends past EOF streams the
        available tail and terminates with kXR_FinalResult at the short read —
        no error frame, no phantom padding."""
        primary, sec, fh, pathid = offload_pair
        tail = 2 * 1024 * 1024 + 512 * 1024          # 2.5 MiB of real bytes
        offset = FILE_SIZE - tail
        rlen = 4 * 1024 * 1024                        # asks 1.5 MiB past EOF
        _send_pgread(primary, fh, offset, rlen, pathid, b"\x00\x65")
        frames = _drain_train(sec, b"\x00\x65")
        assert frames[-1][0] == kXR_FinalResult
        out = _reassemble_train(frames, offset)
        assert out == CONTENT[offset:], "EOF train differs from the file tail"
        assert len(out) == tail, f"expected {tail} tail bytes, got {len(out)}"

    def test_bogus_fhandle_yields_error_no_desync(self, offload_pair):
        """error: a pgread on an invalid file handle is refused with kXR_error
        (on the control stream, before any offload), and BOTH connections
        remain usable afterwards."""
        primary, sec, fh, pathid = offload_pair
        _send_pgread(primary, b"\xde\xad\xbe\xef", 0, FILE_SIZE, pathid,
                     b"\x00\x66")
        errnum, msg = _drain_error(primary)
        assert errnum != 0
        assert _ping_ok(primary), "primary desynced after handle refusal"
        # the secondary must still stream a valid train
        _send_pgread(primary, fh, 0, FILE_SIZE, pathid, b"\x00\x67")
        frames = _drain_train(sec, b"\x00\x67")
        assert frames[-1][0] == kXR_FinalResult

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_slow_reader_park_handoff_completes_train(self, data_file):
        """success under backpressure: a tiny receive buffer plus a stalled
        reader exhausts the in-thread send budget mid-train, forcing the
        park-front handoff to the event loop — the train must still arrive
        complete, in order, and byte-exact."""
        primary, sessid = _establish_primary(HOST, PORT)
        sec = None
        try:
            sec = _engage_tiny_rcvbuf_secondary(primary, sessid, data_file)
            # Stall long past the in-thread send budget (12 consecutive 25 ms
            # zero-progress polls = 300 ms) so the thread parks the tail and
            # the event loop finishes the train.
            time.sleep(1.5)
            frames = _drain_train(sec, b"\x00\x72")
            assert frames[-1][0] == kXR_FinalResult
            out = _reassemble_train(frames, 0)
            assert out == CONTENT, "parked/handoff train differs from the file"
        finally:
            if sec is not None:
                sec.close()
            primary.close()

    def test_unbound_pathid_refused(self, data_file):
        """security-negative: a pgread tagged with a pathid this session never
        bound must be refused with kXR_ArgInvalid — the response must not be
        served inline as if pathid 0, and the connection must not desync."""
        primary, _sessid = _establish_primary(HOST, PORT)
        try:
            fh = _open_read(primary, b"\x00\x68", data_file)
            _send_pgread(primary, fh, 0, 64 * 1024, 200, b"\x00\x69")
            errnum, msg = _drain_error(primary)
            assert errnum == kXR_ArgInvalid, (
                f"unbound pathid must be kXR_ArgInvalid, got {errnum} ({msg})")
            assert "path" in msg.lower()
            assert _ping_ok(primary), "connection desynced after refusal"
        finally:
            primary.close()
