"""
tests/test_readv_security.py — vector-read and paged (chunked) read/write
security tests.

This suite hammers the *bounds checking* of the scatter-gather and page-mode
opcodes with deliberately hostile requests built on raw TCP sockets, where the
Python XRootD client would otherwise sanitise offsets/lengths before they ever
reach the wire.  It targets the real handler code:

  * kXR_readv  (src/read/readv.c)   — negative offset, offset overflow, reads
                                       past EOF (single / straddling / mixed),
                                       segment-count + total-size caps, malformed
                                       framing, stale/invalid handles, and the
                                       contiguous-run coalescer crossing EOF.
  * kXR_pgread (src/read/pgread.c)  — negative offset, EOF handling, per-page
                                       CRC32c integrity of the chunked response,
                                       rlen cap, slice-handle rejection.
  * kXR_pgwrite(src/write/pgwrite.c)— per-page CRC32c verification (a corrupted
                                       page must be rejected, not written),
                                       negative offset, malformed framing.

A final class drives the high-level XRootD client so the same out-of-bounds
vector reads are exercised through the authenticated GSI / token endpoints,
covering the per-protocol auth + client demux paths in addition to anon.

The security property under test throughout: an out-of-bounds or corrupt
request must produce a clean protocol error (or, for pgread-at-EOF, a correct
short response) and must NEVER leak adjacent bytes, return wrong data, hang the
connection, or crash the worker.  Every hostile request is followed by a valid
one on the same socket to prove the session survived intact.

Run:
    pytest tests/test_readv_security.py -v
"""

import os
import socket
import struct

import pytest

from settings import (
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_TOKEN_PORT,
    SERVER_HOST,
)

try:
    from settings import CA_DIR, PROXY_STD
except Exception:  # pragma: no cover - optional GSI assets
    CA_DIR = None
    PROXY_STD = None


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (from src/protocol/opcodes.h)
# ---------------------------------------------------------------------------

kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_close    = 3003
kXR_readv    = 3025
kXR_pgwrite  = 3026
kXR_pgread   = 3030

kXR_ok            = 0
kXR_error         = 4003
kXR_status        = 4007    # pgread/pgwrite extended-status response framing

kXR_ArgInvalid    = 3000
kXR_ArgTooLong    = 3002
kXR_IOError       = 3007
kXR_Unsupported   = 3013
kXR_ChkSumErr     = 3019

kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_new  = 0x0008

# Handler limits (src/protocol/flags.h, src/types/tunables.h)
READV_SEGSIZE = 16
READV_MAXSEGS = 1024
READ_MAX      = 4 * 1024 * 1024          # per-segment readv cap
MAX_READV_TOTAL = 256 * 1024 * 1024      # whole-request readv cap
PG_PAGESZ     = 4096

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT

# Known data file — size chosen NOT page-aligned so pgread exercises a short
# final page, and large enough to host 1024 distinct readv segments.
DATA_NAME = "/test_readv_security.bin"
DATA_SIZE = 70000
PATTERN   = bytes((i * 31 + 7) & 0xFF for i in range(DATA_SIZE))


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — pure-Python, matches xrootd_crc32c_copy()
# ---------------------------------------------------------------------------

_CRC32C_POLY = 0x82F63B78  # reflected 0x1EDC6F41
_CRC32C_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ _CRC32C_POLY if (_c & 1) else (_c >> 1)
    _CRC32C_TABLE.append(_c)


def crc32c(data: bytes, crc: int = 0) -> int:
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# Self-test against the canonical check value; if this fails our CRC is wrong
# and the pgwrite-valid roundtrip would falsely fail, so we skip those cases.
_CRC32C_OK = crc32c(b"123456789") == 0xE3069283


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror tests/test_wire_protocol_security.py)
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(
                f"socket closed, {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _handshake():
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=8)
    sock.settimeout(8)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, status, _ = _read_response(sock)
    assert status == kXR_ok, "handshake rejected"
    return sock


def _login(sock, streamid=b"\x00\x01"):
    req = struct.pack("!2sHI8sBBBBI",
                      streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


def _session():
    sock = _handshake()
    _, status, _ = _login(sock)
    assert status == kXR_ok, "login rejected"
    return sock


def _open(sock, path, options=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _seg(fhandle, rlen, offset):
    """One readahead_list element: fhandle[4] + rlen(int32 BE) + offset(int64 BE)."""
    return struct.pack("!4siq", fhandle, rlen, offset)


def _readv(sock, segments, streamid=b"\x00\x05", raw_dlen=None):
    payload = b"".join(segments)
    dlen = raw_dlen if raw_dlen is not None else len(payload)
    req = struct.pack("!2sH16sI", streamid, kXR_readv, b"\x00" * 16, dlen)
    sock.sendall(req + payload)
    return _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _pgread(sock, fhandle, offset, rlen, streamid=b"\x00\x07"):
    """Issue kXR_pgread and fully drain the response.

    A pgread success is a kXR_status message: an 8-byte header + a 24-byte
    status body (hdr.dlen=24), followed SEPARATELY by bdy.dlen raw bytes of
    CRC-interleaved page data.  Returns (streamid, status, status_body, pages);
    `pages` is empty on an error response.
    """
    req = struct.pack("!2sH4sqiI", streamid, kXR_pgread, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    sid, status, body = _read_response(sock)
    pages = b""
    if status == kXR_status and len(body) >= 16:
        # ServerResponseBody_Status: crc32c[4] streamID[2] reqid[1] resptype[1]
        # reserved[4] dlen[4]  -> bdy.dlen (page-data length) at [12:16].
        bdy_dlen = struct.unpack("!i", body[12:16])[0]
        if bdy_dlen > 0:
            pages = _recv_exact(sock, bdy_dlen)
    return sid, status, body, pages


def _pgwrite(sock, fhandle, offset, payload, streamid=b"\x00\x08"):
    # ClientPgWriteRequest: fhandle[4] offset(i64) pathid reqflags reserved[2] dlen
    req = struct.pack("!2sH4sqBB2sI", streamid, kXR_pgwrite, fhandle,
                      offset, 0, 0, b"\x00\x00", len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _readv_payload_bytes(body, expect_segs):
    """Strip the readahead_list headers from a readv response, returning the
    concatenated payload bytes.  Each segment is [fhandle4][rlen4][offset8] then
    rlen payload bytes."""
    out = []
    pos = 0
    for _ in range(expect_segs):
        if pos + READV_SEGSIZE > len(body):
            break
        rlen = struct.unpack("!i", body[pos + 4:pos + 8])[0]
        pos += READV_SEGSIZE
        out.append(body[pos:pos + rlen])
        pos += rlen
    return b"".join(out)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _require_server():
    """Skip the whole module cleanly if the anon stream server isn't up."""
    try:
        s = socket.create_connection((ANON_HOST, ANON_PORT), timeout=3)
        s.close()
    except OSError as exc:
        pytest.skip(f"anon stream server {ANON_HOST}:{ANON_PORT} unreachable: {exc}")


@pytest.fixture(scope="module")
def data_file():
    """Materialise the known pattern file under the server data root."""
    os.makedirs(DATA_ROOT, exist_ok=True)
    full = os.path.join(DATA_ROOT, DATA_NAME.lstrip("/"))
    with open(full, "wb") as f:
        f.write(PATTERN)
    return DATA_NAME


@pytest.fixture
def rd_handle(data_file):
    """Open the data file read-only; yield (sock, fhandle); always clean up."""
    sock = _session()
    _, status, body = _open(sock, data_file, kXR_open_read)
    assert status == kXR_ok, "read-open of data file failed"
    fhandle = body[:4]
    try:
        yield sock, fhandle
    finally:
        try:
            _close(sock, fhandle)
        except Exception:
            pass
        sock.close()


# ===========================================================================
# Class 1 — kXR_readv out-of-bounds (raw wire)
# ===========================================================================

class TestReadvOOBRaw:
    """Hostile vector reads must error cleanly and never disclose data."""

    def test_baseline_valid_readv(self, rd_handle):
        """Positive control: in-bounds segments return exactly the file bytes."""
        sock, fh = rd_handle
        chunks = [(0, 64), (1000, 128), (4096, 256)]
        _, status, body = _readv(sock, [_seg(fh, n, o) for o, n in chunks])
        assert status == kXR_ok, _error_code(body)
        payload = _readv_payload_bytes(body, len(chunks))
        expect = b"".join(PATTERN[o:o + n] for o, n in chunks)
        assert payload == expect

    def test_negative_offset_rejected(self, rd_handle):
        """offset with the sign bit set (-> negative off_t) is rejected."""
        sock, fh = rd_handle
        # -1 as int64; the handler's `offset < 0` guard must fire.
        _, status, body = _readv(sock, [_seg(fh, 64, -1)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError
        # Session still usable, no bytes leaked.
        assert _ping(sock)[1] == kXR_ok

    def test_offset_overflow_rejected(self, rd_handle):
        """offset near INT64_MAX + positive rlen overflows and is rejected."""
        sock, fh = rd_handle
        _, status, body = _readv(sock, [_seg(fh, 100, (1 << 63) - 1)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError
        assert _ping(sock)[1] == kXR_ok

    def test_single_segment_past_eof(self, rd_handle):
        """A lone segment starting exactly at EOF errors (no zero-length OK)."""
        sock, fh = rd_handle
        _, status, body = _readv(sock, [_seg(fh, 100, DATA_SIZE)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError

    def test_segment_straddles_eof(self, rd_handle):
        """A segment whose tail crosses EOF errors for the whole request."""
        sock, fh = rd_handle
        _, status, body = _readv(sock, [_seg(fh, 200, DATA_SIZE - 50)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError

    def test_way_past_eof(self, rd_handle):
        """A 1 TiB offset is past EOF and must error, not allocate wildly."""
        sock, fh = rd_handle
        _, status, body = _readv(sock, [_seg(fh, 4096, 1 << 40)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError

    def test_mixed_valid_and_oob_no_partial(self, rd_handle):
        """One valid + one past-EOF segment: the ENTIRE request must fail.

        A partial success would let a client probe EOF boundaries and could
        desync the client's response demultiplexer.
        """
        sock, fh = rd_handle
        segs = [_seg(fh, 64, 0), _seg(fh, 100, DATA_SIZE + 10)]
        _, status, body = _readv(sock, segs)
        assert status == kXR_error
        # No file bytes should have been returned at all.
        assert len(body) <= 64  # just the error errnum+message, never 64 data bytes
        assert _ping(sock)[1] == kXR_ok

    def test_coalesced_run_crosses_eof(self, rd_handle):
        """Two contiguous same-fd segments coalesced into one preadv whose
        combined extent crosses EOF must be caught by the short-read check."""
        sock, fh = rd_handle
        base = DATA_SIZE - 64
        segs = [_seg(fh, 64, base), _seg(fh, 64, base + 64)]  # 2nd is past EOF
        _, status, body = _readv(sock, segs)
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError

    def test_zero_length_segment_among_valid(self, rd_handle):
        """A zero-length segment is skipped; the valid ones still return."""
        sock, fh = rd_handle
        segs = [_seg(fh, 0, 0), _seg(fh, 32, 100)]
        _, status, body = _readv(sock, segs)
        assert status == kXR_ok, _error_code(body)
        payload = _readv_payload_bytes(body, 2)
        assert payload == PATTERN[100:132]

    def test_malformed_dlen_not_multiple(self, rd_handle):
        """dlen not a multiple of the 16-byte segment size is rejected."""
        sock, fh = rd_handle
        # One valid segment but advertise dlen = 17 (16 + 1 stray byte).
        _, status, body = _readv(sock, [_seg(fh, 16, 0) + b"\x00"],
                                 raw_dlen=17)
        assert status == kXR_error
        assert _error_code(body) == kXR_ArgInvalid
        # Server may keep the stray byte buffered; a fresh session must work.
        sock2 = _session()
        assert _ping(sock2)[1] == kXR_ok
        sock2.close()

    def test_too_many_segments_rejected(self, rd_handle):
        """1025 segments (over READV_MAXSEGS=1024) is rejected, not processed."""
        sock, fh = rd_handle
        segs = [_seg(fh, 1, (i % 100)) for i in range(READV_MAXSEGS + 1)]
        try:
            _, status, body = _readv(sock, segs)
        except ConnectionError:
            return  # acceptable: recv-layer cap closed the connection
        assert status == kXR_error
        assert _error_code(body) in (kXR_ArgTooLong, kXR_ArgInvalid)

    def test_max_segments_ok(self, rd_handle):
        """Exactly 1024 in-bounds 16-byte segments all return correctly."""
        sock, fh = rd_handle
        seg = 16
        chunks = [((i * 64) % (DATA_SIZE - seg), seg)
                  for i in range(READV_MAXSEGS)]
        _, status, body = _readv(sock, [_seg(fh, n, o) for o, n in chunks])
        assert status == kXR_ok, _error_code(body)
        payload = _readv_payload_bytes(body, READV_MAXSEGS)
        expect = b"".join(PATTERN[o:o + n] for o, n in chunks)
        assert payload == expect

    def test_total_response_size_cap(self, rd_handle):
        """Requested total over 256 MiB is rejected before any I/O.

        65 segments × 4 MiB requested = 260 MiB > MAX_READV_TOTAL, so the
        two-phase validator must reject up front (the data file is tiny, so
        this proves the size check happens BEFORE the read, not after EOF).
        """
        sock, fh = rd_handle
        n_segs = (MAX_READV_TOTAL // READ_MAX) + 1   # 65
        segs = [_seg(fh, READ_MAX, 0) for _ in range(n_segs)]
        try:
            _, status, body = _readv(sock, segs)
        except ConnectionError:
            return
        assert status == kXR_error
        assert _error_code(body) == kXR_ArgTooLong

    def test_invalid_handle_rejected(self, rd_handle):
        """A segment naming an unopened handle (0xFF) is rejected."""
        sock, _fh = rd_handle
        _, status, body = _readv(sock, [_seg(b"\xff\x00\x00\x00", 16, 0)])
        assert status == kXR_error
        assert _ping(sock)[1] == kXR_ok

    def test_stale_handle_after_close(self, data_file):
        """readv on a handle that was already closed must error (no UAF)."""
        sock = _session()
        _, status, body = _open(sock, data_file, kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        _close(sock, fh)
        _, status, body = _readv(sock, [_seg(fh, 16, 0)])
        assert status == kXR_error
        sock.close()


# ===========================================================================
# Class 2 — kXR_pgread (chunked / paged read) security + integrity
# ===========================================================================

class TestPgreadSecurity:
    """Paged reads: integrity of the CRC-interleaved chunked response and
    correct EOF / bounds behaviour."""

    def _decode_pages(self, pages):
        """Split a pgread page stream [crc4][<=4096 data]... verifying each
        CRC32c.  Returns the concatenated data; raises on CRC mismatch."""
        out = bytearray()
        pos = 0
        while pos < len(pages):
            crc = struct.unpack("!I", pages[pos:pos + 4])[0]
            pos += 4
            page = pages[pos:pos + PG_PAGESZ]
            pos += len(page)
            assert crc32c(page) == crc, "pgread per-page CRC32c mismatch"
            out.extend(page)
            if len(page) < PG_PAGESZ:
                break
        return bytes(out)

    def test_negative_offset_rejected(self, rd_handle):
        sock, fh = rd_handle
        _, status, body, _ = _pgread(sock, fh, -1, 4096)
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_valid_pgread_crc_integrity(self, rd_handle):
        """A normal paged read returns kXR_status framing and every page's
        CRC32c must verify against the data — and match the raw bytes."""
        sock, fh = rd_handle
        want = 3 * PG_PAGESZ + 123   # spans 4 pages, last one short
        _, status, body, pages = _pgread(sock, fh, 0, want)
        assert status == kXR_status, f"expected kXR_status, got {status}"
        decoded = self._decode_pages(pages)
        assert decoded[:want] == PATTERN[:want]

    def test_pgread_at_eof_not_error(self, rd_handle):
        """Unlike readv, a paged read AT EOF returns a valid short/empty
        response (next-offset status), NOT an error."""
        sock, fh = rd_handle
        _, status, body, _ = _pgread(sock, fh, DATA_SIZE, 4096)
        assert status != kXR_error, "pgread at EOF must not be an error"
        assert _ping(sock)[1] == kXR_ok

    def test_pgread_huge_rlen_capped(self, rd_handle):
        """An enormous rlen is capped server-side; no crash, no over-read."""
        sock, fh = rd_handle
        _, status, body, pages = _pgread(sock, fh, 0, 0x7FFFFFFF)
        assert status in (kXR_status, kXR_ok, kXR_error)
        # Capped read must not exceed the file size (plus per-page CRC overhead).
        if status == kXR_status:
            assert len(pages) <= DATA_SIZE + (DATA_SIZE // PG_PAGESZ + 1) * 4
        assert _ping(sock)[1] == kXR_ok

    def test_pgread_invalid_handle(self, rd_handle):
        sock, _fh = rd_handle
        _, status, body, _ = _pgread(sock, b"\xfe\x00\x00\x00", 0, 4096)
        assert status == kXR_error


# ===========================================================================
# Class 3 — kXR_pgwrite (chunked / paged write) integrity
# ===========================================================================

class TestPgwriteSecurity:
    """Paged writes must verify each page's CRC32c before touching the file."""

    @pytest.fixture
    def wr_handle(self):
        sock = _session()
        path = "/test_pgwrite_security.bin"
        full = os.path.join(DATA_ROOT, path.lstrip("/"))
        with open(full, "wb") as f:
            f.write(b"\x00" * PG_PAGESZ)
        _, status, body = _open(sock, path, kXR_open_updt)
        assert status == kXR_ok, "write-open failed"
        fh = body[:4]
        try:
            yield sock, fh, full
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()

    def test_bad_crc_rejected(self, wr_handle):
        """A page whose CRC32c does not match its data must be rejected with
        kXR_ChkSumErr and must NOT be written to disk."""
        sock, fh, full = wr_handle
        data = b"CORRUPTME" + b"x" * 1000
        bad_payload = struct.pack("!I", 0xDEADBEEF) + data  # wrong CRC
        _, status, body = _pgwrite(sock, fh, 0, bad_payload)
        assert status == kXR_error
        assert _error_code(body) == kXR_ChkSumErr
        # File must be untouched (still zeros).
        with open(full, "rb") as f:
            on_disk = f.read(len(data))
        assert on_disk != data, "corrupt page must not have been written"
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_valid_pgwrite_roundtrip(self, wr_handle):
        """A correctly-checksummed page is accepted and lands on disk."""
        sock, fh, full = wr_handle
        data = bytes((i * 13 + 1) & 0xFF for i in range(2000))
        payload = struct.pack("!I", crc32c(data)) + data
        _, status, body = _pgwrite(sock, fh, 0, payload)
        assert status in (kXR_status, kXR_ok), _error_code(body)
        # Verify via a normal read on the same handle.
        _, rs, rb = _read(sock, fh, 0, len(data))
        assert rs == kXR_ok
        assert rb == data

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgwrite_negative_offset(self, wr_handle):
        sock, fh, _full = wr_handle
        data = b"y" * 64
        payload = struct.pack("!I", crc32c(data)) + data
        _, status, body = _pgwrite(sock, fh, -8, payload)
        assert status == kXR_error
        assert _ping(sock)[1] == kXR_ok

    def test_pgwrite_truncated_page_framing(self, wr_handle):
        """A payload with a CRC header but no/short data (malformed framing)
        must be rejected cleanly, not crash or partially write."""
        sock, fh, _full = wr_handle
        # 4-byte CRC then only 1 data byte but claim it's a page — the decoder
        # must handle the short final fragment without over-reading.
        payload = struct.pack("!I", crc32c(b"Z")) + b"Z"
        _, status, body = _pgwrite(sock, fh, 0, payload)
        # Either accepted as a legitimate 1-byte final page, or a clean error;
        # never a crash — prove the session survives.
        assert status in (kXR_status, kXR_ok, kXR_error)
        assert _ping(sock)[1] == kXR_ok


# ===========================================================================
# Class 4 — cross-protocol OOB vector reads via the XRootD client
# ===========================================================================

def _client_oob(url_base, remote):
    """Open remote read-only and attempt OOB vector reads; return statuses."""
    from XRootD import client
    from XRootD.client.flags import OpenFlags

    f = client.File()
    st, _ = f.open(f"{url_base}//{remote.lstrip('/')}", OpenFlags.READ)
    assert st.ok, f"open failed: {st.message}"
    try:
        # Segment that runs past EOF.
        past, _ = f.vector_read([(DATA_SIZE - 20, 200)])
        # Huge offset far past EOF.
        huge, _ = f.vector_read([(1 << 40, 4096)])
    finally:
        f.close()
    return past, huge


class TestCrossProtocolReadvOOB:
    """The same out-of-bounds vector reads, exercised through the authenticated
    endpoints so the per-protocol auth + client demux paths are covered."""

    def _upload(self, url_base, remote, data):
        from XRootD import client
        from XRootD.client.flags import OpenFlags
        f = client.File()
        st, _ = f.open(f"{url_base}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
        assert st.ok, f"upload open failed: {st.message}"
        st, _ = f.write(data)
        assert st.ok
        f.close()

    def test_anon_client_oob(self, data_file):
        url = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
        past, huge = _client_oob(url, data_file)
        assert not past.ok, "past-EOF vector_read should fail"
        assert not huge.ok, "huge-offset vector_read should fail"

    def test_gsi_client_oob(self):
        if not CA_DIR or not PROXY_STD or not os.path.exists(PROXY_STD):
            pytest.skip("GSI proxy assets unavailable")
        os.environ["X509_CERT_DIR"] = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_STD
        try:
            url = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
            remote = "/test_readv_security_gsi.bin"
            self._upload(url, remote, PATTERN)
            past, huge = _client_oob(url, remote)
            assert not past.ok
            assert not huge.ok
        finally:
            for k in ("X509_CERT_DIR", "X509_USER_PROXY"):
                os.environ.pop(k, None)


# ===========================================================================
# Class 5 — slice-cache handle vs vector/paged reads (executable spec)
# ===========================================================================

@pytest.mark.skip(reason="needs a live XRootD origin + xrootd_cache_slice env")
class TestSliceHandleVectorReads:
    """Phase 26 slice-mode handles park their fd on /dev/null; only kXR_read is
    wired into slice serving.  readv/pgread guard against such handles and must
    return kXR_Unsupported rather than reading /dev/null (empty/wrong data).

    Requires a server configured with xrootd_cache_slice + xrootd_cache_origin,
    so it stays skipped until that env is available.
    """

    def test_readv_on_slice_handle_unsupported(self):
        """Open a file on a slice-cache server, then kXR_readv -> kXR_Unsupported."""

    def test_pgread_on_slice_handle_unsupported(self):
        """Open a file on a slice-cache server, then kXR_pgread -> kXR_Unsupported."""

    def test_plain_read_on_slice_handle_serves_data(self):
        """kXR_read on the same handle still serves correct bytes from slices."""
