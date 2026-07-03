"""
tests/test_pgread_wire_conformance.py — raw-wire kXR_pgread (3030) protocol
conformance.

This suite verifies that the paged-read opcode emitted by the nginx-xrootd
stream module is byte- and frame-faithful to the XRootD wire spec
(/tmp/brix-src/src/XProtocol/XProtocol.hh).  Every request is built by hand
over a raw TCP socket — the high-level XRootD python client sanitises
offsets/lengths and re-frames the chunked response before it is observable, so
only raw framing can prove the on-the-wire contract.  We assert: the success
response uses kXR_status (4007) framing (8-byte ServerResponseHeader followed,
as a SEPARATE network unit, by the CRC-interleaved page data); each page is
prefixed by its own standard CRC32c (Castagnoli, reflected poly 0x82F63B78)
which must recompute locally; sub-page / unaligned first pages, a single page,
a zero-length read, and reads at/near EOF behave correctly; pgread bytes equal
a plain kXR_read of the same extent; an over-large rlen is capped server-side;
and bad/stale handles and negative offsets produce clean protocol errors.  Each
hostile/edge request is followed by a sanity op (ping or a valid read) proving
the session survived.  Runs against the shared anon stream fleet
(root://localhost:11094); skips cleanly if it is unreachable or if the server's
data root is not locally writable.

Wire structs verified against XProtocol.hh:
  * ClientPgReadRequest  (line 540): streamid[2] requestid(u16) fhandle[4]
                                     offset(i64) rlen(i32) dlen(i32)
  * ClientReadRequest    (line 678): same layout as pgread
  * ClientOpenRequest    (line 509): streamid[2] requestid mode options optiont
                                     reserved[6] fhtemplt[4] dlen
  * ServerResponseHeader (line 955): streamid[2] status(u16) dlen(i32)
  * ServerResponseBody_Status (line 1277): crc32c(u32) streamID[2] requestid(1)
                                     resptype(1) reserved[4] dlen(i32)
                                     -> bdy.dlen at body[12:16], min len 16

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_pgread_wire_conformance.py -v
"""

import os
import socket
import struct

import pytest

from settings import (
    DATA_ROOT,
    NGINX_ANON_PORT,
    SERVER_HOST,
)


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (src/protocols/root/protocol/opcodes.h, XProtocol.hh)
# ---------------------------------------------------------------------------

kXR_login   = 3007
kXR_open    = 3010
kXR_ping    = 3011
kXR_read    = 3013
kXR_close   = 3003
kXR_pgread  = 3030

kXR_ok      = 0
kXR_error   = 4003
kXR_status  = 4007            # pgread/pgwrite extended-status response framing

kXR_ArgInvalid = 3000
kXR_IOError    = 3007

kXR_open_read = 0x0010

PG_PAGESZ = 4096              # kXR_pgPageSZ
# ServerResponseBody_Status: crc32c[4] streamID[2] requestid[1] resptype[1]
# reserved[4] dlen[4]  -> bdy.dlen (page-data byte count) lives at body[12:16],
# so the minimum status body length is 16 bytes.
STATUS_BODY_DLEN_OFF = 12
STATUS_BODY_MIN_LEN = STATUS_BODY_DLEN_OFF + 4

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT

# Known data file.  Size is deliberately NOT a page multiple so the final page
# is short, and starts off-page-boundary tests have headroom.  ~70 KiB => 18
# pages (17 full + one 1456-byte tail).
DATA_NAME = "/test_pgread_wire_conformance.bin"
DATA_SIZE = 70000
PATTERN   = bytes((i * 31 + 7) & 0xFF for i in range(DATA_SIZE))


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — pure-Python, matches brix_crc32c_copy()
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


# Self-test against the canonical RFC check value; a wrong table would make the
# CRC-integrity assertions falsely fail, so those cases skip if this trips.
_CRC32C_OK = crc32c(b"123456789") == 0xE3069283


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror tests/test_readv_security.py exactly)
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
    # ClientLoginRequest: streamid[2] requestid(u16) pid(i32) username[8]
    # ability2(1) ability(1) capver[1] reserved2(1) dlen(i32).
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
    # ClientOpenRequest: streamid[2] requestid(u16) mode(u16) options(u16)
    # optiont(u16) reserved[6] fhtemplt[4] dlen(i32).
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    # ClientCloseRequest: streamid[2] requestid(u16) fhandle[4] reserved[12] dlen.
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    # ClientPingRequest: streamid[2] requestid(u16) reserved[16] dlen.
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    """Plain kXR_read; returns (streamid, status, body).

    ClientReadRequest: streamid[2] requestid(u16) fhandle[4] offset(i64)
    rlen(i32) dlen(i32=0).
    """
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _pgread(sock, fhandle, offset, rlen, streamid=b"\x00\x07"):
    """Issue kXR_pgread and fully drain the response.

    ClientPgReadRequest: streamid[2] requestid(u16) fhandle[4] offset(i64)
    rlen(i32) dlen(i32=0, no args).

    A pgread success is a kXR_status message: an 8-byte ServerResponseHeader +
    a status body (hdr.dlen bytes), followed SEPARATELY on the wire by
    bdy.dlen raw bytes of CRC-interleaved page data.  Returns
    (streamid, status, status_body, pages); `pages` is empty on error.
    """
    req = struct.pack("!2sH4sqiI", streamid, kXR_pgread, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    sid, status, body = _read_response(sock)
    pages = b""
    if status == kXR_status and len(body) >= STATUS_BODY_MIN_LEN:
        bdy_dlen = struct.unpack(
            "!i", body[STATUS_BODY_DLEN_OFF:STATUS_BODY_DLEN_OFF + 4])[0]
        if bdy_dlen > 0:
            pages = _recv_exact(sock, bdy_dlen)
    return sid, status, body, pages


def _decode_pages(pages, first_offset=0):
    """Split a pgread page stream into bytes, verifying each CRC32c.

    Wire layout per page unit: crc32c(u32 BE)[4] + up to 4096 data bytes.  The
    FIRST page may be short when `first_offset` is not page-aligned (the page
    boundary is absolute file-offset based), so its length is bounded by the
    distance to the next 4 KiB boundary.  Returns the concatenated data;
    asserts on any CRC mismatch.  A short page (< its cap) is the final unit
    and terminates decoding — this also makes the loop robust against a
    truncated final fragment from a non-conformant server.
    """
    out = bytearray()
    pos = 0
    abs_off = first_offset
    first = True
    while pos + 4 <= len(pages):
        crc = struct.unpack("!I", pages[pos:pos + 4])[0]
        pos += 4
        if first and (abs_off % PG_PAGESZ):
            cap = PG_PAGESZ - (abs_off % PG_PAGESZ)
        else:
            cap = PG_PAGESZ
        page = pages[pos:pos + cap]
        pos += len(page)
        assert crc32c(page) == crc, "pgread per-page CRC32c mismatch"
        out.extend(page)
        abs_off += len(page)
        first = False
        if len(page) < cap:
            break
    return bytes(out)


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
        pytest.skip(f"anon stream server {ANON_HOST}:{ANON_PORT} "
                    f"unreachable: {exc}")


@pytest.fixture(scope="module")
def data_file():
    """Materialise the known pattern file under the server data root.

    Skips (rather than errors) when the data root is not locally writable —
    e.g. when pointed at a remote TEST_SERVER_HOST whose filesystem this
    process cannot reach.
    """
    try:
        os.makedirs(DATA_ROOT, exist_ok=True)
        full = os.path.join(DATA_ROOT, DATA_NAME.lstrip("/"))
        with open(full, "wb") as f:
            f.write(PATTERN)
    except OSError as exc:
        pytest.skip(f"server data root {DATA_ROOT!r} not locally writable: "
                    f"{exc}")
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
# kXR_pgread wire-conformance
# ===========================================================================

class TestPgreadWireConformance:
    """Frame, CRC, EOF, parity, cap, and error behaviour of kXR_pgread."""

    def test_status_4007_framing(self, rd_handle):
        """A successful pgread returns kXR_status (4007) with a status body
        whose embedded bdy.dlen equals the number of page-data bytes that
        actually follow on the wire.

        This is the core framing invariant: ServerResponseHeader.dlen covers
        the fixed status body; the CRC-interleaved page data is a SEPARATE
        network unit sized by bdy.dlen at body[12:16].
        """
        sock, fh = rd_handle
        want = PG_PAGESZ + 100          # one full page + part of a second
        sid, status, body, pages = _pgread(sock, fh, 0, want, streamid=b"\x00\x21")
        assert status == kXR_status, f"expected kXR_status(4007), got {status}"
        # Header dlen (= len(body)) must cover at least the fixed status body
        # (crc32c+streamID+requestid+resptype+reserved+dlen = 16 bytes).
        assert len(body) >= STATUS_BODY_MIN_LEN, "status body too short"
        bdy_dlen = struct.unpack(
            "!i", body[STATUS_BODY_DLEN_OFF:STATUS_BODY_DLEN_OFF + 4])[0]
        # The bytes we drained as page data must match the advertised count.
        assert bdy_dlen == len(pages), (
            f"bdy.dlen={bdy_dlen} but {len(pages)} page bytes followed")
        # Echoed stream id must match what we sent.
        assert sid == b"\x00\x21", f"stream id mismatch: {sid!r}"
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_per_page_crc32c_matches_recompute(self, rd_handle):
        """Every per-page CRC32c on the wire recomputes to the same value with
        a local Castagnoli implementation, and the decoded payload is exactly
        the file bytes."""
        sock, fh = rd_handle
        want = 3 * PG_PAGESZ + 123       # 4 pages, last short
        _, status, body, pages = _pgread(sock, fh, 0, want, streamid=b"\x00\x22")
        assert status == kXR_status, f"expected kXR_status, got {status}"
        decoded = _decode_pages(pages, first_offset=0)
        assert decoded[:want] == PATTERN[:want]
        # Belt-and-braces: at least one full page must have been returned, so
        # the CRC check above was non-trivial.
        assert len(decoded) >= PG_PAGESZ

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_sub_page_unaligned_first_page_crc(self, rd_handle):
        """A read starting at a NON-page-aligned offset yields a short first
        page (only up to the next 4 KiB boundary) whose CRC32c still verifies.

        Per spec the CRC is computed over the actual page bytes, and page
        boundaries are absolute-file-offset based — so the first unit here is
        (PG_PAGESZ - 100) bytes, not a full page."""
        sock, fh = rd_handle
        off = 100                        # 100 bytes into page 0
        want = PG_PAGESZ                 # spills into page 1
        _, status, body, pages = _pgread(sock, fh, off, want, streamid=b"\x00\x23")
        assert status == kXR_status, f"expected kXR_status, got {status}"
        assert len(pages) >= 4, "no page unit returned for unaligned read"
        # First page unit must be the short remainder of page 0.
        first_crc = struct.unpack("!I", pages[:4])[0]
        first_cap = PG_PAGESZ - (off % PG_PAGESZ)
        first_page = pages[4:4 + first_cap]
        assert crc32c(first_page) == first_crc, "unaligned first-page CRC bad"
        decoded = _decode_pages(pages, first_offset=off)
        assert decoded[:want] == PATTERN[off:off + want]
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_single_page_and_zero_length(self, rd_handle):
        """A single-page read returns exactly one CRC-prefixed page; a
        zero-length read returns a clean status with no page bytes (and never
        errors or hangs)."""
        sock, fh = rd_handle

        # --- single page ---
        _, status, body, pages = _pgread(sock, fh, 0, PG_PAGESZ, streamid=b"\x00\x24")
        assert status == kXR_status, f"single-page: expected status, got {status}"
        # One page unit = 4 CRC bytes + 4096 data bytes.
        assert len(pages) == 4 + PG_PAGESZ, f"single-page wire size {len(pages)}"
        decoded = _decode_pages(pages, first_offset=0)
        assert decoded == PATTERN[:PG_PAGESZ]

        # --- zero length ---
        _, status0, body0, pages0 = _pgread(sock, fh, 0, 0, streamid=b"\x00\x25")
        # A zero-length paged read must not be an error; no page data follows.
        assert status0 != kXR_error, "zero-length pgread must not error"
        assert pages0 == b"", "zero-length pgread returned page bytes"
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_eof_short_final_page(self, rd_handle):
        """A read whose extent ends at EOF yields a correctly-sized short final
        page; reading exactly the file size returns all bytes and stops, never
        padding to a full page or over-reading."""
        sock, fh = rd_handle
        # Start two pages before EOF so we straddle the last full->short boundary.
        off = (DATA_SIZE // PG_PAGESZ - 1) * PG_PAGESZ
        want = DATA_SIZE - off           # to exactly EOF
        _, status, body, pages = _pgread(sock, fh, off, want, streamid=b"\x00\x26")
        assert status == kXR_status, f"expected kXR_status, got {status}"
        decoded = _decode_pages(pages, first_offset=off)
        assert decoded == PATTERN[off:DATA_SIZE], "EOF tail bytes wrong"
        # The decoded length must not exceed what the file holds from `off`.
        assert len(decoded) == DATA_SIZE - off
        assert _ping(sock)[1] == kXR_ok

    def test_pgread_at_eof_not_error(self, rd_handle):
        """A paged read starting exactly AT EOF returns a valid (empty/short)
        status response, NOT an error — unlike readv."""
        sock, fh = rd_handle
        _, status, body, pages = _pgread(sock, fh, DATA_SIZE, PG_PAGESZ,
                                         streamid=b"\x00\x27")
        assert status != kXR_error, "pgread at EOF must not be an error"
        assert pages == b"", "no data should follow at EOF"
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgread_equals_plain_read(self, rd_handle):
        """The payload decoded from a pgread must be byte-exact with a plain
        kXR_read of the same (offset, length) — pgread only adds integrity
        framing, never alters the data."""
        sock, fh = rd_handle
        off, want = 8192, 2 * PG_PAGESZ + 777
        _, rs, rb = _read(sock, fh, off, want)
        assert rs == kXR_ok, f"plain read failed: {_error_code(rb)}"
        _, ps, _body, pages = _pgread(sock, fh, off, want, streamid=b"\x00\x28")
        assert ps == kXR_status, f"pgread failed: {ps}"
        decoded = _decode_pages(pages, first_offset=off)
        assert decoded == rb, "pgread payload != plain read payload"
        assert decoded == PATTERN[off:off + want]

    def test_huge_rlen_capped(self, rd_handle):
        """An enormous rlen (INT32_MAX) is capped server-side to the available
        file bytes — no crash, no over-read, no wild allocation."""
        sock, fh = rd_handle
        _, status, body, pages = _pgread(sock, fh, 0, 0x7FFFFFFF,
                                         streamid=b"\x00\x29")
        # pgread success is kXR_status; tolerate a plain status or a clean
        # error so an implementation choosing to reject the oversize request
        # is not hard-failed — the property under test is "no over-read".
        assert status in (kXR_status, kXR_ok, kXR_error)
        if status == kXR_status:
            # Page data <= file size + per-page CRC overhead (4 bytes/page).
            max_pages = DATA_SIZE // PG_PAGESZ + 1
            assert len(pages) <= DATA_SIZE + max_pages * 4, (
                f"capped pgread returned {len(pages)} bytes, over-read")
            if _CRC32C_OK and pages:
                decoded = _decode_pages(pages, first_offset=0)
                assert decoded == PATTERN[:len(decoded)]
        assert _ping(sock)[1] == kXR_ok

    def test_invalid_handle_rejected(self, rd_handle):
        """pgread on a never-opened handle (0xFE) must produce a clean protocol
        error and leave the session usable."""
        sock, _fh = rd_handle
        _, status, body, pages = _pgread(sock, b"\xfe\x00\x00\x00", 0, PG_PAGESZ,
                                         streamid=b"\x00\x2a")
        assert status == kXR_error, "invalid handle must error"
        assert pages == b"", "no page data on error"
        assert _ping(sock)[1] == kXR_ok

    def test_stale_handle_after_close(self, data_file):
        """pgread on a handle closed mid-session must error (no use-after-free),
        and the connection must stay alive for further requests."""
        sock = _session()
        try:
            _, status, body = _open(sock, data_file, kXR_open_read)
            assert status == kXR_ok
            fh = body[:4]
            _close(sock, fh)
            _, st, _b, pages = _pgread(sock, fh, 0, PG_PAGESZ, streamid=b"\x00\x2b")
            assert st == kXR_error, "pgread on closed handle must error"
            assert pages == b""
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_negative_offset_ioerror(self, rd_handle):
        """A negative offset (sign bit set in the i64) must be rejected with a
        clean error — the documented mapping is kXR_IOError; we accept any
        clean protocol error but assert IOError/ArgInvalid when reported."""
        sock, fh = rd_handle
        _, status, body, pages = _pgread(sock, fh, -1, PG_PAGESZ,
                                         streamid=b"\x00\x2c")
        assert status == kXR_error, "negative offset must error"
        assert pages == b"", "no data should leak on negative offset"
        # Documented errno->kXR mapping: negative seek -> EINVAL/EIO -> IOError.
        code = _error_code(body)
        assert code in (kXR_IOError, kXR_ArgInvalid), (
            f"unexpected error code {code} for negative offset")
        assert _ping(sock)[1] == kXR_ok
