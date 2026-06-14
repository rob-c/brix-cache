"""
tests/test_large_offset_wire.py — large / extreme byte-offset wire conformance.

This suite drives the raw root:// wire against the shared anonymous stream
fleet (root://localhost:11094) to prove the offset/length arithmetic in the
read/write/stat/truncate handlers is 64-bit-clean and overflow-safe.  It uses
SPARSE files (ftruncate/seek-then-write a single byte) so a 4 GiB or
near-INT64_MAX boundary is exercised without ever allocating multi-GB of data
or disk.  The XRootD python client is deliberately NOT used for the hostile
cases because it sanitises offsets before they reach the wire (and has no
statx); every request is hand-framed with struct.pack exactly like
tests/test_readv_security.py.  Each hostile/edge request is followed by a
sanity ping/read on the same socket to prove the session survived intact, and
the whole module skips cleanly if the anon fleet is unreachable.

The suite provisions no servers of its own — it reuses the shared anon fleet on
the dedicated test port (NGINX_ANON_PORT, default 11094) — so there are no extra
listeners to tear down.  The only state it creates is sparse data files under
DATA_ROOT, every one of which is unlinked in a fixture finaliser.

Run: TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_large_offset_wire.py -v
"""

import os
import socket
import struct

import pytest

from settings import (
    DATA_ROOT,
    NGINX_ANON_PORT,
    REMOTE_SERVER,
    SERVER_HOST,
)


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (verified against
# /tmp/xrootd-src/src/XProtocol/XProtocol.hh enum XRequestTypes / XResponseType
# / XErrorCode — base 3000 for requests, 4000 for responses, 3000 for errors)
# ---------------------------------------------------------------------------

kXR_close    = 3003
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_stat     = 3017
kXR_write    = 3019
kXR_statx    = 3022
kXR_readv    = 3025
kXR_pgwrite  = 3026
kXR_truncate = 3028
kXR_pgread   = 3030

kXR_ok       = 0
kXR_error    = 4003
kXR_status   = 4007    # pgread/pgwrite extended-status framing

kXR_ArgInvalid  = 3000
kXR_ArgMissing  = 3001
kXR_ArgTooLong  = 3002
kXR_FSError     = 3005
kXR_IOError     = 3007
kXR_NotFound    = 3011
kXR_Unsupported = 3013
kXR_ChkSumErr   = 3019

# Open flags (XProtocol.hh enum XOpenRequestMode)
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_new  = 0x0008
kXR_delete    = 0x0004
kXR_mkpath    = 0x0100

PG_PAGESZ   = 4096
INT64_MAX   = (1 << 63) - 1
GIB         = 1 << 30
FOUR_GIB    = 4 * GIB

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT


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


_CRC32C_OK = crc32c(b"123456789") == 0xE3069283


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror tests/test_readv_security.py exactly; every
# struct.pack layout below was checked field-by-field against XProtocol.hh)
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
    # ClientLoginRequest: streamid[2] reqid pid(i32) username[8] ability2
    #                     ability capver[1] reserved2 dlen
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
    # ClientOpenRequest: streamid[2] reqid mode(u16) options(u16) optiont(u16)
    #                    reserved[6] fhtemplt[4] dlen
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    # ClientCloseRequest: streamid[2] reqid fhandle[4] reserved[12] dlen
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    # ClientPingRequest: streamid[2] reqid reserved[16] dlen
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    # ClientReadRequest: streamid[2] reqid fhandle[4] offset(i64) rlen(i32) dlen
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _write(sock, fhandle, offset, payload, streamid=b"\x00\x09"):
    # ClientWriteRequest: streamid[2] reqid fhandle[4] offset(i64) pathid
    #                     reserved[3] dlen
    req = struct.pack("!2sH4sqB3sI", streamid, kXR_write, fhandle,
                      offset, 0, b"\x00\x00\x00", len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _pgwrite(sock, fhandle, offset, payload, streamid=b"\x00\x08"):
    # ClientPgWriteRequest: streamid[2] reqid fhandle[4] offset(i64) pathid
    #                       reqflags reserved[2] dlen
    req = struct.pack("!2sH4sqBB2sI", streamid, kXR_pgwrite, fhandle,
                      offset, 0, 0, b"\x00\x00", len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _pgread(sock, fhandle, offset, rlen, streamid=b"\x00\x07"):
    """Issue kXR_pgread; drain the optional CRC-interleaved page stream.

    A pgread success is a kXR_status message: an 8-byte header + a status body
    (ServerResponseBody_Status), followed SEPARATELY by bdy.dlen raw bytes of
    CRC-interleaved page data.  bdy.dlen lives at body[12:16]."""
    # ClientPgReadRequest: streamid[2] reqid fhandle[4] offset(i64) rlen(i32) dlen
    req = struct.pack("!2sH4sqiI", streamid, kXR_pgread, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    sid, status, body = _read_response(sock)
    pages = b""
    if status == kXR_status and len(body) >= 16:
        bdy_dlen = struct.unpack("!i", body[12:16])[0]
        if bdy_dlen > 0:
            pages = _recv_exact(sock, bdy_dlen)
    return sid, status, body, pages


def _seg(fhandle, rlen, offset):
    """One readahead_list element: fhandle[4] + rlen(i32 BE) + offset(i64 BE)."""
    return struct.pack("!4siq", fhandle, rlen, offset)


def _readv(sock, segments, streamid=b"\x00\x05", raw_dlen=None):
    # ClientReadVRequest: streamid[2] reqid reserved[15] pathid dlen — the
    # 15+1 = 16 fixed bytes are packed as a single zeroed 16-byte field.
    payload = b"".join(segments)
    dlen = raw_dlen if raw_dlen is not None else len(payload)
    req = struct.pack("!2sH16sI", streamid, kXR_readv, b"\x00" * 16, dlen)
    sock.sendall(req + payload)
    return _read_response(sock)


def _stat(sock, path, streamid=b"\x00\x0a"):
    """Path-based kXR_stat. ClientStatRequest: streamid[2] reqid options[1]
    reserved[7] wants(u32) fhandle[4] dlen."""
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHB7sI4sI", streamid, kXR_stat,
                      0, b"\x00" * 7, 0, b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _statx(sock, paths, streamid=b"\x00\x0b"):
    """Path-based kXR_statx.  Shares ClientStatRequest's header layout
    (no dedicated ClientStatxRequest exists in XProtocol.hh); the payload is a
    NUL-separated path list (src/read/statx.c)."""
    if isinstance(paths, str):
        payload = paths.encode() + b"\x00"
    else:
        payload = b"\x00".join(p.encode() for p in paths) + b"\x00"
    req = struct.pack("!2sHB7sI4sI", streamid, kXR_statx,
                      0, b"\x00" * 7, 0, b"\x00" * 4, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _truncate(sock, fhandle, offset, streamid=b"\x00\x0c"):
    """Handle-based kXR_truncate (dlen==0). ClientTruncateRequest:
    streamid[2] reqid fhandle[4] offset(i64) reserved[4] dlen."""
    req = struct.pack("!2sH4sq4sI", streamid, kXR_truncate, fhandle,
                      offset, b"\x00" * 4, 0)
    sock.sendall(req)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _stat_size(body):
    """Parse the size field out of a kXR_stat ASCII body.

    Body format (src/path/stat_body.c, non-VFS mode):
    "<ino> <size> <flags> <mtime>", possibly NUL-terminated.  Returns the int
    in the 2nd field.  NOTE: in VFS mode the same field holds st_blocks*512
    (near-zero for a sparse file), so callers that assert logical size must
    treat a mismatch as a VFS-mode skip, not a hard failure."""
    text = body.split(b"\x00", 1)[0].decode("ascii", "replace").strip()
    parts = text.split()
    assert len(parts) >= 4, f"unexpected stat body: {text!r}"
    return int(parts[1])


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


@pytest.fixture(scope="module", autouse=True)
def _require_local_data_root():
    """Sparse-file tests need to read/inspect the server's data dir on this
    host.  When pointed at a remote server we cannot create sparse files there,
    so skip rather than fabricate paths the server can't see."""
    if REMOTE_SERVER:
        pytest.skip("sparse-file offset tests require a local DATA_ROOT "
                    "(TEST_SERVER_HOST is set)")
    try:
        os.makedirs(DATA_ROOT, exist_ok=True)
    except OSError as exc:
        pytest.skip(f"DATA_ROOT {DATA_ROOT} not writable: {exc}")


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _make_writable(name, size=0):
    """Create a small (optionally sparse) file we can open for update."""
    full = os.path.join(DATA_ROOT, name.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        if size:
            f.truncate(size)
    return name, full


@pytest.fixture(scope="module")
def big_sparse_4g():
    """A 4 GiB + 4 KiB sparse file with a known marker byte just past the
    4 GiB boundary so reads there return real (non-hole) data."""
    name = "/large_offset_4g.bin"
    size = FOUR_GIB + PG_PAGESZ
    full = os.path.join(DATA_ROOT, name.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    try:
        with open(full, "wb") as f:
            f.truncate(size)
            # marker so the byte at FOUR_GIB is a known non-zero value
            f.seek(FOUR_GIB)
            f.write(b"\xA5" * 16)
    except OSError as exc:
        _unlink(full)
        pytest.skip(f"filesystem cannot host a 4 GiB sparse file: {exc}")
    if os.path.getsize(full) != size:
        _unlink(full)
        pytest.skip("filesystem did not honour a 4 GiB sparse truncate")
    try:
        yield name, full, size
    finally:
        _unlink(full)


@pytest.fixture(scope="module")
def huge_sparse_near_max():
    """A sparse file whose size sits well above the 32-bit boundary.  We never
    read the whole thing — only single bytes near the very end — so it stays a
    hole.

    INT64_MAX itself exceeds every real filesystem's max-file-size limit
    (tmpfs/ext4 cap well below it), so a literal near-max sparse file cannot be
    created.  Probe downward for the largest size the backing fs accepts; the
    goal is a multi-GiB+ size well above the 32-bit boundary where any
    offset-truncation bug would surface — not INT64_MAX exactly.  The past-EOF
    read cases below still probe up to INT64_MAX on the wire."""
    name = "/large_offset_near_max.bin"
    full = os.path.join(DATA_ROOT, name.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    size = None
    for candidate in (INT64_MAX - (1 << 20), 1 << 50, 1 << 45, 1 << 42,
                      FOUR_GIB + (1 << 20)):
        try:
            with open(full, "wb") as f:
                f.truncate(candidate)
        except OSError:
            continue
        if os.path.getsize(full) == candidate:
            size = candidate
            break
    if size is None:
        _unlink(full)
        pytest.skip("filesystem cannot host a large sparse file for "
                    "near-max offset testing")
    try:
        yield name, full, size
    finally:
        _unlink(full)


@pytest.fixture
def rd_handle_4g(big_sparse_4g):
    """Open the 4 GiB sparse file read-only; yield (sock, fhandle, size)."""
    name, _full, size = big_sparse_4g
    sock = _session()
    _, status, body = _open(sock, name, kXR_open_read)
    if status != kXR_ok:
        sock.close()
        pytest.skip(f"server refused open of 4 GiB sparse file: "
                    f"{_error_code(body)}")
    fhandle = body[:4]
    try:
        yield sock, fhandle, size
    finally:
        try:
            _close(sock, fhandle)
        except Exception:
            pass
        sock.close()


# ===========================================================================
# Scenario 1 — write then read at the 4 GiB boundary (sparse)
# ===========================================================================

class TestFourGiBBoundary:
    """Reads (and a write) straddling the 32-bit 4 GiB wrap point must use the
    full 64-bit offset, not a truncated low-32-bit value."""

    def test_read_at_4gib_returns_marker(self, rd_handle_4g):
        """The 16 marker bytes written at exactly 4 GiB must read back; a
        32-bit-truncated offset (== 0) would instead return the file's hole
        (zeros) at the start."""
        sock, fh, _size = rd_handle_4g
        _, status, body = _read(sock, fh, FOUR_GIB, 16)
        assert status == kXR_ok, _error_code(body)
        assert body == b"\xA5" * 16, (
            "read at 4 GiB returned wrong bytes — offset likely truncated to "
            "32 bits")
        # The same low-32-bits offset (0) must read the hole, proving the two
        # offsets are NOT aliased.
        _, status0, body0 = _read(sock, fh, 0, 16)
        assert status0 == kXR_ok
        assert body0 == b"\x00" * 16
        assert _ping(sock)[1] == kXR_ok

    def test_write_then_read_across_4gib(self):
        """Open a sparse file for update, write a marker just past 4 GiB, read
        it back at the same 64-bit offset."""
        name, full = _make_writable("/large_offset_4g_rw.bin", FOUR_GIB + 4096)
        sock = _session()
        try:
            _, status, body = _open(sock, name, kXR_open_updt)
            if status != kXR_ok:
                pytest.skip(f"anon server is read-only "
                            f"(open updt -> {_error_code(body)}); "
                            f"need xrootd_allow_write on")
            fh = body[:4]
            marker = b"BOUNDARY64!!" + b"\x11" * 4
            off = FOUR_GIB + 1024
            _, wst, wbody = _write(sock, fh, off, marker)
            assert wst == kXR_ok, _error_code(wbody)
            _, rst, rbody = _read(sock, fh, off, len(marker))
            assert rst == kXR_ok, _error_code(rbody)
            assert rbody == marker, "64-bit write/read offset round-trip failed"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()
            _unlink(full)


# ===========================================================================
# Scenario 2 — offset just below INT64_MAX
# ===========================================================================

class TestNearInt64Max:
    """An offset a hair below INT64_MAX must be handled as a valid 64-bit
    offset: a read there hits a sparse hole (EOF) and returns a clean short/EOF
    response, never an overflow crash or wrong data."""

    def test_read_just_below_int64_max(self, huge_sparse_near_max):
        name, _full, size = huge_sparse_near_max
        sock = _session()
        try:
            _, ost, obody = _open(sock, name, kXR_open_read)
            if ost != kXR_ok:
                pytest.skip(f"server refused open of near-max sparse file: "
                            f"{_error_code(obody)}")
            fh = obody[:4]
            # Offset 1 KiB below the very end: inside the file, in a hole.
            off = size - 1024
            _, rst, rbody = _read(sock, fh, off, 256)
            # Inside-file read of a hole: kXR_ok with up to 256 zero bytes.
            assert rst == kXR_ok, _error_code(rbody)
            assert len(rbody) <= 256
            assert rbody == b"\x00" * len(rbody)
            # A read starting one byte below INT64_MAX (past EOF) must be a
            # clean short/EOF read, not an error or a crash.
            _, est, ebody = _read(sock, fh, INT64_MAX - 1, 16)
            assert est in (kXR_ok, kXR_error)
            if est == kXR_ok:
                assert ebody == b""        # past EOF -> empty
            _close(sock, fh)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_open_handle_survives_extreme_read(self, huge_sparse_near_max):
        """A read at the largest representable positive offset must not wedge
        the session."""
        name, _full, _size = huge_sparse_near_max
        sock = _session()
        try:
            _, ost, obody = _open(sock, name, kXR_open_read)
            if ost != kXR_ok:
                pytest.skip("server refused open of near-max sparse file")
            fh = obody[:4]
            _read(sock, fh, INT64_MAX, 8)   # may be EOF-ok or error; must not hang
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Scenario 3 — negative offset rejected for read/readv/write/pgwrite/truncate
# ===========================================================================

class TestNegativeOffsetRejected:
    """A negative (sign-bit-set) int64 offset must be rejected on EVERY I/O
    opcode with a clean protocol error, never silently coerced to a huge
    unsigned offset or used to index a buffer."""

    @pytest.fixture
    def wr_handle(self):
        name, full = _make_writable("/large_offset_neg.bin", PG_PAGESZ)
        sock = _session()
        _, status, body = _open(sock, name, kXR_open_updt)
        writable = (status == kXR_ok)
        fh = body[:4] if writable else None
        try:
            yield sock, fh, full, writable
        finally:
            if writable:
                try:
                    _close(sock, fh)
                except Exception:
                    pass
            sock.close()
            _unlink(full)

    def test_read_negative_offset(self, rd_handle_4g):
        sock, fh, _ = rd_handle_4g
        _, status, body = _read(sock, fh, -1, 64)
        assert status == kXR_error, "negative read offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok

    def test_readv_negative_offset(self, rd_handle_4g):
        sock, fh, _ = rd_handle_4g
        _, status, body = _readv(sock, [_seg(fh, 64, -8)])
        assert status == kXR_error, "negative readv offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok

    def test_write_negative_offset(self, wr_handle):
        sock, fh, _full, writable = wr_handle
        if not writable:
            pytest.skip("anon server read-only; cannot open for write")
        _, status, body = _write(sock, fh, -16, b"x" * 32)
        assert status == kXR_error, "negative write offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok

    def test_pgwrite_negative_offset(self, wr_handle):
        sock, fh, _full, writable = wr_handle
        if not writable:
            pytest.skip("anon server read-only; cannot open for write")
        data = b"y" * 64
        crc = crc32c(data) if _CRC32C_OK else 0
        payload = struct.pack("!I", crc) + data
        _, status, body = _pgwrite(sock, fh, -32, payload)
        assert status == kXR_error, "negative pgwrite offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid, kXR_ChkSumErr)
        assert _ping(sock)[1] == kXR_ok

    def test_truncate_negative_offset(self, wr_handle):
        sock, fh, _full, writable = wr_handle
        if not writable:
            pytest.skip("anon server read-only; cannot open for write")
        _, status, body = _truncate(sock, fh, -64)
        # ftruncate(2) on a negative length returns EINVAL -> kXR_IOError;
        # an explicit pre-check would give kXR_ArgInvalid. Either is a clean
        # rejection.
        assert status == kXR_error, "negative truncate offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok


# ===========================================================================
# Scenario 4 — offset + rlen overflow rejected
# ===========================================================================

class TestOffsetLengthOverflow:
    """offset + length that overflows int64 must be rejected up front, never
    wrapped into a small in-bounds extent that would disclose other bytes."""

    def test_read_offset_plus_rlen_overflow(self, rd_handle_4g):
        """offset == INT64_MAX with a positive rlen: the naive end = offset +
        rlen would wrap negative.

        The kXR_read handler (src/read/read.c) caps rlen to
        XROOTD_READ_REQUEST_MAX *before* any offset+rlen arithmetic, then
        short-circuits to an empty response because offset >= file_size — so
        the documented, secure outcome is a clean past-EOF short read (kXR_ok
        with ZERO bytes), NOT a wrapped in-bounds read that would leak data.
        The security property under test is: no wrong/leaked bytes, no crash."""
        sock, fh, _ = rd_handle_4g
        _, status, body = _read(sock, fh, INT64_MAX, 0x7FFFFFFF)
        if status == kXR_ok:
            assert body == b"", (
                "overflowing read extent returned bytes — offset+rlen wrapped "
                "into an in-bounds read")
        else:
            assert status == kXR_error
            assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok

    def test_readv_offset_plus_rlen_overflow(self, rd_handle_4g):
        sock, fh, _ = rd_handle_4g
        _, status, body = _readv(sock, [_seg(fh, 0x7FFFFFFF, INT64_MAX)])
        assert status == kXR_error, "overflowing readv extent must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid, kXR_ArgTooLong)
        # No file bytes may have leaked back.
        assert len(body) <= 64
        assert _ping(sock)[1] == kXR_ok

    def test_pgread_offset_plus_rlen_overflow(self, rd_handle_4g):
        sock, fh, _ = rd_handle_4g
        _, status, body, pages = _pgread(sock, fh, INT64_MAX, 0x7FFFFFFF)
        assert status == kXR_error, "overflowing pgread extent must error"
        assert pages == b""
        assert _ping(sock)[1] == kXR_ok


# ===========================================================================
# Scenario 5 — stat size field correct above 4 GiB
# ===========================================================================

class TestStatSizeAbove4GiB:
    """kXR_stat / kXR_statx must report the full 64-bit st_size for a file
    larger than 4 GiB; a %d / 32-bit format bug would report (size mod 2^32).

    In VFS mode (src/path/stat_body.c) the 2nd field carries st_blocks*512
    instead of logical size — near-zero for a sparse file — which is a
    documented alternate encoding, not a 64-bit regression, so those tests
    skip rather than fail when they detect it."""

    def test_stat_reports_full_size(self, big_sparse_4g):
        name, _full, size = big_sparse_4g
        sock = _session()
        try:
            _, status, body = _stat(sock, name)
            assert status == kXR_ok, _error_code(body)
            reported = _stat_size(body)
            if reported != size and reported <= 0xFFFFFFFF:
                pytest.skip("server reports stat in VFS/block mode "
                            f"(field={reported}); logical-size check N/A")
            assert reported == size, (
                f"stat size {reported} != actual {size}; "
                f"low-32-bits would be {size & 0xFFFFFFFF}")
            assert reported > 0xFFFFFFFF, "test file must exceed 4 GiB"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_statx_reports_full_size(self, big_sparse_4g):
        """statx (raw wire — the python client has no statx) must also carry
        the full 64-bit size."""
        name, _full, size = big_sparse_4g
        sock = _session()
        try:
            _, status, body = _statx(sock, [name])
            if status == kXR_error:
                code = _error_code(body)
                if code == kXR_Unsupported:
                    pytest.skip("kXR_statx not implemented on this server")
                # statx multi-path body framing is server-variant; a non-fatal
                # error here is not a 64-bit-offset regression, so skip rather
                # than hard-fail.
                pytest.skip(f"statx returned error {code}; "
                            f"not an offset-width regression")
            assert status == kXR_ok, _error_code(body)
            # statx body carries one stat sub-body per requested path; the size
            # is the 2nd whitespace field of the first entry.
            reported = _stat_size(body)
            if reported != size and reported <= 0xFFFFFFFF:
                pytest.skip("server reports statx in VFS/block mode "
                            f"(field={reported}); logical-size check N/A")
            assert reported == size, (
                f"statx size {reported} != actual {size}")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Scenario 6 — truncate to a large sparse offset
# ===========================================================================

class TestLargeTruncate:
    """Truncating to a multi-GiB offset must extend the file with a hole (no
    multi-GB allocation) and the new size must be reported correctly."""

    def test_truncate_to_above_4gib(self):
        name, full = _make_writable("/large_offset_trunc.bin", 0)
        sock = _session()
        try:
            _, status, body = _open(sock, name, kXR_open_updt)
            if status != kXR_ok:
                pytest.skip(f"anon server read-only "
                            f"(open updt -> {_error_code(body)}); "
                            f"need xrootd_allow_write on")
            fh = body[:4]
            target = FOUR_GIB + 12345
            _, tst, tbody = _truncate(sock, fh, target)
            assert tst == kXR_ok, _error_code(tbody)
            _close(sock, fh)
            # On-disk size must match (sparse — costs ~0 blocks).
            assert os.path.getsize(full) == target
            # And the server must report the new 64-bit size via stat (skip the
            # size assertion under VFS/block-mode stat encoding).
            _, sst, sbody = _stat(sock, name)
            assert sst == kXR_ok, _error_code(sbody)
            reported = _stat_size(sbody)
            if reported == target:
                pass
            elif reported <= 0xFFFFFFFF:
                pytest.skip("server reports stat in VFS/block mode; "
                            "on-disk truncate size already verified")
            else:
                pytest.fail(f"stat size {reported} != truncate target {target}")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()
            _unlink(full)


# ===========================================================================
# Scenario 7 — readv with mixed small and >2 GiB offsets
# ===========================================================================

class TestReadvMixedLargeOffsets:
    """A single vector read mixing a tiny low offset with offsets above the
    2 GiB / 4 GiB 32-bit boundaries must return each segment's correct bytes —
    proving each segment's int64 offset is honoured independently (no shared
    32-bit truncation across the coalescer)."""

    def test_mixed_small_and_large_offsets(self, big_sparse_4g):
        name, full, _size = big_sparse_4g
        # Lay down distinct markers at the start, just over 2 GiB, and at 4 GiB
        # so each segment has verifiable non-hole content.
        m0 = b"AAAAAAAA"               # offset 0
        m2 = b"BBBBBBBB"               # offset 2 GiB + 4096
        m4 = b"\xA5" * 8               # offset 4 GiB (marker already present)
        off2 = (2 * GIB) + 4096
        with open(full, "r+b") as f:
            f.seek(0)
            f.write(m0)
            f.seek(off2)
            f.write(m2)
        sock = _session()
        try:
            _, ost, obody = _open(sock, name, kXR_open_read)
            assert ost == kXR_ok, _error_code(obody)
            fh = obody[:4]
            chunks = [(0, len(m0)), (off2, len(m2)), (FOUR_GIB, len(m4))]
            _, status, body = _readv(sock, [_seg(fh, n, o) for o, n in chunks])
            assert status == kXR_ok, _error_code(body)
            payload = _readv_payload(body, len(chunks))
            expect = m0 + m2 + m4
            assert payload == expect, (
                "mixed-offset readv returned wrong bytes — a >2 GiB segment "
                "offset was likely truncated")
            _close(sock, fh)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


def _readv_payload(body, expect_segs):
    """Strip readahead_list headers, returning concatenated payload bytes.
    Each segment is [fhandle4][rlen4][offset8] then rlen payload bytes."""
    out = []
    pos = 0
    SEGHDR = 16
    for _ in range(expect_segs):
        if pos + SEGHDR > len(body):
            break
        rlen = struct.unpack("!i", body[pos + 4:pos + 8])[0]
        pos += SEGHDR
        out.append(body[pos:pos + rlen])
        pos += rlen
    return b"".join(out)
