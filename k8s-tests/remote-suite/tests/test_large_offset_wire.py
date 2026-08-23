# brix-remote-ok
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
# /tmp/brix-src/src/XProtocol/XProtocol.hh enum XRequestTypes / XResponseType
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
    NUL-separated path list (src/protocols/root/read/statx.c)."""
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

    Body format (src/protocols/root/path/stat_body.c, non-VFS mode):
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

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "_test_large_offset_wire_cases.py")
