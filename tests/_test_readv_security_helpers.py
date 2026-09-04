"""
tests/test_readv_security.py — vector-read and paged (chunked) read/write
security tests.

This suite hammers the *bounds checking* of the scatter-gather and page-mode
opcodes with deliberately hostile requests built on raw TCP sockets, where the
Python XRootD client would otherwise sanitise offsets/lengths before they ever
reach the wire.  It targets the real handler code:

  * kXR_readv  (src/protocols/root/read/readv.c)   — negative offset, offset overflow, reads
                                       past EOF (single / straddling / mixed),
                                       segment-count + total-size caps, malformed
                                       framing, stale/invalid handles, and the
                                       contiguous-run coalescer crossing EOF.
  * kXR_pgread (src/protocols/root/read/pgread.c)  — negative offset, EOF handling, per-page
                                       CRC32c integrity of the chunked response,
                                       rlen cap, slice-handle rejection.
  * kXR_pgwrite(src/protocols/root/write/pgwrite.c)— per-page CRC32c verification (a corrupted
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
from _xrdcl_proxy import real_bindings_available

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

pytestmark = [
    pytest.mark.registry_server("main"),
    pytest.mark.xdist_group("readv-security-shared-data"),
]
bindings_required = pytest.mark.skipif(
    not real_bindings_available(), reason="real libXrdCl bindings unavailable")


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (from src/protocols/root/protocol/opcodes.h)
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

# Handler limits (src/protocols/root/protocol/flags.h, src/core/types/tunables.h)
READV_SEGSIZE = 16
READV_MAXSEGS = 1024
# Per-segment readv cap = the server's default brix_readv_segment_size, which
# matches stock XRootD's maxReadv_ior = maxBuffsz(2 MiB) - sizeof(readahead_list).
READ_MAX      = 2 * 1024 * 1024 - READV_SEGSIZE
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
def _require_server(test_env):
    """Skip the whole module cleanly if the anon stream server isn't up."""
    try:
        s = socket.create_connection((ANON_HOST, ANON_PORT), timeout=3)
        s.close()
    except OSError as exc:
        pytest.skip(f"anon stream server {ANON_HOST}:{ANON_PORT} unreachable: {exc}")


@pytest.fixture(scope="module")
def data_file(test_env):
    """Materialise the known pattern file under the server data root."""
    data_root = test_env["data_dir"]
    os.makedirs(data_root, exist_ok=True)
    full = os.path.join(data_root, DATA_NAME.lstrip("/"))
    with open(full, "wb") as f:
        f.write(PATTERN)
    os.chmod(full, 0o644)
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
