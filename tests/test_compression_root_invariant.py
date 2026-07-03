"""
tests/test_compression_root_invariant.py — Phase-42 W4 PLAINTEXT invariant for
paged / vector reads on a compression-negotiated root:// handle.

W4 adds inline read compression to root://: a handle opened with the opaque
"?xrootd.compress=<codec>" (against a server with `brix_read_compress on`)
makes each kXR_read response a self-contained codec frame of the requested
plaintext range.  The hard invariant we prove here is that this compression is
confined to kXR_read ONLY:

  * kXR_pgread (src/protocols/root/read/pgread.c) MUST stay plaintext — its kXR_status(4007)
    page framing with per-page CRC32c is byte-for-byte preserved.  Compressing
    it would break the CRC32c-over-plaintext contract.
  * kXR_readv (src/protocols/root/read/readv.c) MUST stay plaintext — the scatter-gather
    readahead_list payload is raw file bytes.

The contrast control is a kXR_read on the *same* handle, which IS compressed
(its body is a gzip frame whose inflation yields the plaintext) — so we prove
the handle really is in compression mode and that paged/vector reads opt out of
it explicitly, not because compression was silently disabled.

All of this is driven over raw root:// wire framing (mirroring
tests/test_readv_security.py) so we observe the exact bytes on the wire, before
any client-side inflation can hide the distinction.  The known payload is
uploaded once via the native xrdcp in a fixture.

Run:
    pytest tests/test_compression_root_invariant.py -v
"""

import os
import socket
import struct
import subprocess
import uuid
import zlib

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (from src/protocols/root/protocol/opcodes.h)
# ---------------------------------------------------------------------------

kXR_login   = 3007
kXR_open    = 3010
kXR_read    = 3013
kXR_close   = 3003
kXR_readv   = 3025
kXR_pgread  = 3030

kXR_ok      = 0
kXR_error   = 4003
kXR_status  = 4007    # pgread extended-status response framing

kXR_open_read = 0x0010

# Phase-42 W4 inline-compression open-reply signalling (src/core/compat/codec_core.h):
# ServerResponseBody_Open.cpsize = BRIX_INLINE_CMP_MAGIC ('Z' = 0x5A) and
# cptype[0] = <codec id ordinal>.  Codec ordinals: GZIP=1 (always available;
# zlib is mandatory).
INLINE_CMP_MAGIC = 0x5A
CODEC_GZIP       = 1

PG_PAGESZ = 4096

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
BASE = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

# Highly compressible ~200 KiB payload; ~3700 * 54 = 199800 bytes, NOT page
# aligned so the final pgread page is short.  Repeating text guarantees a gzip
# frame is dramatically smaller than the plaintext (so "z=" really fires) and
# that gzip magic is unmistakably present on the compressed read path.
_LINE = b"the quick brown fox jumps over the lazy dog 0123456789\n"  # 54 bytes
PAYLOAD = _LINE * 3700
DATA_SIZE = len(PAYLOAD)


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — pure-Python, matches brix_crc32c_copy()
# (mirrors tests/test_readv_security.py)
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
# and the per-page integrity check below would falsely fail, so we skip it.
_CRC32C_OK = crc32c(b"123456789") == 0xE3069283


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror tests/test_readv_security.py)
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
    """kXR_open.  `path` may carry an opaque '?...' suffix (CGI) inline; the
    wire path field is the full string + NUL, exactly as a stock client sends
    'name?cgi'."""
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


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _seg(fhandle, rlen, offset):
    """One readahead_list element: fhandle[4] + rlen(int32 BE) + offset(int64 BE)."""
    return struct.pack("!4siq", fhandle, rlen, offset)


def _readv(sock, segments, streamid=b"\x00\x05"):
    payload = b"".join(segments)
    req = struct.pack("!2sH16sI", streamid, kXR_readv, b"\x00" * 16, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


READV_SEGSIZE = 16


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


def _pgread(sock, fhandle, offset, rlen, streamid=b"\x00\x07"):
    """Issue kXR_pgread and fully drain the response.

    A pgread success is a kXR_status message: an 8-byte header + a status body
    (hdr.dlen), followed SEPARATELY by bdy.dlen raw bytes of CRC-interleaved
    page data.  Returns (streamid, status, status_body, pages); `pages` is empty
    on an error response.
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


def _decode_pages(pages):
    """Split a pgread page stream [crc4][<=4096 data]... verifying each CRC32c.
    Returns the concatenated data; asserts on CRC mismatch."""
    out = bytearray()
    pos = 0
    while pos < len(pages):
        crc = struct.unpack("!I", pages[pos:pos + 4])[0]
        pos += 4
        page = pages[pos:pos + PG_PAGESZ]
        pos += len(page)
        if _CRC32C_OK:
            assert crc32c(page) == crc, "pgread per-page CRC32c mismatch"
        out.extend(page)
        if len(page) < PG_PAGESZ:
            break
    return bytes(out)


def _gunzip(data):
    """Inflate a gzip frame (zlib with the gzip wrapper, wbits=31)."""
    return zlib.decompress(data, 31)


def _looks_gzip(data):
    """gzip magic is 0x1f 0x8b."""
    return len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B


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
def uploaded(tmp_path_factory):
    """Upload the known compressible payload via the native xrdcp; yield the
    remote path.  Cleaned up with xrdfs rm.  Skips if the client isn't built or
    the upload fails (no server-side prerequisites are assumed beyond a writable
    anon root, which the harness provides)."""
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")
    d = tmp_path_factory.mktemp("cmprootinv")
    src = str(d / "payload.bin")
    with open(src, "wb") as fh:
        fh.write(PAYLOAD)

    remote = f"/cmprootinv_{uuid.uuid4().hex}.bin"
    up = subprocess.run([XRDCP, "-f", src, f"{BASE}{remote}"],
                        capture_output=True, text=True, timeout=60)
    if up.returncode != 0:
        pytest.skip(f"upload to root:// server failed: {up.stderr[:300]}")
    yield remote
    if os.access(XRDFS, os.X_OK):
        subprocess.run([XRDFS, BASE, "rm", remote], capture_output=True)


def _open_compressed(sock, remote, codec="gzip"):
    """Open `remote` read-only WITH the inline-compression opaque and assert the
    open reply negotiated compression.  Returns the fhandle bytes."""
    _, status, body = _open(sock, f"{remote}?xrootd.compress={codec}",
                            kXR_open_read)
    assert status == kXR_ok, f"compressed open failed (status={status})"
    # ServerResponseBody_Open: fhandle[4] cpsize(int32 BE) cptype[4]
    assert len(body) >= 12, f"open reply too short for ServerOpenBody: {len(body)}"
    fhandle = body[:4]
    cpsize = struct.unpack("!i", body[4:8])[0]
    cptype = body[8:12]
    assert cpsize == INLINE_CMP_MAGIC, (
        f"compression not negotiated: cpsize={cpsize:#x} "
        f"(expected {INLINE_CMP_MAGIC:#x}); is brix_read_compress on?")
    assert cptype[0] != 0, "cptype[0] is zero — no codec ordinal signalled"
    assert cptype[0] == CODEC_GZIP, (
        f"unexpected codec ordinal {cptype[0]} (expected gzip={CODEC_GZIP})")
    return fhandle


@pytest.fixture
def cmp_handle(uploaded):
    """Open the uploaded file read-only WITH '?xrootd.compress=gzip'; yield
    (sock, fhandle, remote) and always clean up.  Asserts the open reply
    actually negotiated compression so every test below runs against a genuinely
    compression-mode handle."""
    remote = uploaded
    sock = _session()
    fhandle = _open_compressed(sock, remote, "gzip")
    try:
        yield sock, fhandle, remote
    finally:
        try:
            _close(sock, fhandle)
        except Exception:
            pass
        sock.close()


# ===========================================================================
# Class 1 — the W4 invariant: paged/vector reads stay PLAINTEXT on a
#           compression-negotiated handle
# ===========================================================================

class TestCompressionRootInvariant:
    """On a handle opened '?xrootd.compress=gzip' (compression negotiated in the
    open reply), kXR_read is compressed but kXR_pgread and kXR_readv must remain
    raw plaintext on the wire."""

    def test_open_reply_signals_compression(self, cmp_handle):
        """Sanity / positive control: the open reply carried the inline-compression
        magic + gzip ordinal (already asserted in the fixture; restate so this
        appears as its own pass)."""
        sock, fh, _remote = cmp_handle
        assert fh is not None and len(fh) == 4

    def test_plain_read_is_compressed(self, cmp_handle):
        """Contrast control: a kXR_read on this handle IS a gzip frame whose
        inflation yields the plaintext slice.  Proves the handle is genuinely in
        compression mode (so the pgread/readv plaintext result below is the
        opt-out, not compression-disabled)."""
        sock, fh, _remote = cmp_handle
        want = 64 * 1024  # spans several internal read windows
        _, status, body = _read(sock, fh, 0, want)
        assert status == kXR_ok, f"read failed (status={status})"
        assert _looks_gzip(body), (
            "kXR_read body is not a gzip frame — compression did not engage "
            f"(first bytes: {body[:4].hex()})")
        inflated = _gunzip(body)
        assert inflated == PAYLOAD[:want], "inflated read != plaintext slice"
        # The frame must actually be smaller than the plaintext (it is highly
        # compressible), confirming it is a real codec frame not a stored copy.
        assert len(body) < want, "gzip frame not smaller than plaintext"

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgread_stays_plaintext(self, cmp_handle):
        """THE INVARIANT: kXR_pgread on the compression-negotiated handle returns
        kXR_status(4007) page framing whose page DATA is raw plaintext (per-page
        CRC32c over plaintext verifies), NOT a gzip codec frame."""
        sock, fh, _remote = cmp_handle
        want = 3 * PG_PAGESZ + 123   # spans 4 pages, last one short
        _, status, body, pages = _pgread(sock, fh, 0, want)
        assert status == kXR_status, (
            f"pgread did not use kXR_status framing (status={status}) — the "
            "page/CRC32c invariant is broken")
        assert pages, "pgread returned no page data"
        # The page DATA region must be raw bytes, never a gzip frame.
        assert not _looks_gzip(pages[4:6]), (
            "pgread first page begins with gzip magic — pgread was compressed, "
            "violating the W4 plaintext invariant")
        decoded = _decode_pages(pages)
        assert decoded[:want] == PAYLOAD[:want], (
            "pgread page data is not byte-exact plaintext")

    def test_pgread_data_region_equals_plaintext_minimal(self, cmp_handle):
        """Lower-bar restatement of the invariant that does NOT depend on
        replicating the full CRC framing: read one page worth via pgread, strip
        the 4-byte leading per-page CRC, and assert the data equals the plaintext
        and is not gzip-magic (0x1f8b)."""
        sock, fh, _remote = cmp_handle
        _, status, body, pages = _pgread(sock, fh, 0, PG_PAGESZ)
        assert status == kXR_status, f"expected kXR_status, got {status}"
        assert len(pages) >= 4, "pgread page stream too short"
        data = pages[4:]                       # drop the leading per-page CRC32c
        assert not _looks_gzip(data), "pgread data region is gzip-framed"
        assert data[:len(data)] == PAYLOAD[:len(data)], (
            "pgread data region != plaintext")

    def test_readv_stays_plaintext(self, cmp_handle):
        """THE INVARIANT (vector path): kXR_readv on the compression-negotiated
        handle returns the raw file bytes in its readahead_list payload — never a
        codec frame."""
        sock, fh, _remote = cmp_handle
        chunks = [(0, 4096), (8192, 4096), (40000, 4096)]
        _, status, body = _readv(sock, [_seg(fh, n, o) for o, n in chunks])
        assert status == kXR_ok, f"readv failed (status={status})"
        payload = _readv_payload_bytes(body, len(chunks))
        expect = b"".join(PAYLOAD[o:o + n] for o, n in chunks)
        assert not _looks_gzip(payload), (
            "readv payload begins with gzip magic — readv was compressed, "
            "violating the W4 plaintext invariant")
        assert payload == expect, "readv payload is not byte-exact plaintext"

    def test_read_vs_pgread_same_handle_diverge(self, cmp_handle):
        """End-to-end contrast on ONE handle: kXR_read of a range is gzip-framed,
        kXR_pgread of the SAME range is raw plaintext — same bytes underneath,
        different wire representation, exactly as W4 specifies."""
        sock, fh, _remote = cmp_handle
        off, want = 0, 2 * PG_PAGESZ

        _, rstatus, rbody = _read(sock, fh, off, want)
        assert rstatus == kXR_ok
        assert _looks_gzip(rbody), "kXR_read not compressed"
        assert _gunzip(rbody) == PAYLOAD[off:off + want]

        _, pstatus, _pb, pages = _pgread(sock, fh, off, want)
        assert pstatus == kXR_status
        pg_data = _decode_pages(pages)
        assert not _looks_gzip(pages[4:6]), "kXR_pgread unexpectedly compressed"
        assert pg_data[:want] == PAYLOAD[off:off + want]

        # The two wire forms must differ (read is compressed, pgread is not).
        assert rbody != pages, "read and pgread produced identical wire bytes"
