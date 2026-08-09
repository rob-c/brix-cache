"""
tests/test_compression_write_adversarial.py — Phase-42 W5 adversarial coverage of
root:// INLINE WRITE decompression, driven over the RAW root:// wire against the
shared anon server (port 11094), which has `brix_write_compress on` and
advertises `cmpwrite=...,zstd,...`.

W5 (src/protocols/root/write/write_compress.c) is the write-direction counterpart of W4: a handle
opened for write with the opaque "?xrootd.compress=<codec>" makes the server treat
each kXR_write payload as ONE self-contained codec frame, decompress it under a
decompression-bomb guard, and pwrite() the recovered PLAINTEXT to disk.  It is
deliberately isolated from the proven write path — brix_handle_write() routes to
brix_write_compressed() only when files[idx].write_codec != IDENTITY, so the
default (uncompressed) write keeps its AIO fast path and write-recovery journal
byte-identical.  Critically, pgwrite/writev have their OWN handlers that never
consult write_codec, so their plaintext + per-page-CRC32c invariant is preserved
even on a compression-negotiated handle.

This module proves three things, all on the real wire so we observe exact bytes:

  (1) WCMP-CORRUPT  — a kXR_write whose payload is a TRUNCATED/garbage codec frame
      is REJECTED with kXR_error (errcode 3007 / "corrupt or oversized compressed
      write"), and the target file is NOT left containing partial garbage.  The
      server's pinned contract (verified live): the file is created by kXR_new but
      stays 0 bytes — no decompressed prefix is committed before the frame faults.

  (2) WCMP-INVARIANT — on a write handle opened "?xrootd.compress=zstd", a
      kXR_pgwrite is treated as PLAINTEXT (the compression invariant excludes
      pgwrite/writev): the page data is written verbatim and reads back byte-exact,
      with the pgwrite kXR_status(4007) framing intact.

  (3) WCMP-OK (control) — a CORRECT single-frame compressed kXR_write stores the
      exact plaintext (downloads byte-exact), proving the harness write-compress
      path actually works so that (1)'s rejection is meaningful, not a path that is
      simply broken for all input.

The compression codec used is zstd: the harness advertises it for cmpwrite and the
Python `zstandard` module is available, so we can build genuine codec frames in
pure Python (no CLI shell-out, no native client needed for the write side).

Run:
    TEST_SKIP_SERVER_SETUP=1 X509_USER_PROXY=/nonexistent PYTHONPATH=. \
      NGINX_BIN=/tmp/nginx-1.28.3/objs/nginx \
      python -m pytest tests/test_compression_write_adversarial.py -q
"""

import os
import socket
import struct
import uuid

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST

zstandard = pytest.importorskip(
    "zstandard", reason="python zstandard module required to build zstd frames")


# ---------------------------------------------------------------------------
# Opcodes / status / error codes / open options (src/protocols/root/protocol/{opcodes,flags}.h)
# ---------------------------------------------------------------------------

kXR_login    = 3007
kXR_open     = 3010
kXR_read     = 3013
kXR_write    = 3019
kXR_close    = 3003
kXR_pgwrite  = 3026

kXR_ok       = 0
kXR_error    = 4003
kXR_status   = 4007    # pgwrite/pgread extended-status response framing

kXR_open_read = 0x0010
kXR_open_updt = 0x0020   # open for read+write (O_RDWR)
kXR_new       = 0x0008   # create; fail kXR_ItExists if it already exists
kXR_mkpath    = 0x0100   # create parent directories

# Phase-42 open-reply inline-compression signalling
# (ServerResponseBody_Open.cpsize == BRIX_INLINE_CMP_MAGIC ('Z'=0x5A),
#  cptype[0] == codec ordinal).  zstd is ordinal 3 (src/core/compat/codec_core.h).
INLINE_CMP_MAGIC = 0x5A
CODEC_ZSTD       = 3

# Error code carried in a kXR_error body for a corrupt compressed write.  The
# server maps the decode failure to kXR_IOError; on this wire build that ordinal
# is 3007 (src/protocols/root/protocol/opcodes.h).  We assert the human-readable message rather
# than hard-coding the ordinal as the primary check, but record it for clarity.
CORRUPT_WRITE_MSG = b"corrupt or oversized compressed write"

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT

XRD_PGWRITE_PAGESZ = 4096


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — pure-Python, matches brix_crc32c_copy()
# (mirrors tests/test_compression_root_invariant.py / test_readv_security.py)
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


# Self-test against the canonical check value.  pgwrite payload framing depends
# on this being correct (a wrong CRC would make the server reject our pgwrite
# with kXR_ChkSumErr and mask the real plaintext-invariant result), so the
# invariant test is skipped if our CRC engine is wrong.
_CRC32C_OK = crc32c(b"123456789") == 0xE3069283


# ---------------------------------------------------------------------------
# Raw root:// wire helpers (mirror test_compression_root_invariant.py)
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


def _open(sock, path, options, streamid=b"\x00\x02"):
    """kXR_open.  `path` may carry an inline '?...' opaque (CGI); the wire path
    field is the full string + NUL, exactly as a stock client sends 'name?cgi'."""
    p = path.encode() + b"\x00"
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


def _write(sock, fhandle, offset, data, streamid=b"\x00\x03"):
    """kXR_write: streamid[2] reqid[2] fhandle[4] offset(i64) pathid[1]
    reserved[3] dlen[4], then dlen payload bytes."""
    req = struct.pack("!2sH4sqB3sI", streamid, kXR_write, fhandle,
                      offset, 0, b"\x00\x00\x00", len(data))
    sock.sendall(req + data)
    return _read_response(sock)


def _pgwrite_single_page(sock, fhandle, offset, data, streamid=b"\x00\x04"):
    """kXR_pgwrite for a single (<=4096-byte) page: the payload is one 4-byte
    big-endian CRC32c of `data` followed by `data`.  Request header is
    streamid[2] reqid[2] fhandle[4] offset(i64) pathid[1] reqflags[1]
    reserved[2] dlen[4] (ClientPgWriteRequest)."""
    assert len(data) <= XRD_PGWRITE_PAGESZ, "single-page helper: data > 4096"
    payload = struct.pack("!I", crc32c(data)) + data
    req = struct.pack("!2sH4sqBB2sI", streamid, kXR_pgwrite, fhandle,
                      offset, 0, 0, b"\x00\x00", len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _err_fields(body):
    """Decode a kXR_error body: errnum(int32 BE) + NUL-terminated message."""
    if len(body) < 4:
        return None, b""
    errnum = struct.unpack("!i", body[:4])[0]
    msg = body[4:].rstrip(b"\x00")
    return errnum, msg


def _open_write_compressed(sock, remote, codec="zstd"):
    """Open `remote` for write WITH the inline-compression opaque and create flags;
    assert the open reply negotiated compression for the WRITE direction.  Returns
    the fhandle bytes."""
    _, status, body = _open(sock, f"{remote}?xrootd.compress={codec}",
                            kXR_open_updt | kXR_new | kXR_mkpath)
    assert status == kXR_ok, f"compressed write-open failed (status={status})"
    assert len(body) >= 12, f"open reply too short for ServerOpenBody: {len(body)}"
    fhandle = body[:4]
    cpsize = struct.unpack("!i", body[4:8])[0]
    cptype = body[8:12]
    assert cpsize == INLINE_CMP_MAGIC, (
        f"write compression not negotiated: cpsize={cpsize:#x} "
        f"(expected {INLINE_CMP_MAGIC:#x}); is brix_write_compress on?")
    assert cptype[0] == CODEC_ZSTD, (
        f"unexpected codec ordinal {cptype[0]} (expected zstd={CODEC_ZSTD})")
    return fhandle


def _zstd_frame(plaintext: bytes) -> bytes:
    """One self-contained zstd frame of `plaintext` (the codec frame W5 decodes)."""
    return zstandard.ZstdCompressor().compress(plaintext)


def _readback(remote):
    """Open `remote` read-only (plaintext, no compress opaque) and return its full
    stored content, then close.  Uses a fresh session so a stale write handle
    can't influence the read."""
    sock = _session()
    try:
        _, status, body = _open(sock, remote, kXR_open_read, streamid=b"\x00\x07")
        if status != kXR_ok:
            return status, b""
        fh = body[:4]
        # Read a generous window; small payloads return in one reply.
        _, rstatus, rbody = _read(sock, fh, 0, 8 * 1024 * 1024)
        _close(sock, fh, streamid=b"\x00\x0f")
        return rstatus, rbody
    finally:
        sock.close()


def _rm(remote):
    """Best-effort cleanup via the native xrdfs, if present.  Failures are ignored
    (the harness root is ephemeral test storage)."""
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    xrdfs = os.path.join(repo, "client", "bin", "xrdfs")
    if os.access(xrdfs, os.X_OK):
        subprocess.run([xrdfs, f"root://{ANON_HOST}:{ANON_PORT}", "rm", remote],
                       capture_output=True)


# ---------------------------------------------------------------------------
# Module-level guards
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _require_server():
    """Skip the whole module cleanly if the anon stream server isn't up."""
    try:
        s = socket.create_connection((ANON_HOST, ANON_PORT), timeout=3)
        s.close()
    except OSError as exc:
        pytest.skip(f"anon stream server {ANON_HOST}:{ANON_PORT} unreachable: {exc}")


@pytest.fixture(scope="module", autouse=True)
def _require_write_compress():
    """Skip if the server does not actually negotiate write compression (i.e.
    brix_write_compress is off or zstd is unavailable).  We probe by opening a
    throwaway path for compressed write and checking the open reply; if it doesn't
    carry the inline-compression magic, the adversarial assertions would be moot."""
    remote = f"/wcmp_probe_{uuid.uuid4().hex}.bin"
    sock = _session()
    try:
        _, status, body = _open(sock, f"{remote}?xrootd.compress=zstd",
                                kXR_open_updt | kXR_new | kXR_mkpath)
        if status != kXR_ok or len(body) < 8:
            pytest.skip(f"compressed write-open probe failed (status={status})")
        cpsize = struct.unpack("!i", body[4:8])[0]
        fh = body[:4]
        _close(sock, fh, streamid=b"\x00\x0e")
        if cpsize != INLINE_CMP_MAGIC:
            pytest.skip("server did not negotiate write compression "
                        "(brix_write_compress off?); skipping W5 adversarial suite")
    finally:
        sock.close()
    _rm(remote)


# ===========================================================================
# (3) WCMP-OK control — a correct single-frame compressed write stores exact
#     plaintext.  Proves the path works so the rejection in (1) is meaningful.
# ===========================================================================
