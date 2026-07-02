"""
tests/test_compression_write_adversarial.py — Phase-42 W5 adversarial coverage of
root:// INLINE WRITE decompression, driven over the RAW root:// wire against the
shared anon server (port 11094), which has `xrootd_write_compress on` and
advertises `cmpwrite=...,zstd,...`.

W5 (src/protocols/root/write/write_compress.c) is the write-direction counterpart of W4: a handle
opened for write with the opaque "?xrootd.compress=<codec>" makes the server treat
each kXR_write payload as ONE self-contained codec frame, decompress it under a
decompression-bomb guard, and pwrite() the recovered PLAINTEXT to disk.  It is
deliberately isolated from the proven write path — xrootd_handle_write() routes to
xrootd_write_compressed() only when files[idx].write_codec != IDENTITY, so the
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
# (ServerResponseBody_Open.cpsize == XROOTD_INLINE_CMP_MAGIC ('Z'=0x5A),
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
# CRC32c (Castagnoli) — pure-Python, matches xrootd_crc32c_copy()
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
        f"(expected {INLINE_CMP_MAGIC:#x}); is xrootd_write_compress on?")
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
    xrootd_write_compress is off or zstd is unavailable).  We probe by opening a
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
                        "(xrootd_write_compress off?); skipping W5 adversarial suite")
    finally:
        sock.close()
    _rm(remote)


# ===========================================================================
# (3) WCMP-OK control — a correct single-frame compressed write stores exact
#     plaintext.  Proves the path works so the rejection in (1) is meaningful.
# ===========================================================================

class TestCompressedWriteOkControl:

    def test_correct_zstd_frame_stores_exact_plaintext(self):
        """A single zstd frame written to a compression-mode handle is stored as
        its decompressed PLAINTEXT, byte-exact on readback."""
        remote = f"/wcmp_ok_{uuid.uuid4().hex}.bin"
        # Highly compressible so the wire frame is dramatically smaller than the
        # stored plaintext (proves a real codec frame, not a stored copy).
        plaintext = b"the quick brown fox jumps over the lazy dog 0123456789\n" * 400
        frame = _zstd_frame(plaintext)
        assert len(frame) < len(plaintext), "zstd frame not smaller than plaintext"

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, wstatus, wbody = _write(sock, fh, 0, frame)
            assert wstatus == kXR_ok, (
                f"correct compressed write rejected (status={wstatus}, "
                f"body={_err_fields(wbody)})")
            _close(sock, fh)
        finally:
            sock.close()

        rstatus, content = _readback(remote)
        try:
            assert rstatus == kXR_ok, f"readback open/read failed (status={rstatus})"
            assert content == plaintext, (
                "stored content is not the byte-exact decompressed plaintext")
            assert len(content) == len(plaintext)
        finally:
            _rm(remote)

    def test_compressed_write_at_offset_addresses_plaintext(self):
        """Each kXR_write is an independent whole frame, so writes stay offset-
        addressable: two frames at 0 and len(p0) reconstruct p0+p1 contiguously."""
        remote = f"/wcmp_off_{uuid.uuid4().hex}.bin"
        p0 = b"AAAA-block-zero-" * 64
        p1 = b"BBBB-block-one--" * 64

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, w0, b0 = _write(sock, fh, 0, _zstd_frame(p0))
            assert w0 == kXR_ok, f"frame@0 rejected ({_err_fields(b0)})"
            _, w1, b1 = _write(sock, fh, len(p0), _zstd_frame(p1),
                               streamid=b"\x00\x05")
            assert w1 == kXR_ok, f"frame@len(p0) rejected ({_err_fields(b1)})"
            _close(sock, fh)
        finally:
            sock.close()

        rstatus, content = _readback(remote)
        try:
            assert rstatus == kXR_ok
            assert content == p0 + p1, "offset-addressed frames did not reassemble"
        finally:
            _rm(remote)


# ===========================================================================
# (1) WCMP-CORRUPT — a truncated/garbage codec frame is rejected and leaves no
#     partial garbage on disk.
# ===========================================================================

class TestCompressedWriteCorrupt:

    def _assert_rejected(self, wstatus, wbody):
        assert wstatus == kXR_error, (
            f"corrupt compressed write was NOT rejected (status={wstatus}); "
            "the server accepted a malformed codec frame")
        errnum, msg = _err_fields(wbody)
        # The decode failure maps to the corrupt/oversized error message; assert
        # on the message (stable) rather than the numeric ordinal alone.
        assert msg == CORRUPT_WRITE_MSG, (
            f"unexpected error message for corrupt write: {msg!r} "
            f"(errnum={errnum})")

    def _assert_no_partial_garbage(self, remote):
        """Pinned contract (verified against the live harness): the corrupt frame
        is rejected BEFORE any decompressed prefix is committed, so the file is
        either not present OR present and 0 bytes — never holding partial garbage.

        We accept both 'not created' and '0 bytes' so the test is robust to the
        kXR_new-created-empty-file detail, but it MUST NOT contain any bytes."""
        rstatus, content = _readback(remote)
        if rstatus == kXR_ok:
            assert content == b"", (
                f"corrupt write left {len(content)} bytes of partial data on "
                f"disk: {content[:32]!r}... — partial-garbage commit is a bug")
        else:
            # Not openable as a regular readable file (e.g. not found) is also an
            # acceptable 'no garbage committed' outcome.
            assert rstatus != kXR_ok

    def test_truncated_zstd_frame_rejected_no_garbage(self):
        """A zstd frame chopped mid-stream: server must reply kXR_error and leave
        no partial plaintext on disk."""
        remote = f"/wcmp_trunc_{uuid.uuid4().hex}.bin"
        plaintext = b"this plaintext is long enough to span a real zstd frame " * 80
        full = _zstd_frame(plaintext)
        truncated = full[: max(4, len(full) // 2)]  # keep magic, drop the tail

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, wstatus, wbody = _write(sock, fh, 0, truncated)
            self._assert_rejected(wstatus, wbody)
            _close(sock, fh)
        finally:
            sock.close()

        try:
            self._assert_no_partial_garbage(remote)
        finally:
            _rm(remote)

    def test_garbage_after_magic_rejected_no_garbage(self):
        """Valid zstd magic followed by random bytes (a hostile/garbage frame):
        rejected, nothing committed."""
        remote = f"/wcmp_garb_{uuid.uuid4().hex}.bin"
        garbage = b"\x28\xb5\x2f\xfd" + os.urandom(64)  # zstd magic + junk

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, wstatus, wbody = _write(sock, fh, 0, garbage)
            self._assert_rejected(wstatus, wbody)
            _close(sock, fh)
        finally:
            sock.close()

        try:
            self._assert_no_partial_garbage(remote)
        finally:
            _rm(remote)

    def test_pure_random_rejected_no_garbage(self):
        """Payload with no valid codec magic at all: rejected, nothing committed."""
        remote = f"/wcmp_rand_{uuid.uuid4().hex}.bin"
        junk = os.urandom(128)

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, wstatus, wbody = _write(sock, fh, 0, junk)
            self._assert_rejected(wstatus, wbody)
            _close(sock, fh)
        finally:
            sock.close()

        try:
            self._assert_no_partial_garbage(remote)
        finally:
            _rm(remote)


# ===========================================================================
# (2) WCMP-INVARIANT — pgwrite on a compression-negotiated WRITE handle is
#     treated as PLAINTEXT (the W5 invariant excludes pgwrite/writev).
# ===========================================================================

class TestPgwritePlaintextInvariant:

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgwrite_on_compressed_handle_is_plaintext(self):
        """THE INVARIANT: a kXR_pgwrite on a handle opened '?xrootd.compress=zstd'
        is NOT decompressed — its page data is written verbatim and reads back
        byte-exact as plaintext, with pgwrite's kXR_status(4007) framing intact.

        If pgwrite were (incorrectly) routed through the write_codec decompressor,
        this PLAINTEXT page would be interpreted as a codec frame and either be
        rejected (kXR_error) or stored as decode garbage — so a byte-exact
        plaintext readback proves the opt-out."""
        remote = f"/wcmp_pg_{uuid.uuid4().hex}.bin"
        plaintext = b"pgwrite plaintext invariant on a compress handle " * 28
        assert len(plaintext) <= XRD_PGWRITE_PAGESZ, "single-page assumption broke"

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, pstatus, pbody = _pgwrite_single_page(sock, fh, 0, plaintext)
            assert pstatus == kXR_status, (
                f"pgwrite did not use kXR_status(4007) framing (status={pstatus}, "
                f"body={_err_fields(pbody)}) — pgwrite may have been routed through "
                "the compression decoder, violating the W5 invariant")
            _close(sock, fh)
        finally:
            sock.close()

        rstatus, content = _readback(remote)
        try:
            assert rstatus == kXR_ok, f"readback failed (status={rstatus})"
            assert content == plaintext, (
                "pgwrite on a compression-mode handle was NOT stored as verbatim "
                "plaintext — the compression invariant excludes pgwrite")
        finally:
            _rm(remote)

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgwrite_rejects_a_compressed_frame_as_plaintext(self):
        """Negative-control of the invariant: because pgwrite is plaintext, sending
        a *compressed* zstd frame through pgwrite stores the COMPRESSED BYTES
        verbatim (it is NOT decompressed).  Readback equals the frame bytes, never
        the underlying plaintext — confirming pgwrite never engages the codec."""
        remote = f"/wcmp_pg_neg_{uuid.uuid4().hex}.bin"
        plaintext = b"X" * 512
        frame = _zstd_frame(plaintext)
        assert len(frame) <= XRD_PGWRITE_PAGESZ
        assert frame != plaintext

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, pstatus, pbody = _pgwrite_single_page(sock, fh, 0, frame)
            assert pstatus == kXR_status, (
                f"pgwrite of a frame did not return kXR_status (status={pstatus}, "
                f"body={_err_fields(pbody)})")
            _close(sock, fh)
        finally:
            sock.close()

        rstatus, content = _readback(remote)
        try:
            assert rstatus == kXR_ok, f"readback failed (status={rstatus})"
            assert content == frame, (
                "pgwrite stored something other than the verbatim frame bytes")
            assert content != plaintext, (
                "pgwrite DECOMPRESSED a frame — it must treat input as plaintext, "
                "violating the W5 compression invariant")
        finally:
            _rm(remote)
