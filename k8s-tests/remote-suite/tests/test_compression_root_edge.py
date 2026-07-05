"""
tests/test_compression_root_edge.py — Phase-42 W4 EDGE cases for root:// inline
read compression.

W4 lets a read handle opened with the opaque "?xrootd.compress=<codec>" (the
native xrdcp `--compress <codec>` flag) ask the server (which has
`brix_read_compress on`) to compress each kXR_read response as ONE
self-contained codec frame of the requested plaintext range.  test_compression_
root.py proves the byte-exact round trip on highly-compressible data and the
graceful-degrade path; test_compression_root_invariant.py proves pgread/readv
stay plaintext.  This file fills the EDGE gaps:

 (1) INCOMPRESSIBLE — os.urandom(2 MiB) downloaded WITH --compress for several
     codecs is still byte-exact.  Random data is the codec worst case: every
     window's frame is >= its plaintext input, so this exercises the server's
     worst-case expansion bound (brix_codec_max_out) and cmp_scratch sizing.
     If the bound under-allocated or the frame were truncated/corrupted, the
     download would not match.

 (2) EOF / EMPTY — a 0-byte file with --compress is byte-exact empty (the server
     sends an empty frame for an empty range), and a small file is byte-exact
     (the final short window + a read past EOF returns no extra bytes).

 (3) OFFSET-RESUME (raw wire) — open '?xrootd.compress=gzip', issue a kXR_read at
     a non-zero offset (filesize/2) and assert the inflated frame equals the
     source slice AT THAT OFFSET.  Frames are independent whole-range frames, so
     reads are offset-addressable / resumable.

 (4) INVISIBILITY (raw wire) — opening the SAME file WITHOUT the opaque (a stock
     kXR_open) yields cpsize == 0 and cptype[0] == 0 (a stock client sees no
     compression signal — opt-in invisibility), and a plain kXR_read returns the
     raw plaintext.

The byte-exact download tests use the native clean-room xrdcp against the shared
anon root:// server (port 11094), which the harness has configured with
`brix_read_compress on`.  The wire tests speak raw root:// framing (mirroring
test_compression_root_invariant.py) so we observe the exact bytes before any
client-side inflation can hide a distinction.

Run:
    pytest tests/test_compression_root_edge.py -v
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
# Client paths / target
# ---------------------------------------------------------------------------

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
BASE = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT


# ---------------------------------------------------------------------------
# Opcodes / status (from src/protocols/root/protocol/opcodes.h)
# ---------------------------------------------------------------------------

kXR_login = 3007
kXR_open  = 3010
kXR_read  = 3013
kXR_close = 3003

kXR_ok    = 0
kXR_error = 4003

kXR_open_read = 0x0010

# Phase-42 W4 open-reply signalling (src/core/compat/codec_core.h):
# ServerResponseBody_Open.cpsize = BRIX_INLINE_CMP_MAGIC ('Z' = 0x5A) and
# cptype[0] = <codec id ordinal>.  GZIP ordinal = 1 (zlib is mandatory).
INLINE_CMP_MAGIC = 0x5A
CODEC_GZIP       = 1


# ---------------------------------------------------------------------------
# Codec availability — gzip/deflate are always built in (zlib mandatory); zstd,
# lz4, etc. are compile-gated, so the SERVER simply won't compress for an absent
# codec and the native client falls back to plaintext.  Either way the download
# is byte-exact, which is exactly the contract we assert.  We pick a spread that
# stresses several backends on the incompressible path.
# ---------------------------------------------------------------------------
INCOMPRESSIBLE_CODECS = ["gzip", "zstd", "lz4"]


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror test_compression_root_invariant.py)
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
    """kXR_open.  `path` may carry an opaque '?...' (CGI) suffix inline; the wire
    path field is the full string + NUL, exactly as a stock client sends
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


def _parse_open_body(body):
    """ServerResponseBody_Open: fhandle[4] then OPTIONAL cpsize(int32 BE) cptype[4].
    A stock/plain kXR_open (no compression, no kXR_retstat) replies with JUST the
    4-byte fhandle — which is precisely 'no compression signal' (cpsize == 0,
    cptype all-zero).  The compression fields appear only when the server actually
    negotiated a codec.  Returns (fhandle, cpsize, cptype)."""
    assert len(body) >= 4, f"open reply too short for an fhandle: {len(body)}"
    fhandle = body[:4]
    if len(body) < 12:
        return fhandle, 0, b"\x00\x00\x00\x00"
    cpsize = struct.unpack("!i", body[4:8])[0]
    cptype = body[8:12]
    return fhandle, cpsize, cptype


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


@pytest.fixture(scope="module", autouse=True)
def _require_client():
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"xrdcp not built: {XRDCP}")


def _upload(payload, tag, tmpdir):
    """Write `payload` to a temp file and xrdcp it to a unique remote path.
    Returns (remote, local_src).  Skips on upload failure (no server-side
    prerequisites beyond a writable anon root, which the harness provides)."""
    src = os.path.join(tmpdir, f"{tag}.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    remote = f"/cmprootedge_{tag}_{uuid.uuid4().hex}.bin"
    up = subprocess.run([XRDCP, "-f", src, f"{BASE}{remote}"],
                        capture_output=True, text=True, timeout=120)
    if up.returncode != 0:
        pytest.skip(f"upload to root:// server failed: {up.stderr[:300]}")
    return remote, src


def _rm(remote):
    if os.access(XRDFS, os.X_OK):
        subprocess.run([XRDFS, BASE, "rm", remote], capture_output=True)


def _download(remote, out, codec=None):
    cmd = [XRDCP, "-f"]
    if codec is not None:
        cmd += ["--compress", codec]
    cmd += [f"{BASE}{remote}", out]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


# Incompressible 2 MiB payload: os.urandom spans multiple internal read windows
# and the codec output for each window is >= its plaintext input — the codec
# worst case.  Fixed seed-free random is fine; we keep the exact bytes in the
# fixture so the round-trip assertion is byte-exact.
@pytest.fixture(scope="module")
def random_uploaded(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("cmprootedge_rand"))
    payload = os.urandom(2 * 1024 * 1024)
    remote, _src = _upload(payload, "rand", d)
    yield remote, payload
    _rm(remote)


# A small, highly-compressible file for the EOF / short-final-window case and the
# raw-wire offset/invisibility tests (so a gzip frame is unmistakably smaller and
# gzip magic is present on the compressed path).
_LINE = b"the quick brown fox jumps over the lazy dog 0123456789\n"  # 54 bytes
SMALL_PAYLOAD = _LINE * 1300   # 70200 bytes, NOT a power of two


@pytest.fixture(scope="module")
def small_uploaded(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("cmprootedge_small"))
    remote, _src = _upload(SMALL_PAYLOAD, "small", d)
    yield remote, SMALL_PAYLOAD
    _rm(remote)


@pytest.fixture(scope="module")
def empty_uploaded(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("cmprootedge_empty"))
    remote, _src = _upload(b"", "empty", d)
    yield remote, b""
    _rm(remote)


# ===========================================================================
# (1) INCOMPRESSIBLE — worst-case expansion bound + cmp_scratch sizing
# ===========================================================================

class TestIncompressible:
    """Random 2 MiB data downloaded WITH --compress for several codecs must stay
    byte-exact even though every codec frame is >= its plaintext input.  Proves
    the server never corrupts or truncates incompressible data when the frame
    expands past the plaintext size (brix_codec_max_out bound + cmp_scratch)."""

    @pytest.mark.parametrize("codec", INCOMPRESSIBLE_CODECS)
    def test_random_download_byte_exact(self, random_uploaded, tmp_path, codec):
        remote, payload = random_uploaded
        out = str(tmp_path / f"rand_{codec}.out")
        r = _download(remote, out, codec=codec)
        assert r.returncode == 0, (
            f"--compress {codec} download of random data failed: {r.stderr[:300]}")
        with open(out, "rb") as fh:
            got = fh.read()
        assert len(got) == len(payload), (
            f"--compress {codec}: length mismatch "
            f"(got {len(got)}, want {len(payload)}) — truncation on the "
            "worst-case expansion path")
        assert got == payload, (
            f"--compress {codec}: incompressible 2 MiB download not byte-exact "
            "— corruption on the worst-case expansion path")

    def test_random_plain_download_byte_exact(self, random_uploaded, tmp_path):
        """Control: the same random file WITHOUT --compress is byte-exact (the
        uncompressed hot path is untouched)."""
        remote, payload = random_uploaded
        out = str(tmp_path / "rand_plain.out")
        r = _download(remote, out)
        assert r.returncode == 0, f"plain download failed: {r.stderr[:300]}"
        with open(out, "rb") as fh:
            assert fh.read() == payload, "plain random download not byte-exact"


# ===========================================================================
# (2) EOF / EMPTY
# ===========================================================================

class TestEofEmpty:
    """A 0-byte file with --compress is byte-exact empty (empty frame inflates to
    nothing) and a small file read entirely + past EOF returns exactly the source
    (no extra bytes after the final short window)."""

    @pytest.mark.parametrize("codec", ["gzip", "zstd"])
    def test_empty_file_compressed_byte_exact(self, empty_uploaded, tmp_path, codec):
        remote, payload = empty_uploaded
        out = str(tmp_path / f"empty_{codec}.out")
        r = _download(remote, out, codec=codec)
        assert r.returncode == 0, (
            f"--compress {codec} download of empty file failed: {r.stderr[:300]}")
        with open(out, "rb") as fh:
            got = fh.read()
        assert got == payload == b"", (
            f"--compress {codec}: empty file not byte-exact empty (got "
            f"{len(got)} bytes)")

    def test_small_file_compressed_byte_exact(self, small_uploaded, tmp_path):
        """A small file fully read with --compress (the body is one short final
        window; the client reads to EOF and a read past EOF yields no extra
        bytes) is byte-exact."""
        remote, payload = small_uploaded
        out = str(tmp_path / "small.out")
        r = _download(remote, out, codec="gzip")
        assert r.returncode == 0, f"small --compress download failed: {r.stderr[:300]}"
        with open(out, "rb") as fh:
            assert fh.read() == payload, "small --compress download not byte-exact"

    def test_read_past_eof_returns_no_extra_bytes(self, small_uploaded):
        """Raw wire: on a compression handle, a kXR_read whose offset is AT EOF
        returns an empty body (an empty frame inflating to zero bytes), proving
        the EOF/empty-range branch sends no spurious payload."""
        remote, payload = small_uploaded
        sock = _session()
        try:
            _, status, body = _open(sock, f"{remote}?xrootd.compress=gzip",
                                    kXR_open_read)
            assert status == kXR_ok, f"compressed open failed (status={status})"
            fh, cpsize, cptype = _parse_open_body(body)
            assert cpsize == INLINE_CMP_MAGIC and cptype[0] == CODEC_GZIP, (
                "compression not negotiated; is brix_read_compress on?")
            # Read AT EOF: offset == filesize.
            _, rstatus, rbody = _read(sock, fh, len(payload), 65536)
            assert rstatus == kXR_ok, f"read-at-EOF failed (status={rstatus})"
            assert rbody == b"", (
                f"read at EOF returned {len(rbody)} bytes; expected an empty "
                "frame/body")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()


# ===========================================================================
# (3) OFFSET-RESUME (raw wire) — frames are offset-addressable
# ===========================================================================

class TestOffsetResume:
    """Each kXR_read is an independent whole-range frame, so a read at a non-zero
    offset inflates to the source slice STARTING at that offset (resumable)."""

    def test_read_at_offset_matches_source_slice(self, small_uploaded):
        remote, payload = small_uploaded
        offset = len(payload) // 2
        want = 4096
        sock = _session()
        try:
            _, status, body = _open(sock, f"{remote}?xrootd.compress=gzip",
                                    kXR_open_read)
            assert status == kXR_ok, f"compressed open failed (status={status})"
            fh, cpsize, cptype = _parse_open_body(body)
            assert cpsize == INLINE_CMP_MAGIC and cptype[0] == CODEC_GZIP, (
                "compression not negotiated; is brix_read_compress on?")

            _, rstatus, rbody = _read(sock, fh, offset, want)
            assert rstatus == kXR_ok, f"offset read failed (status={rstatus})"
            assert _looks_gzip(rbody), (
                "offset read body is not a gzip frame — compression did not "
                f"engage (first bytes: {rbody[:4].hex()})")
            inflated = _gunzip(rbody)
            expect = payload[offset:offset + want]
            assert inflated == expect, (
                "inflated offset frame != source slice at that offset "
                f"(offset={offset}, got {len(inflated)} bytes)")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()

    def test_offset_zero_and_nonaligned_offset_differ(self, small_uploaded):
        """Two reads on the SAME handle at different offsets yield DIFFERENT
        plaintext slices — proving the frame really is keyed on the requested
        offset, not always serving from byte 0.

        The payload is a 54-byte line repeated, so an offset must be chosen that
        is NOT a multiple of 54 (otherwise both slices begin at the same phase of
        the repeating pattern and are legitimately identical — a property of the
        DATA, not the server).  37 is coprime with 54, so payload[37:] is phase-
        shifted relative to payload[0:]."""
        remote, payload = small_uploaded
        want = 4096
        off = 37  # not a multiple of the 54-byte line → genuinely different slice
        sock = _session()
        try:
            _, status, body = _open(sock, f"{remote}?xrootd.compress=gzip",
                                    kXR_open_read)
            assert status == kXR_ok, f"compressed open failed (status={status})"
            fh, cpsize, _cptype = _parse_open_body(body)
            assert cpsize == INLINE_CMP_MAGIC, "compression not negotiated"

            _, s0, b0 = _read(sock, fh, 0, want)
            _, s1, b1 = _read(sock, fh, off, want)
            assert s0 == kXR_ok and s1 == kXR_ok
            assert _gunzip(b0) == payload[:want]
            assert _gunzip(b1) == payload[off:off + want]
            assert _gunzip(b0) != _gunzip(b1), (
                "offset-0 and offset-37 frames inflate to identical bytes — "
                "frames are not offset-addressable")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()


# ===========================================================================
# (4) INVISIBILITY (raw wire) — a stock open sees no compression signal
# ===========================================================================

class TestInvisibilityWire:
    """Opening the SAME file WITHOUT the opaque (a stock kXR_open) yields cpsize
    == 0 and cptype[0] == 0 — a stock client sees no compression signal (opt-in
    invisibility) — and a plain kXR_read returns the raw plaintext."""

    def test_plain_open_reply_has_no_compression_signal(self, small_uploaded):
        remote, _payload = small_uploaded
        sock = _session()
        try:
            _, status, body = _open(sock, remote, kXR_open_read)
            assert status == kXR_ok, f"plain open failed (status={status})"
            fh, cpsize, cptype = _parse_open_body(body)
            assert cpsize == 0, (
                f"stock open reply leaked a compression signal: cpsize={cpsize:#x} "
                f"(expected 0) — invisibility violated")
            assert cptype[0] == 0, (
                f"stock open reply cptype[0]={cptype[0]} (expected 0) — "
                "invisibility violated")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()

    def test_plain_read_returns_raw_plaintext(self, small_uploaded):
        remote, payload = small_uploaded
        want = 4096
        sock = _session()
        try:
            _, status, body = _open(sock, remote, kXR_open_read)
            assert status == kXR_ok, f"plain open failed (status={status})"
            fh, cpsize, _cptype = _parse_open_body(body)
            assert cpsize == 0, "stock open unexpectedly negotiated compression"

            _, rstatus, rbody = _read(sock, fh, 0, want)
            assert rstatus == kXR_ok, f"plain read failed (status={rstatus})"
            assert not _looks_gzip(rbody), (
                "plain read body begins with gzip magic — a stock read was "
                "compressed, violating opt-in invisibility")
            assert rbody == payload[:want], (
                "plain read body is not raw plaintext")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()

    def test_same_file_plain_vs_compressed_open_diverge(self, small_uploaded):
        """End-to-end contrast: the SAME file opened plain reports cpsize==0,
        opened '?xrootd.compress=gzip' reports the magic + gzip ordinal — the
        compression signal is strictly opt-in per open."""
        remote, _payload = small_uploaded

        sock_p = _session()
        sock_c = _session()
        fh_p = fh_c = None
        try:
            _, sp, bp = _open(sock_p, remote, kXR_open_read)
            assert sp == kXR_ok
            fh_p, cpsize_p, cptype_p = _parse_open_body(bp)

            _, sc, bc = _open(sock_c, f"{remote}?xrootd.compress=gzip",
                              kXR_open_read)
            assert sc == kXR_ok
            fh_c, cpsize_c, cptype_c = _parse_open_body(bc)

            assert cpsize_p == 0 and cptype_p[0] == 0, "plain open leaked signal"
            assert cpsize_c == INLINE_CMP_MAGIC and cptype_c[0] == CODEC_GZIP, (
                "compressed open did not negotiate; is brix_read_compress on?")
        finally:
            for s, fhh in ((sock_p, fh_p), (sock_c, fh_c)):
                try:
                    if fhh is not None:
                        _close(s, fhh)
                except Exception:
                    pass
                s.close()
