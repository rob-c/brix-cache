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
