"""Differential conformance for STATEFUL OP SEQUENCES and end-to-end integrity.

Where the sibling single-op files (test_conf_write.py [N/A], test_conf_truncate_sync.py,
test_conf_openflags.py) pin ONE operation at a time, this file pins CHAINS of
operations carried on a single handle / session, and verifies that the result
matches the stock XRootD data server at EVERY checkpoint — handle coherence,
cross-op consistency, durability across reopen, rename-preserves-bytes, etc.

Every sequence is run IDENTICALLY against BOTH our nginx-xrootd server and the
stock xrootd data server (via official_interop_lib.start_pair), on independent
throwaway trees, and the outcome (size / bytes / flags / durability / coherence)
is compared at each step. The stock server is the reference.

Headline invariant (per the maintainer): a full
    create -> write -> close -> reopen -> read
chain MUST yield byte-identical data on OUR exactly as it does on STOCK. Any
divergence at ANY checkpoint — a different size, different bytes, lost durability,
a coherence difference between two handles, a checksum mismatch — is a BUG IN OUR
SERVER. We pin stock; no xfail / skip is used to hide a real difference.

Coverage families (each a DISTINCT multi-op sequence):
  1. create -> write N -> fstat(handle)==N -> read-back -> close -> stat(path)==N
     -> reopen read-back  (size matrix)
  2. create -> write -> sync -> write more -> close -> verify full content
  3. create -> write -> truncate(handle) smaller -> fstat==new -> read shows
     truncated -> close -> verify on disk
  4. create -> write -> truncate larger (extend) -> read zero-fill region
  5. open(update existing) -> overwrite middle -> close -> only middle changed
  6. create -> write -> close -> reopen(update) -> append at size -> verify grown
  7. create -> write -> close -> open(read) -> readv multi-seg -> bytes match
  8. create -> write -> close -> open(delete/truncate-create) -> size 0 ->
     write new -> verify replaced
  9. two sequential sessions: s1 creates+writes+closes; s2 opens+reads (durability)
 10. open same file twice in one session -> write via h1 -> read via h2 (coherence)
 11. create -> write -> close -> rename -> open new name -> verify + checksum parity
 12. create -> write -> checksum(query) == zlib.adler32(written)  [OUR-verifiable]
 13. create in a NEW dir (mkpath) -> write -> close -> ls -> stat -> rm -> rmdir
 14. xrdcp upload -> stat -> download -> md5 round-trip -> overwrite -f -> re-md5
 15. create -> write -> close -> truncate(path) to 0 -> stat 0 -> read empty ->
     write again
 16. error-mid-sequence: write to a CLOSED handle -> error parity, prior data intact
 17. many small files in a loop: create+write+close 20 -> ls 20 -> stat/read each -> rm each
 18. pgwrite a file then plain-read it back == written (cross-mode coherence)
 19. write -> sync -> mtime advances vs pre-write

Self-provisioning on high ports; skips entirely without the stock toolchain.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    python -m pytest tests/test_conf_sequences.py -q
"""

import hashlib
import os
import socket
import struct
import time
import zlib

import pytest

import official_interop_lib as L
from settings import BIND_HOST

pytestmark = [pytest.mark.timeout(360),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14056)
OFF_PORT = L.worker_port(14057)
BIND = BIND_HOST


# --------------------------------------------------------------------------- #
# Fixture: one server pair for the whole module (skip cleanly if it can't run)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("seq"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Stock-client + on-disk helpers
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    """Run the stock xrdfs against a server url -> (rc, out, err)."""
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def cp(*args, timeout=300):
    """Run the stock xrdcp -> (rc, out, err)."""
    return L.run([L.OFF_XRDCP, *args], timeout=timeout)


def uniq(name):
    return "/" + name


def our_disk(ctx, path):
    return os.path.join(ctx["our_data"], path.lstrip("/"))


def off_disk(ctx, path):
    return os.path.join(ctx["off_data"], path.lstrip("/"))


def disk_for(ctx, url, path):
    return our_disk(ctx, path) if url == ctx["our"] else off_disk(ctx, path)


def host_port(url):
    rest = url.split("://", 1)[1]
    host, _, port = rest.partition(":")
    return host, int(port)


def det_bytes(n, seed=0):
    return bytes((i * 37 + 11 + seed) & 0xff for i in range(n))


def make_local(path, n, seed=0):
    with open(path, "wb") as f:
        f.write(det_bytes(n, seed))
    return path


def md5(b):
    return hashlib.md5(b).hexdigest()


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _stat_size_if_ok(status, body):
    if status != kXR_ok:
        return None
    return _stat_size(body)


def both(ctx):
    """Iterate (who, url) for the two servers, stock first is irrelevant; we run
    the identical chain on each and compare the per-step outcome."""
    return (("our", ctx["our"]), ("off", ctx["off"]))


# --------------------------------------------------------------------------- #
# RAW-WIRE client (login / open / write / pgwrite / read / readv / fstat /
# sync / truncate / close). Framing per XProtocol.hh, copied from the sibling
# conformance files so the wire path is identical.
# --------------------------------------------------------------------------- #
kXR_close, kXR_open, kXR_read, kXR_readv = 3003, 3010, 3013, 3025
kXR_sync, kXR_write, kXR_stat, kXR_truncate = 3016, 3019, 3017, 3028
kXR_pgwrite = 3026               # XProtocol.hh:139 (NOT 3031 = kXR_writev)
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003
kXR_status = 4007                # pgwrite/pgread reply carries a kXR_status frame

# open option bits (XProtocol.hh XOpenRequestOption)
kXR_delete = 0x0002
kXR_new = 0x0008
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_mkpath = 0x0100
kXR_open_wrto = 0x8000

# stat() request option: kXR_vfs is for filesystem; default (0) stats the path.


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("connection closed")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    return sid, status, (_recv_exact(s, dlen) if dlen else b"")


def _connect(host, port):
    s = socket.create_connection((host, port), timeout=15)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, st, _ = _resp(s)            # handshake reply
    assert st == kXR_ok, "handshake failed"
    return s


def _login(s, sid=b"\x00\x01"):
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, 3007,
                          os.getpid() & 0x7fffffff, b"sequ\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(url):
    host, port = host_port(url)
    s = _connect(host, port)
    _login(s)
    return s


def _open(s, path, options, mode=0o0644, sid=b"\x00\x03"):
    p = path.encode()
    s.sendall(struct.pack("!2sHHH12sI", sid, kXR_open, mode, options,
                          b"\x00" * 12, len(p)) + p)
    _, st, body = _resp(s)
    return st, body


def _open_handle(s, path, options, mode=0o0644):
    st, body = _open(s, path, options, mode)
    assert st == kXR_ok, \
        f"open {path} (opt=0x{options:x}) failed: st={st} body={body!r}"
    return body[0:4]


def _write(s, fhandle, offset, data, sid=b"\x00\x07"):
    hdr = struct.pack("!2sH4sqB3sI", sid, kXR_write, fhandle, offset,
                      0, b"\x00\x00\x00", len(data))
    s.sendall(hdr + data)
    _, st, body = _resp(s)
    return st, body


def _pgwrite(s, fhandle, offset, data, sid=b"\x00\x08"):
    """kXR_pgwrite: the request carries a leading per-page CRC32c for the data.
    Wire (XProtocol.hh ClientPgWriteRequest): streamid[2] reqid[2] fhandle[4]
    offset[8] pathid[1] reserved[3] dlen[4]; the payload is
    crc32c(page0)[4] + page0bytes ... per 4096-byte page (CRC precedes each
    page's bytes). For a single sub-page write the payload is crc[4]+bytes."""
    PAGE = 4096
    payload = b""
    pos = 0
    pg_off = offset
    while pos < len(data):
        # first page may be short if offset is not page-aligned
        room = PAGE - (pg_off % PAGE)
        chunk = data[pos:pos + room]
        crc = _crc32c(chunk)
        payload += struct.pack("!I", crc) + chunk
        pos += len(chunk)
        pg_off += len(chunk)
    # ClientPgWriteRequest: streamid[2] reqid[2] fhandle[4] offset[8] pathid[1]
    # reqflags[1] reserved[2] dlen[4] (XProtocol.hh:562).
    hdr = struct.pack("!2sH4sqBB2sI", sid, kXR_pgwrite, fhandle, offset,
                      0, 0, b"\x00\x00", len(payload))
    s.sendall(hdr + payload)
    # pgwrite replies with a kXR_status(4007) frame (not plain kXR_ok). Read
    # until a terminal status; success is kXR_ok or kXR_status. Any kXR_error
    # means this wire path rejects pgwrite, so the caller can skip cleanly.
    _, st, body = _resp(s)
    return st, body


def _read(s, fhandle, offset, rlen, sid=b"\x00\x06"):
    s.sendall(struct.pack("!2sH4sqiI", sid, kXR_read, fhandle, offset, rlen, 0))
    data = b""
    while True:
        _, st, body = _resp(s)
        if st not in (kXR_ok, kXR_oksofar):
            return st, data
        data += body
        if st == kXR_ok:
            return st, data


def _readv(s, segments, sid=b"\x00\x09"):
    """kXR_readv over a list of (fhandle, offset, length). The request body is a
    sequence of read_list entries: fhandle[4] rlen[4] offset[8] (XProtocol.hh
    readahead_list). Returns (status, list-of-segment-bytes)."""
    body = b""
    for fh, off, ln in segments:
        body += struct.pack("!4siq", fh, ln, off)
    s.sendall(struct.pack("!2sH16sI", sid, kXR_readv, b"\x00" * 16, len(body))
              + body)
    raw = b""
    while True:
        _, st, chunk = _resp(s)
        if st not in (kXR_ok, kXR_oksofar):
            return st, raw
        raw += chunk
        if st == kXR_ok:
            break
    # parse readv response: each segment is preceded by a
    # ServerResponseBody_ReadV header: fhandle[4] rlen[4] offset[8] = 16 bytes
    out = []
    pos = 0
    while pos + 16 <= len(raw):
        rlen = struct.unpack("!i", raw[pos + 4:pos + 8])[0]
        pos += 16
        out.append(raw[pos:pos + rlen])
        pos += rlen
    return st, out


def _fstat(s, fhandle, sid=b"\x00\x0c"):
    """kXR_stat with a 4-byte fhandle (dlen==0, fhandle in the request) returns
    a stat line for the OPEN handle. Wire: streamid[2] reqid[2] opts[1]
    reserved[11] fhandle[4] dlen[4]. The XRootD stat-by-handle uses the
    fhandle field; we send dlen=0 and the fhandle in the reserved/fhandle slot
    per ClientStatRequest (XProtocol.hh:619: opts[1] reserved[11] fhandle[4])."""
    s.sendall(struct.pack("!2sHB11s4sI", sid, kXR_stat, 0, b"\x00" * 11,
                          fhandle, 0))
    _, st, body = _resp(s)
    return st, body


def _stat_path(s, path, sid=b"\x00\x0d"):
    p = path.encode()
    s.sendall(struct.pack("!2sHB11s4sI", sid, kXR_stat, 0, b"\x00" * 11,
                          b"\x00" * 4, len(p)) + p)
    _, st, body = _resp(s)
    return st, body


def _sync(s, fhandle, sid=b"\x00\x0a"):
    s.sendall(struct.pack("!2sH4s12sI", sid, kXR_sync, fhandle, b"\x00" * 12, 0))
    _, st, body = _resp(s)
    return st, body


def _truncate_handle(s, fhandle, size, sid=b"\x00\x0b"):
    s.sendall(struct.pack("!2sH4sq4sI", sid, kXR_truncate, fhandle, size,
                          b"\x00" * 4, 0))
    _, st, body = _resp(s)
    return st, body


def _close(s, fhandle, sid=b"\x00\x0e"):
    s.sendall(struct.pack("!2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0))
    _, st, body = _resp(s)
    return st, body


def _err(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _stat_size(body):
    """Parse the size field out of a kXR_stat reply ('id size flags modtime')."""
    txt = body.split(b"\x00")[0].decode("ascii", "replace").strip()
    fields = txt.split()
    if len(fields) >= 4 and all(f.lstrip("-").isdigit() for f in fields[:4]):
        return int(fields[1])
    return None


def _stat_mtime(body):
    txt = body.split(b"\x00")[0].decode("ascii", "replace").strip()
    fields = txt.split()
    if len(fields) >= 4 and all(f.lstrip("-").isdigit() for f in fields[:4]):
        return int(fields[3])
    return None


# --- CRC-32C (Castagnoli) for pgwrite payloads ----------------------------- #
_CRC32C_TABLE = []


def _build_crc32c_table():
    poly = 0x82F63B78
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if (c & 1) else c >> 1
        _CRC32C_TABLE.append(c & 0xFFFFFFFF)


_build_crc32c_table()


def _crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# Open option for a fresh create-or-truncate write handle.
WRITE_NEW = kXR_new | kXR_open_updt | kXR_delete
WRITE_UPD = kXR_open_updt


# =========================================================================== #
# 1. CREATE -> write N -> fstat(handle)==N -> read-back -> close ->
#    stat(path)==N -> reopen read-back. Full happy-path coherence chain, run
#    identically on BOTH servers and compared step-by-step. (size matrix)
# =========================================================================== #
_SEQ_SIZES = [0, 1, 100, 255, 4095, 4096, 4097, 8192, 65536, 1 << 20]
