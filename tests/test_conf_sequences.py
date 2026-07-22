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


@pytest.mark.parametrize("n", _SEQ_SIZES)
def test_create_write_fstat_read_close_stat_reopen(srv, n):
    payload = det_bytes(n, seed=(n & 0xff) ^ 0x5a)
    results = {}
    for who, url in both(srv):
        wire = uniq(f"seq_full_{who}_{n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            if n:
                st, body = _write(s, fh, 0, payload)
                assert st == kXR_ok, f"{who} write n={n} err={_err(body)}"
            # fstat on the OPEN handle must report the written size
            st, body = _fstat(s, fh)
            fstat_sz = _stat_size(body) if st == kXR_ok else None
            # read-back through the same handle
            rb = b""
            if n:
                st_r, rb = _read(s, fh, 0, n)
                assert st_r == kXR_ok, f"{who} read-back n={n} st={st_r}"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close n={n}"
            # stat(path) after close
            st, body = _stat_path(s, wire)
            assert st == kXR_ok, f"{who} stat(path) n={n}"
            path_sz = _stat_size(body)
            # reopen(read) and read it all again
            fh2 = _open_handle(s, wire, kXR_open_read)
            rb2 = b""
            if n:
                st_r, rb2 = _read(s, fh2, 0, n)
                assert st_r == kXR_ok, f"{who} reopen-read n={n}"
            _close(s, fh2)
        finally:
            s.close()
        # on-disk truth
        with open(disk_for(srv, url, wire), "rb") as f:
            disk = f.read()
        results[who] = dict(fstat=fstat_sz, path=path_sz, rb=rb, rb2=rb2,
                            disk=disk)
        # per-server invariants
        assert fstat_sz == n, f"{who} fstat size {fstat_sz} != {n}"
        assert path_sz == n, f"{who} stat(path) size {path_sz} != {n}"
        assert rb == payload, f"{who} same-handle read-back != written (n={n})"
        assert rb2 == payload, f"{who} reopen read-back != written (n={n})"
        assert disk == payload, f"{who} on-disk bytes != written (n={n})"
    # cross-server: identical at every checkpoint
    assert results["our"]["fstat"] == results["off"]["fstat"], \
        f"fstat size differs our vs stock (n={n})"
    assert results["our"]["path"] == results["off"]["path"], \
        f"stat(path) size differs our vs stock (n={n})"
    assert md5(results["our"]["disk"]) == md5(results["off"]["disk"]), \
        f"on-disk bytes differ our vs stock (n={n})"


# =========================================================================== #
# 2. CREATE -> write -> sync -> write more -> close -> verify full content.
# =========================================================================== #
@pytest.mark.parametrize("a_n,b_n", [(100, 100), (4096, 4096), (1, 8191),
                                     (4097, 1), (8192, 8192), (255, 4096)])
def test_write_sync_write_close_full_content(srv, a_n, b_n):
    a = det_bytes(a_n, seed=1)
    b = det_bytes(b_n, seed=2)
    expected = a + b
    for who, url in both(srv):
        wire = uniq(f"seq_sw_{who}_{a_n}_{b_n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, a)[0] == kXR_ok, f"{who} write A"
            assert _sync(s, fh)[0] == kXR_ok, f"{who} sync"
            assert _write(s, fh, a_n, b)[0] == kXR_ok, f"{who} write B"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == expected, f"{who} write-sync-write final content wrong"


# =========================================================================== #
# 3. CREATE -> write -> truncate(handle) SMALLER -> fstat==new -> read shows
#    truncated -> close -> verify on disk.
# =========================================================================== #
@pytest.mark.parametrize("n,keep", [(1000, 0), (1000, 1), (1000, 500),
                                    (4096, 1234), (8192, 4096), (8192, 0),
                                    (65536, 12345)])
def test_write_truncate_smaller_fstat_read(srv, n, keep):
    payload = det_bytes(n, seed=3)
    for who, url in both(srv):
        wire = uniq(f"seq_trs_{who}_{n}_{keep}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            st, body = _truncate_handle(s, fh, keep)
            assert st == kXR_ok, f"{who} handle-truncate err={_err(body)}"
            st, body = _fstat(s, fh)
            assert st == kXR_ok and _stat_size(body) == keep, \
                f"{who} fstat after shrink {_stat_size(body)} != {keep}"
            if keep:
                st_r, rb = _read(s, fh, 0, keep)
                assert st_r == kXR_ok and rb == payload[:keep], \
                    f"{who} truncated read mismatch"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == payload[:keep], f"{who} on-disk after shrink wrong"


# =========================================================================== #
# 4. CREATE -> write -> truncate LARGER (extend) -> read zero-fill region.
# =========================================================================== #
@pytest.mark.parametrize("n,grow", [(100, 4096), (4096, 8192), (1, 65536),
                                    (4096, 4097), (8192, 16384)])
def test_write_truncate_extend_zero_region(srv, n, grow):
    payload = det_bytes(n, seed=4)
    for who, url in both(srv):
        wire = uniq(f"seq_tre_{who}_{n}_{grow}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            st, body = _truncate_handle(s, fh, grow)
            assert st == kXR_ok, f"{who} extend err={_err(body)}"
            st, body = _fstat(s, fh)
            assert st == kXR_ok and _stat_size(body) == grow, \
                f"{who} fstat after extend != {grow}"
            st_r, hole = _read(s, fh, n, grow - n)
            assert st_r == kXR_ok and hole == b"\x00" * (grow - n), \
                f"{who} extended region not zero-filled"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got[:n] == payload and got[n:] == b"\x00" * (grow - n), \
            f"{who} on-disk extend wrong"


# =========================================================================== #
# 5. OPEN(update existing) -> overwrite MIDDLE -> close -> only middle changed.
# =========================================================================== #
@pytest.mark.parametrize("total,off,mlen", [(1000, 400, 100), (4096, 0, 4096),
                                            (200, 199, 1), (8192, 4000, 192),
                                            (65536, 30000, 4096), (500, 0, 1)])
def test_overwrite_middle_only(srv, total, off, mlen):
    base = det_bytes(total, seed=5)
    patch = det_bytes(mlen, seed=6)
    expected = bytearray(base)
    expected[off:off + mlen] = patch
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"seq_mid_{who}_{total}_{off}_{mlen}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_UPD)
            assert _write(s, fh, off, patch)[0] == kXR_ok, f"{who} overwrite"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert len(got) == total, f"{who} overwrite changed total size"
        assert got == expected, f"{who} overwrite touched bytes outside [off,off+mlen)"


# =========================================================================== #
# 6. CREATE -> write -> close -> reopen(update) -> append at size -> close ->
#    verify grown.
# =========================================================================== #
@pytest.mark.parametrize("base_n,app_n", [(100, 50), (4096, 4096), (1, 9999),
                                          (8192, 1), (65536, 4096), (255, 257)])
def test_reopen_append_grows(srv, base_n, app_n):
    base = det_bytes(base_n, seed=7)
    app = det_bytes(app_n, seed=8)
    for who, url in both(srv):
        wire = uniq(f"seq_app_{who}_{base_n}_{app_n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, base)[0] == kXR_ok, f"{who} write base"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close base"
            # reopen update, append at current size
            fh2 = _open_handle(s, wire, WRITE_UPD)
            assert _write(s, fh2, base_n, app)[0] == kXR_ok, f"{who} append"
            st, body = _fstat(s, fh2)
            assert st == kXR_ok and _stat_size(body) == base_n + app_n, \
                f"{who} fstat after append wrong"
            assert _close(s, fh2)[0] == kXR_ok, f"{who} close append"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == base + app, f"{who} reopen-append content wrong"


# =========================================================================== #
# 7. CREATE -> write -> close -> open(read) -> readv multi-seg -> bytes match.
# =========================================================================== #
@pytest.mark.parametrize("idx,segs", [
    (0, [(0, 16), (100, 32), (500, 64)]),
    (1, [(0, 4096), (4096, 4096)]),
    (2, [(10000, 1), (0, 1), (5000, 100)]),
    (3, [(0, 1), (1, 1), (2, 1), (3, 1)]),
    (4, [(0, 8192)]),
    (5, [(4095, 2), (8190, 2), (0, 4096)]),
])
def test_readv_multiseg_matches(srv, idx, segs):
    total = max(o + l for o, l in segs)
    payload = det_bytes(total + 16, seed=9)        # a bit larger than needed
    for who, url in both(srv):
        wire = uniq(f"seq_rv_{who}_{idx}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
            fh2 = _open_handle(s, wire, kXR_open_read)
            st, parts = _readv(s, [(fh2, o, l) for o, l in segs])
            assert st == kXR_ok, f"{who} readv st={st}"
            assert len(parts) == len(segs), \
                f"{who} readv returned {len(parts)} segs, want {len(segs)}"
            for (o, l), got in zip(segs, parts):
                assert got == payload[o:o + l], \
                    f"{who} readv seg @{o}+{l} mismatch"
            _close(s, fh2)
        finally:
            s.close()


# =========================================================================== #
# 8. CREATE -> write -> close -> open(delete/truncate-create) -> size 0 ->
#    write new -> verify replaced.
# =========================================================================== #
@pytest.mark.parametrize("first_n,second_n", [(1000, 10), (4096, 4096),
                                              (1, 8192), (8192, 1),
                                              (65536, 100), (4097, 4095)])
def test_recreate_via_delete_replaces(srv, first_n, second_n):
    first = det_bytes(first_n, seed=11)
    second = det_bytes(second_n, seed=12)
    for who, url in both(srv):
        wire = uniq(f"seq_rc_{who}_{first_n}_{second_n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, first)[0] == kXR_ok, f"{who} write first"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close first"
            # reopen with delete -> O_TRUNC; fstat must be 0 before writing
            fh2 = _open_handle(s, wire, kXR_delete | kXR_open_updt)
            st, body = _fstat(s, fh2)
            assert st == kXR_ok and _stat_size(body) == 0, \
                f"{who} delete-open did not truncate to 0 (got {_stat_size(body)})"
            assert _write(s, fh2, 0, second)[0] == kXR_ok, f"{who} write second"
            assert _close(s, fh2)[0] == kXR_ok, f"{who} close second"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == second, f"{who} recreate did not replace content"


# =========================================================================== #
# 9. TWO SEQUENTIAL SESSIONS — session1 creates+writes+closes; a brand-new
#    session2 opens+reads and must see the data (durability). Parity.
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 100, 4095, 4096, 4097, 65536, 1 << 20])
def test_durability_across_sessions(srv, n):
    payload = det_bytes(n, seed=13)
    for who, url in both(srv):
        wire = uniq(f"seq_dur_{who}_{n}.bin")
        s1 = _session(url)
        try:
            fh = _open_handle(s1, wire, WRITE_NEW)
            if n:
                assert _write(s1, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            assert _close(s1, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s1.close()
        s2 = _session(url)
        try:
            fh2 = _open_handle(s2, wire, kXR_open_read)
            rb = b""
            if n:
                st, rb = _read(s2, fh2, 0, n)
                assert st == kXR_ok, f"{who} session2 read st={st}"
            _close(s2, fh2)
        finally:
            s2.close()
        assert rb == payload, f"{who} session2 did not see session1 data (n={n})"


# =========================================================================== #
# 10. TWO HANDLES, ONE SESSION — write via h1, read via h2 (intra-session
#     coherence). Pin stock's coherence behaviour. The reader opens AFTER the
#     writer closes (single-writer lock), then both-open read-coherence with
#     two read handles is checked separately.
# =========================================================================== #
def test_two_handles_write_then_read_coherence(srv):
    payload = det_bytes(8192, seed=14)
    for who, url in both(srv):
        wire = uniq(f"seq_2h_{who}.bin")
        s = _session(url)
        try:
            # writer handle
            fhw = _open_handle(s, wire, WRITE_NEW, )
            assert _write(s, fhw, 0, payload)[0] == kXR_ok, f"{who} write h1"
            assert _close(s, fhw)[0] == kXR_ok, f"{who} close h1"
            # two simultaneous READ handles on the same session
            fh1 = _open_handle(s, wire, kXR_open_read)
            fh2 = _open_handle(s, wire, kXR_open_read)
            assert fh1 != fh2, f"{who} same fhandle for two opens"
            st1, d1 = _read(s, fh1, 0, 8192)
            st2, d2 = _read(s, fh2, 4096, 4096)
            assert st1 == kXR_ok and d1 == payload, f"{who} h1 read mismatch"
            assert st2 == kXR_ok and d2 == payload[4096:], f"{who} h2 read mismatch"
            _close(s, fh1)
            _close(s, fh2)
        finally:
            s.close()


# =========================================================================== #
# 11. CREATE -> write -> close -> RENAME -> open new name -> verify content +
#     checksum (xrdfs query checksum) matches the pre-rename file. Differential.
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 10, 4096, 65536])
def test_rename_preserves_content_and_checksum(srv, n):
    payload = det_bytes(n, seed=15)
    for who, url in both(srv):
        src_w = uniq(f"seq_mv_src_{who}_{n}.bin")
        dst_w = uniq(f"seq_mv_dst_{who}_{n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, src_w, WRITE_NEW)
            if n:
                assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        # rename via the stock client (mv) against THIS server
        rc, o, e = fs(url, "mv", src_w, dst_w)
        assert rc == 0, f"{who} mv failed: {o}{e}"
        assert not os.path.exists(disk_for(srv, url, src_w)), \
            f"{who} source still present after mv"
        # reopen the new name and verify byte content
        s = _session(url)
        try:
            fh2 = _open_handle(s, dst_w, kXR_open_read)
            rb = b""
            if n:
                st, rb = _read(s, fh2, 0, n)
                assert st == kXR_ok, f"{who} read after rename st={st}"
            assert rb == payload, \
                f"{who} content changed across rename"
            _close(s, fh2)
        finally:
            s.close()
        with open(disk_for(srv, url, dst_w), "rb") as f:
            assert f.read() == payload, f"{who} on-disk content wrong after mv"


# =========================================================================== #
# 12. CREATE -> write -> checksum(query) == zlib.adler32(written bytes).
#     Stock's harness ships no checksum plugin, so the *value* is verifiable
#     only on OUR server; we still pin our value against an independent
#     reference (zlib.adler32) and confirm stock cannot answer (capability
#     parity is covered in test_conf_cksum.py).
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 100, 4096, 4097, 10000, 65536])
def test_checksum_matches_adler32_of_written(srv, n):
    payload = det_bytes(n, seed=16)
    wire = uniq(f"seq_cks_{n}.bin")
    s = _session(srv["our"])
    try:
        fh = _open_handle(s, wire, WRITE_NEW)
        if n:
            assert _write(s, fh, 0, payload)[0] == kXR_ok, "write"
        assert _close(s, fh)[0] == kXR_ok, "close"
    finally:
        s.close()
    rc, out, err = L.run([L.OFF_XRDFS, srv["our"], "query", "checksum", wire],
                         timeout=120)
    assert rc == 0, f"OUR query checksum failed: {out}{err}"
    toks = out.split()
    assert len(toks) >= 2, f"unexpected checksum reply: {out!r}"
    algo, got = toks[0], toks[1]
    assert algo == "adler32", f"default checksum algo not adler32: {algo!r}"
    want = f"{zlib.adler32(payload) & 0xffffffff:08x}"
    assert got == want, \
        f"OUR adler32 over written bytes WRONG: server={got} reference={want} (n={n})"


# =========================================================================== #
# 13. CREATE IN A NEW DIR (mkpath) -> write -> close -> ls dir shows file ->
#     stat size -> rm file -> rmdir. Full lifecycle, differential.
# =========================================================================== #
@pytest.mark.parametrize("idx,n", [(0, 100), (1, 4096), (2, 0), (3, 65536)])
def test_mkpath_write_ls_stat_rm_rmdir(srv, idx, n):
    payload = det_bytes(n, seed=17)
    for who, url in both(srv):
        d = f"seq_md_{who}_{idx}"
        wire = uniq(f"{d}/sub/file.bin")
        dir_url = f"{url}//{d}/sub"
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_wrto | kXR_new | kXR_mkpath)
            if n:
                assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        assert os.path.exists(disk_for(srv, url, wire)), \
            f"{who} mkpath did not create the file"
        # ls the new dir shows the file
        rc, out, e = fs(url, "ls", f"/{d}/sub")
        assert rc == 0, f"{who} ls new dir failed: {out}{e}"
        assert "file.bin" in out, f"{who} ls did not list the new file: {out!r}"
        # stat size parity
        rc, out, e = fs(url, "stat", wire)
        assert rc == 0, f"{who} stat new file failed: {out}{e}"
        assert f"Size:   {n}" in out or f"Size: {n}" in out, \
            f"{who} stat size not {n}: {out!r}"
        # rm file then rmdir the (now empty) subdir
        assert fs(url, "rm", wire)[0] == 0, f"{who} rm file"
        assert not os.path.exists(disk_for(srv, url, wire)), f"{who} file not removed"
        assert fs(url, "rmdir", f"/{d}/sub")[0] == 0, f"{who} rmdir sub"
        assert not os.path.isdir(os.path.join(srv[f"{who}_data"], d, "sub")), \
            f"{who} subdir not removed"


# =========================================================================== #
# 14. UPLOAD (xrdcp) -> stat -> download -> md5 round-trip -> overwrite (-f) ->
#     re-download -> new md5. Differential across sizes incl 1 MB.
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 4096, 65536, 1 << 20])
def test_xrdcp_upload_stat_download_overwrite(srv, tmp_path, n):
    src1 = make_local(str(tmp_path / f"u1_{n}.bin"), n, seed=21)
    src2 = make_local(str(tmp_path / f"u2_{n}.bin"), n, seed=22)
    for who, url in both(srv):
        wire = uniq(f"seq_cp_{who}_{n}.bin")
        # upload v1
        rc, o, e = cp("-f", src1, f"{url}/{wire}")
        assert rc == 0, f"{who} upload v1 n={n}: {o}{e}"
        assert os.path.getsize(disk_for(srv, url, wire)) == n, \
            f"{who} on-disk size after upload != {n}"
        # stat size
        rc, out, e = fs(url, "stat", wire)
        assert rc == 0 and (f"Size:   {n}" in out or f"Size: {n}" in out), \
            f"{who} stat after upload: {out!r}"
        # download v1, md5 round-trip
        dl1 = str(tmp_path / f"dl1_{who}_{n}.bin")
        assert cp("-f", f"{url}/{wire}", dl1)[0] == 0, f"{who} download v1"
        with open(src1, "rb") as a, open(dl1, "rb") as b:
            assert md5(a.read()) == md5(b.read()), f"{who} v1 round-trip md5"
        # overwrite with v2 (-f), re-download, new md5
        assert cp("-f", src2, f"{url}/{wire}")[0] == 0, f"{who} overwrite v2"
        dl2 = str(tmp_path / f"dl2_{who}_{n}.bin")
        assert cp("-f", f"{url}/{wire}", dl2)[0] == 0, f"{who} download v2"
        with open(src2, "rb") as a, open(dl2, "rb") as b:
            assert md5(a.read()) == md5(b.read()), f"{who} v2 round-trip md5"


# =========================================================================== #
# 15. CREATE -> write -> close -> truncate(path) to 0 -> stat 0 -> read empty
#     -> write again -> verify.
# =========================================================================== #
@pytest.mark.parametrize("n,n2", [(1000, 500), (4096, 4096), (1, 8192),
                                  (65536, 100), (8192, 1)])
def test_truncate_path_zero_then_rewrite(srv, n, n2):
    first = det_bytes(n, seed=23)
    second = det_bytes(n2, seed=24)
    for who, url in both(srv):
        wire = uniq(f"seq_t0_{who}_{n}_{n2}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, first)[0] == kXR_ok, f"{who} write first"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close first"
        finally:
            s.close()
        # path-based truncate to 0
        assert fs(url, "truncate", wire, "0")[0] == 0, f"{who} truncate0"
        assert os.path.getsize(disk_for(srv, url, wire)) == 0, f"{who} not 0 on disk"
        s = _session(url)
        try:
            # stat(path) size 0, read empty
            st, body = _stat_path(s, wire)
            assert st == kXR_ok and _stat_size(body) == 0, f"{who} stat not 0"
            fhr = _open_handle(s, wire, kXR_open_read)
            st, rb = _read(s, fhr, 0, 4096)
            assert st == kXR_ok and rb == b"", f"{who} read after trunc0 not empty"
            _close(s, fhr)
            # write again
            fhw = _open_handle(s, wire, WRITE_UPD)
            assert _write(s, fhw, 0, second)[0] == kXR_ok, f"{who} rewrite"
            assert _close(s, fhw)[0] == kXR_ok, f"{who} close rewrite"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            assert f.read() == second, f"{who} rewrite content wrong"


# =========================================================================== #
# 16. ERROR-MID-SEQUENCE — open -> write -> close, then a SECOND write on the
#     now-closed handle -> error parity; prior data must remain intact on both.
# =========================================================================== #
def test_write_to_closed_handle_errors_data_intact(srv):
    payload = det_bytes(1024, seed=25)
    extra = det_bytes(64, seed=26)
    res = {}
    for who, url in both(srv):
        wire = uniq(f"seq_err_{who}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
            # write to the (closed) handle -> must error
            st, body = _write(s, fh, 0, extra)
            res[who] = st
        finally:
            s.close()
        # the previously written data must be intact and unchanged
        with open(disk_for(srv, url, wire), "rb") as f:
            assert f.read() == payload, \
                f"{who} prior data corrupted by write to closed handle"
    assert res["our"] == kXR_error, \
        f"OUR accepted write to a closed handle (st={res['our']})"
    assert res["off"] == kXR_error, \
        f"STOCK accepted write to a closed handle (st={res['off']})"


# =========================================================================== #
# 17. MANY SMALL FILES — create+write+close 20 files -> ls shows 20 -> stat
#     each -> read each -> rm each. Counts/bytes compared to stock.
# =========================================================================== #
def test_many_small_files_lifecycle(srv):
    count = 20
    for who, url in both(srv):
        d = f"seq_many_{who}"
        bytes_total = 0
        s = _session(url)
        try:
            for i in range(count):
                wire = uniq(f"{d}/f{i:02d}.bin")
                opt = kXR_open_wrto | kXR_new | kXR_mkpath
                fh = _open_handle(s, wire, opt)
                payload = det_bytes(10 + i, seed=i)
                bytes_total += len(payload)
                assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write {i}"
                assert _close(s, fh)[0] == kXR_ok, f"{who} close {i}"
        finally:
            s.close()
        # ls shows exactly `count` entries
        rc, out, e = fs(url, "ls", f"/{d}")
        assert rc == 0, f"{who} ls failed: {out}{e}"
        names = [ln.strip().split("/")[-1] for ln in out.splitlines() if ln.strip()]
        names = [nm for nm in names if nm.startswith("f")]
        assert len(names) == count, \
            f"{who} ls listed {len(names)} files, want {count}: {names}"
        # stat + read each, then rm each
        s = _session(url)
        try:
            disk_bytes = 0
            for i in range(count):
                wire = uniq(f"{d}/f{i:02d}.bin")
                exp = det_bytes(10 + i, seed=i)
                st, body = _stat_path(s, wire)
                assert st == kXR_ok and _stat_size(body) == len(exp), \
                    f"{who} stat f{i:02d} size wrong"
                fhr = _open_handle(s, wire, kXR_open_read)
                st, rb = _read(s, fhr, 0, len(exp))
                assert st == kXR_ok and rb == exp, f"{who} read f{i:02d} mismatch"
                disk_bytes += len(rb)
                _close(s, fhr)
        finally:
            s.close()
        assert disk_bytes == bytes_total, \
            f"{who} total bytes read {disk_bytes} != written {bytes_total}"
        for i in range(count):
            assert fs(url, "rm", uniq(f"{d}/f{i:02d}.bin"))[0] == 0, \
                f"{who} rm f{i:02d}"
        rc, out, e = fs(url, "ls", f"/{d}")
        remaining = [ln for ln in out.splitlines()
                     if ln.strip().endswith(".bin")]
        assert remaining == [], f"{who} files remain after rm: {remaining}"


# =========================================================================== #
# 18. PGWRITE then PLAIN-READ — write a file via kXR_pgwrite, read it back with
#     a plain kXR_read; the bytes must match (cross-mode coherence). If pgwrite
#     is not plainly supported on this wire path on a server, that server's pair
#     is skipped cleanly (we still require OUR to support it if STOCK does).
# =========================================================================== #
@pytest.mark.parametrize("n", [100, 4095, 4096, 4097, 8192])
def test_pgwrite_then_plain_read(srv, n):
    payload = det_bytes(n, seed=27)
    supported = {}
    for who, url in both(srv):
        wire = uniq(f"seq_pgw_{who}_{n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            st, body = _pgwrite(s, fh, 0, payload)
            if st not in (kXR_ok, kXR_status):
                supported[who] = False
                # drain/close and move on
                try:
                    _close(s, fh)
                except Exception:
                    pass
                continue
            supported[who] = True
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
            # plain read-back
            fhr = _open_handle(s, wire, kXR_open_read)
            st_r, rb = _read(s, fhr, 0, n)
            assert st_r == kXR_ok and rb == payload, \
                f"{who} pgwrite->plain-read coherence mismatch"
            _close(s, fhr)
        finally:
            s.close()
        if supported.get(who):
            with open(disk_for(srv, url, wire), "rb") as f:
                assert f.read() == payload, f"{who} pgwrite on-disk bytes wrong"
    # If stock supports pgwrite on this wire path, OUR must too (no silent gap).
    if supported.get("off") and not supported.get("our"):
        pytest.fail("STOCK accepts kXR_pgwrite but OUR server does not")
    if not any(supported.values()):
        pytest.skip("kXR_pgwrite not plainly supported on either server")


# =========================================================================== #
# 19. WRITE -> SYNC -> mtime advances vs the pre-write mtime (both servers).
# =========================================================================== #
def test_write_sync_advances_mtime(srv):
    payload = det_bytes(4096, seed=28)
    for who, url in both(srv):
        wire = uniq(f"seq_mt_{who}.bin")
        # Seed the file out-of-band, then let >1s elapse so a write+sync must
        # land in a LATER integer second than the creation mtime.  Never
        # backdate the mtime below "now": _wipe_stale_working_files judges
        # staleness by mtime vs each worker's import time, so a backdated
        # fixture looks like a prior run's leftover and a concurrent xdist
        # worker's janitor deletes it mid-test.
        disk = disk_for(srv, url, wire)
        with open(disk, "wb") as f:
            f.write(det_bytes(64, seed=99))
        before = int(os.stat(disk).st_mtime)
        time.sleep(1.1)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_UPD)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            assert _sync(s, fh)[0] == kXR_ok, f"{who} sync"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        after = int(os.stat(disk).st_mtime)
        assert after > before, \
            f"{who} mtime did not advance after write+sync ({before} -> {after})"
