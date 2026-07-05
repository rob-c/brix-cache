# _test_conf_pgio_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_pgio.py.  `from _test_conf_pgio_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""Differential PAGED-I/O (kXR_pgread / kXR_pgwrite) conformance.

kXR_pgread (3030) and kXR_pgwrite (3026) move file data in 4096-byte *pages*,
each page preceded (pgread) or prefixed (pgwrite) by a 4-byte CRC-32C
(Castagnoli, IETF RFC 7143) of that page's bytes. The response framing is the
kXR_status (4007) message family (ServerResponseBody_Status + an 8-byte file
offset + the interleaved [crc32c][page] data stream).

The reference for every assertion here is the STOCK XRootD server (launched on
an identical data tree next to our nginx-xrootd) and the stock client tools
(xrdcp). Wherever the high-level tools cannot exercise a wire corner, the
request is crafted as RAW WIRE over a plain TCP socket and replayed against BOTH
servers; the two answers, and the bytes/CRCs they carry, must agree. Any
divergence -- a wrong per-page CRC, a wrong page boundary / short-page split, a
botched reassembly, a corrupt page that is NOT rejected, or framing that
differs from stock -- is treated as a BUG IN OUR SERVER, and the assertion is
written to fail (no xfail/skip to paper over a real diff).

Wire references (consulted, not modified):
  /tmp/brix-src/src/XProtocol/XProtocol.hh
      ClientPgReadRequest / ClientPgWriteRequest
      ServerResponseBody_Status (kXR_status)  + ServerResponseBody_pgRead
      ServerResponseBody_pgWrite + ServerResponseBody_pgWrCSE
      kXR_pgPageSZ=4096  kXR_pgUnitSZ=4100  kXR_pgRetry=0x01
  /tmp/brix-src/src/XrdXrootd/XrdXrootdXeqPgrw.cc  do_PgRIO / do_PgWIO
  /tmp/brix-src/src/XrdXrootd/XrdXrootdResponse.cc srsComplete (status framing)

The status-response crc32c body field covers streamID..info (NOT the page
data); the per-page CRC32c values are what this suite verifies for data
integrity. Self-provisions on high ports; skips entirely without the stock
toolchain.
"""

import hashlib
import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Opcodes / status / error codes (XProtocol.hh).                              #
# --------------------------------------------------------------------------- #
kXR_login = 3007
kXR_open = 3010
kXR_close = 3003
kXR_read = 3013
kXR_pgwrite = 3026
kXR_pgread = 3030
kXR_1stRequest = 3000

kXR_ok = 0
kXR_oksofar = 4000
kXR_error = 4003
kXR_status = 4007

kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_new = 0x0008
kXR_delete = 0x0002
kXR_mkpath = 0x0100
kXR_open_wrto = 0x8000

# kXR_status RespType (XrdProto::RespType).
kXR_FinalResult = 0x00
kXR_PartialResult = 0x01

# Paged-I/O framing constants (XProtocol.hh XrdProto namespace).
PG_PAGE = 4096                 # kXR_pgPageSZ
PG_CRC = 4                     # sizeof(kXR_unt32)
PG_UNIT = PG_PAGE + PG_CRC     # kXR_pgUnitSZ = 4100
kXR_pgRetry = 0x01

# ServerResponseBody_Status length (crc32c[4]+streamID[2]+requestid[1]+
# resptype[1]+reserved[4]+dlen[4]); the kXR_status "info" for pg-I/O is the
# 8-byte file offset.
STATUS_BODY_LEN = 16
PG_INFO_LEN = 8

# Deterministic file sizes materialised by official_interop_lib.make_rich_tree.
SZ_FILES = {
    "sz_1.bin": 1,
    "sz_255.bin": 255,
    "sz_4095.bin": 4095,
    "sz_4096.bin": 4096,
    "sz_4097.bin": 4097,
    "sz_8192.bin": 8192,
    "sz_65536.bin": 65536,
}
DATA_BIN = "data.bin"      # 4096
DATA_SIZE = 4096
BIG_BIN = "big1m.bin"      # 1048576
BIG_SIZE = 1024 * 1024
CKSUM_BIN = "cksum.bin"    # 10000


# ===========================================================================
# Software CRC-32C (Castagnoli, poly 0x1EDC6F41 reflected = 0x82F63B78).
# Self-checked against the canonical vector "123456789" -> 0xe3069283.
# ===========================================================================
def _build_crc32c_table():
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if (c & 1) else (c >> 1)
        table.append(c & 0xFFFFFFFF)
    return table


_CRC32C_TABLE = _build_crc32c_table()


def crc32c(data, crc=0):
    """CRC-32C (Castagnoli) over `data`, returned as an unsigned 32-bit int."""
    c = crc ^ 0xFFFFFFFF
    tbl = _CRC32C_TABLE
    for b in data:
        c = tbl[(c ^ b) & 0xFF] ^ (c >> 8)
    return (c ^ 0xFFFFFFFF) & 0xFFFFFFFF


# ===========================================================================
# Page math: the documented kXR_pgread/pgwrite offset-alignment rule. The
# first page is short to the next 4096 boundary when offset is unaligned;
# interior pages are full 4096; the final page is the short remainder.
# Mirrors XrdOucPgrwUtils::csNum exactly.
# ===========================================================================
def page_lengths(offset, total):
    """List of per-page data lengths for `total` bytes starting at `offset`."""
    if total <= 0:
        return []
    lens = []
    remaining = total
    pgoff = offset & (PG_PAGE - 1)
    if pgoff:
        first = min(PG_PAGE - pgoff, remaining)
        lens.append(first)
        remaining -= first
    while remaining > 0:
        n = min(PG_PAGE, remaining)
        lens.append(n)
        remaining -= n
    return lens


def page_slices(src, offset, total):
    """(off, bytes) per page over src[offset:offset+total] per the page rule."""
    out = []
    o = offset
    for ln in page_lengths(offset, total):
        out.append((o, src[o:o + ln]))
        o += ln
    return out


# ===========================================================================
# Module-scoped server pair: our nginx-xrootd + stock xrootd, identical tree.
# ===========================================================================
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conf_pgio"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14042), off_port=L.worker_port(14043))
    except Exception as e:  # noqa: BLE001 - any launch failure -> skip cleanly
        pytest.skip(f"server pair did not start: {e}")
    ctx["our_hp"] = _split_hostport(ctx["our"])
    ctx["off_hp"] = _split_hostport(ctx["off"])
    yield ctx
    L.stop_pair(procs)


def _split_hostport(url):
    rest = url.split("://", 1)[1]
    host, _, port = rest.partition(":")
    return host, int(port)


def _local(ctx, name):
    with open(os.path.join(ctx["our_data"], name), "rb") as f:
        return f.read()


# --------------------------------------------------------------------------- #
# Minimal raw-wire client (login + open + read + pgread + pgwrite + close).   #
# --------------------------------------------------------------------------- #
def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed, {nbytes - len(data)} left")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _handshake(host, port):
    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(30)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, status, _ = _read_response(sock)
    assert status == kXR_ok, "handshake rejected"
    return sock


def _login(sock, streamid=b"\x00\x01"):
    req = struct.pack("!2sHI8sBBBBI", streamid, kXR_login,
                      os.getpid() & 0x7fffffff, b"pytest\x00\x00",
                      0, 0, 0, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


def _session(host, port):
    sock = _handshake(host, port)
    _, status, _ = _login(sock)
    assert status == kXR_ok, "login rejected"
    return sock


def _open(sock, path, options=kXR_open_read, mode=0o644, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI", streamid, kXR_open,
                      mode, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
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


def _read_drain(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    """Issue kXR_read; gather chunks until the terminating kXR_ok."""
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    data = bytearray()
    while True:
        _, status, chunk = _read_response(sock)
        if status == kXR_error:
            return kXR_error, bytes(chunk)
        data.extend(chunk)
        if status == kXR_ok:
            return kXR_ok, bytes(data)
        assert status == kXR_oksofar, f"unexpected read status {status}"


# --------------------------------------------------------------------------- #
# kXR_pgread request + kXR_status response reassembly.                        #
#                                                                             #
# Request body: fhandle[4] offset(i64) rlen(i32) dlen(i32=0).                 #
# Response: a sequence of kXR_status messages. Each message header dlen counts #
# ONLY the status body(16) + info(8); the status body's own dlen field counts  #
# the page-data bytes that follow. We must read both. resptype distinguishes   #
# kXR_PartialResult (more to come) from kXR_FinalResult (done).               #
# --------------------------------------------------------------------------- #
def _pgread_req(fhandle, offset, rlen, reqflags=0, streamid=b"\x00\x07"):
    dlen = 0
    body = b""
    if reqflags:
        # ClientPgReadReqArgs: pathid + reqflags (dlen=2; pathid=0).
        body = struct.pack("!BB", 0, reqflags)
        dlen = len(body)
    req = struct.pack("!2sH4sqiI", streamid, kXR_pgread, fhandle,
                      offset, rlen, dlen)
    return req + body


def _read_status_message(sock):
    """Read ONE kXR_status message: returns (resptype, info_offset, data)."""
    streamid, status, hdrbody = _read_response(sock)
    if status == kXR_error:
        return ("error", None, hdrbody)
    assert status == kXR_status, f"expected kXR_status, got {status}"
    # hdrbody = status-body(16) + info(8)  (== header dlen bytes).
    assert len(hdrbody) >= STATUS_BODY_LEN + PG_INFO_LEN, (
        f"kXR_status body too short: {len(hdrbody)}")
    (_crc, _sid, _reqid, resptype) = struct.unpack("!I2sBB", hdrbody[:8])
    (data_dlen,) = struct.unpack("!i", hdrbody[12:16])
    (info_offset,) = struct.unpack("!q", hdrbody[16:24])
    data = _recv_exact(sock, data_dlen) if data_dlen > 0 else b""
    return (resptype, info_offset, data)


def pgread(sock, fhandle, offset, rlen, reqflags=0, streamid=b"\x00\x07"):
    """Issue a pgread and reassemble every kXR_status chunk.

    Returns (status, pages) where status is kXR_ok or kXR_error and pages is a
    list of (page_offset, page_bytes, page_crc) in wire order across all chunks.
    The page_offset is computed from the per-message info offset + running page
    spans (csNum's offset-alignment rule)."""
    sock.sendall(_pgread_req(fhandle, offset, rlen, reqflags, streamid))
    pages = []
    while True:
        resptype, info_off, data = _read_status_message(sock)
        if resptype == "error":
            return kXR_error, data
        # Split the data stream into [crc(4)][page(<=4096)] units. The page
        # length is whatever remains up to the next 4096 file-offset boundary.
        pos = 0
        cur = info_off
        while pos < len(data):
            crc = struct.unpack("!I", data[pos:pos + PG_CRC])[0]
            pos += PG_CRC
            pgoff = cur & (PG_PAGE - 1)
            span = PG_PAGE - pgoff if pgoff else PG_PAGE
            take = min(span, len(data) - pos)
            page = data[pos:pos + take]
            pos += take
            pages.append((cur, page, crc))
            cur += take
        if resptype == kXR_FinalResult:
            return kXR_ok, pages
        assert resptype == kXR_PartialResult, f"bad resptype {resptype}"


def pgread_bytes(pages):
    return b"".join(p for (_o, p, _c) in pages)


# --------------------------------------------------------------------------- #
# kXR_pgwrite request: fhandle[4] offset(i64) pathid(1) reqflags(1) rsvd[2]   #
# dlen(i32). Payload = [crc(4)][page] units (first page short if unaligned).  #
# --------------------------------------------------------------------------- #
def build_pgwrite_payload(offset, data, corrupt_index=None):
    """[crc32c(4)][page] for each page of `data` placed at file `offset`.

    If corrupt_index is set, that page's CRC is deliberately flipped so the
    server must detect the bad page."""
    payload = bytearray()
    # Slice on absolute file-offset page boundaries (unaligned first page).
    pages = []
    o = offset
    rel = 0
    for ln in page_lengths(offset, len(data)):
        pages.append((o, data[rel:rel + ln]))
        o += ln
        rel += ln
    for i, (_po, page) in enumerate(pages):
        c = crc32c(page)
        if corrupt_index is not None and i == corrupt_index:
            c ^= 0xFFFFFFFF  # guaranteed-different CRC
        payload += struct.pack("!I", c)
        payload += page
    return bytes(payload)


def pgwrite(sock, fhandle, offset, data, reqflags=0, corrupt_index=None,
            streamid=b"\x00\x08"):
    """Issue a pgwrite; return (status, info_offset, cse_data).

    status is kXR_ok or kXR_error; on kXR_ok cse_data is empty for a clean
    write and a ServerResponseBody_pgWrCSE blob if pages were rejected."""
    payload = build_pgwrite_payload(offset, data, corrupt_index)
    req = struct.pack("!2sH4sqBBHI", streamid, kXR_pgwrite, fhandle,
                      offset, 0, reqflags & 0xFF, 0, len(payload))
    sock.sendall(req + payload)
    resptype, info_off, cse = _read_status_message(sock)
    if resptype == "error":
        return kXR_error, None, cse
    return kXR_ok, info_off, cse


# --------------------------------------------------------------------------- #
# Per-server raw-wire open helpers with guaranteed cleanup.                   #
# --------------------------------------------------------------------------- #
def _wire_path(name):
    return name if name.startswith("/") else "/" + name


class _Handle:
    def __init__(self, host, port, path, options=kXR_open_read, mode=0o644):
        self.sock = _session(host, port)
        _, status, body = _open(self.sock, _wire_path(path), options, mode)
        assert status == kXR_ok, (
            f"open({path}, opt={options:#x}) on {host}:{port} failed (st={status})")
        self.fh = body[:4]

    def close(self):
        try:
            _close(self.sock, self.fh)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def _open_both_read(srv, path):
    return (_Handle(*srv["our_hp"], path), _Handle(*srv["off_hp"], path))


# ===========================================================================
# 2) pgread MULTI-PAGE: 2/4/16 pages. Each page's data + CRC correct; page
#    count correct; final short page CRC over the actual short length.
# ===========================================================================
def _multi_cases():
    cases = []
    # whole sz_* files (exercise short final pages: 4095, 4097, 65536, ...).
    for name, size in SZ_FILES.items():
        if size > PG_PAGE:
            cases.append((name, 0, size))
    cases.append((DATA_BIN, 0, 4096))         # exactly one page
    cases.append((CKSUM_BIN, 0, 10000))       # 2 full + short 1808
    cases.append(("sz_8192.bin", 0, 8192))    # 2 full pages
    cases.append(("sz_65536.bin", 0, 4096 * 2))   # first 2 pages
    cases.append(("sz_65536.bin", 0, 4096 * 4))   # first 4 pages
    cases.append(("sz_65536.bin", 0, 4096 * 16))  # 16 pages == whole file
    cases.append(("sz_65536.bin", 0, 4097))   # 1 full + 1-byte page
    cases.append(("sz_65536.bin", 0, 8193))   # 2 full + 1-byte page
    return cases


# ===========================================================================
# 3) pgread FILE-OFFSET-ALIGNED short first page: offset NOT a multiple of
#    4096. The first returned page is short to the next 4096 boundary and its
#    CRC covers only the short page. Differential vs stock. (csNum rule.)
# ===========================================================================
def _odd_offset_cases():
    cases = []
    for off in (1, 100, 1000, 4095, 5000, 8191, 12345, 60000):
        cases.append(("sz_65536.bin", off, 200))     # short first page only
        cases.append(("sz_65536.bin", off, 5000))    # crosses into next page(s)
    cases.append(("big1m.bin", 4097, 9000))
    cases.append(("big1m.bin", 1, 8192))
    cases.append(("cksum.bin", 100, 4096))
    return cases


# ===========================================================================
# 7) pgread CRC == own crc32c over returned bytes: the headline, on BOTH
#    servers, across a broad offset/len matrix.
# ===========================================================================
def _crc_matrix():
    cases = []
    for off in (0, 1, 100, 4095, 4096, 4097, 8192, 9000):
        for rlen in (1, 4096, 4097, 9000, 16384):
            cases.append((off, rlen))
    return cases


# ===========================================================================
# pgwrite helpers: read a freshly written file back via plain read for the
# integrity check, and stat its on-disk size from the local filesystem.
# ===========================================================================
def _our_writer(srv, path, options):
    return _Handle(*srv["our_hp"], path, options=options, mode=0o644)


def _off_writer(srv, path, options):
    return _Handle(*srv["off_hp"], path, options=options, mode=0o644)


def _readback(host, port, name, size):
    h = _Handle(host, port, name, options=kXR_open_read)
    try:
        st, data = _read_drain(h.sock, h.fh, 0, size + 4096)
        assert st == kXR_ok
        return data
    finally:
        h.close()


WR_NEW = kXR_open_updt | kXR_new | kXR_mkpath


def _cse_offsets(cse):
    """Parse ServerResponseBody_pgWrCSE: cseCRC[4] dlFirst[2] dlLast[2] then a
    list of int64 page offsets."""
    if len(cse) < 8:
        return []
    body = cse[8:]
    n = len(body) // 8
    return list(struct.unpack("!" + "q" * n, body[:n * 8]))


def _cse_lengths(cse):
    """Return (dlFirst, dlLast) from a CSE trailer."""
    if len(cse) < 8:
        return (None, None)
    return struct.unpack("!hh", cse[4:8])


_kXR_ChkSumErr = 3019


def _retry_one_page(sock, fh, offset, data, index):
    """Resend page `index` (kXR_pgRetry) with a correct payload."""
    lens = page_lengths(offset, len(data))
    pgoff = offset + sum(lens[:index])
    rel = pgoff - offset
    return pgwrite(sock, fh, pgoff, data[rel:rel + lens[index]],
                   reqflags=kXR_pgRetry)


def _corrupt_pages(data, offset, indices):
    """Build a pgwrite payload corrupting the DATA of each listed page index."""
    payload = bytearray()
    lens = page_lengths(offset, len(data))
    rel = 0
    for i, ln in enumerate(lens):
        page = bytearray(data[rel:rel + ln])
        c = crc32c(bytes(page))
        if i in indices:
            page[0] ^= 0xFF       # data mismatches its CRC
        payload += struct.pack("!I", c)
        payload += bytes(page)
        rel += ln
    return bytes(payload)


def _send_raw_pgwrite(sock, fh, offset, payload, reqflags=0, streamid=b"\x00\x08"):
    """Send a prebuilt pgwrite payload; return (status, info_offset, cse)."""
    req = struct.pack("!2sH4sqBBHI", streamid, kXR_pgwrite, fh,
                      offset, 0, reqflags & 0xFF, 0, len(payload))
    sock.sendall(req + payload)
    resptype, info_off, cse = _read_status_message(sock)
    if resptype == "error":
        return kXR_error, None, cse
    return kXR_ok, info_off, cse

__all__ = [n for n in dir() if not n.startswith('__')]
