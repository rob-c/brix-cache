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
  /tmp/xrootd-src/src/XProtocol/XProtocol.hh
      ClientPgReadRequest / ClientPgWriteRequest
      ServerResponseBody_Status (kXR_status)  + ServerResponseBody_pgRead
      ServerResponseBody_pgWrite + ServerResponseBody_pgWrCSE
      kXR_pgPageSZ=4096  kXR_pgUnitSZ=4100  kXR_pgRetry=0x01
  /tmp/xrootd-src/src/XrdXrootd/XrdXrootdXeqPgrw.cc  do_PgRIO / do_PgWIO
  /tmp/xrootd-src/src/XrdXrootd/XrdXrootdResponse.cc srsComplete (status framing)

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


def test_crc32c_known_vector():
    """The headline integrity primitive must match the published test vector;
    every per-page CRC assertion in this file depends on it being correct."""
    assert crc32c(b"123456789") == 0xE3069283, (
        "software CRC-32C is wrong -- the whole pg-I/O CRC suite is invalid")


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
# 1) pgread SINGLE PAGE at offset 0: bytes == file[0:4096] AND per-page CRC32c
#    == crc32c(file[0:4096]). On BOTH servers. Parametrised over many files.
# ===========================================================================
@pytest.mark.parametrize("name", list(SZ_FILES) + [DATA_BIN, CKSUM_BIN])
def test_pgread_single_page_off0(srv, name):
    size = len(_local(srv, name))
    rlen = min(PG_PAGE, size)
    if rlen == 0:
        pytest.skip("covered by empty-file test")
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, 0, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, 0, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"pgread {name}@0+{rlen}: ours={st_o} stock={st_f}"
    want = _local(srv, name)[0:rlen]
    assert pgread_bytes(pg_o) == want, f"OUR pgread {name} bytes wrong"
    assert len(pg_o) == 1, f"OUR pgread {name}: expected 1 page, got {len(pg_o)}"
    off, page, crc = pg_o[0]
    assert off == 0, f"OUR pgread page offset {off} != 0"
    assert crc == crc32c(page), f"OUR pgread {name} per-page CRC32c wrong"
    assert crc == crc32c(want), "OUR pgread CRC32c != crc of source bytes"
    # Differential: stock must carry identical bytes + identical CRC.
    assert pgread_bytes(pg_f) == want, "stock pgread bytes diverge from source"
    assert pg_o == pg_f, f"pgread {name}@0 diverges from stock (page+CRC)"


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


@pytest.mark.parametrize("name,off,rlen", _multi_cases())
def test_pgread_multi_page(srv, name, off, rlen):
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"pgread {name}@{off}+{rlen}: ours={st_o} stock={st_f}")
    src = _local(srv, name)
    want_pages = page_slices(src, off, min(rlen, len(src) - off))
    # Page count + each page's offset/bytes/CRC.
    assert len(pg_o) == len(want_pages), (
        f"OUR pgread {name}@{off}+{rlen}: {len(pg_o)} pages, "
        f"want {len(want_pages)}")
    for i, (wo, wbytes) in enumerate(want_pages):
        po, page, crc = pg_o[i]
        assert po == wo, f"page {i} offset ours={po} want={wo}"
        assert page == wbytes, f"page {i} OUR bytes wrong"
        assert crc == crc32c(wbytes), (
            f"page {i} OUR CRC32c wrong (len {len(wbytes)} short-page CRC)")
    assert pgread_bytes(pg_o) == src[off:off + rlen], "OUR reassembly wrong"
    assert pg_o == pg_f, f"pgread {name}@{off}+{rlen} diverges from stock"


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


@pytest.mark.parametrize("name,off,rlen", _odd_offset_cases())
def test_pgread_unaligned_first_page(srv, name, off, rlen):
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"unaligned pgread {name}@{off}+{rlen}: ours={st_o} stock={st_f}")
    src = _local(srv, name)
    eff = min(rlen, len(src) - off)
    want_pages = page_slices(src, off, eff)
    assert len(pg_o) == len(want_pages), (
        f"OUR unaligned pgread {name}@{off}: {len(pg_o)} pages vs {len(want_pages)}")
    # The first page must be short to the next 4096 boundary.
    first_off, first_page, first_crc = pg_o[0]
    expect_first = min(PG_PAGE - (off % PG_PAGE), eff)
    assert first_off == off, f"first page offset {first_off} != requested {off}"
    assert len(first_page) == expect_first, (
        f"OUR first page len {len(first_page)} != short-to-boundary {expect_first}")
    assert first_crc == crc32c(first_page), "OUR short first-page CRC32c wrong"
    for i, (wo, wbytes) in enumerate(want_pages):
        po, page, crc = pg_o[i]
        assert (po, page) == (wo, wbytes), f"page {i} offset/bytes wrong"
        assert crc == crc32c(wbytes), f"page {i} CRC32c wrong"
    assert pg_o == pg_f, f"unaligned pgread {name}@{off} diverges from stock"


# ===========================================================================
# 4) pgread AT / PAST EOF: short/empty parity vs stock.
# ===========================================================================
@pytest.mark.parametrize("name,off,rlen", [
    ("data.bin", DATA_SIZE, 4096),         # start exactly at EOF
    ("data.bin", DATA_SIZE - 1, 4096),     # 1 byte then EOF
    ("data.bin", DATA_SIZE - 100, 4096),   # short tail page
    ("sz_4096.bin", 4096, 4096),           # at EOF, page-aligned file
    ("sz_4097.bin", 4096, 4096),           # 1 trailing byte
    ("sz_65536.bin", 65000, 4096),         # short tail crossing EOF
    ("data.bin", 1 << 30, 4096),           # far past EOF
])
def test_pgread_eof_parity(srv, name, off, rlen):
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"pgread EOF status diverges {name}@{off}+{rlen}: ours={st_o} stock={st_f}")
    if st_o != kXR_ok:
        return
    src = _local(srv, name)
    avail = max(0, len(src) - off)
    want = src[off:off + rlen]
    assert pgread_bytes(pg_o) == want, (
        f"OUR pgread-at-EOF {name}@{off} returned {len(pgread_bytes(pg_o))}B "
        f"want {avail}B")
    for (_po, page, crc) in pg_o:
        assert crc == crc32c(page), "OUR pgread-at-EOF page CRC32c wrong"
    assert pgread_bytes(pg_o) == pgread_bytes(pg_f), "EOF pgread bytes vs stock"


# ===========================================================================
# 5) pgread of EMPTY file: parity vs stock.
# ===========================================================================
def test_pgread_empty_file(srv):
    name = "empty.txt"
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, 0, 4096)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, 0, 4096)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, f"pgread empty: ours={st_o} stock={st_f}"
    if st_o == kXR_ok:
        assert pgread_bytes(pg_o) == b"" == pgread_bytes(pg_f), (
            "empty-file pgread returned bytes")


# ===========================================================================
# 6) pgread REASSEMBLY of big1m -> md5 == source (and == stock). Multi-chunk
#    kXR_status response stitched back together.
# ===========================================================================
@pytest.mark.parametrize("off,rlen", [
    (0, BIG_SIZE),            # whole file
    (0, BIG_SIZE // 2),       # first half
    (BIG_SIZE // 2, BIG_SIZE // 2),  # second half
    (4096, BIG_SIZE - 4096),  # page-aligned tail
    (1, BIG_SIZE - 1),        # unaligned whole-ish
])
def test_pgread_big_reassembly(srv, off, rlen):
    name = BIG_BIN
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"big pgread @{off}+{rlen}: ours={st_o} stock={st_f}"
    src = _local(srv, name)
    want = src[off:off + rlen]
    got = pgread_bytes(pg_o)
    assert len(got) == len(want), f"OUR big pgread {len(got)}B want {len(want)}B"
    assert hashlib.md5(got).digest() == hashlib.md5(want).digest(), (
        f"OUR big1m pgread @{off}+{rlen} md5 mismatch vs source")
    # Every per-page CRC must be self-consistent on our server.
    for (_po, page, crc) in pg_o:
        assert crc == crc32c(page), "OUR big pgread page CRC32c wrong"
    assert got == pgread_bytes(pg_f), f"big1m pgread @{off}+{rlen} diverges from stock"


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


@pytest.mark.parametrize("off,rlen", _crc_matrix())
def test_pgread_crc_self_consistent_both(srv, off, rlen):
    name = "sz_65536.bin"
    src = _local(srv, name)
    if off >= len(src):
        pytest.skip("offset past EOF handled by EOF parity test")
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"crc matrix @{off}+{rlen}: ours={st_o} stock={st_f}"
    for (po, page, crc) in pg_o:
        assert crc == crc32c(page), (
            f"OUR pgread CRC32c WRONG @page {po} (len {len(page)})")
    for (po, page, crc) in pg_f:
        assert crc == crc32c(page), f"stock pgread CRC32c wrong @page {po}"
    assert pgread_bytes(pg_o) == src[off:off + rlen], "OUR bytes != source slice"
    assert pg_o == pg_f, f"pgread @{off}+{rlen} diverges from stock"


# ===========================================================================
# 8) pgread vs plain kXR_read of the SAME range: identical data bytes.
# ===========================================================================
@pytest.mark.parametrize("name,off,rlen", [
    ("sz_65536.bin", 0, 4096),
    ("sz_65536.bin", 0, 16384),
    ("sz_65536.bin", 100, 5000),
    ("sz_65536.bin", 4096, 8192),
    ("data.bin", 0, 4096),
    ("cksum.bin", 0, 10000),
    ("big1m.bin", 0, 65536),
    ("sz_4097.bin", 0, 4097),
])
def test_pgread_equals_plain_read(srv, name, off, rlen):
    our = _Handle(*srv["our_hp"], name)
    try:
        st_pg, pg = pgread(our.sock, our.fh, off, rlen)
        st_rd, rd = _read_drain(our.sock, our.fh, off, rlen)
    finally:
        our.close()
    assert st_pg == kXR_ok and st_rd == kXR_ok, (
        f"pgread/read {name}@{off}+{rlen}: pg={st_pg} read={st_rd}")
    assert pgread_bytes(pg) == rd, (
        f"OUR pgread bytes != plain read bytes for {name}@{off}+{rlen}")


# ===========================================================================
# 9) pgUnitSZ framing constant honoured: a full-page pgread carries exactly
#    4 CRC bytes + 4096 data bytes == kXR_pgUnitSZ (4100) per page.
# ===========================================================================
@pytest.mark.parametrize("npages", [1, 2, 4])
def test_pgread_unit_size_framing(srv, npages):
    name = "sz_65536.bin"
    rlen = PG_PAGE * npages
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, 0, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, 0, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok
    assert len(pg_o) == npages == len(pg_f)
    for (_po, page, _crc) in pg_o:
        # full page: data == 4096, the unit (crc+data) == 4100.
        assert len(page) == PG_PAGE, "OUR full page != 4096 data bytes"
        assert PG_CRC + len(page) == PG_UNIT, "pgUnitSZ (4100) framing wrong"
    assert pg_o == pg_f, "pgread unit framing diverges from stock"


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


# ===========================================================================
# 10) pgwrite SINGLE PAGE: open new, write one page with correct CRC, read
#     back == written; on-disk size correct. Parametrise page sizes incl short.
# ===========================================================================
@pytest.mark.parametrize("size", [1, 100, 4095, 4096])
def test_pgwrite_single_page(srv, size):
    data = bytes((i * 31 + 7) & 0xFF for i in range(size))
    rel = f"pgw_single_{size}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        st_o, ofo, cse_o = pgwrite(our.sock, our.fh, 0, data)
        st_f, off_off, cse_f = pgwrite(off_h.sock, off_h.fh, 0, data)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"pgwrite single {size}: ours={st_o} stock={st_f}")
    assert cse_o == b"" == cse_f, "clean pgwrite must report no CRC errors"
    assert ofo == off_off, (
        f"pgwrite info offset diverges from stock: ours={ofo} stock={off_off}")
    # On-disk content + size, byte-exact on our server.
    our_path = os.path.join(srv["our_data"], rel)
    assert os.path.getsize(our_path) == size, "OUR pgwrite on-disk size wrong"
    with open(our_path, "rb") as f:
        assert f.read() == data, "OUR pgwrite on-disk content wrong"
    # Read it back over the wire too (and parity vs stock's file).
    back = _readback(*srv["our_hp"], rel, size)
    assert back == data, "OUR pgwrite read-back != written bytes"
    off_path = os.path.join(srv["off_data"], rel)
    with open(off_path, "rb") as f:
        assert f.read() == data, "stock pgwrite on-disk content diverges"


# ===========================================================================
# 11) pgwrite MULTI-PAGE + short final page: file content byte-exact vs an
#     independently built buffer (and vs stock's file). Parametrise sizes.
# ===========================================================================
@pytest.mark.parametrize("size", [4097, 8192, 8193, 10000, 65536, 100000])
def test_pgwrite_multi_page(srv, size):
    data = bytes((i * 17 + 3) & 0xFF for i in range(size))
    rel = f"pgw_multi_{size}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        st_o, _ofo, cse_o = pgwrite(our.sock, our.fh, 0, data)
        st_f, _off, cse_f = pgwrite(off_h.sock, off_h.fh, 0, data)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"pgwrite multi {size}: ours={st_o} stock={st_f}"
    assert cse_o == b"" == cse_f, "clean multi-page pgwrite reported CRC errors"
    our_path = os.path.join(srv["our_data"], rel)
    off_path = os.path.join(srv["off_data"], rel)
    assert os.path.getsize(our_path) == size, "OUR multi pgwrite size wrong"
    with open(our_path, "rb") as f:
        assert f.read() == data, "OUR multi-page pgwrite content wrong"
    with open(off_path, "rb") as f:
        assert f.read() == data, "stock multi-page pgwrite content diverges"


# ===========================================================================
# 12) pgwrite with a WRONG CRC32c: the server MUST detect the corrupt page.
#     Stock returns a kXR_status carrying a ServerResponseBody_pgWrCSE list
#     (cseCRC[4] dlFirst[2] dlLast[2] then offsets) -- i.e. non-empty CSE
#     data. Both servers must flag (not silently accept) the bad page.
# ===========================================================================
@pytest.mark.parametrize("size,bad", [
    (4096, 0),       # single page corrupt
    (8192, 0),       # first of two corrupt
    (8192, 1),       # second of two corrupt
    (10000, 2),      # short final page corrupt
])
def test_pgwrite_corrupt_page_rejected(srv, size, bad):
    data = bytes((i * 13 + 5) & 0xFF for i in range(size))
    rel = f"pgw_bad_{size}_{bad}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        st_o, _ofo, cse_o = pgwrite(our.sock, our.fh, 0, data, corrupt_index=bad)
        st_f, _off, cse_f = pgwrite(off_h.sock, off_h.fh, 0, data, corrupt_index=bad)
    finally:
        our.close()
        off_h.close()
    # The corrupt page MUST be detected: either an error status OR a non-empty
    # CSE retransmit list in the kXR_status response. Silent acceptance (kXR_ok
    # with empty CSE) is a server bug.
    detected_o = (st_o == kXR_error) or (st_o == kXR_ok and len(cse_o) > 0)
    detected_f = (st_f == kXR_error) or (st_f == kXR_ok and len(cse_f) > 0)
    assert detected_f, "stock did not flag a corrupt page (tooling/assumption?)"
    assert detected_o, (
        f"OUR server ACCEPTED a corrupt pgwrite page (size={size} bad={bad}) "
        f"without flagging it -- silent data corruption")
    # The detection SHAPE must match stock (both error, or both CSE-list).
    assert (st_o == kXR_error) == (st_f == kXR_error), (
        f"corrupt-page rejection diverges from stock: ours st={st_o} "
        f"stock st={st_f}")
    if st_o == kXR_ok and st_f == kXR_ok:
        # Both report via CSE list: the bad-page offset must be present. The
        # CSE body is cseCRC[4] dlFirst[2] dlLast[2] then int64 offsets.
        assert len(cse_o) >= 8 and len(cse_f) >= 8, "CSE list too short"
        bad_off = sum(page_lengths(0, size)[:bad])
        offs_o = _cse_offsets(cse_o)
        assert bad_off in offs_o, (
            f"OUR CSE list {offs_o} missing corrupt page offset {bad_off}")


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


# ===========================================================================
# 12b) Differential CSE parity: the FULL retransmit list (offsets + dlFirst/
#      dlLast), the close gate, and retry-correction must match stock exactly.
# ===========================================================================
@pytest.mark.parametrize("size,bad", [
    (4096 * 3, [0, 2]),         # two full-page corruptions
    (4096 * 2 + 500, [0, 1, 2]),  # all three incl short final
    (4096 * 4, [1, 3]),
])
def test_pgwrite_cse_list_matches_stock(srv, size, bad):
    data = bytes((i * 7 + 3) & 0xFF for i in range(size))
    rel = f"pgw_cselist_{size}_{'_'.join(map(str, bad))}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        # Corrupt the same pages on both by issuing per-page flips through the
        # builder: build a payload that corrupts the first listed page, then
        # patch the rest. Simplest: corrupt each independently via repeated XOR.
        payload_o = _corrupt_pages(data, 0, bad)
        payload_f = payload_o
        st_o, _o, cse_o = _send_raw_pgwrite(our.sock, our.fh, 0, payload_o)
        st_f, _f, cse_f = _send_raw_pgwrite(off_h.sock, off_h.fh, 0, payload_f)
    finally:
        our.close()
        off_h.close()
    assert st_o == kXR_ok and st_f == kXR_ok, (st_o, st_f)
    assert _cse_offsets(cse_o) == _cse_offsets(cse_f), "CSE offset list diverges"
    assert _cse_lengths(cse_o) == _cse_lengths(cse_f), "dlFirst/dlLast diverge"


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


def test_pgwrite_cse_close_gate_matches_stock(srv):
    data = bytes((i * 11 + 1) & 0xFF for i in range(4096))
    rel = "pgw_cse_closegate.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        _send_raw_pgwrite(our.sock, our.fh, 0, _corrupt_pages(data, 0, [0]))
        _send_raw_pgwrite(off_h.sock, off_h.fh, 0, _corrupt_pages(data, 0, [0]))
        _so, st_o, _bo = _close(our.sock, our.fh)
        _sf, st_f, _bf = _close(off_h.sock, off_h.fh)
    finally:
        our.sock.close()
        off_h.sock.close()
    assert st_o == st_f == kXR_error, (st_o, st_f)


def test_pgwrite_cse_retry_then_close_matches_stock(srv):
    data = bytes((i * 5 + 9) & 0xFF for i in range(4096 * 2))
    rel = "pgw_cse_retry_close.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        for h in (our, off_h):
            _send_raw_pgwrite(h.sock, h.fh, 0, _corrupt_pages(data, 0, [1]))
            # Resend page 1 correctly.
            st, _o, cse = _retry_one_page(h.sock, h.fh, 0, data, 1)
            assert st == kXR_ok and len(cse) == 0, "retry should verify clean"
        _so, st_o, _bo = _close(our.sock, our.fh)
        _sf, st_f, _bf = _close(off_h.sock, off_h.fh)
    finally:
        our.sock.close()
        off_h.sock.close()
    assert st_o == st_f == kXR_ok, (st_o, st_f)


# ===========================================================================
# 13) pgwrite at OFFSET (sparse): hole reads back as zero, the written page is
#     correct, on-disk size == offset+len. Parity vs stock's file.
# ===========================================================================
@pytest.mark.parametrize("offset,size", [
    (4096, 4096),     # one-page hole then a page
    (8192, 100),      # two-page hole then short page
    (4096, 8192),     # hole then two pages
    (100, 4096),      # unaligned write past a small hole
])
def test_pgwrite_sparse_offset(srv, offset, size):
    data = bytes((i * 7 + 1) & 0xFF for i in range(size))
    rel = f"pgw_sparse_{offset}_{size}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        st_o, ofo, cse_o = pgwrite(our.sock, our.fh, offset, data)
        st_f, off2, cse_f = pgwrite(off_h.sock, off_h.fh, offset, data)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"sparse pgwrite @{offset}+{size}: ours={st_o} stock={st_f}")
    assert cse_o == b"" == cse_f, "clean sparse pgwrite reported CRC errors"
    assert ofo == off2, (
        f"sparse pgwrite info offset diverges from stock: ours={ofo} stock={off2}")
    expect = b"\x00" * offset + data
    our_path = os.path.join(srv["our_data"], rel)
    off_path = os.path.join(srv["off_data"], rel)
    assert os.path.getsize(our_path) == offset + size, "OUR sparse size wrong"
    with open(our_path, "rb") as f:
        got = f.read()
    assert got[:offset] == b"\x00" * offset, "OUR sparse hole not zero-filled"
    assert got[offset:] == data, "OUR sparse written page wrong"
    with open(off_path, "rb") as f:
        assert f.read() == expect, "stock sparse pgwrite content diverges"


# ===========================================================================
# 14) pgwrite then pgread round-trip: write a multi-page buffer, read it back
#     via pgread, and verify every per-page CRC + bytes. End-to-end on OUR
#     server, with the source buffer as the oracle.
# ===========================================================================
@pytest.mark.parametrize("size", [4096, 4097, 8192, 10000, 20000])
def test_pgwrite_then_pgread_roundtrip(srv, size):
    data = bytes((i * 19 + 11) & 0xFF for i in range(size))
    rel = f"pgw_rt_{size}.bin"
    w = _our_writer(srv, rel, WR_NEW)
    try:
        st, _ofo, cse = pgwrite(w.sock, w.fh, 0, data)
    finally:
        w.close()
    assert st == kXR_ok and cse == b"", f"pgwrite roundtrip {size} failed"
    r = _Handle(*srv["our_hp"], rel, options=kXR_open_read)
    try:
        st_r, pages = pgread(r.sock, r.fh, 0, size)
    finally:
        r.close()
    assert st_r == kXR_ok, "pgread of written file failed"
    want_pages = page_slices(data, 0, size)
    assert len(pages) == len(want_pages), "roundtrip page count wrong"
    for i, (wo, wbytes) in enumerate(want_pages):
        po, page, crc = pages[i]
        assert (po, page) == (wo, wbytes), f"roundtrip page {i} bytes/offset wrong"
        assert crc == crc32c(wbytes), f"roundtrip page {i} CRC32c wrong"
    assert pgread_bytes(pages) == data, "roundtrip reassembly != source"


# ===========================================================================
# 15) pgwrite OVERWRITE of an existing file region (open updt, write at offset
#     0 over data): content matches and parity vs stock.
# ===========================================================================
@pytest.mark.parametrize("size", [4096, 8192])
def test_pgwrite_overwrite_region(srv, size):
    init = bytes((i * 3) & 0xFF for i in range(size))
    new = bytes((255 - (i & 0xFF)) for i in range(size))
    rel = f"pgw_ovr_{size}.bin"
    # Create both files with identical initial content.
    for writer in (_our_writer, _off_writer):
        h = writer(srv, rel, WR_NEW)
        try:
            st, _o, c = pgwrite(h.sock, h.fh, 0, init)
            assert st == kXR_ok and c == b""
        finally:
            h.close()
    # Reopen for update and overwrite.
    our = _our_writer(srv, rel, kXR_open_updt)
    off_h = _off_writer(srv, rel, kXR_open_updt)
    try:
        st_o, _o, cse_o = pgwrite(our.sock, our.fh, 0, new)
        st_f, _f, cse_f = pgwrite(off_h.sock, off_h.fh, 0, new)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"overwrite {size}: ours={st_o} stock={st_f}"
    assert cse_o == b"" == cse_f
    with open(os.path.join(srv["our_data"], rel), "rb") as f:
        assert f.read() == new, "OUR overwrite content wrong"
    with open(os.path.join(srv["off_data"], rel), "rb") as f:
        assert f.read() == new, "stock overwrite content diverges"


# ===========================================================================
# 16) INTEGRITY: pgwrite a buffer, then download via stock xrdcp -> bytes
#     match. The raw pgwrite path and the high-level read path must agree.
# ===========================================================================
@pytest.mark.parametrize("size", [4096, 10000, 65536])
def test_pgwrite_then_xrdcp_download(srv, tmp_path, size):
    data = bytes((i * 23 + 9) & 0xFF for i in range(size))
    rel = f"pgw_dl_{size}.bin"
    w = _our_writer(srv, rel, WR_NEW)
    try:
        st, _o, cse = pgwrite(w.sock, w.fh, 0, data)
    finally:
        w.close()
    assert st == kXR_ok and cse == b"", "pgwrite for xrdcp download failed"
    dst = str(tmp_path / f"dl_{rel}")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//{rel}", dst],
                         timeout=90)
    assert rc == 0, f"xrdcp download of pgwritten {rel} failed: {out}{err}"
    with open(dst, "rb") as f:
        assert f.read() == data, "xrdcp download != pgwritten bytes"


# ===========================================================================
# 17) INTEGRITY: stock xrdcp UPLOAD a file, then pgread it back -> every CRC
#     valid and bytes match the uploaded source. End-to-end the other way.
# ===========================================================================
@pytest.mark.parametrize("size", [4096, 10000, 65536])
def test_xrdcp_upload_then_pgread(srv, tmp_path, size):
    data = bytes((i * 29 + 4) & 0xFF for i in range(size))
    src_path = str(tmp_path / f"up_{size}.bin")
    with open(src_path, "wb") as f:
        f.write(data)
    rel = f"pgup_{size}.bin"
    rc, out, err = L.run([L.OFF_XRDCP, "-f", src_path, f"{srv['our']}//{rel}"],
                         timeout=90)
    assert rc == 0, f"xrdcp upload to OUR server failed: {out}{err}"
    r = _Handle(*srv["our_hp"], rel, options=kXR_open_read)
    try:
        st, pages = pgread(r.sock, r.fh, 0, size)
    finally:
        r.close()
    assert st == kXR_ok, "pgread of xrdcp-uploaded file failed"
    for (_po, page, crc) in pages:
        assert crc == crc32c(page), "pgread of uploaded file has wrong CRC32c"
    assert pgread_bytes(pages) == data, "pgread of uploaded file != source"


# ===========================================================================
# 18) pgread with kXR_pgRetry flag set (verify): a normal read should still
#     return correct bytes + CRCs and match stock. Pins the reqflags path.
# ===========================================================================
@pytest.mark.parametrize("name,off,rlen", [
    ("sz_65536.bin", 0, 8192),
    ("sz_65536.bin", 100, 5000),
    ("data.bin", 0, 4096),
])
def test_pgread_retry_flag(srv, name, off, rlen):
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen, reqflags=kXR_pgRetry)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen, reqflags=kXR_pgRetry)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, f"pgread retry-flag status diverges: ours={st_o} stock={st_f}"
    if st_o != kXR_ok:
        return
    src = _local(srv, name)
    assert pgread_bytes(pg_o) == src[off:off + rlen], "OUR retry-flag pgread bytes wrong"
    for (_po, page, crc) in pg_o:
        assert crc == crc32c(page), "OUR retry-flag pgread CRC32c wrong"
    assert pgread_bytes(pg_o) == pgread_bytes(pg_f), "retry-flag pgread vs stock"


# ===========================================================================
# 19) pgread rlen invalid (negative): error parity vs stock.
# ===========================================================================
@pytest.mark.parametrize("rlen", [-1, -4096])
def test_pgread_negative_len_parity(srv, rlen):
    name = "sz_65536.bin"
    our, off_h = _open_both_read(srv, name)
    try:
        try:
            st_o, _ = pgread(our.sock, our.fh, 0, rlen)
        except ConnectionError:
            st_o = kXR_error
        try:
            st_f, _ = pgread(off_h.sock, off_h.fh, 0, rlen)
        except ConnectionError:
            st_f = kXR_error
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"pgread negative-len status diverges: ours={st_o} stock={st_f}")


# ===========================================================================
# Oracle: stock xrdcp stock->stock on a multi-page file, proving the tooling
# is sound (a failure here is environmental, not ours).
# ===========================================================================
def test_oracle_stock_to_stock(srv, tmp_path):
    dst = str(tmp_path / "oracle.bin")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['off']}//cksum.bin", dst])
    assert rc == 0, f"oracle stock->stock failed (tooling broken): {out}{err}"
    with open(dst, "rb") as f:
        assert f.read() == _local(srv, "cksum.bin")
