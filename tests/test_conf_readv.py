"""Differential VECTOR-READ (kXR_readv) and read-offset/EOF conformance.

The reference for every assertion in this suite is the STOCK XRootD server
(launched on an identical data tree alongside our nginx-xrootd server) and the
stock XRootD client tools (xrdcp/xrdfs). Wherever the wire framing is too
fine-grained for the high-level tools, the request is crafted as RAW WIRE over a
plain TCP socket and replayed against BOTH servers; the two responses must
agree byte-for-byte. Any divergence — wrong bytes, wrong readahead_list
framing, wrong segment order or count, or different EOF handling — is treated as
a BUG IN OUR SERVER, and the assertion is written to fail.

Scope (deliberately broader than tests/test_readv_security.py, which already
covers the hostile/bounds-checking angle):
  * single-segment readv across the full (offset,len) page-boundary matrix
  * multi-segment readv (2/4/8/16 segments), ordering + per-segment framing
  * non-monotonic segment ordering (server must answer in request order)
  * readv referencing MULTIPLE open file handles in one request
  * zero-length segments, at/past-EOF segments — pinned against stock
  * segment-count cap (readv_iov_max) at and over the boundary
  * large whole-file reassembly via N readv segments (md5 == source)
  * plain kXR_read offset/len matrix + EOF/short-read parity vs stock
  * empty-file reads, interleaved read/readv on one handle
  * full-file readv reassembly byte-identical to an xrdcp download

Wire framing references (consulted, not modified):
  /tmp/brix-src/src/XProtocol/XProtocol.hh        read_list / readahead_list
  /tmp/brix-src/src/XrdXrootd/XrdXrootdXeq.cc      do_ReadV  (EOF -> error)

Self-provisioning on high ports; skips entirely without the stock toolchain.
"""

import hashlib
import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Opcodes / status / error codes (src/protocols/root/protocol/opcodes.h, XProtocol.hh).      #
# --------------------------------------------------------------------------- #
kXR_login = 3007
kXR_open = 3010
kXR_close = 3003
kXR_read = 3013
kXR_readv = 3025

kXR_ok = 0
kXR_oksofar = 4000
kXR_error = 4003

kXR_open_read = 0x0010

# One readahead_list / read_list element on the wire is 16 bytes.
READV_SEGSIZE = 16
# maxRvecsz = maxRvecln(16384) / rlItemLen(16) = 1024 (XProtocol.hh).
READV_MAXSEGS = 1024

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


# ===========================================================================
# Module-scoped server pair: our nginx-xrootd + stock xrootd, identical tree.
# ===========================================================================
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conf_readv"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14022), off_port=L.worker_port(14023))
    except Exception as e:  # noqa: BLE001 - any launch failure -> skip cleanly
        pytest.skip(f"server pair did not start: {e}")
    # Bind the two endpoints to host/port pairs for raw-wire use.
    ctx["our_hp"] = _split_hostport(ctx["our"])
    ctx["off_hp"] = _split_hostport(ctx["off"])
    yield ctx
    L.stop_pair(procs)


def _split_hostport(url):
    """root://127.0.0.1:14022 -> ('127.0.0.1', 14022)."""
    rest = url.split("://", 1)[1]
    host, _, port = rest.partition(":")
    return host, int(port)


# --------------------------------------------------------------------------- #
# Local source bytes (identical on both data dirs).                           #
# --------------------------------------------------------------------------- #
def _local(ctx, name):
    with open(os.path.join(ctx["our_data"], name), "rb") as f:
        return f.read()


# --------------------------------------------------------------------------- #
# Minimal raw-wire client (login + open + read + readv + close).             #
# Modelled on tests/test_readv_security.py / test_brix_conformance.py.      #
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
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(15)
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


def _open(sock, path, options=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI", streamid, kXR_open,
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


def _read_drain(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    """Issue a kXR_read and gather every chunk until the terminating kXR_ok.

    A short or large read may be framed as one or more kXR_oksofar messages
    followed by a final kXR_ok (the reference chunks at its buffer size); both
    that and a single kXR_ok are protocol-legal, so we reassemble and return the
    full byte stream plus the FINAL status, independent of chunk granularity.
    """
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


def _seg(fhandle, rlen, offset):
    """One read_list element: fhandle[4] + rlen(int32 BE) + offset(int64 BE)."""
    return struct.pack("!4siq", fhandle, rlen, offset)


def _readv(sock, segments, streamid=b"\x00\x05"):
    payload = b"".join(segments)
    req = struct.pack("!2sH16sI", streamid, kXR_readv, b"\x00" * 16,
                      len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _readv_drain(sock, segments, streamid=b"\x00\x05"):
    """Issue a readv and gather ALL response messages until the terminating
    kXR_ok (large readv responses are split into kXR_oksofar chunks). Returns
    (final_status, concatenated_body) where body is the raw readahead_list
    stream across every chunk."""
    payload = b"".join(segments)
    req = struct.pack("!2sH16sI", streamid, kXR_readv, b"\x00" * 16,
                      len(payload))
    sock.sendall(req + payload)
    body = bytearray()
    while True:
        _, status, chunk = _read_response(sock)
        if status == kXR_error:
            return kXR_error, bytes(chunk)
        body.extend(chunk)
        if status == kXR_ok:
            return kXR_ok, bytes(body)
        # kXR_oksofar -> more chunks to come.
        assert status == kXR_oksofar, f"unexpected readv status {status}"


def _parse_segments(body):
    """Strip readahead_list headers from a readv response body, returning a list
    of (fhandle_bytes, rlen, offset, payload) tuples in wire order."""
    out = []
    pos = 0
    while pos + READV_SEGSIZE <= len(body):
        fh = body[pos:pos + 4]
        rlen, offset = struct.unpack("!iq", body[pos + 4:pos + 16])
        pos += READV_SEGSIZE
        payload = body[pos:pos + rlen]
        pos += rlen
        out.append((fh, rlen, offset, payload))
    return out


def _readv_payload(body, expect_segs):
    """Concatenated payload bytes only (headers stripped)."""
    return b"".join(p for (_fh, _rl, _off, p) in _parse_segments(body)[:expect_segs])


# --------------------------------------------------------------------------- #
# Per-server raw-wire open helper with guaranteed cleanup.                    #
# --------------------------------------------------------------------------- #
def _wire_path(name):
    """The stock and our servers both resolve open paths from the namespace
    root, so a leading slash is mandatory on the wire."""
    return name if name.startswith("/") else "/" + name


class _Handle:
    def __init__(self, host, port, path):
        self.sock = _session(host, port)
        _, status, body = _open(self.sock, _wire_path(path), kXR_open_read)
        assert status == kXR_ok, f"read-open of {path} on {host}:{port} failed"
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


def _open_both(srv, path):
    return (_Handle(*srv["our_hp"], path), _Handle(*srv["off_hp"], path))


# ===========================================================================
# RAW single-segment readv: bytes == source slice AND == stock (differential).
# Parametrised across offset/len that straddle the 4096-byte page boundaries.
# ===========================================================================
def _single_cases():
    cases = []
    # offset 0 with assorted lengths including page-boundary edges + len 1.
    for ln in (1, 64, 255, 4095, 4096, 4097, 8192):
        cases.append(("sz_65536.bin", 0, ln))
    # mid-file reads.
    for off in (1, 100, 4095, 4096, 4097, 8000, 60000):
        cases.append(("sz_65536.bin", off, 256))
    # last-page reads that end exactly at EOF.
    cases.append(("sz_4096.bin", 0, 4096))
    cases.append(("sz_4097.bin", 0, 4097))
    cases.append(("sz_4095.bin", 0, 4095))
    cases.append(("sz_8192.bin", 4096, 4096))
    # length crossing a page boundary from a non-zero offset.
    cases.append(("sz_8192.bin", 1, 4096))
    cases.append(("sz_8192.bin", 4095, 2))
    # whole tiny file in one segment.
    cases.append(("sz_1.bin", 0, 1))
    cases.append(("sz_255.bin", 0, 255))
    # whole data.bin.
    cases.append(("data.bin", 0, 4096))
    return cases


@pytest.mark.parametrize("name,off,ln", _single_cases())
def test_readv_single_segment(srv, name, off, ln):
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, off)])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, off)])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"single readv {name}@{off}+{ln}: status ours={st_o} stock={st_f}")
    want = _local(srv, name)[off:off + ln]
    payload_o = _readv_payload(body_o, 1)
    payload_f = _readv_payload(body_f, 1)
    assert payload_o == want, (
        f"OUR readv {name}@{off}+{ln} returned wrong bytes "
        f"(got {len(payload_o)}, want {len(want)})")
    assert payload_o == payload_f, (
        f"readv {name}@{off}+{ln} diverges from stock "
        f"(ours={len(payload_o)}B stock={len(payload_f)}B)")


# ===========================================================================
# RAW single-segment readahead_list framing: the response header echoes the
# requested fhandle, the served rlen, and the requested offset (vs stock).
# ===========================================================================
@pytest.mark.parametrize("name,off,ln", [
    ("sz_65536.bin", 0, 256),
    ("sz_65536.bin", 4096, 4096),
    ("sz_65536.bin", 12345, 1000),
    ("data.bin", 0, 4096),
])
def test_readv_single_framing(srv, name, off, ln):
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, off)])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, off)])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok
    segs_o = _parse_segments(body_o)
    segs_f = _parse_segments(body_f)
    assert len(segs_o) == len(segs_f) == 1, (
        f"segment count ours={len(segs_o)} stock={len(segs_f)}")
    fh_o, rlen_o, roff_o, _ = segs_o[0]
    fh_f, rlen_f, roff_f, _ = segs_f[0]
    # The fhandle in the response header must equal the one we opened/requested.
    assert fh_o == our.fh, "OUR readv header fhandle mismatch vs request"
    assert rlen_o == ln == rlen_f, (
        f"readv header rlen ours={rlen_o} stock={rlen_f} want={ln}")
    assert roff_o == off == roff_f, (
        f"readv header offset ours={roff_o} stock={roff_f} want={off}")


# ===========================================================================
# RAW multi-segment readv: N segments on one handle. Each segment's bytes are
# correct, segment count + ordering + per-segment framing all match stock.
# ===========================================================================
def _multi_chunks(n, size=200, span=65000):
    """n evenly-spaced (offset, len) chunks within `span` bytes."""
    step = max(1, span // n)
    return [((i * step) % (span - size), size) for i in range(n)]


@pytest.mark.parametrize("n", [2, 4, 8, 16])
def test_readv_multi_segment(srv, n):
    name = "sz_65536.bin"
    chunks = _multi_chunks(n)
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, o) for o, ln in chunks])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in chunks])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"multi readv n={n}: ours={st_o} stock={st_f}"
    segs_o = _parse_segments(body_o)
    segs_f = _parse_segments(body_f)
    assert len(segs_o) == n, f"OUR segment count {len(segs_o)} != {n}"
    assert len(segs_f) == n, f"stock segment count {len(segs_f)} != {n}"
    src = _local(srv, name)
    # Per-segment: framing (rlen, offset) and bytes match request + stock.
    for i, (o, ln) in enumerate(chunks):
        fh_o, rlen_o, roff_o, pay_o = segs_o[i]
        fh_f, rlen_f, roff_f, pay_f = segs_f[i]
        assert roff_o == o == roff_f, (
            f"seg {i} offset ours={roff_o} stock={roff_f} want={o}")
        assert rlen_o == ln == rlen_f, (
            f"seg {i} rlen ours={rlen_o} stock={rlen_f} want={ln}")
        assert pay_o == src[o:o + ln], f"seg {i} OUR bytes wrong"
        assert pay_o == pay_f, f"seg {i} bytes diverge from stock"


# ===========================================================================
# RAW non-monotonic ordering: read [high..] then [low..]; the server MUST
# return segments in request order, with correct bytes (differential vs stock).
# ===========================================================================
@pytest.mark.parametrize("order", [
    [(4096, 128), (0, 128)],
    [(60000, 200), (100, 200), (30000, 200)],
    [(8192, 64), (4096, 64), (2048, 64), (0, 64)],
])
def test_readv_non_monotonic_order(srv, order):
    name = "sz_65536.bin"
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, o) for o, ln in order])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in order])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok
    segs_o = _parse_segments(body_o)
    segs_f = _parse_segments(body_f)
    src = _local(srv, name)
    # Response order must equal request order (NOT offset-sorted).
    req_offsets = [o for o, _ in order]
    assert [s[2] for s in segs_o] == req_offsets, (
        f"OUR server reordered readv segments: {[s[2] for s in segs_o]} "
        f"!= request order {req_offsets}")
    assert [s[2] for s in segs_f] == req_offsets, "stock reordered (tooling?)"
    for i, (o, ln) in enumerate(order):
        assert segs_o[i][3] == src[o:o + ln], f"seg {i} OUR bytes wrong"
        assert segs_o[i][3] == segs_f[i][3], f"seg {i} diverges from stock"


# ===========================================================================
# RAW readv across MULTIPLE file handles in one request. do_ReadV switches the
# active file when info (fhandle) changes, so a request mixing two open handles
# must serve each from its own file. Pin against stock.
# ===========================================================================
def _readv_two_handles(host, port, name_a, name_b, plan):
    """Open two files on one session, issue a readv whose segments reference
    both fhandles per `plan` = [(which, off, len), ...] (which in {0,1}).
    Returns (status, parsed_segments)."""
    sock = _session(host, port)
    try:
        _, sa, ba = _open(sock, _wire_path(name_a), kXR_open_read, streamid=b"\x00\x02")
        assert sa == kXR_ok, f"open {name_a} failed"
        fh_a = ba[:4]
        _, sb, bb = _open(sock, _wire_path(name_b), kXR_open_read, streamid=b"\x00\x03")
        assert sb == kXR_ok, f"open {name_b} failed"
        fh_b = bb[:4]
        handles = (fh_a, fh_b)
        segs = [_seg(handles[w], ln, o) for (w, o, ln) in plan]
        _, status, body = _readv(sock, segs)
        return status, _parse_segments(body), handles
    finally:
        sock.close()


@pytest.mark.parametrize("plan", [
    [(0, 0, 100), (1, 0, 100)],
    [(0, 10, 200), (1, 50, 200), (0, 1000, 64)],
    [(1, 0, 4096), (0, 0, 4096)],
])
def test_readv_multiple_handles(srv, plan):
    name_a, name_b = "data.bin", "sz_8192.bin"
    src_a = _local(srv, name_a)
    src_b = _local(srv, name_b)
    sources = (src_a, src_b)

    st_o, segs_o, _ = _readv_two_handles(*srv["our_hp"], name_a, name_b, plan)
    st_f, segs_f, _ = _readv_two_handles(*srv["off_hp"], name_a, name_b, plan)
    assert st_o == st_f, (
        f"multi-handle readv status diverges: ours={st_o} stock={st_f}")
    if st_o != kXR_ok:
        # Stock may not support cross-handle readv; just pin parity of refusal.
        return
    assert len(segs_o) == len(plan), f"OUR segment count {len(segs_o)} != {len(plan)}"
    for i, (w, o, ln) in enumerate(plan):
        want = sources[w][o:o + ln]
        assert segs_o[i][3] == want, (
            f"seg {i} (handle {w}) OUR bytes wrong: from wrong file?")
        assert segs_o[i][3] == segs_f[i][3], f"seg {i} diverges from stock"


# ===========================================================================
# RAW zero-length segment: pin stock behaviour (skipped/empty, not error).
# ===========================================================================
@pytest.mark.parametrize("segs_plan", [
    [(0, 0)],                       # lone zero-length
    [(0, 0), (100, 32)],            # zero-length followed by valid
    [(100, 32), (0, 0)],            # valid then zero-length
    [(100, 32), (0, 0), (200, 16)],  # zero in the middle
])
def test_readv_zero_length_segment(srv, segs_plan):
    name = "data.bin"
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, o) for o, ln in segs_plan])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in segs_plan])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"zero-length readv status diverges: ours={st_o} stock={st_f}")
    if st_o != kXR_ok:
        return
    src = _local(srv, name)
    want = b"".join(src[o:o + ln] for o, ln in segs_plan if ln > 0)
    pay_o = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_o))
    pay_f = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_f))
    assert pay_o == want, f"OUR zero-length-mixed payload wrong for {segs_plan}"
    assert pay_o == pay_f, "zero-length-mixed payload diverges from stock"


# ===========================================================================
# RAW readv at / just past EOF: error parity vs stock (do_ReadV -> ENODATA).
# ===========================================================================
@pytest.mark.parametrize("name,off,ln", [
    ("data.bin", DATA_SIZE, 10),           # start exactly at EOF
    ("data.bin", DATA_SIZE - 1, 10),       # straddles EOF
    ("data.bin", DATA_SIZE - 50, 200),     # tail crosses EOF
    ("sz_4096.bin", 4096, 4096),           # at EOF on page-aligned file
    ("sz_4097.bin", 4097, 1),              # at EOF on +1 file
    ("data.bin", 1 << 40, 4096),           # way past EOF
])
def test_readv_eof_parity(srv, name, off, ln):
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, _ = _readv(our.sock, [_seg(our.fh, ln, off)])
        _, st_f, _ = _readv(off_h.sock, [_seg(off_h.fh, ln, off)])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"readv EOF behaviour diverges for {name}@{off}+{ln}: "
        f"ours={st_o} stock={st_f} (stock reads past EOF as an error)")


# ===========================================================================
# RAW segment-count cap (readv_iov_max): exactly the cap is OK, over the cap is
# an error — parity with stock at the boundary.
# ===========================================================================
def _iov_max(srv):
    """Both servers' advertised readv_iov_max (the cap). Asserts they agree."""
    rc, out_o, _ = L.run([L.OFF_XRDFS, srv["our"], "query", "config", "readv_iov_max"])
    rc2, out_f, _ = L.run([L.OFF_XRDFS, srv["off"], "query", "config", "readv_iov_max"])
    vo = int(out_o.split()[0]) if rc == 0 and out_o.split() else READV_MAXSEGS
    vf = int(out_f.split()[0]) if rc2 == 0 and out_f.split() else READV_MAXSEGS
    return vo, vf


def test_readv_iov_max_advertised_matches_stock(srv):
    vo, vf = _iov_max(srv)
    assert vo == vf == READV_MAXSEGS, (
        f"readv_iov_max differs: ours={vo} stock={vf} (expected {READV_MAXSEGS})")


def test_readv_at_segment_cap_ok(srv):
    name = "sz_65536.bin"
    n = READV_MAXSEGS  # exactly at the cap
    chunks = [((i * 16) % (65536 - 16), 16) for i in range(n)]
    our, off_h = _open_both(srv, name)
    try:
        st_o, body_o = _readv_drain(our.sock, [_seg(our.fh, ln, o) for o, ln in chunks])
        st_f, body_f = _readv_drain(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in chunks])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"cap readv: ours={st_o} stock={st_f}"
    src = _local(srv, name)
    want = b"".join(src[o:o + ln] for o, ln in chunks)
    pay_o = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_o))
    pay_f = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_f))
    assert pay_o == want, "OUR readv at the segment cap returned wrong bytes"
    assert pay_o == pay_f, "readv at the segment cap diverges from stock"


def test_readv_over_segment_cap_error_parity(srv):
    name = "sz_65536.bin"
    n = READV_MAXSEGS + 1  # one over the cap
    chunks = [(i % 1000, 1) for i in range(n)]
    our, off_h = _open_both(srv, name)
    try:
        try:
            _, st_o, _ = _readv(our.sock, [_seg(our.fh, ln, o) for o, ln in chunks])
        except ConnectionError:
            st_o = kXR_error
        try:
            _, st_f, _ = _readv(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in chunks])
        except ConnectionError:
            st_f = kXR_error
    finally:
        our.close()
        off_h.close()
    assert st_o == kXR_error, "OUR server accepted a readv over readv_iov_max"
    assert st_f == kXR_error, "stock accepted over-cap readv (tooling?)"


# ===========================================================================
# RAW large whole-file readv reassembly: read all of big1m in N segments and
# verify the reassembled bytes md5 == source. Differential vs stock too.
# ===========================================================================
def _equal_segments(total, n):
    base = total // n
    plan = []
    off = 0
    for i in range(n):
        ln = base if i < n - 1 else (total - off)
        plan.append((off, ln))
        off += ln
    return plan


@pytest.mark.parametrize("n", [8, 16, 64])
def test_readv_big_reassembly(srv, n):
    name = BIG_BIN
    plan = _equal_segments(BIG_SIZE, n)
    our, off_h = _open_both(srv, name)
    try:
        st_o, body_o = _readv_drain(our.sock, [_seg(our.fh, ln, o) for o, ln in plan])
        st_f, body_f = _readv_drain(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in plan])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"big readv n={n}: ours={st_o} stock={st_f}"
    src = _local(srv, name)
    pay_o = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_o))
    pay_f = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_f))
    assert len(pay_o) == BIG_SIZE, f"OUR big readv reassembled {len(pay_o)} bytes"
    assert hashlib.md5(pay_o).digest() == hashlib.md5(src).digest(), (
        f"OUR big1m readv reassembly (n={n}) md5 mismatch vs source")
    assert pay_o == pay_f, f"big1m readv (n={n}) diverges from stock"


# ===========================================================================
# RAW plain kXR_read offset/len matrix on the sz_* files: bytes == slice,
# differential vs stock.
# ===========================================================================
def _read_cases():
    cases = []
    for name, size in SZ_FILES.items():
        # whole file in one read.
        cases.append((name, 0, size))
        # a mid read clamped to the file.
        mid = max(0, size // 2)
        cases.append((name, mid, min(64, size - mid) or 1))
        # last byte.
        if size >= 1:
            cases.append((name, size - 1, 1))
    return cases


@pytest.mark.parametrize("name,off,ln", _read_cases())
def test_plain_read_matrix(srv, name, off, ln):
    our, off_h = _open_both(srv, name)
    try:
        st_o, body_o = _read_drain(our.sock, our.fh, off, ln)
        st_f, body_f = _read_drain(off_h.sock, off_h.fh, off, ln)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"plain read {name}@{off}+{ln}: ours={st_o} stock={st_f}")
    want = _local(srv, name)[off:off + ln]
    assert body_o == want, (
        f"OUR plain read {name}@{off}+{ln} wrong bytes "
        f"(got {len(body_o)}, want {len(want)})")
    assert body_o == body_f, f"plain read {name}@{off}+{ln} diverges from stock"


# ===========================================================================
# RAW plain kXR_read EOF / short-read parity vs stock.
# ===========================================================================
@pytest.mark.parametrize("name,off,ln,wantlen", [
    ("data.bin", DATA_SIZE, 10, 0),        # at EOF -> 0 bytes
    ("data.bin", DATA_SIZE - 4, 10, 4),    # straddle EOF -> short read (4)
    ("data.bin", DATA_SIZE + 100, 10, 0),  # past EOF -> 0 bytes
    ("sz_4097.bin", 4096, 10, 1),          # 1 byte left on +1 file
    ("sz_1.bin", 0, 10, 1),                # over-read a 1-byte file -> 1
    ("sz_1.bin", 1, 10, 0),                # at EOF of 1-byte file -> 0
])
def test_plain_read_eof_parity(srv, name, off, ln, wantlen):
    our, off_h = _open_both(srv, name)
    try:
        st_o, body_o = _read_drain(our.sock, our.fh, off, ln)
        st_f, body_f = _read_drain(off_h.sock, off_h.fh, off, ln)
    finally:
        our.close()
        off_h.close()
    # The reference serves short/zero reads as a success (no error past EOF),
    # possibly chunked as kXR_oksofar then kXR_ok; _read_drain normalises that to
    # the final kXR_ok plus the reassembled bytes. The byte COUNT and content
    # are the conformance contract, not the chunk framing.
    assert st_o == st_f, (
        f"plain read EOF status diverges {name}@{off}+{ln}: "
        f"ours={st_o} stock={st_f}")
    if st_o == kXR_ok:
        assert len(body_o) == wantlen, (
            f"OUR short read {name}@{off}+{ln} returned {len(body_o)} "
            f"bytes (want {wantlen})")
        assert body_o == body_f, "short-read bytes diverge from stock"
        want = _local(srv, name)[off:off + ln]
        assert body_o == want, "OUR short read bytes != source slice"


# ===========================================================================
# RAW plain read with len == 0: pin stock behaviour (0 bytes, kXR_ok).
# ===========================================================================
@pytest.mark.parametrize("name", ["data.bin", "sz_4096.bin", "empty.txt"])
def test_plain_read_zero_length(srv, name):
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _read(our.sock, our.fh, 0, 0)
        _, st_f, body_f = _read(off_h.sock, off_h.fh, 0, 0)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, f"zero-length read status diverges: ours={st_o} stock={st_f}"
    if st_o == kXR_ok:
        assert body_o == b"" == body_f, "zero-length read should yield no bytes"


# ===========================================================================
# RAW read of empty.txt: 0 bytes, rc OK on both.
# ===========================================================================
def test_plain_read_empty_file(srv):
    name = "empty.txt"
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _read(our.sock, our.fh, 0, 4096)
        _, st_f, body_f = _read(off_h.sock, off_h.fh, 0, 4096)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"empty read: ours={st_o} stock={st_f}"
    assert body_o == b"" == body_f, "empty.txt read returned bytes"


# ===========================================================================
# RAW readv of empty.txt: pin stock behaviour for a zero-byte file.
# ===========================================================================
def test_readv_empty_file(srv):
    name = "empty.txt"
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, _ = _readv(our.sock, [_seg(our.fh, 16, 0)])
        _, st_f, _ = _readv(off_h.sock, [_seg(off_h.fh, 16, 0)])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"readv of empty.txt diverges: ours={st_o} stock={st_f}")


# ===========================================================================
# RAW interleave on ONE handle: read, readv (multi-seg), read again — all
# correct, and identical to stock.
# ===========================================================================
def _interleave(host, port, name):
    sock = _session(host, port)
    _, st, body = _open(sock, _wire_path(name), kXR_open_read)
    assert st == kXR_ok
    fh = body[:4]
    try:
        _, s1, b1 = _read(sock, fh, 0, 100)
        chunks = [(0, 64), (1000, 128), (4096, 256)]
        _, s2, vbody = _readv(sock, [_seg(fh, ln, o) for o, ln in chunks])
        _, s3, b3 = _read(sock, fh, 2048, 512)
        return (s1, b1), (s2, _readv_payload(vbody, len(chunks)), chunks), (s3, b3)
    finally:
        try:
            _close(sock, fh)
        except Exception:
            pass
        sock.close()


def test_interleave_read_readv_read(srv):
    name = "sz_65536.bin"
    src = _local(srv, name)
    (s1o, b1o), (s2o, vo, chunks), (s3o, b3o) = _interleave(*srv["our_hp"], name)
    (s1f, b1f), (s2f, vf, _), (s3f, b3f) = _interleave(*srv["off_hp"], name)
    assert s1o == s1f == kXR_ok and s2o == s2f == kXR_ok and s3o == s3f == kXR_ok
    assert b1o == src[0:100], "OUR first read wrong"
    assert b1o == b1f, "first read diverges from stock"
    want_v = b"".join(src[o:o + ln] for o, ln in chunks)
    assert vo == want_v, "OUR interleaved readv wrong"
    assert vo == vf, "interleaved readv diverges from stock"
    assert b3o == src[2048:2048 + 512], "OUR third read wrong"
    assert b3o == b3f, "third read diverges from stock"


# ===========================================================================
# INTEGRITY: full-file readv reassembly == xrdcp download of the same file.
# The raw readv path and the high-level client read path must agree.
# ===========================================================================
@pytest.mark.parametrize("name", ["data.bin", "sz_8192.bin", "sz_65536.bin",
                                  "big1m.bin"])
def test_readv_reassembly_equals_xrdcp(srv, tmp_path, name):
    # 1) full-file via raw readv on OUR server.
    size = len(_local(srv, name))
    n = 16 if size > 65536 else 4
    plan = _equal_segments(size, n)
    our = _Handle(*srv["our_hp"], name)
    try:
        st, body = _readv_drain(our.sock, [_seg(our.fh, ln, o) for o, ln in plan])
    finally:
        our.close()
    assert st == kXR_ok, f"raw readv reassembly of {name} failed"
    via_readv = b"".join(p for (_f, _r, _o, p) in _parse_segments(body))

    # 2) full-file via stock xrdcp download from OUR server.
    dst = str(tmp_path / f"dl_{name}")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//{name}", dst],
                         timeout=120 if name == "big1m.bin" else 60)
    assert rc == 0, f"xrdcp download of {name} from OUR server failed: {out}{err}"
    via_xrdcp = open(dst, "rb").read()

    assert via_readv == via_xrdcp, (
        f"OUR readv reassembly of {name} differs from the xrdcp download "
        f"(readv={len(via_readv)}B xrdcp={len(via_xrdcp)}B)")
    assert via_readv == _local(srv, name), (
        f"OUR readv reassembly of {name} differs from the local source")


# ===========================================================================
# Oracle: stock xrdcp stock->stock on a page-boundary file, proving the
# tooling itself is sound (a failure here is environmental, not ours).
# ===========================================================================
def test_oracle_stock_to_stock(srv, tmp_path):
    dst = str(tmp_path / "oracle.bin")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['off']}//sz_4097.bin", dst])
    assert rc == 0, f"oracle stock->stock failed (tooling broken): {out}{err}"
    assert open(dst, "rb").read() == _local(srv, "sz_4097.bin")
