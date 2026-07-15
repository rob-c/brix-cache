"""Differential conformance for the kXR_write DATA PLANE.

Drives a minimal RAW-WIRE XRootD client (login / open / write / read / sync /
truncate / close) AND the stock xrdcp end-to-end, against BOTH our nginx-xrootd
server and the stock xrootd data server, on identical throwaway trees, and
asserts byte-exact POSIX-correct write behaviour with the STOCK server pinned as
the reference.

Philosophy (per the maintainer): any divergence — wrong bytes on disk, wrong
size, a sparse hole that is not zero, a read-only handle that accepts a write, a
stale/closed fhandle that is accepted, pipelined-write corruption, or a
different error CATEGORY — is a BUG IN OUR SERVER unless there is positive
evidence otherwise. The stock xrootd server / POSIX define the contract. No
xfail/skip is used to paper over a real divergence.

Scope (the WRITE path only; read/sync/truncate appear solely to OBSERVE the
result of writes):
  * sequential contiguous writes: chunk sizes {1,512,4096,4097,65536} x counts
  * single write at offset 0 of various sizes
  * random / out-of-order writes -> final file md5 vs an independent buffer
  * overlapping writes (last-writer-wins region)
  * sparse write past EOF -> apparent size, zero hole, written bytes
  * append past a small file (write @ EOF grows)
  * zero-length write -> no-op parity
  * write to a READ-ONLY handle -> error parity
  * write to a bad / closed / stale fhandle -> error parity (FileNotOpen)
  * write + read-back on the SAME handle (handle coherence)
  * interleaved write/read/sync/write/close -> final content
  * large multi-MB write in chunks -> md5 stable
  * PIPELINED writes (many kXR_write sent before draining acks) -> all land
  * write after close -> error parity
  * malformed write (dlen mismatch / oversized) -> error parity
  * end-to-end xrdcp upload at many sizes -> read back byte-exact, differential
  * write then truncate-shrink then read -> only the kept prefix
  * two open-write handles to different files in ONE session -> both correct

The framing is copied from test_conf_truncate_sync.py / test_conf_openflags.py
and pinned against /tmp/brix-src/src/XProtocol/XProtocol.hh:
  ClientWriteRequest = streamid[2] requestid[2] fhandle[4] offset[8]
    pathid[1] reserved[3] dlen[4] then `dlen` data bytes  (XProtocol.hh:845),
  do_Write in XrdXrootd/XrdXrootdXeq.cc.
kXR_write == 3019, kXR_read == 3013, kXR_sync == 3016, kXR_truncate == 3028,
kXR_open == 3010, kXR_close == 3003 (XProtocol.hh:116-141).

Every mutation uses a UNIQUE wire path so the module-scoped shared tree never
lets one test pollute another. Multi-MB transfers get generous timeouts.

Self-provisioning on high ports; skips entirely without the stock toolchain.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    python -m pytest tests/test_conf_write.py -q
"""

import hashlib
import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(360),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14044)
OFF_PORT = L.worker_port(14045)
# --------------------------------------------------------------------------- #
# Fixture: one server pair for the whole module (skip cleanly if it can't run)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conf_write"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Thin helpers over the stock client + on-disk verification
# --------------------------------------------------------------------------- #
def cp(*args, timeout=300):
    """Run the stock xrdcp -> (rc, out, err)."""
    return L.run([L.OFF_XRDCP, *args], timeout=timeout)


def uniq(name):
    # Tag every working-file name with the pytest-xdist worker id so that under
    # `-n8 --dist load` no two concurrent workers ever create the same fixed-name
    # file in the shared export (which would race a create-NEW/O_EXCL open, e.g.
    # "open /overlap_off_2.bin failed; file exists"). Serial runs use "main".
    return "/%s_%s" % (L.worker_tag(), name)


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


def read_disk(ctx, url, path):
    with open(disk_for(ctx, url, path), "rb") as f:
        return f.read()


def both(ctx):
    """Iterate ('our', url) and ('off', url)."""
    return (("our", ctx["our"]), ("off", ctx["off"]))


# --------------------------------------------------------------------------- #
# RAW-WIRE client (login / open / write / read / sync / truncate / close)
# Framing copied from test_conf_truncate_sync.py + XProtocol.hh.
# --------------------------------------------------------------------------- #
kXR_close, kXR_open, kXR_read = 3003, 3010, 3013
kXR_sync, kXR_write, kXR_truncate = 3016, 3019, 3028
kXR_login = 3007
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003

# open options (XProtocol.hh XOpenRequestOption)
kXR_delete = 0x0002
kXR_force = 0x0004
kXR_new = 0x0008
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_mkpath = 0x0100
kXR_open_wrto = 0x8000


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        try:
            c = s.recv(n - len(b))
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            raise EOFError("connection reset")
        if not c:
            raise EOFError("closed")
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
    _, st, _ = _resp(s)          # handshake reply
    assert st == kXR_ok, "handshake failed"
    return s


def _login(s, sid=b"\x00\x01"):
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, b"wrte\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(url):
    host, port = host_port(url)
    s = _connect(host, port)
    _login(s)
    return s


def _open(s, path, options, sid=b"\x00\x03"):
    p = path.encode()
    s.sendall(struct.pack("!2sHHH12sI", sid, kXR_open, 0o0644, options,
                          b"\x00" * 12, len(p)) + p)
    _, st, body = _resp(s)
    return st, body


def _open_handle(s, path, options):
    st, body = _open(s, path, options)
    assert st == kXR_ok, \
        f"open {path} (opt=0x{options:x}) failed: st={st} body={body!r}"
    return body[0:4]


def _write_frame(fhandle, offset, dlen, sid=b"\x00\x07"):
    """Build a kXR_write header with an arbitrary declared `dlen` (for malformed
    cases the declared dlen need not equal the trailing payload length)."""
    return struct.pack("!2sH4sqB3sI", sid, kXR_write, fhandle, offset,
                       0, b"\x00\x00\x00", dlen)


def _write(s, fhandle, offset, data, sid=b"\x00\x07"):
    s.sendall(_write_frame(fhandle, offset, len(data), sid) + data)
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


def _new_handle(s, wire):
    """Open a fresh writable+truncated file and return its fhandle."""
    return _open_handle(s, wire, kXR_new | kXR_open_updt | kXR_delete)


def _build_expected(regions, total):
    buf = bytearray(total)
    for off, data in regions:
        buf[off:off + len(data)] = data
    return bytes(buf)


# =========================================================================== #
# 1. SEQUENTIAL CONTIGUOUS WRITES — open(new), write `count` chunks back to
#    back, close; on-disk == concatenation. Differential vs stock + on-disk
#    integrity against an independently built buffer.
#    chunk sizes {1,512,4096,4097,65536} x counts.  (25 params)
# =========================================================================== #
_SEQ = []
for _cs in (1, 512, 4096, 4097, 65536):
    for _cnt in (1, 2, 3, 5, 8):
        _SEQ.append((_cs, _cnt))


@pytest.mark.parametrize("chunk,count", _SEQ)
def test_sequential_contiguous_writes(srv, chunk, count):
    chunks = [det_bytes(chunk, seed=(chunk + i) & 0xff) for i in range(count)]
    expected = b"".join(chunks)
    for who, url in both(srv):
        wire = uniq(f"seq_{who}_{chunk}_{count}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            off = 0
            for c in chunks:
                st, body = _write(s, fh, off, c)
                assert st == kXR_ok, \
                    f"{who} seq write @{off} (cs={chunk}) failed: err={_err(body)}"
                off += len(c)
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == len(expected), \
            f"{who} seq size {len(got)} != {len(expected)} (cs={chunk} n={count})"
        assert md5(got) == md5(expected), \
            f"{who} seq content mismatch (cs={chunk} n={count})"


# =========================================================================== #
# 2. SINGLE WRITE @ offset 0 of various sizes -> file == data, size exact.
# =========================================================================== #
_SINGLE = [0, 1, 2, 511, 512, 513, 4095, 4096, 4097, 65535, 65536, 131072]


@pytest.mark.parametrize("n", _SINGLE)
def test_single_write_at_zero(srv, n):
    payload = det_bytes(n, seed=(n + 3) & 0xff)
    for who, url in both(srv):
        wire = uniq(f"single_{who}_{n}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            st, body = _write(s, fh, 0, payload)
            assert st == kXR_ok, f"{who} single write n={n}: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == n, f"{who} single size {len(got)} != {n}"
        assert got == payload, f"{who} single content wrong n={n}"


# =========================================================================== #
# 3. RANDOM / OUT-OF-ORDER WRITES -> final file correct (md5 vs expected).
#    Write the regions in a scrambled order; result must equal in-order.
# =========================================================================== #
_RANDOM = [
    (0, [(8192, det_bytes(256, 1)), (0, det_bytes(256, 2)),
         (4096, det_bytes(256, 3))]),
    (1, [(1000, det_bytes(500, 4)), (0, det_bytes(100, 5)),
         (5000, det_bytes(123, 6)), (300, det_bytes(50, 7))]),
    (2, [(4097, det_bytes(4097, 8)), (0, det_bytes(1, 9)),
         (9000, det_bytes(7, 10))]),
]


@pytest.mark.parametrize("idx,regions", _RANDOM)
def test_random_out_of_order_writes(srv, idx, regions):
    total = max(off + len(d) for off, d in regions)
    expected = _build_expected(regions, total)
    for who, url in both(srv):
        wire = uniq(f"rand_{who}_{idx}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            for off, data in regions:
                st, body = _write(s, fh, off, data)
                assert st == kXR_ok, \
                    f"{who} ooo write @{off} failed: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == total, f"{who} ooo size {len(got)} != {total}"
        assert md5(got) == md5(expected), f"{who} ooo content mismatch idx={idx}"


# =========================================================================== #
# 4. OVERLAPPING WRITES — last-writer-wins region correct.
# =========================================================================== #
_OVERLAP = [
    (0, 0, det_bytes(100, 1), 50, det_bytes(100, 2)),
    (1, 0, det_bytes(100, 3), 0, det_bytes(40, 4)),
    (2, 4090, det_bytes(20, 5), 4096, det_bytes(20, 6)),
    (3, 100, det_bytes(200, 7), 150, det_bytes(50, 8)),
]


@pytest.mark.parametrize("idx,a_off,a,b_off,b", _OVERLAP)
def test_overlapping_writes_last_wins(srv, idx, a_off, a, b_off, b):
    total = max(a_off + len(a), b_off + len(b))
    expected = bytearray(total)
    expected[a_off:a_off + len(a)] = a
    expected[b_off:b_off + len(b)] = b      # B applied second -> wins overlap
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"overlap_{who}_{idx}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, a_off, a)[0] == kXR_ok, f"{who} write A"
            assert _write(s, fh, b_off, b)[0] == kXR_ok, f"{who} write B"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert got == expected, f"{who} overlap final bytes wrong idx={idx}"


# =========================================================================== #
# 5. SPARSE WRITE past EOF -> size==offset+len, hole zero, bytes correct;
#    files identical across our vs stock.
# =========================================================================== #
@pytest.mark.parametrize("offset,wlen", [(4096, 16), (65536, 32),
                                         (100000, 48), (1 << 20, 64)])
def test_sparse_write_at_offset(srv, offset, wlen):
    payload = det_bytes(wlen, seed=42)
    paths = {}
    for who, url in both(srv):
        wire = uniq(f"sparse_{who}_{offset}.bin")
        paths[who] = wire
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            st, body = _write(s, fh, offset, payload)
            assert st == kXR_ok, f"{who} sparse write failed: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == offset + wlen, \
            f"{who} sparse size {len(got)} != {offset + wlen}"
        assert got[:offset] == b"\x00" * offset, f"{who} sparse hole not zero"
        assert got[offset:] == payload, f"{who} sparse written bytes wrong"
    assert md5(read_disk(srv, srv["our"], paths["our"])) == \
        md5(read_disk(srv, srv["off"], paths["off"])), \
        "sparse-write files diverge our vs stock"


# =========================================================================== #
# 6. APPEND past a small existing file -> grows correctly.
# =========================================================================== #
@pytest.mark.parametrize("base_n,app_off,app_n", [
    (100, 100, 50),       # contiguous append at EOF
    (100, 200, 50),       # gap append (hole 100..200)
    (4096, 4096, 4096),
    (1, 1, 9999),
])
def test_write_past_small_file_grows(srv, base_n, app_off, app_n):
    base = det_bytes(base_n, seed=31)
    app = det_bytes(app_n, seed=32)
    total = max(base_n, app_off + app_n)
    expected = bytearray(total)
    expected[:base_n] = base
    expected[app_off:app_off + app_n] = app
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"grow_{who}_{base_n}_{app_off}_{app_n}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_updt)
            st, body = _write(s, fh, app_off, app)
            assert st == kXR_ok, f"{who} grow write failed: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == total, f"{who} grow size {len(got)} != {total}"
        assert got == expected, f"{who} grow content wrong"


# =========================================================================== #
# 7. ZERO-LENGTH WRITE -> no-op; content/size unchanged; rc parity.
# =========================================================================== #
@pytest.mark.parametrize("at", [0, 64, 256])
def test_zero_length_write_is_noop(srv, at):
    base = det_bytes(256, seed=51)
    res = {}
    for who, url in both(srv):
        wire = uniq(f"zerow_{who}_{at}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_updt)
            st, _b = _write(s, fh, at, b"")
            res[who] = (st == kXR_ok)
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        assert read_disk(srv, url, wire) == base, \
            f"{who} zero-length write @{at} changed content/size"
    assert res["our"] == res["off"], \
        f"zero-length write rc parity differs at={at}: {res}"


# =========================================================================== #
# 8. WRITE to a READ-ONLY handle -> error parity (not silently accepted).
# =========================================================================== #
@pytest.mark.parametrize("at", [0, 4096])
def test_write_to_readonly_handle(srv, at):
    base = det_bytes(8192, seed=71)
    res = {}
    for who, url in both(srv):
        wire = uniq(f"rowrite_{who}_{at}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_read)
            st, body = _write(s, fh, at, det_bytes(64, 99))
            res[who] = (st, _err(body))
            # drain link cleanly if still up
            try:
                _close(s, fh)
            except EOFError:
                pass
        except EOFError:
            res[who] = ("dropped", None)
        finally:
            s.close()
        # on-disk bytes must be untouched regardless of how the error surfaced
        assert read_disk(srv, url, wire) == base, \
            f"{who} RO-handle write mutated file (data corruption) at={at}"
    assert res["our"][0] != kXR_ok, \
        f"OUR server ACCEPTED a write to a read-only handle: {res}"
    assert res["off"][0] != kXR_ok, f"sanity: stock accepted RO write: {res}"


# =========================================================================== #
# 9. WRITE to a BAD / never-opened fhandle -> error parity (FileNotOpen).
# =========================================================================== #
def test_write_bogus_fhandle(srv):
    bogus = b"\x7e\x7e\x7e\x7e"
    res = {}
    for who, url in both(srv):
        s = _session(url)
        try:
            st, body = _write(s, bogus, 0, det_bytes(32, 1))
            res[who] = (st, _err(body))
        except EOFError:
            res[who] = ("dropped", None)
        finally:
            s.close()
    assert res["our"][0] != kXR_ok, \
        f"OUR server accepted write to bogus fhandle: {res}"
    assert res["off"][0] != kXR_ok, f"sanity: stock accepted bogus fhandle: {res}"


# =========================================================================== #
# 10. WRITE to a CLOSED / STALE fhandle -> error parity.
# =========================================================================== #
def test_write_after_close_stale_handle(srv):
    res = {}
    for who, url in both(srv):
        wire = uniq(f"stale_{who}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, 0, det_bytes(128, 2))[0] == kXR_ok
            assert _close(s, fh)[0] == kXR_ok
            # fh is now stale: a further write must be rejected
            try:
                st, body = _write(s, fh, 128, det_bytes(128, 3))
                res[who] = (st, _err(body))
            except EOFError:
                res[who] = ("dropped", None)
        finally:
            s.close()
        # the post-close write must not have extended the file
        assert len(read_disk(srv, url, wire)) == 128, \
            f"{who} write to stale handle mutated file"
    assert res["our"][0] != kXR_ok, \
        f"OUR server accepted write to closed handle: {res}"
    assert res["off"][0] != kXR_ok, f"sanity: stock accepted stale handle: {res}"


# =========================================================================== #
# 11. WRITE + READ-BACK on the SAME handle -> sees the just-written bytes
#     (handle coherence pinned to stock).
# =========================================================================== #
@pytest.mark.parametrize("off,n", [(0, 4096), (0, 100), (4096, 4096), (1234, 777)])
def test_write_then_read_same_handle(srv, off, n):
    payload = det_bytes(n, seed=81)
    for who, url in both(srv):
        wire = uniq(f"rbsame_{who}_{off}_{n}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, off, payload)[0] == kXR_ok, f"{who} write"
            st, data = _read(s, fh, off, n)
            assert st == kXR_ok, f"{who} read-back same handle failed"
            assert data == payload, \
                f"{who} same-handle read does not see written bytes (off={off})"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()


# =========================================================================== #
# 12. INTERLEAVE write/read/sync/write/close -> final content correct.
# =========================================================================== #
def test_interleave_write_read_sync_write(srv):
    a = det_bytes(4096, seed=91)
    b = det_bytes(2048, seed=92)
    c = det_bytes(1024, seed=93)
    expected = bytearray(4096 + 2048 + 1024)
    expected[0:4096] = a
    expected[4096:4096 + 2048] = b
    expected[4096 + 2048:] = c
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"interleave_{who}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, 0, a)[0] == kXR_ok, f"{who} w1"
            st, got = _read(s, fh, 0, 4096)
            assert st == kXR_ok and got == a, f"{who} read1 wrong"
            assert _sync(s, fh)[0] == kXR_ok, f"{who} sync"
            assert _write(s, fh, 4096, b)[0] == kXR_ok, f"{who} w2"
            st, got = _read(s, fh, 4096, 2048)
            assert st == kXR_ok and got == b, f"{who} read2 wrong"
            assert _write(s, fh, 4096 + 2048, c)[0] == kXR_ok, f"{who} w3"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert got == expected, f"{who} interleave final content wrong"


# =========================================================================== #
# 13. LARGE write (multi-MB in chunks) -> md5 stable round-trip.
# =========================================================================== #
@pytest.mark.parametrize("total,chunk", [(1 << 20, 65536), (5 << 20, 1 << 20),
                                         (3 << 20, 4096)])
def test_large_chunked_write(srv, total, chunk):
    src = det_bytes(total, seed=7)
    for who, url in both(srv):
        wire = uniq(f"large_{who}_{total}_{chunk}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            off = 0
            while off < total:
                seg = src[off:off + chunk]
                st, body = _write(s, fh, off, seg)
                assert st == kXR_ok, \
                    f"{who} large write @{off} failed: err={_err(body)}"
                off += len(seg)
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == total, f"{who} large size {len(got)} != {total}"
        assert md5(got) == md5(src), \
            f"{who} large write md5 mismatch (total={total} chunk={chunk})"


# =========================================================================== #
# 14. PIPELINED WRITES — send several kXR_write frames before draining ANY
#     acks, then read all acks; every byte must land. Exercises our write
#     pipelining (wr_inflight) without corruption.
# =========================================================================== #
@pytest.mark.parametrize("nchunks,chunk", [(8, 4096), (16, 65536),
                                           (32, 4096), (5, 1 << 20)])
def test_pipelined_writes(srv, nchunks, chunk):
    chunks = [det_bytes(chunk, seed=(i * 13 + 1) & 0xff) for i in range(nchunks)]
    expected = b"".join(chunks)
    for who, url in both(srv):
        wire = uniq(f"pipe_{who}_{nchunks}_{chunk}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            # fire ALL writes back-to-back without reading replies yet
            off = 0
            for c in chunks:
                s.sendall(_write_frame(fh, off, len(c)) + c)
                off += len(c)
            # now drain exactly nchunks acks
            for i in range(nchunks):
                _, st, body = _resp(s)
                assert st == kXR_ok, \
                    f"{who} pipelined ack #{i} not ok: st={st} err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == len(expected), \
            f"{who} pipelined size {len(got)} != {len(expected)}"
        assert md5(got) == md5(expected), \
            f"{who} pipelined write CORRUPTION (n={nchunks} cs={chunk})"


def test_pipelined_writes_out_of_order_offsets(srv):
    """Pipeline writes whose offsets are scrambled; bytes must still land at the
    declared offsets (proves offset is honoured per-frame under pipelining)."""
    regions = [(16384, det_bytes(4096, 1)), (0, det_bytes(4096, 2)),
               (8192, det_bytes(4096, 3)), (4096, det_bytes(4096, 4)),
               (12288, det_bytes(4096, 5))]
    total = max(o + len(d) for o, d in regions)
    expected = _build_expected(regions, total)
    for who, url in both(srv):
        wire = uniq(f"pipeooo_{who}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            for off, data in regions:
                s.sendall(_write_frame(fh, off, len(data)) + data)
            for i in range(len(regions)):
                _, st, body = _resp(s)
                assert st == kXR_ok, \
                    f"{who} pipe-ooo ack #{i} not ok: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert md5(got) == md5(expected), \
            f"{who} pipelined out-of-order write corruption"


# =========================================================================== #
# 15. MALFORMED WRITE — declared dlen does not match the actual payload, or is
#     absurdly large. The server must reject cleanly (error / link drop), never
#     silently accept it as a valid write. Pinned to stock behaviour.
#     A fresh session per case (a malformed frame may poison the link).
# =========================================================================== #
@pytest.mark.parametrize("kind", ["short_payload", "oversized_dlen"])
def test_malformed_write_rejected(srv, kind):
    res = {}
    for who, url in both(srv):
        wire = uniq(f"malformed_{who}_{kind}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            if kind == "short_payload":
                # declare 4096 bytes but send only 100, then a close request.
                # The server must NOT treat the close bytes as write payload.
                hdr = _write_frame(fh, 0, 4096)
                s.sendall(hdr + det_bytes(100, 1))
                # follow with a close frame; a correct server reading 4096 bytes
                # would consume these bytes and the link state diverges -> we
                # simply observe that the eventual response is not a clean ok
                # for a 4096-byte write that never arrived.
                s.sendall(struct.pack("!2sH4s12sI", b"\x00\x0e", kXR_close,
                                      fh, b"\x00" * 12, 0))
                try:
                    _, st, _b = _resp(s)
                    res[who] = st
                except EOFError:
                    res[who] = "dropped"
            else:  # oversized_dlen: declare 1 GiB, send nothing more
                s.sendall(_write_frame(fh, 0, 1 << 30))
                try:
                    s.settimeout(8)
                    _, st, _b = _resp(s)
                    res[who] = st
                except (EOFError, socket.timeout):
                    res[who] = "dropped_or_timeout"
        finally:
            s.close()
    # The two servers should agree on *category*: neither returns a clean ok
    # acknowledging a well-formed 4096B / 1GiB write that never happened.
    assert res["our"] != kXR_ok, \
        f"OUR server returned clean ok for a malformed write ({kind}): {res}"
    assert res["off"] != kXR_ok, \
        f"sanity: stock returned clean ok for malformed write ({kind}): {res}"


# =========================================================================== #
# 16. END-TO-END xrdcp upload at many sizes -> read back byte-exact (our &
#     stock), differential. (write path exercised through the official client)
# =========================================================================== #
_E2E_SIZES = [0, 1, 512, 4095, 4096, 4097, 65536, 1 << 20, 5 << 20]


@pytest.mark.parametrize("n", _E2E_SIZES)
def test_e2e_upload_roundtrip_our(srv, tmp_path, n):
    src = make_local(str(tmp_path / f"e2e_our_{n}.bin"), n, seed=(n & 0xff))
    wire = uniq(f"e2e_our_{n}.bin")
    rc, o, e = cp("-f", src, f"{srv['our']}/{wire}")
    assert rc == 0, f"upload N={n} -> OUR failed: {o}{e}"
    assert os.path.getsize(our_disk(srv, wire)) == n, \
        f"on-disk size {os.path.getsize(our_disk(srv, wire))} != {n}"
    dl = str(tmp_path / f"e2e_our_dl_{n}.bin")
    rc, o, e = cp("-f", f"{srv['our']}/{wire}", dl)
    assert rc == 0, f"download N={n} from OUR failed: {o}{e}"
    with open(src, "rb") as a, open(dl, "rb") as b:
        assert md5(a.read()) == md5(b.read()), f"N={n} roundtrip integrity mismatch"


@pytest.mark.parametrize("n", _E2E_SIZES)
def test_e2e_upload_differential(srv, tmp_path, n):
    src = make_local(str(tmp_path / f"e2e_diff_{n}.bin"), n, seed=((n + 1) & 0xff))
    our_w = uniq(f"e2e_diff_our_{n}.bin")
    off_w = uniq(f"e2e_diff_off_{n}.bin")
    assert cp("-f", src, f"{srv['our']}/{our_w}")[0] == 0, f"upload our N={n}"
    assert cp("-f", src, f"{srv['off']}/{off_w}")[0] == 0, f"upload off N={n}"
    assert os.path.getsize(our_disk(srv, our_w)) == n
    assert os.path.getsize(off_disk(srv, off_w)) == n
    with open(src, "rb") as fsrc:
        want = md5(fsrc.read())
    assert md5(read_disk(srv, srv["our"], our_w)) == want, \
        f"N={n}: OUR uploaded bytes differ from source"
    assert md5(read_disk(srv, srv["off"], off_w)) == want, \
        f"N={n}: STOCK uploaded bytes differ from source"


# =========================================================================== #
# 17. WRITE then TRUNCATE-SHRINK then READ -> only the kept prefix remains.
# =========================================================================== #
@pytest.mark.parametrize("write_n,keep", [(4096, 0), (4096, 1), (4096, 2048),
                                          (65536, 4096), (10000, 9999)])
def test_write_then_shrink_then_read(srv, write_n, keep):
    payload = det_bytes(write_n, seed=61)
    for who, url in both(srv):
        wire = uniq(f"wshrink_{who}_{write_n}_{keep}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            st, body = _truncate_handle(s, fh, keep)
            assert st == kXR_ok, f"{who} shrink failed: err={_err(body)}"
            st, data = _read(s, fh, 0, write_n)
            assert st == kXR_ok, f"{who} read-after-shrink failed"
            assert data == payload[:keep], \
                f"{who} read-after-shrink sees wrong prefix (keep={keep})"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == keep, f"{who} shrink size {len(got)} != {keep}"
        assert got == payload[:keep], f"{who} shrink kept wrong prefix"


# =========================================================================== #
# 18. CONCURRENT — two open-write handles to DIFFERENT files in ONE session;
#     both must be written correctly and independently.
# =========================================================================== #
@pytest.mark.parametrize("n1,n2", [(4096, 8192), (1, 65536), (100, 100)])
def test_two_handles_one_session(srv, n1, n2):
    d1 = det_bytes(n1, seed=111)
    d2 = det_bytes(n2, seed=222)
    for who, url in both(srv):
        w1 = uniq(f"two_{who}_{n1}_{n2}_a.bin")
        w2 = uniq(f"two_{who}_{n1}_{n2}_b.bin")
        s = _session(url)
        try:
            fh1 = _open_handle(s, w1, kXR_new | kXR_open_updt | kXR_delete)
            fh2 = _open_handle(s, w2, kXR_new | kXR_open_updt | kXR_delete)
            assert fh1 != fh2, f"{who} server reused fhandle for two opens"
            # interleave the two streams
            assert _write(s, fh1, 0, d1[:n1 // 2 or n1])[0] == kXR_ok
            assert _write(s, fh2, 0, d2[:n2 // 2 or n2])[0] == kXR_ok
            if n1 // 2:
                assert _write(s, fh1, n1 // 2, d1[n1 // 2:])[0] == kXR_ok
            if n2 // 2:
                assert _write(s, fh2, n2 // 2, d2[n2 // 2:])[0] == kXR_ok
            assert _close(s, fh1)[0] == kXR_ok
            assert _close(s, fh2)[0] == kXR_ok
        finally:
            s.close()
        g1 = read_disk(srv, url, w1)
        g2 = read_disk(srv, url, w2)
        assert g1 == d1, f"{who} two-handle file1 wrong"
        assert g2 == d2, f"{who} two-handle file2 wrong"


# =========================================================================== #
# 19. WRITE with kXR_open_wrto (write-to / write-only create) -> sequential
#     writes land correctly (covers the alternate write-open option).
# =========================================================================== #
@pytest.mark.parametrize("n", [100, 4096, 65536])
def test_write_with_wrto_open(srv, n):
    payload = det_bytes(n, seed=131)
    for who, url in both(srv):
        wire = uniq(f"wrto_{who}_{n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_new | kXR_open_wrto | kXR_delete)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} wrto write"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert got == payload, f"{who} wrto write content wrong n={n}"


# =========================================================================== #
# 20. OVERWRITE existing region in an UPDATE-opened file -> in-place modify,
#     size unchanged, untouched bytes preserved.
# =========================================================================== #
@pytest.mark.parametrize("base_n,at,wn", [(4096, 0, 100), (4096, 2000, 96),
                                          (65536, 32768, 4096), (200, 100, 100)])
def test_inplace_overwrite_update_open(srv, base_n, at, wn):
    base = det_bytes(base_n, seed=141)
    patch = det_bytes(wn, seed=142)
    expected = bytearray(base)
    expected[at:at + wn] = patch
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"inplace_{who}_{base_n}_{at}_{wn}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_updt)
            assert _write(s, fh, at, patch)[0] == kXR_ok, f"{who} in-place write"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == base_n, \
            f"{who} in-place overwrite changed size {len(got)} != {base_n}"
        assert got == expected, f"{who} in-place overwrite content wrong"
