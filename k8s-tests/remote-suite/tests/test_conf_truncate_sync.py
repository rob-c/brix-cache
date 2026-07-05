"""Differential conformance for TRUNCATE / SYNC / SPARSE / partial I/O / large-file size matrix.

Drives the STOCK XRootD client (xrdfs/xrdcp) AND a minimal RAW-WIRE client
against BOTH our nginx-xrootd server and the stock xrootd data server, on
identical throwaway trees, and asserts byte-exact POSIX-correct behavior with
the stock server pinned as the reference.

Philosophy (per the maintainer): any divergence — wrong on-disk size, a
non-zero sparse hole, a sync that is not durable, a different extend semantic,
or a different error category — is a BUG IN OUR SERVER unless there is positive
evidence otherwise. The stock xrootd server / POSIX define the contract.

This file goes DEEPER than test_conf_write_ops.py's truncate cases (which only
covered path-based shrink to {0,10,50,200} + a single extend + missing-file).
Here we add:
  * path-based truncate to {0, 1, N//2, N, N+1000} with zero-fill verification
  * truncate via an OPEN HANDLE (raw-wire kXR_truncate on an fhandle)
  * truncate to a huge SPARSE size (apparent size vs allocated blocks)
  * sparse writes (write past EOF -> hole reads as zero)
  * non-contiguous partial writes, overlapping writes, append-style writes
  * raw-wire kXR_sync durability (read back on a 2nd handle)
  * a LARGE-FILE size matrix {0,1,512,4095,4096,4097,1<<16,1<<20,5<<20}
  * shrink-then-read prefix integrity

Every mutation uses a UNIQUE wire path so the module-scoped shared tree never
lets one test pollute another. Multi-MB transfers get generous timeouts.

Self-provisioning; skips entirely without the stock xrootd toolchain.
"""

import hashlib
import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14026)
OFF_PORT = L.worker_port(14027)
# --------------------------------------------------------------------------- #
# Fixture: one server pair for the whole module (skip cleanly if it can't run)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("trunc_sync"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Thin helpers over the stock client + on-disk verification
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    """Run the stock xrdfs against a server url -> (rc, out, err)."""
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def cp(*args, timeout=240):
    """Run the stock xrdcp -> (rc, out, err)."""
    return L.run([L.OFF_XRDCP, *args], timeout=timeout)


def uniq(name):
    return "/" + name


def our_disk(ctx, path):
    return os.path.join(ctx["our_data"], path.lstrip("/"))


def off_disk(ctx, path):
    return os.path.join(ctx["off_data"], path.lstrip("/"))


def host_port(url):
    """root://127.0.0.1:PORT -> (host, port)."""
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


def disk_for(ctx, url, path):
    return our_disk(ctx, path) if url == ctx["our"] else off_disk(ctx, path)


def diff_fail(ctx, do):
    """Run a *failing* op on BOTH servers; return (rc_o, rc_f, cat_o, cat_f, raw)."""
    rc_o, o_o, e_o = do(ctx["our"])
    rc_f, o_f, e_f = do(ctx["off"])
    cat_o = L.err_code(o_o + e_o)
    cat_f = L.err_code(o_f + e_f)
    raw = (f"\n  OURS  rc={rc_o} cat={cat_o!r} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} cat={cat_f!r} :: {(o_f + e_f).strip()!r}")
    return rc_o, rc_f, cat_o, cat_f, raw


# --------------------------------------------------------------------------- #
# RAW-WIRE client (login / open / write / read / sync / truncate / close)
# Framing copied from test_brix_conformance.py + XProtocol.hh.
# --------------------------------------------------------------------------- #
kXR_close, kXR_open, kXR_read = 3003, 3010, 3013
kXR_sync, kXR_write, kXR_truncate = 3016, 3019, 3028
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003

# open options (XProtocol.hh XOpenRequestOption)
kXR_delete = 0x0002
kXR_new = 0x0008
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_mkpath = 0x0100


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
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
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, 3007,
                          os.getpid() & 0x7fffffff, b"trsy\x00\x00\x00\x00",
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
    assert st == kXR_ok, f"open {path} (opt=0x{options:x}) failed: st={st} body={body!r}"
    return body[0:4]


def _write(s, fhandle, offset, data, sid=b"\x00\x07"):
    hdr = struct.pack("!2sH4sqB3sI", sid, kXR_write, fhandle, offset,
                      0, b"\x00\x00\x00", len(data))
    s.sendall(hdr + data)
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
    # dlen==0 -> handle-based truncate; offset carries the size.
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


# =========================================================================== #
# 1. PATH-BASED TRUNCATE matrix: create file of N, truncate to S, verify
#    on-disk size == S and the extended region reads as zeros.
#    (N, S) parametrized; S in {0, 1, N//2, N, N+1000(extend)}.
# =========================================================================== #
_TRUNC_NS = []
for _n in (100, 4096, 10000):
    for _label, _s in (("0", 0), ("1", 1), ("half", _n // 2),
                       ("same", _n), ("ext", _n + 1000)):
        _TRUNC_NS.append((_n, _s, _label))


@pytest.mark.parametrize("n,s,label", _TRUNC_NS)
def test_truncate_path_size_and_zerofill(srv, n, s, label):
    """xrdfs truncate /f S (path-based): on-disk size becomes S exactly; any
    extended region reads back as zeros."""
    wire = uniq(f"trp_{n}_{label}.bin")
    disk = our_disk(srv, wire)
    with open(disk, "wb") as f:
        f.write(det_bytes(n, seed=n))
    rc, o, e = fs(srv["our"], "truncate", wire, str(s))
    assert rc == 0, f"truncate N={n} -> S={s}: {o}{e}"
    assert os.path.getsize(disk) == s, f"on-disk size {os.path.getsize(disk)} != {s}"
    with open(disk, "rb") as f:
        got = f.read()
    if s <= n:
        assert got == det_bytes(n, seed=n)[:s], "kept-prefix bytes corrupted on shrink"
    else:
        assert got[:n] == det_bytes(n, seed=n), "original bytes corrupted on extend"
        assert got[n:] == b"\x00" * (s - n), "extended region is not zero-filled"


# DIFFERENTIAL: extend must succeed identically and be zero-filled on BOTH.
@pytest.mark.parametrize("n,extra", [(100, 900), (4096, 4096), (1, 99999)])
def test_truncate_path_extend_differential(srv, n, extra):
    s = n + extra
    our_w = uniq(f"trpx_our_{n}_{extra}.bin")
    off_w = uniq(f"trpx_off_{n}_{extra}.bin")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "wb") as f:
            f.write(det_bytes(n, seed=1))
    rc_o, o_o, e_o = fs(srv["our"], "truncate", our_w, str(s))
    rc_f, o_f, e_f = fs(srv["off"], "truncate", off_w, str(s))
    assert (rc_o == 0) == (rc_f == 0), \
        f"extend success differs: ours={rc_o} stock={rc_f} {o_o}{e_o}|{o_f}{e_f}"
    if rc_o == 0:
        for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
            with open(disk_for(srv, url, w), "rb") as f:
                b = f.read()
            assert len(b) == s, f"{url} extend size {len(b)} != {s}"
            assert b[:n] == det_bytes(n, seed=1), f"{url} extend corrupted prefix"
            assert b[n:] == b"\x00" * extra, f"{url} extend hole not zero"


# =========================================================================== #
# 2. TRUNCATE via OPEN HANDLE (raw-wire kXR_truncate on an open fhandle), and
#    compare the resulting size to the path-based route.
# =========================================================================== #
@pytest.mark.parametrize("n,s", [(1000, 0), (1000, 1), (1000, 500),
                                 (1000, 1000), (1000, 3000)])
def test_truncate_handle_raw_wire(srv, n, s):
    wire = uniq(f"trh_{n}_{s}.bin")
    disk = our_disk(srv, wire)
    with open(disk, "wb") as f:
        f.write(det_bytes(n, seed=5))
    s_sock = _session(srv["our"])
    try:
        fh = _open_handle(s_sock, wire, kXR_open_updt)
        st, body = _truncate_handle(s_sock, fh, s)
        assert st == kXR_ok, f"handle truncate failed: st={st} err={_err(body)}"
        _close(s_sock, fh)
    finally:
        s_sock.close()
    assert os.path.getsize(disk) == s, f"handle-truncate size {os.path.getsize(disk)} != {s}"
    with open(disk, "rb") as f:
        got = f.read()
    if s <= n:
        assert got == det_bytes(n, seed=5)[:s], "handle-truncate corrupted kept prefix"
    else:
        assert got[n:] == b"\x00" * (s - n), "handle-truncate extend not zero-filled"


def test_truncate_handle_matches_path_route(srv):
    """The OPEN-HANDLE truncate and the PATH truncate must land identical bytes."""
    n, s = 2048, 777
    seed = 9
    h_wire = uniq("trh_cmp_handle.bin")
    p_wire = uniq("trh_cmp_path.bin")
    for w in (h_wire, p_wire):
        with open(our_disk(srv, w), "wb") as f:
            f.write(det_bytes(n, seed=seed))
    # handle route
    s_sock = _session(srv["our"])
    try:
        fh = _open_handle(s_sock, h_wire, kXR_open_updt)
        st, body = _truncate_handle(s_sock, fh, s)
        assert st == kXR_ok, f"handle truncate failed: err={_err(body)}"
        _close(s_sock, fh)
    finally:
        s_sock.close()
    # path route
    assert fs(srv["our"], "truncate", p_wire, str(s))[0] == 0
    with open(our_disk(srv, h_wire), "rb") as a, open(our_disk(srv, p_wire), "rb") as b:
        assert a.read() == b.read(), "handle-route and path-route truncate diverge"


# =========================================================================== #
# 3. TRUNCATE of a nonexistent file -> error category parity vs stock.
# =========================================================================== #
def test_truncate_nonexistent_category(srv):
    def do(url):
        return fs(url, "truncate", uniq("tr_missing_xyz.bin"), "10")
    rc_o, rc_f, cat_o, cat_f, raw = diff_fail(srv, do)
    assert rc_o != 0 and rc_f != 0, f"truncate of missing file must fail:{raw}"
    assert cat_o == cat_f, f"truncate-missing error category differs:{raw}"


def test_truncate_handle_missing_fhandle_rejected(srv):
    """Raw-wire handle truncate on a never-opened fhandle -> kXR_error on both."""
    bogus = b"\x7f\x7f\x7f\x7f"
    cats = {}
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        s_sock = _session(url)
        try:
            st, body = _truncate_handle(s_sock, bogus, 10)
            cats[who] = (st, _err(body))
        finally:
            s_sock.close()
    assert cats["our"][0] == kXR_error, f"our server accepted bogus fhandle: {cats}"
    assert cats["off"][0] == kXR_error, f"stock accepted bogus fhandle: {cats}"


# =========================================================================== #
# 4. TRUNCATE to a HUGE size -> sparse: apparent size correct, allocated blocks
#    small; the far byte reads as zero. Parity vs stock.
# =========================================================================== #
@pytest.mark.parametrize("huge", [16 * 1024 * 1024, 64 * 1024 * 1024])
def test_truncate_sparse_huge(srv, huge):
    our_w = uniq(f"sparse_our_{huge}.bin")
    off_w = uniq(f"sparse_off_{huge}.bin")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "wb") as f:
            f.write(b"AB")        # 2 real bytes, then a giant hole
    rc_o = fs(srv["our"], "truncate", our_w, str(huge))[0]
    rc_f = fs(srv["off"], "truncate", off_w, str(huge))[0]
    assert (rc_o == 0) == (rc_f == 0), f"sparse truncate success differs ours={rc_o} off={rc_f}"
    if rc_o != 0:
        return
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        disk = disk_for(srv, url, w)
        stt = os.stat(disk)
        assert stt.st_size == huge, f"{url} apparent size {stt.st_size} != {huge}"
        # sparse: allocated blocks must be far smaller than the apparent size.
        allocated = stt.st_blocks * 512
        assert allocated < huge // 2, \
            f"{url} file is not sparse: {allocated} bytes allocated for {huge}"
    # the far byte reads as zero through the wire
    s_sock = _session(srv["our"])
    try:
        fh = _open_handle(s_sock, our_w, kXR_open_read)
        st, data = _read(s_sock, fh, huge - 1, 1)
        assert st == kXR_ok and data == b"\x00", \
            f"far sparse byte not zero: st={st} data={data!r}"
        _close(s_sock, fh)
    finally:
        s_sock.close()


# =========================================================================== #
# 5. SPARSE WRITE: write at a large offset into a fresh file -> size==offset+len,
#    bytes before are zero, written bytes correct. Differential vs stock.
# =========================================================================== #
@pytest.mark.parametrize("offset,wlen", [(4096, 16), (100000, 32), (1 << 20, 64)])
def test_sparse_write_at_offset(srv, offset, wlen):
    payload = det_bytes(wlen, seed=42)
    our_w = uniq(f"spw_our_{offset}.bin")
    off_w = uniq(f"spw_off_{offset}.bin")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, w, kXR_new | kXR_open_updt | kXR_delete)
            st, body = _write(s_sock, fh, offset, payload)
            assert st == kXR_ok, f"{url} sparse write failed: err={_err(body)}"
            st, body = _close(s_sock, fh)
            assert st == kXR_ok, f"{url} close failed: err={_err(body)}"
        finally:
            s_sock.close()
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "rb") as f:
            b = f.read()
        assert len(b) == offset + wlen, f"{url} size {len(b)} != {offset + wlen}"
        assert b[:offset] == b"\x00" * offset, f"{url} sparse hole before write not zero"
        assert b[offset:] == payload, f"{url} written bytes wrong"
    # cross-check both servers produced identical files
    with open(our_disk(srv, our_w), "rb") as a, open(off_disk(srv, off_w), "rb") as b:
        assert md5(a.read()) == md5(b.read()), "sparse-write files diverge our vs stock"


# =========================================================================== #
# 6. PARTIAL WRITES: open(new), 3 non-contiguous regions, close -> read back;
#    holes zero, regions correct (md5 vs independently constructed buffer).
# =========================================================================== #
def _build_expected(regions, total):
    buf = bytearray(total)
    for off, data in regions:
        buf[off:off + len(data)] = data
    return bytes(buf)


@pytest.mark.parametrize("idx,regions,total", [
    (0, [(0, det_bytes(10, 1)), (100, det_bytes(20, 2)), (500, det_bytes(30, 3))], 530),
    (1, [(50, det_bytes(64, 4)), (4096, det_bytes(64, 5)), (9000, det_bytes(100, 6))], 9100),
    (2, [(0, det_bytes(1, 7)), (1, det_bytes(1, 8)), (4095, det_bytes(2, 9))], 4097),
])
def test_partial_noncontiguous_writes(srv, idx, regions, total):
    expected = _build_expected(regions, total)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"partial_{who}_{idx}.bin")
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_new | kXR_open_updt | kXR_delete)
            for off, data in regions:
                st, body = _write(s_sock, fh, off, data)
                assert st == kXR_ok, f"{who} write @{off} failed: err={_err(body)}"
            st, body = _close(s_sock, fh)
            assert st == kXR_ok, f"{who} close failed: err={_err(body)}"
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert len(got) == total, f"{who} partial size {len(got)} != {total}"
        assert md5(got) == md5(expected), f"{who} partial-write content mismatch"


# =========================================================================== #
# 7. OVERLAPPING WRITES: write region A then overwrite part of it -> final bytes.
# =========================================================================== #
@pytest.mark.parametrize("idx,a_off,a,b_off,b", [
    (0, 0, det_bytes(100, 1), 40, det_bytes(40, 2)),
    (1, 10, det_bytes(50, 3), 0, det_bytes(30, 4)),
    (2, 4090, det_bytes(20, 5), 4096, det_bytes(20, 6)),
])
def test_overlapping_writes(srv, idx, a_off, a, b_off, b):
    total = max(a_off + len(a), b_off + len(b))
    expected = bytearray(total)
    expected[a_off:a_off + len(a)] = a
    expected[b_off:b_off + len(b)] = b
    expected = bytes(expected)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"overlap_{who}_{idx}.bin")
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s_sock, fh, a_off, a)[0] == kXR_ok, f"{who} write A"
            assert _write(s_sock, fh, b_off, b)[0] == kXR_ok, f"{who} write B"
            assert _close(s_sock, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == expected, f"{who} overlapping-write final bytes wrong"


# =========================================================================== #
# 8. kXR_sync on an open write handle -> rc ok; data durable (read-back on a
#    SECOND handle). Parity vs stock.
# =========================================================================== #
def test_sync_makes_data_durable(srv):
    """write -> sync -> read-back (same handle) proves the synced bytes are
    persisted; then close and a SECOND fresh session must still see them. The
    second reader opens only AFTER the writer closes (stock enforces a single
    writer lock, so a read while the writer holds the file is correctly denied)."""
    payload = det_bytes(8192, seed=11)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"sync_durable_{who}.bin")
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s_sock, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            st, body = _sync(s_sock, fh)
            assert st == kXR_ok, f"{who} sync rc not ok: err={_err(body)}"
            # read-back on the same (writer) handle after the sync
            st, data = _read(s_sock, fh, 0, len(payload))
            assert st == kXR_ok, f"{who} read-after-sync failed"
            assert data == payload, f"{who} sync not durable: same-handle read differs"
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        # writer is closed; a brand-new session must still see the synced bytes
        s2 = _session(url)
        try:
            fh2 = _open_handle(s2, wire, kXR_open_read)
            st, data = _read(s2, fh2, 0, len(payload))
            assert st == kXR_ok, f"{who} reopen-after-close read failed"
            assert data == payload, f"{who} synced data lost after close+reopen"
            _close(s2, fh2)
        finally:
            s2.close()


def test_sync_then_write_then_close_final_content(srv):
    """write -> sync -> write -> close -> final content is the union, correct."""
    a = det_bytes(4096, seed=21)
    b = det_bytes(4096, seed=22)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"sync_seq_{who}.bin")
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s_sock, fh, 0, a)[0] == kXR_ok
            assert _sync(s_sock, fh)[0] == kXR_ok, f"{who} sync"
            assert _write(s_sock, fh, 4096, b)[0] == kXR_ok
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == a + b, f"{who} write-sync-write-close final content wrong"


def test_sync_missing_fhandle_rejected(srv):
    """Raw-wire sync on a never-opened fhandle -> kXR_error on both servers."""
    bogus = b"\x6f\x6f\x6f\x6f"
    res = {}
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        s_sock = _session(url)
        try:
            res[who] = _sync(s_sock, bogus)[0]
        finally:
            s_sock.close()
    assert res["our"] == kXR_error, f"our server accepted sync on bogus fhandle: {res}"
    assert res["off"] == kXR_error, f"stock accepted sync on bogus fhandle: {res}"


# =========================================================================== #
# 9. LARGE-FILE SIZE MATRIX: upload (xrdcp) sizes -> read back byte-identical,
#    on-disk size exact. Parametrized across both servers.
# =========================================================================== #
_SIZES = [0, 1, 512, 4095, 4096, 4097, 1 << 16, 1 << 20, 5 << 20]


@pytest.mark.parametrize("n", _SIZES)
def test_size_matrix_upload_roundtrip_our(srv, tmp_path, n):
    src = make_local(str(tmp_path / f"sm_our_{n}.bin"), n, seed=(n & 0xff))
    wire = uniq(f"sizematrix_our_{n}.bin")
    rc, o, e = cp("-f", src, f"{srv['our']}/{wire}")
    assert rc == 0, f"upload N={n} -> OUR failed: {o}{e}"
    disk = our_disk(srv, wire)
    assert os.path.getsize(disk) == n, f"on-disk size {os.path.getsize(disk)} != {n}"
    dl = str(tmp_path / f"sm_our_dl_{n}.bin")
    rc, o, e = cp("-f", f"{srv['our']}/{wire}", dl)
    assert rc == 0, f"download N={n} from OUR failed: {o}{e}"
    with open(src, "rb") as a, open(dl, "rb") as b:
        assert md5(a.read()) == md5(b.read()), f"N={n} roundtrip integrity mismatch"


@pytest.mark.parametrize("n", _SIZES)
def test_size_matrix_differential_our_vs_stock(srv, tmp_path, n):
    """Same source uploaded to BOTH servers; downloaded copies must be identical
    and match the source byte-for-byte."""
    src = make_local(str(tmp_path / f"sm_diff_{n}.bin"), n, seed=((n + 1) & 0xff))
    our_w = uniq(f"sizematrix_diff_our_{n}.bin")
    off_w = uniq(f"sizematrix_diff_off_{n}.bin")
    assert cp("-f", src, f"{srv['our']}/{our_w}")[0] == 0, f"upload our N={n}"
    assert cp("-f", src, f"{srv['off']}/{off_w}")[0] == 0, f"upload off N={n}"
    assert os.path.getsize(our_disk(srv, our_w)) == n
    assert os.path.getsize(off_disk(srv, off_w)) == n
    a = str(tmp_path / f"sm_diff_dl_our_{n}.bin")
    b = str(tmp_path / f"sm_diff_dl_off_{n}.bin")
    assert cp("-f", f"{srv['our']}/{our_w}", a)[0] == 0
    assert cp("-f", f"{srv['off']}/{off_w}", b)[0] == 0
    with open(src, "rb") as fs_, open(a, "rb") as fa, open(b, "rb") as fb:
        want, ga, gb = md5(fs_.read()), md5(fa.read()), md5(fb.read())
    assert ga == want, f"N={n}: OUR roundtrip differs from source"
    assert gb == want, f"N={n}: STOCK roundtrip differs from source"
    assert ga == gb, f"N={n}: OUR vs STOCK downloads differ"


# =========================================================================== #
# 10. TRUNCATE big1m down to a small prefix -> only the kept prefix remains.
# =========================================================================== #
@pytest.mark.parametrize("keep", [0, 1, 4096, 100000])
def test_truncate_big_down_prefix(srv, keep):
    src = det_bytes(1 << 20, seed=7)        # mirrors make_rich_tree big1m.bin seed
    our_w = uniq(f"bigtrunc_our_{keep}.bin")
    off_w = uniq(f"bigtrunc_off_{keep}.bin")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "wb") as f:
            f.write(src)
    assert fs(srv["our"], "truncate", our_w, str(keep))[0] == 0, "our shrink"
    assert fs(srv["off"], "truncate", off_w, str(keep))[0] == 0, "off shrink"
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "rb") as f:
            got = f.read()
        assert got == src[:keep], f"{url} big-shrink kept wrong prefix (keep={keep})"


# =========================================================================== #
# 11. APPEND-STYLE: open(update) existing, write at offset==size -> grows file.
# =========================================================================== #
@pytest.mark.parametrize("base_n,app_n", [(100, 50), (4096, 4096), (1, 9999)])
def test_append_at_eof_grows(srv, base_n, app_n):
    base = det_bytes(base_n, seed=31)
    app = det_bytes(app_n, seed=32)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"append_{who}_{base_n}_{app_n}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_open_updt)
            st, body = _write(s_sock, fh, base_n, app)
            assert st == kXR_ok, f"{who} append write failed: err={_err(body)}"
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert len(got) == base_n + app_n, f"{who} append size wrong"
        assert got == base + app, f"{who} append content wrong"


# =========================================================================== #
# 12. READ AFTER TRUNCATE-EXTEND: bytes in [oldsize,newsize) are zero on BOTH.
# =========================================================================== #
@pytest.mark.parametrize("old,new", [(100, 4096), (4096, 8192), (1, 65536)])
def test_read_after_extend_zero_region(srv, old, new):
    base = det_bytes(old, seed=41)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"extread_{who}_{old}_{new}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        assert fs(url, "truncate", wire, str(new))[0] == 0, f"{who} extend"
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_open_read)
            st, data = _read(s_sock, fh, old, new - old)
            assert st == kXR_ok, f"{who} read extended region failed"
            assert data == b"\x00" * (new - old), \
                f"{who} extended [old,new) region not zero"
            _close(s_sock, fh)
        finally:
            s_sock.close()


# =========================================================================== #
# 13. ZERO-LENGTH WRITE -> no-op; size unchanged; rc ok parity.
# =========================================================================== #
def test_zero_length_write_is_noop(srv):
    base = det_bytes(256, seed=51)
    res = {}
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"zerowrite_{who}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_open_updt)
            st, body = _write(s_sock, fh, 128, b"")
            res[who] = st
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            assert f.read() == base, f"{who} zero-length write changed content/size"
    assert (res["our"] == kXR_ok) == (res["off"] == kXR_ok), \
        f"zero-length write rc parity differs: {res}"


# =========================================================================== #
# 14. WRITE PAST a truncated-shrunk file then read -> correct (re-grow via write).
# =========================================================================== #
@pytest.mark.parametrize("idx,shrink_to,write_off,wlen", [
    (0, 10, 100, 16),
    (1, 0, 4096, 32),
    (2, 50, 50, 64),
])
def test_write_past_shrunk_file(srv, idx, shrink_to, write_off, wlen):
    base = det_bytes(200, seed=61)
    payload = det_bytes(wlen, seed=62)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"shrinkwrite_{who}_{idx}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        # shrink first (path-based), then write past the new EOF
        assert fs(url, "truncate", wire, str(shrink_to))[0] == 0, f"{who} shrink"
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_open_updt)
            st, body = _write(s_sock, fh, write_off, payload)
            assert st == kXR_ok, f"{who} write past shrunk failed: err={_err(body)}"
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        # expected: kept prefix [0,shrink_to), zeros up to write_off, payload
        expected = bytearray(max(shrink_to, write_off + wlen))
        expected[0:shrink_to] = base[:shrink_to]
        expected[write_off:write_off + wlen] = payload
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == bytes(expected), f"{who} write-past-shrunk content wrong"


# =========================================================================== #
# 15. EXTEND-then-SHRINK round trip leaves exact prefix (extra coverage).
# =========================================================================== #
@pytest.mark.parametrize("n,up,down", [(100, 5000, 50), (4096, 1 << 20, 4096)])
def test_extend_then_shrink_roundtrip(srv, n, up, down):
    base = det_bytes(n, seed=71)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"extshrink_{who}_{n}_{up}_{down}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        assert fs(url, "truncate", wire, str(up))[0] == 0, f"{who} extend"
        assert os.path.getsize(disk_for(srv, url, wire)) == up
        assert fs(url, "truncate", wire, str(down))[0] == 0, f"{who} shrink"
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert len(got) == down, f"{who} ext-shrink size wrong"
        assert got == base[:down], f"{who} ext-shrink prefix corrupted"
