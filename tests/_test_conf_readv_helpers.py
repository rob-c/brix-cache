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

def _multi_chunks(n, size=200, span=65000):
    """n evenly-spaced (offset, len) chunks within `span` bytes."""
    step = max(1, span // n)
    return [((i * step) % (span - size), size) for i in range(n)]

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

def _iov_max(srv):
    """Both servers' advertised readv_iov_max (the cap). Asserts they agree."""
    rc, out_o, _ = L.run([L.OFF_XRDFS, srv["our"], "query", "config", "readv_iov_max"])
    rc2, out_f, _ = L.run([L.OFF_XRDFS, srv["off"], "query", "config", "readv_iov_max"])
    vo = int(out_o.split()[0]) if rc == 0 and out_o.split() else READV_MAXSEGS
    vf = int(out_f.split()[0]) if rc2 == 0 and out_f.split() else READV_MAXSEGS
    return vo, vf



def _equal_segments(total, n):
    base = total // n
    plan = []
    off = 0
    for i in range(n):
        ln = base if i < n - 1 else (total - off)
        plan.append((off, ln))
        off += ln
    return plan

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
