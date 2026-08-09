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
