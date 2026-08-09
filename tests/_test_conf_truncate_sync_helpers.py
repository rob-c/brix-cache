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

def _build_expected(regions, total):
    buf = bytearray(total)
    for off, data in regions:
        buf[off:off + len(data)] = data
    return bytes(buf)
