"""Differential conformance for kXR_statx, stat-by-HANDLE vs PATH, statvfs/vfs,
and stat metadata-field precision — pinned to the STOCK XRootD reference.

Where the stock xrdfs client exposes the op (stat-by-path, statvfs) we diff
OUR-vs-STOCK through `xrdfs`. The ops xrdfs cannot reach cleanly (kXR_statx
multi-path flag bytes, stat-by-fhandle, raw kXR_vfs) are driven over RAW WIRE
against BOTH servers, with the SEMANTICS taken from the C++ reference
(/tmp/brix-src/src):

  XProtocol.hh:1261  kXR_file=0  kXR_xset=1  kXR_isDir=2  kXR_other=4
                     kXR_offline=8  kXR_readable=16  kXR_writable=32
  XrdXrootdXeq.cc do_Statx  — one flag byte per NEWLINE-separated request path;
                     on the FIRST path that fails stat() the whole reply is a
                     single kXR_error (early return), NOT a per-path flag.
  XrdXrootdXeq.cc do_Stat   — when !dlen the request refers to an OPEN FILE
                     HANDLE (fstat), else it stats the path; kXR_vfs (options
                     bit, XProtocol.hh:799) yields the statfs body, not a stat
                     line.

Philosophy (per the maintainer): any divergence — wrong number of statx flag
bytes, wrong bit, handle-stat != path-stat, statvfs field-count, flag mismatch
vs stock — is a BUG IN OUR SERVER. The stock server is the oracle.

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisioning; the whole
module skips without the stock xrootd toolchain.
"""

import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs not installed")]

OUR_PORT = L.worker_port(14030)
OFF_PORT = L.worker_port(14031)
# --------------------------------------------------------------------------- #
# wire constants (XProtocol.hh)
# --------------------------------------------------------------------------- #
kXR_login, kXR_open, kXR_read = 3007, 3010, 3013
kXR_stat, kXR_set, kXR_write = 3017, 3018, 3019
kXR_statx, kXR_close = 3022, 3003
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003

# stat flag bits (XProtocol.hh:1261-1268)
kXR_file, kXR_xset, kXR_isDir, kXR_other = 0, 1, 2, 4
kXR_offline, kXR_readable, kXR_writable = 8, 16, 32

# stat options (XProtocol.hh:799)
kXR_vfs = 1

# open options (XProtocol.hh:483-505)
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_new = 0x0008
kXR_delete = 0x0002
kXR_mkpath = 0x0100

# error codes (XProtocol.hh:1030+)
kXR_FileNotOpen, kXR_NotFound = 3004, 3011


# --------------------------------------------------------------------------- #
# Fixture — our + stock server on byte-identical rich trees
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confstatx"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair launch failed: {e}")
    # Raw-wire client ports: start_pair already sets these to the fleet ports it
    # attached to; keep them (the module OUR_PORT/OFF_PORT are legacy worker-shift
    # values that no longer point at a live server).
    ctx.setdefault("our_port", L.worker_port(14068))   # per-worker (was shared 20003)
    ctx.setdefault("off_port", L.worker_port(14069))
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# raw-wire client — minimal, mirrors test_brix_conformance.py framing but is
# port-parametric so the same probe runs against our server and the stock one.
# --------------------------------------------------------------------------- #
def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("connection closed mid-frame")
        b += c
    return b


def _resp(s):
    """Read one response frame -> (streamid, status, body)."""
    h = _recv_exact(s, 8)
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    return sid, status, (_recv_exact(s, dlen) if dlen else b"")


def _err(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _connect(port):
    s = socket.create_connection((L.BIND, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))  # handshake
    _, st, _ = _resp(s)
    assert st == kXR_ok, "handshake reply not kXR_ok"
    return s


def _login(s, sid=b"\x00\x01"):
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, b"cstx\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(port):
    s = _connect(port)
    _login(s)
    return s


def _statx(s, paths, sid=b"\x00\x12"):
    """kXR_statx: NEWLINE-joined request paths (XProtocol.hh / do_Statx)."""
    p = "\n".join(paths).encode()
    s.sendall(struct.pack("!2sH16sI", sid, kXR_statx, b"\x00" * 16, len(p)) + p)
    return _resp(s)


def _stat_path(s, path, options=0, sid=b"\x00\x02"):
    """kXR_stat by PATH (dlen>0).

    ClientStatRequest: streamid[2] reqid[2] options[1] reserved[7] wants[4]
                       fhandle[4] dlen[4]  (XProtocol.hh:806)
    """
    p = path.encode()
    hdr = struct.pack("!2sHB7sI4sI", sid, kXR_stat, options, b"\x00" * 7,
                      0, b"\x00" * 4, len(p))
    s.sendall(hdr + p)
    return _resp(s)


def _stat_handle(s, fhandle, options=0, sid=b"\x00\x03"):
    """kXR_stat by HANDLE (dlen==0): the request refers to an open file (fstat).

    Same struct, but the fhandle field carries the handle and dlen==0.
    """
    hdr = struct.pack("!2sHB7sI4sI", sid, kXR_stat, options, b"\x00" * 7,
                      0, fhandle, 0)
    s.sendall(hdr)
    return _resp(s)


def _open(s, path, options=kXR_open_read, mode=0o644, sid=b"\x00\x04"):
    """kXR_open: ClientOpenRequest streamid[2] reqid[2] mode[2] options[2]
       optiont[2] reserved[6] fhtemplt[4] dlen[4] (XProtocol.hh)."""
    p = path.encode()
    hdr = struct.pack("!2sHHHH6s4sI", sid, kXR_open, mode, options, 0,
                      b"\x00" * 6, b"\x00" * 4, len(p))
    s.sendall(hdr + p)
    return _resp(s)


def _write(s, fhandle, offset, data, sid=b"\x00\x05"):
    """kXR_write: streamid[2] reqid[2] fhandle[4] offset[8] pathid[1]
       reserved[3] dlen[4] (XProtocol.hh ClientWriteRequest)."""
    hdr = struct.pack("!2sH4sqB3sI", sid, kXR_write, fhandle, offset, 0,
                      b"\x00" * 3, len(data))
    s.sendall(hdr + data)
    return _resp(s)


def _close(s, fhandle, sid=b"\x00\x0e"):
    s.sendall(struct.pack("!2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0))
    try:
        return _resp(s)
    except EOFError:
        return None, kXR_ok, b""


def _open_handle(s, path, options=kXR_open_read):
    """Open and return the 4-byte file handle (ServerResponseBody_Open)."""
    st, body = _open(s, path, options=options)[1:]
    assert st == kXR_ok, f"open {path} failed (status={st}, err={_err(body)})"
    assert len(body) >= 4, f"open reply too short: {len(body)} bytes"
    return body[0:4]


def _stat_fields(body):
    """Parse a StatGen reply 'id size flags mtime' -> list[int-ish str]."""
    return body.rstrip(b"\x00").decode("ascii", "replace").split()


def _statx_both(srv, paths):
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, paths)[1:]
        fst, fbody = _statx(f, paths)[1:]
        return (ost, obody), (fst, fbody)
    finally:
        o.close(); f.close()


# --------------------------------------------------------------------------- #
# xrdfs runner (stock client) for the ops xrdfs reaches cleanly
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def _statf(out):
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
    return d


def _stat_both(srv, path):
    o = _statf(fs(srv["our"], "stat", path)[1])
    f = _statf(fs(srv["off"], "stat", path)[1])
    return o, f


# =========================================================================== #
# kXR_statx — SINGLE file path -> exactly ONE flag byte, NOT a directory.
# Reference: a regular file yields kXR_file(0); the isDir bit must be clear.
# =========================================================================== #
