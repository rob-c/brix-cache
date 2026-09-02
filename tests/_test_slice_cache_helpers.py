"""
tests/test_slice_cache.py — Phase 26 slice-granular caching tests.

Two layers:

  * TestSliceLibrary — compiles and runs the standalone C unit tests for the
    shared slice library (src/fs/cache/slice.c) against the real build objects.
    This is the LANDED foundation (Phase 26 Step A) and runs with no server.

  * TestSliceCacheIntegration — end-to-end coverage of slice serving over the
    WebDAV and stream planes.  These are SKIPPED until the read-time slice
    serving path (Steps C/D) is wired into the cache open/VFS layer; the doc's
    original C/D design predates the current open-time/whole-file/VFS cache
    architecture and needs a redesign + a healthy origin+cache test env to
    validate.  The cases are kept here as the executable spec for that work.
"""

import glob
import os
import socket
import struct
import subprocess
import time

import pytest

from cmdscripts import c_object_units
from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN



def _guard_cached_1(on_disk, obj, bs, wholes, fields, slices):
    if not (fields["flags"] & _CINFO_F_COMPLETE) \
       and on_disk > sum(slices.values()) + bs:
        wholes.append(obj)


pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-slice-cache")]

_HERE = os.path.dirname(__file__)
_OBJS = os.environ.get("TEST_NGINX_OBJS", "/tmp/nginx-1.28.3/objs")
_NGINX = os.environ.get("TEST_NGINX_BIN", os.path.join(_OBJS, "nginx"))

_SLICE = 1024 * 1024
_NSLICES = 16
_FILESIZE = _SLICE * _NSLICES
_SLICE_DEFERRED = ("superseded phase-26 protocol-plane spec — the shipped "
                   "slice cache lives in the VFS decorator "
                   "(sd_cache_partial.c); see test_cache_partial_fill.py for "
                   "the live coverage")

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed (%d/%d bytes)" % (len(buf), n))
        buf += chunk
    return buf


def _resp(sock):
    hdr = _recvn(sock, 8)
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    return status, (_recvn(sock, dlen) if dlen else b"")


def _session(host, port):
    sock = socket.create_connection((host, port), timeout=15)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))   # client handshake
    _recvn(sock, 16)                                         # handshake reply
    sock.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", _kXR_login,
                             os.getpid() & 0xffffffff, b"\x00" * 8, 0, 0, 0, 0, 0))
    status, body = _resp(sock)
    assert status == _kXR_ok, "login failed: status=%d %r" % (status, body)
    return sock


def _open_read(sock, path):
    p = path.encode()
    req = struct.pack("!2sHHH2s6s4sI", b"\x00\x02", _kXR_open, 0o644,
                      _kXR_open_read, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p)) + p
    sock.sendall(req)
    status, body = _resp(sock)
    assert status == _kXR_ok, "open %s failed: status=%d %r" % (path, status, body)
    return body[:4]            # fhandle


def _read(sock, fhandle, offset, length, deadline=30.0):
    """A single kXR_read; transparently retries on kXR_wait (the async slice
    fill in progress) until the data arrives or `deadline` seconds elapse, and
    stitches kXR_oksofar continuation frames."""
    end = time.time() + deadline
    while time.time() < end:
        sock.sendall(struct.pack("!2sH4sqiI", b"\x00\x06", _kXR_read, fhandle,
                                 offset, length, 0))
        status, body = _resp(sock)
        if status == _kXR_wait:
            # Ignore the server-suggested delay: on loopback a 1 MiB slice
            # fill lands in milliseconds, and honoring a whole advertised
            # second per slice turns a 16-slice read into ~16 s of idling.
            # A herd-polite backoff protects a shared production cache, not
            # a single-client test against its own private instance.
            time.sleep(0.05)
            continue
        if status in (_kXR_ok, _kXR_oksofar):
            data = body
            while status == _kXR_oksofar:
                status, more = _resp(sock)
                data += more
            return data
        raise AssertionError("read off=%d len=%d failed: status=%d %r"
                             % (offset, length, status, body))
    raise AssertionError("read off=%d len=%d still waiting after %ss "
                         "(slice fill never completed)" % (offset, length, deadline))


@pytest.fixture
def xcache(lifecycle, tmp_path_factory):
    """An ORIGIN data server + a CACHE server in 1 MiB slice mode in front of it."""
    base = str(tmp_path_factory.mktemp("xcache"))
    origin_data = os.path.join(base, "origin_data")
    cache_root = os.path.join(base, "cache_root")
    for d in (origin_data, cache_root):
        os.makedirs(d, exist_ok=True)

    origin = lifecycle.start(NginxInstanceSpec(
        name="lc-slice-cache-origin",
        template="nginx_slice_cache_origin.conf",
        protocol="root",
        readiness="tcp",
        data_root=origin_data,
        reason="Slice-cache origin data server.",
    ))
    cache = lifecycle.start(NginxInstanceSpec(
        name="lc-slice-cache-node",
        template="nginx_slice_cache_cache.conf",
        protocol="root",
        readiness="tcp",
        template_values={"ORIGIN_PORT": origin.port, "CACHE_DIR": cache_root},
        reason="Slice-cache node (1 MiB slice mode) in front of the origin.",
    ))
    return {"host": HOST, "port": cache.port,
            "origin_data": origin_data, "cache_root": cache_root}


def _seed(xc, name, size=_FILESIZE):
    """Write `size` random bytes to the origin under `name`; return the bytes.
    Random content makes every slice unique, so a mis-offset read is caught and
    each test's file is independent in the cache."""
    data = os.urandom(size)
    with open(os.path.join(xc["origin_data"], name), "wb") as f:
        f.write(data)
    return data


def _cached(xc, name):
    """Inspect cache_root for `name` under the phase-64 sd_cache on-disk format:
    ONE SPARSE object file named exactly `name` (filesystem holes for the slices
    not yet fetched) plus a `<name>.cinfo` present-bitmap sidecar — the old
    per-slice `<name>.__xrds_<k>_<idx>` files are gone.

    Returns (slices, wholes, metas) with the SAME contract the assertions expect:
      slices : {slice-index -> logical slice size} for each block the .cinfo
               bitmap records present (last slice clamped to the remainder),
      wholes : [] for a correctly SPARSE object; [obj] only if a PARTIAL object is
               materialized full on disk (a genuine whole-file copy — the
               invariant these tests guard). A COMPLETE file is legitimately full,
               so it is NOT a whole-file copy,
      metas  : the `.cinfo` sidecar list (the file-level record)."""
    root = xc["cache_root"]
    metas = glob.glob(os.path.join(root, "**", name + ".cinfo"), recursive=True)
    objs = [f for f in glob.glob(os.path.join(root, "**", name), recursive=True)
            if os.path.isfile(f)]
    slices = {}
    wholes = []
    ci = _read_cinfo(xc, name)
    for obj in objs:
        st = os.stat(obj)
        on_disk = st.st_blocks * 512               # bytes actually allocated
        if ci is None:
            wholes.append(obj)                     # object with no bitmap == blob
            continue
        fields, present = ci
        bs = fields["block_size"]
        for idx in present:
            slices[idx] = min(bs, fields["size"] - idx * bs)
        # Sparse invariant: a PARTIAL object must hold ~ only its present slices on
        # disk, never the whole apparent file. Allow one slice of slack.
        _guard_cached_1(on_disk, obj, bs, wholes, fields, slices)
    return slices, wholes, metas


def _slice_bytes(xc, name, idx):
    """Read slice `idx`'s bytes from the sparse cache object (the slice must be
    present, else the read returns hole zeros)."""
    matches = [f for f in glob.glob(os.path.join(xc["cache_root"], "**", name),
                                    recursive=True) if os.path.isfile(f)]
    assert matches, "cache object %s not on disk" % name
    with open(matches[0], "rb") as f:
        f.seek(idx * _SLICE)
        return f.read(_SLICE)


@pytest.mark.xfail(reason=_SLICE_DEFERRED, strict=False)

def _read_cinfo(xc, name):
    """Parse "<cache_root>/.../<name>.cinfo": return (fields, present_set) where
    fields has magic/version/flags/block_size/size/nblocks and present_set is the
    set of block indices whose bit is 1. None if the sidecar is absent.

    The bitmap is the LAST ceil(nblocks/8) bytes of the file (the store truncates
    to header+bitmap), so we never need to hardcode the header size."""
    matches = glob.glob(os.path.join(xc["cache_root"], "**", name + ".cinfo"),
                        recursive=True)
    if not matches:
        return None
    with open(matches[0], "rb") as f:
        blob = f.read()
    magic = struct.unpack_from("<I", blob, 0)[0]
    version = struct.unpack_from("<H", blob, 4)[0]
    flags = struct.unpack_from("<H", blob, 6)[0]
    block_size = struct.unpack_from("<I", blob, 8)[0]
    size = struct.unpack_from("<Q", blob, 16)[0]
    nblocks = struct.unpack_from("<Q", blob, 32)[0]
    blen = (nblocks + 7) // 8
    bitmap = blob[len(blob) - blen:] if blen else b""
    present = {i for i in range(nblocks)
               if (bitmap[i >> 3] >> (i & 7)) & 1}
    fields = {"magic": magic, "version": version, "flags": flags,
              "block_size": block_size, "size": size, "nblocks": nblocks}
    return fields, present


_CINFO_MAGIC = 0x58434931
_CINFO_F_COMPLETE = 0x1
_CINFO_F_PARTIAL = 0x2


def _wait_cinfo(xc, name, want_block, timeout=8.0):
    """Poll until the .cinfo for `name` exists and records `want_block` present
    (the fill thread writes the bitmap just after the slice file lands, so it can
    lag the client read by a moment); return (fields, present_set)."""
    end = time.time() + timeout
    grace = time.time() + 2.0
    last = None
    while time.time() < end:
        last = _read_cinfo(xc, name)
        if last is not None and want_block in last[1]:
            return last
        if last is None and time.time() >= grace:
            # No sidecar AT ALL after the grace window: the store never began
            # a fill, so the full timeout (meant for a bitmap write lagging a
            # completed read) buys nothing but idle seconds.
            break
        time.sleep(0.1)
    raise AssertionError("cinfo for %s never recorded block %d (got %r)"
                         % (name, want_block, last))
