"""
Helpers for the read-cache partial-fill suite: stand up a composable cache node
in front of a modular backend, issue precise raw-wire kXR_read ranges, and read
back cache residency via client/bin/xrdcinfo.

Reuses the raw-wire request builders from _test_a_robustness_helpers so the wire
format stays single-sourced. See
docs/superpowers/specs/2026-07-01-read-cache-partial-fill-tests-design.md.
"""
import json
import os
import socket
import struct
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST
from server_registry import NginxInstanceSpec
from _test_a_robustness_helpers import (
    make_protocol_req, make_login_req, make_open_req, make_read_req,
    make_close_req,
)

# Module-level marker so the phase-81 registry lint treats this helper (imported
# by test_cache_partial_fill.py) as registry-driven; harmless in a non-test
# module.
pytestmark = pytest.mark.uses_lifecycle_harness

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCINFO = os.path.join(REPO, "client", "bin", "xrdcinfo")

# Stable registry names for the throwaway cache/origin instances.  Each test owns
# its own function-scoped `lifecycle` harness whose close() stops+unregisters
# them, so reusing fixed names across the (serial) suite never collides.
ORIGIN_NAME = "lc-cache-partial-origin"
CACHE_NAME = "lc-cache-partial-cache"


class CacheNode:
    """A registry-driven cache node (plus its root:// origin for the xroot
    backend), holding the LifecycleHarness so teardown stays with the owning
    test."""

    def __init__(self, lifecycle, cache_port, store_dir, backend, backend_port,
                 *, names, origin_name):
        self._lc = lifecycle              # LifecycleHarness owned by the test
        self._names = names               # instance names to stop, cache first
        self._origin_name = origin_name   # root:// origin instance, or None
        self.cache_port = cache_port
        self.store_dir = store_dir
        self.backend = backend            # "xroot" | "posix" | "pblock" | ...
        self.backend_port = backend_port  # origin port (xroot) or None
        self.backend_data = ""            # dir seeded by seed_origin (posix)
        self.seed_mode = "posix"          # "posix" (raw write) | "pblock" (xrdcp)
        self.seed_port = None             # root:// port to xrdcp pblock seeds to

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        stop_node(self)
        return False


def _optline(directive, value, indent="        "):
    """Render an optional cache directive line, or "" when unset — so a template
    placeholder for a directive that is not configured collapses to nothing."""
    return f"{indent}{directive} {value};\n" if value else ""


def make_cache_node(backend, *, tmp, lifecycle, slice_size=None, max_file_size=None,
                    max_object=None, deny_prefix=None, include_regex=None,
                    origin_backend="posix"):
    """Start a cache node in front of `backend` through the registry lifecycle
    harness, returning a CacheNode.

    Two proven config styles (mirror tests/run_root_slice_fill.sh and
    tests/run_cache_backend_source.sh):
      * backend == 'xroot' -> tier grammar over a root:// origin
        (brix_storage_backend root:// + brix_cache_store posix:<dir> +
        brix_cache_slice_size): sparse partial fill via the composed sd_cache
        (§14: the legacy cache_origin/cache_slice model is retired). The origin
        serves posix or pblock (origin_backend); the cached object + .cinfo land
        under the cache dir; seed_origin writes into the ORIGIN's root.
      * other backends -> the same tier grammar over a LOCAL backend
        (posix/pblock): slice_size>0 partial-fills, else whole-file;
        seed_origin writes into the backend's own dir.
    """
    base = str(tmp)

    if backend == "xroot":
        origin_root = os.path.join(base, "origin")
        cache_dir = os.path.join(base, "cache")
        export = os.path.join(base, "export")
        for d in (origin_root, cache_dir, export):
            os.makedirs(d, exist_ok=True)
        # posix origin uses brix_export (the proven run_root_slice_fill.sh config);
        # pblock origin uses the pblock backend + write capability (its seed goes
        # in via xrdcp).
        if origin_backend == "pblock":
            origin_storage = f"brix_storage_backend pblock://{origin_root}/;"
            origin_allow_write = ("        brix_allow_write on;"
                                  " brix_upload_resume off;\n")
        else:
            origin_storage = f"brix_export {origin_root};"
            origin_allow_write = ""
        origin_ep = lifecycle.start(NginxInstanceSpec(
            name=ORIGIN_NAME,
            template="nginx_lc_cache_partial_origin.conf",
            protocol="root",
            data_root=origin_root,
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_STORAGE": origin_storage,
                "ORIGIN_ALLOW_WRITE": origin_allow_write,
            },
            reason="cache partial-fill root:// origin"))
        backend_port = origin_ep.port

        cache_ep = lifecycle.start(NginxInstanceSpec(
            name=CACHE_NAME,
            template="nginx_lc_cache_partial_cache.conf",
            protocol="root",
            data_root=cache_dir,
            template_values={
                "BIND_HOST": BIND_HOST,
                "CACHE_ALLOW_WRITE": "",
                "CACHE_EXPORT": f"        brix_export {export};\n",
                "CACHE_BACKEND": f"root://{HOST}:{backend_port}",
                "CACHE_STORE": cache_dir,
                "CACHE_SLICE_SIZE": _optline("brix_cache_slice_size", slice_size),
                "CACHE_MAX_OBJECT": _optline("brix_cache_max_object", max_file_size),
                "CACHE_DENY_PREFIX": _optline("brix_cache_deny_prefix", deny_prefix),
                "CACHE_INCLUDE_REGEX": _optline("brix_cache_include_regex", include_regex),
            },
            reason="cache partial-fill xroot cache node"))
        node = CacheNode(lifecycle, cache_ep.port, cache_dir, backend, backend_port,
                         names=[CACHE_NAME, ORIGIN_NAME], origin_name=ORIGIN_NAME)
        node.backend_data = origin_root
        node.seed_mode = origin_backend          # posix -> raw; pblock -> xrdcp
        node.seed_port = backend_port            # seed writes go to the origin
        return node

    if backend == "http":
        # A local nginx HTTP static origin (plain file server) behind an http://
        # storage backend: whole-file fill through the composable sd_cache. The
        # test seeds files into the origin's doc root and reads them back through
        # the cache node.
        doc_root = os.path.join(base, "http-origin")
        cache_dir = os.path.join(base, "cache")
        for d in (doc_root, cache_dir):
            os.makedirs(d, exist_ok=True)
        origin_ep = lifecycle.start(NginxInstanceSpec(
            name=ORIGIN_NAME,
            template="nginx_lc_cache_partial_http_origin.conf",
            protocol="http",
            data_root=doc_root,
            template_values={"BIND_HOST": BIND_HOST},
            reason="cache partial-fill http:// origin"))
        backend_port = origin_ep.port

        cache_ep = lifecycle.start(NginxInstanceSpec(
            name=CACHE_NAME,
            template="nginx_lc_cache_partial_cache.conf",
            protocol="root",
            data_root=cache_dir,
            template_values={
                "BIND_HOST": BIND_HOST,
                "CACHE_ALLOW_WRITE": "",
                "CACHE_EXPORT": "",
                "CACHE_BACKEND": f"http://{HOST}:{backend_port}",
                "CACHE_STORE": cache_dir,
                "CACHE_SLICE_SIZE": _optline("brix_cache_slice_size", slice_size),
                "CACHE_MAX_OBJECT": _optline("brix_cache_max_object", max_file_size),
                "CACHE_DENY_PREFIX": _optline("brix_cache_deny_prefix", deny_prefix),
                "CACHE_INCLUDE_REGEX": _optline("brix_cache_include_regex", include_regex),
            },
            reason="cache partial-fill http cache node"))
        node = CacheNode(lifecycle, cache_ep.port, cache_dir, backend, backend_port,
                         names=[CACHE_NAME, ORIGIN_NAME], origin_name=ORIGIN_NAME)
        node.backend_data = doc_root
        node.seed_mode = "posix"          # raw file write into the http doc root
        node.seed_port = None
        return node

    # ---- composable whole-file path (posix/pblock/root backend) -----------
    # backend == 'root' fills from a root:// origin through fetch.c (the origin
    # fetch spine; posix/pblock fill through the local cstore path (max_object
    # gate).
    bdir = os.path.join(base, "backend")
    store = os.path.join(base, "store")
    for d in (bdir, store):
        os.makedirs(d, exist_ok=True)
    drv = {"posix": f"posix:{bdir}", "pblock": f"pblock://{bdir}/"}.get(backend)
    if drv is None:
        raise RuntimeError(f"gated backend {backend} must be caller-skipped")
    cache_ep = lifecycle.start(NginxInstanceSpec(
        name=CACHE_NAME,
        template="nginx_lc_cache_partial_cache.conf",
        protocol="root",
        data_root=store,
        template_values={
            "BIND_HOST": BIND_HOST,
            "CACHE_ALLOW_WRITE": "        brix_allow_write on; brix_upload_resume off;\n",
            "CACHE_EXPORT": "",
            "CACHE_BACKEND": drv,
            "CACHE_STORE": store,
            "CACHE_SLICE_SIZE": _optline("brix_cache_slice_size", slice_size),
            "CACHE_MAX_OBJECT": _optline("brix_cache_max_object", max_object),
            "CACHE_DENY_PREFIX": _optline("brix_cache_deny_prefix", deny_prefix),
            "CACHE_INCLUDE_REGEX": _optline("brix_cache_include_regex", include_regex),
        },
        reason="cache partial-fill local backend cache node"))
    node = CacheNode(lifecycle, cache_ep.port, store, backend, None,
                     names=[CACHE_NAME], origin_name=None)
    node.backend_data = bdir
    node.seed_mode = backend                  # posix -> raw; pblock -> xrdcp
    node.seed_port = cache_ep.port            # seed writes go through the backend
    return node


def stop_node(node):
    """Stop every registry instance the node owns (cache first, then origin)."""
    for name in node._names:
        node._lc.stop(name)


def kill_origin(node, timeout=5.0):
    """Stop the root:// origin and block until its port stops accepting — a
    deterministic backend-offline for the behavioral tests."""
    if node._origin_name is None:
        return
    node._lc.stop(node._origin_name)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, node.backend_port), timeout=0.5):
                time.sleep(0.1)
        except OSError:
            return                                 # port is down
    raise RuntimeError(f"origin on {node.backend_port} did not go down")


XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")


def seed_origin(node, path, size):
    """Write a deterministic byte pattern of `size` into the backend/origin at
    `path`, returning the bytes so tests can byte-check served ranges.

    posix targets get a direct file write (fast); pblock targets are written
    THROUGH the root:// server (xrdcp) so the pblock catalog stores a valid
    object (a raw file in a pblock dir is not a readable pblock object)."""
    data = bytes((i * 131 + 7) & 0xFF for i in range(size))
    if node.seed_mode == "pblock":
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            src = tf.name
        try:
            url = f"root://{HOST}:{node.seed_port}/{path}"
            p = subprocess.run([XRDCP, "-f", src, url],
                               capture_output=True, text=True, timeout=60)
            if p.returncode != 0:
                raise RuntimeError(f"pblock seed via xrdcp failed: {p.stderr[-400:]}")
        finally:
            os.unlink(src)
    else:
        dst = os.path.join(node.backend_data, path.lstrip("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data)
    return data


# ---- raw-wire session + range read (reuses _test_a_robustness_helpers) -----

def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"socket closed, {n - len(buf)} bytes short")
        buf += chunk
    return buf


def _read_frame(s):
    hdr = _recv_exact(s, 8)
    _sid, status, dlen = struct.unpack(">2sHI", hdr)
    body = _recv_exact(s, dlen) if dlen else b""
    return status, body


def _session(port):
    s = socket.create_connection((HOST, port), timeout=5)
    s.settimeout(5)
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))   # 20-byte handshake
    _recv_exact(s, 16)                                    # server hello
    s.sendall(make_protocol_req())
    _read_frame(s)
    s.sendall(make_login_req())
    _read_frame(s)
    return s


READ_CHUNK = 1024 * 1024   # per-kXR_read ceiling (real clients chunk; a single
                           # multi-MiB read takes a different, confinement-buggy
                           # server path — see run_root_slice_fill.sh, which cats
                           # in chunks).


def read_range(port, path, off, length):
    """Open `path`, read [off,off+length) in <=READ_CHUNK kXR_read requests,
    close; return the concatenated bytes. Raises AssertionError on an error
    open/read status."""
    s = _session(port)
    try:
        s.sendall(make_open_req(path.encode()))
        status, body = _read_frame(s)               # open resp: fhandle in body[:4]
        assert status == 0, f"open failed status={status}"
        fh = body[:4]
        data = b""
        pos, remaining = off, length
        while remaining > 0:
            want = min(READ_CHUNK, remaining)
            s.sendall(make_read_req(fh, pos, want))
            while True:                              # 4000 == kXR_oksofar stream
                status, chunk = _read_frame(s)
                data += chunk
                if status != 4000:
                    break
            assert status == 0, f"read failed status={status}"
            pos += want
            remaining -= want
        s.sendall(make_close_req(fh))
        _read_frame(s)
        return data
    finally:
        s.close()


def raw_open_frame(port, path):
    """Open `path` on the node and return the RAW kXR_open response frame bytes
    (8-byte header + body), reading exactly what the server put on the wire.

    Unlike read_range(), this does not parse/validate the frame — it is the probe
    the log-leak regression test uses to assert the open response is a clean
    protocol frame with no server log text spliced ahead of it (a fill-thread
    diagnostic that logged to a stale, fd-reused connection log would land the log
    line on this very socket)."""
    s = _session(port)
    try:
        s.sendall(make_open_req(path.encode()))
        header = _recv_exact(s, 8)
        _sid, _status, dlen = struct.unpack(">HHI", header)
        body = _recv_exact(s, dlen) if 0 < dlen < 65536 else b""
        return header + body
    finally:
        s.close()


def residency(store_dir, key):
    """Return the parsed xrdcinfo record for the cached object <store_dir>/<key>.

    The unified metadata record is xattr-preferred: on an xattr-capable store fs
    it rides the object's ``user.xrd.cinfo`` xattr with NO ``.cinfo`` sidecar, and
    only falls back to a sidecar where xattrs are unsupported. So read the sidecar
    first and, when it is absent, read the xattr off the object itself. Returns
    {'absent': True} only when neither carrier holds a record."""
    cinfo = os.path.join(store_dir, key + ".cinfo")
    p = subprocess.run([XRDCINFO, cinfo], capture_output=True, text=True)
    out = (p.stdout or "").strip()
    parsed = json.loads(out) if out else {"absent": True}
    if not parsed.get("absent"):
        return parsed

    data = os.path.join(store_dir, key)
    px = subprocess.run([XRDCINFO, "--xattr", data], capture_output=True, text=True)
    xout = (px.stdout or "").strip()
    if xout:
        xparsed = json.loads(xout)
        if not xparsed.get("absent"):
            return xparsed
    return {"absent": True}


def backend_available(backend):
    """True iff the backend can be stood up here. http always can — make_cache_node
    launches a local nginx static origin, no external service needed. s3 needs
    XRD_TEST_S3_ENDPOINT and rados needs XRD_TEST_RADOS_POOL (cluster-tier); absent
    -> those tests skip (never fail)."""
    return {
        "http":  True,
        "s3":    bool(os.environ.get("XRD_TEST_S3_ENDPOINT")),
        "rados": bool(os.environ.get("XRD_TEST_RADOS_POOL")),
    }.get(backend, True)
