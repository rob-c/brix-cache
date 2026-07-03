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

from settings import NGINX_BIN, free_ports
from _test_a_robustness_helpers import (
    make_protocol_req, make_login_req, make_open_req, make_read_req,
    make_close_req,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCINFO = os.path.join(REPO, "client", "bin", "xrdcinfo")
HOST = "127.0.0.1"


class CacheNode:
    def __init__(self, cache_port, store_dir, backend, procs, backend_port):
        self.cache_port = cache_port
        self.store_dir = store_dir
        self.backend = backend            # "xroot" | "posix" | "pblock" | ...
        self.backend_port = backend_port  # origin port (xroot) or None
        self._procs = procs               # {name: nginx master pid}
        self.backend_data = ""            # dir seeded by seed_origin (posix)
        self.seed_mode = "posix"          # "posix" (raw write) | "pblock" (xrdcp)
        self.seed_port = None             # root:// port to xrdcp pblock seeds to

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        stop_node(self)
        return False


def _write_conf(path, text):
    with open(path, "w") as f:
        f.write(text)


def _start_nginx(prefix, conf_text, name):
    """Start a daemonized nginx and return its MASTER pid. The master is a
    session/process-group leader (pgid == master pid), so teardown reaps the
    whole group (master + workers) via killpg(pid) — even after the master
    exits, because its workers keep the group alive. See stop_node."""
    os.makedirs(os.path.join(prefix, "logs"), exist_ok=True)
    conf = os.path.join(prefix, f"{name}.conf")
    _write_conf(conf, conf_text)
    p = subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{name} nginx start failed: {p.stderr[-600:]}")
    pidfile = os.path.join(prefix, f"{name}.pid")   # matches the conf `pid` directive
    for _ in range(100):
        try:
            with open(pidfile) as f:
                pid = int(f.read().strip())
            if pid > 0:
                return pid
        except (OSError, ValueError):
            time.sleep(0.02)
    raise RuntimeError(f"{name} nginx pidfile {pidfile} never appeared")


def _wait_port(port, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.15)
    raise RuntimeError(f"port {port} never came up")


def _opt(line, cond):
    return (line + "\n") if cond else ""


def make_cache_node(backend, *, tmp, slice_size=None, max_file_size=None,
                    max_object=None, deny_prefix=None, include_regex=None,
                    origin_backend="posix"):
    """Start a cache node in front of `backend`, returning a CacheNode.

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
    cache_port, backend_port = list(free_ports(2))
    procs = {}
    tp = "thread_pool default threads=2;\n"

    if backend == "xroot":
        origin_root = os.path.join(base, "origin")
        cache_dir = os.path.join(base, "cache")
        export = os.path.join(base, "export")
        for d in (origin_root, cache_dir, export):
            os.makedirs(d, exist_ok=True)
        # posix origin uses brix_root (the proven run_root_slice_fill.sh config);
        # pblock origin uses the pblock backend + write capability (its seed goes
        # in via xrdcp).
        if origin_backend == "pblock":
            obline = (f"  brix_storage_backend pblock://{origin_root}/;"
                      f" brix_auth none;\n"
                      f"  brix_allow_write on; brix_upload_resume off;\n")
        else:
            obline = f"  brix_root {origin_root}; brix_auth none;\n"
        origin_conf = (
            f"daemon on; error_log {base}/o/olog.log error; pid {base}/o/o.pid;\n"
            f"events {{ worker_connections 64; }}\n"
            f"stream {{ server {{ listen {HOST}:{backend_port}; xrootd on;\n"
            f"{obline}}} }}\n")
        procs["origin"] = _start_nginx(base + "/o", origin_conf, "o")
        _wait_port(backend_port)

        cache_conf = (
            f"daemon on; error_log {base}/c/clog.log info; pid {base}/c/c.pid;\n"
            f"{tp}events {{ worker_connections 64; }}\n"
            f"stream {{ server {{\n"
            f"    listen {HOST}:{cache_port}; xrootd on; brix_auth none;\n"
            f"    brix_root {export};\n"
            f"    brix_storage_backend root://{HOST}:{backend_port};\n"
            f"    brix_cache_store posix:{cache_dir};\n"
            f"    brix_cache_root /;\n"
            + _opt(f"    brix_cache_slice_size {slice_size};", slice_size)
            + _opt(f"    brix_cache_max_object {max_file_size};", max_file_size)
            + _opt(f"    brix_cache_deny_prefix {deny_prefix};", deny_prefix)
            + _opt(f"    brix_cache_include_regex {include_regex};", include_regex)
            + f"}} }}\n")
        procs["cache"] = _start_nginx(base + "/c", cache_conf, "c")
        _wait_port(cache_port)
        node = CacheNode(cache_port, cache_dir, backend, procs, backend_port)
        node.backend_data = origin_root
        node.seed_mode = origin_backend          # posix -> raw; pblock -> xrdcp
        node.seed_port = backend_port            # seed writes go to the origin
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
    cache_conf = (
        f"daemon on; error_log {base}/c/clog.log info; pid {base}/c/c.pid;\n"
        f"{tp}events {{ worker_connections 64; }}\n"
        f"stream {{ server {{\n"
        f"    listen {HOST}:{cache_port}; xrootd on; brix_auth none;\n"
        f"    brix_allow_write on; brix_upload_resume off;\n"
        f"    brix_storage_backend {drv};\n"
        f"    brix_cache_store posix:{store}; brix_cache_root /;\n"
        + _opt(f"    brix_cache_slice_size {slice_size};", slice_size)
        + _opt(f"    brix_cache_max_object {max_object};", max_object)
        + _opt(f"    brix_cache_deny_prefix {deny_prefix};", deny_prefix)
        + _opt(f"    brix_cache_include_regex {include_regex};", include_regex)
        + f"}} }}\n")
    procs["cache"] = _start_nginx(base + "/c", cache_conf, "c")
    _wait_port(cache_port)
    node = CacheNode(cache_port, store, backend, procs, backend_port)
    node.backend_data = bdir
    node.seed_mode = backend                  # posix -> raw; pblock -> xrdcp
    node.seed_port = cache_port               # seed writes go through the backend
    return node


def _reap(pid):
    """SIGKILL the process GROUP led by nginx master `pid` (reaps master +
    workers), falling back to the bare pid. Using pid AS the pgid works even
    after the master exits, since its workers keep the group alive."""
    try:
        os.killpg(pid, 9)
    except OSError:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


def stop_node(node):
    """SIGKILL every nginx process group of the node (master + workers)."""
    for _name, pid in node._procs.items():
        _reap(pid)


def kill_origin(node, timeout=5.0):
    """Kill the root:// origin and block until its port stops accepting — a
    deterministic backend-offline for the behavioral tests."""
    pid = node._procs.get("origin")
    if pid is None:
        return
    _reap(pid)
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


def residency(store_dir, key):
    """Run xrdcinfo on <store_dir>/<key>.cinfo; return the parsed dict, or
    {'absent': True} when neither the object nor its sidecar was cached."""
    cinfo = os.path.join(store_dir, key + ".cinfo")
    p = subprocess.run([XRDCINFO, cinfo], capture_output=True, text=True)
    out = (p.stdout or "").strip()
    if not out:
        return {"absent": True}
    return json.loads(out)


def backend_available(backend):
    """True iff the env for a gated backend is present. http needs
    XRD_TEST_HTTP_ORIGIN; s3 needs XRD_TEST_S3_ENDPOINT; rados needs
    XRD_TEST_RADOS_POOL. Absent -> tests skip (never fail)."""
    return {
        "http":  bool(os.environ.get("XRD_TEST_HTTP_ORIGIN")),
        "s3":    bool(os.environ.get("XRD_TEST_S3_ENDPOINT")),
        "rados": bool(os.environ.get("XRD_TEST_RADOS_POOL")),
    }.get(backend, True)
