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
import signal
import socket
import struct
import subprocess
import textwrap
import time

import pytest

from settings import HOST, NGINX_BIN, free_ports

_HERE = os.path.dirname(__file__)
_RUNNER = os.path.join(_HERE, "c", "run_slice_tests.sh")
_OBJS = os.environ.get("TEST_NGINX_OBJS", "/tmp/nginx-1.28.3/objs")
_NGINX = os.environ.get("TEST_NGINX_BIN", os.path.join(_OBJS, "nginx"))


class TestSliceLibrary:
    """Step A — the shared slice enumeration/path/meta/evict library."""

    def test_slice_library_unit_tests_pass(self):
        slice_o = os.path.join(_OBJS, "addon", "cache", "slice.o")
        if not os.path.exists(slice_o):
            pytest.skip(f"slice.o not built under {_OBJS}; build the module first")

        proc = subprocess.run(
            [_RUNNER, _OBJS],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        out = proc.stdout.decode(errors="replace")
        # Surface the C harness output on failure for debugging.
        assert proc.returncode == 0, f"slice unit tests failed:\n{out}"
        assert ", 0 failed" in out, f"unexpected slice unit test output:\n{out}"


class TestSliceConfig:
    """Step F — the brix_cache_slice_size tier directive parses and validates."""

    def _nginx_t(self, tmp_path, slice_value):
        cache = tmp_path / "cache"
        cache.mkdir()
        (tmp_path / "logs").mkdir()
        conf = tmp_path / "nginx.conf"
        conf.write_text(textwrap.dedent(f"""\
            error_log {tmp_path}/logs/error.log;
            pid {tmp_path}/logs/nginx.pid;
            events {{}}
            thread_pool default threads=2 max_queue=128;
            stream {{
                server {{
                    listen 21794;
                    brix_root on;
                    brix_export {tmp_path};
                    brix_auth none;
                    brix_storage_backend root://{HOST}:1095;
                    brix_cache_store posix:{cache};
                    brix_cache_export /;
                    brix_cache_slice_size {slice_value};
                }}
            }}
            """))
        return subprocess.run(
            [_NGINX, "-t", "-p", str(tmp_path), "-c", "nginx.conf"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )

    def test_valid_slice_size_accepted(self, tmp_path):
        if not os.path.exists(_NGINX):
            pytest.skip(f"nginx binary not built at {_NGINX}")
        proc = self._nginx_t(tmp_path, "128m")
        out = proc.stdout.decode(errors="replace")
        assert proc.returncode == 0, f"valid 128m slice rejected:\n{out}"
        assert "successful" in out

    def test_non_multiple_slice_size_rejected(self, tmp_path):
        if not os.path.exists(_NGINX):
            pytest.skip(f"nginx binary not built at {_NGINX}")
        proc = self._nginx_t(tmp_path, "100k")
        out = proc.stdout.decode(errors="replace")
        assert proc.returncode != 0, "non-multiple-of-1m slice must be rejected"
        assert "multiple of 1m" in out


# ---------------------------------------------------------------------------
# Integration coverage — executable spec.  The stream slice path (open + read)
# is implemented (slice_read.c); these end-to-end cases need a live XRootD
# origin + cache, which the current OOM-constrained test host cannot sustain,
# so they remain skipped until a healthy env is available.
# ---------------------------------------------------------------------------

_PENDING = "needs a live XRootD origin + cache env (stream slice serving)"
_SLICE_DEFERRED = ("slice-granular read-caching is deferred; the current open-time/whole-file VFS cache design caches whole files, not per-slice "
                   "windows — see module docstring. xfail until generic-slice serving lands.")


@pytest.mark.skip(reason=_PENDING)
class TestSliceCacheIntegration:

    # --- WebDAV plane ---

    def test_slice_cache_hit(self):
        """Seed slice 0; GET bytes 0-50MiB -> 206 served from cache, no origin call."""

    def test_slice_cache_miss_then_fill(self):
        """Cold cache; GET bytes 0-50MiB on 128MiB slice -> fill triggered, body correct."""

    def test_slice_cache_prefetch(self):
        """GET slice 0 -> slice 1 fill scheduled (a .__xrds_*_1 file appears)."""

    def test_slice_etag_mismatch_invalidates(self):
        """Cache slice 0; change file at origin (new etag); GET -> old slices evicted, fresh data."""

    def test_slice_range_spanning_two_slices(self):
        """GET Range bytes=100m-300m on 128MiB slices -> data stitched correctly."""

    # --- Stream plane ---

    def test_kxr_read_slice_cache_hit(self):
        """Open file; kXR_read in a cached slice -> pread from cache, no kXR_wait."""

    def test_kxr_read_slice_cache_miss_wait(self):
        """Cold cache; kXR_read -> kXR_wait with seconds > 0."""

    def test_kxr_read_resumes_after_fill(self):
        """Cold cache; kXR_read -> kXR_wait; after fill, retry returns correct data."""

    # --- Eviction + security ---

    def test_evict_removes_whole_slice_set(self):
        """Cache several slices; trigger eviction -> all .__xrds_* files removed as a unit."""

    def test_slice_path_cannot_escape_cache_root(self):
        """Path traversal in the slice path stays confined to cache_root."""


# ===========================================================================
# Sparse-storage proof — the stream slice cache stores ONLY the touched
# windows of a file, never the whole file pulled from the origin.
#
# This is the real, runnable end-to-end coverage the spec class above sketched.
# It self-provisions an ORIGIN data server holding a 16 MiB file and a CACHE
# server in slice mode (brix_cache_slice 1m) pointed at it, then drives raw
# kXR_open + kXR_read (handling the async-fill kXR_wait/retry) at chosen offsets
# and INSPECTS cache_root on disk.  The invariant under test, stated three ways:
#   * a partial read materialises only the 1 MiB slice(s) it touched (+ slice 0,
#     the open-time size probe) — never the other 15 slices;
#   * a whole-file blob (a cache file WITHOUT the .__xrds_<k>_<idx> infix) is
#     NEVER created, not even when the entire file is read; and
#   * every slice stored on disk is byte-identical to the matching origin range.
# ===========================================================================

# --- XRootD wire constants (XProtocol.hh) ----------------------------------
_kXR_login, _kXR_open, _kXR_read, _kXR_close = 3007, 3010, 3013, 3003
_kXR_ok, _kXR_oksofar, _kXR_error, _kXR_wait = 0, 4000, 4003, 4005
_kXR_open_read = 0x0010

_SLICE = 1024 * 1024          # bytes; must match `brix_cache_slice 1m`
_NSLICES = 16
_FILESIZE = _SLICE * _NSLICES  # 16 MiB


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


def _complete_response(sock, status, body):
    data = body
    while status == _kXR_oksofar:
        status, more = _resp(sock)
        data += more
    return data


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
            secs = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 1
            time.sleep(min(max(secs, 0.2), 1.0))
            continue
        if status in (_kXR_ok, _kXR_oksofar):
            return _complete_response(sock, status, body)
        raise AssertionError("read off=%d len=%d failed: status=%d %r"
                             % (offset, length, status, body))
    raise AssertionError("read off=%d len=%d still waiting after %ss "
                         "(slice fill never completed)" % (offset, length, deadline))


def _kill(proc):
    if not proc:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _start(base, name, cfg_text, port):
    cfg = os.path.join(base, name)
    with open(cfg, "w") as f:
        f.write(cfg_text)
    proc = subprocess.Popen([NGINX_BIN, "-c", cfg, "-p", base],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    end = time.time() + 10
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return proc
        except OSError:
            time.sleep(0.1)
    _kill(proc)
    return None


def _require_nginx():
    if not (NGINX_BIN and os.path.exists(NGINX_BIN)):
        pytest.skip("nginx-xrootd binary not built at %s" % NGINX_BIN)


def _start_servers(base, origin_cfg, cache_cfg, origin_port, cache_port):
    origin = _start(base, "origin.conf", origin_cfg, origin_port)
    cache = _start(base, "cache.conf", cache_cfg, cache_port)
    if origin and cache:
        return origin, cache
    _kill(cache)
    _kill(origin)
    pytest.skip("origin/cache server did not start")


@pytest.fixture(scope="module")
def xcache(tmp_path_factory):
    """An ORIGIN data server + a CACHE server in 1 MiB slice mode in front of it."""
    _require_nginx()
    base = str(tmp_path_factory.mktemp("xcache"))
    origin_data = os.path.join(base, "origin_data")
    export = os.path.join(base, "export")          # cache server's (empty) export
    cache_root = os.path.join(base, "cache_root")
    for d in (origin_data, export, cache_root, os.path.join(base, "logs")):
        os.makedirs(d, exist_ok=True)

    origin_port, cache_port = free_ports(2)
    head = ("daemon off;\nworker_processes 1;\n"
            "events { worker_connections 64; }\n")
    origin_cfg = head + (
        f"pid {base}/logs/origin.pid;\n"
        f"error_log {base}/logs/origin.log info;\n"
        "stream {\n  server {\n"
        f"    listen 127.0.0.1:{origin_port};\n"
        "    brix_root on;\n"
        f"    brix_export {origin_data};\n"
        "    brix_auth none;\n  }\n}\n")
    cache_cfg = head + (
        f"pid {base}/logs/cache.pid;\n"
        f"error_log {base}/logs/cache.log info;\n"
        "thread_pool default threads=4 max_queue=4096;\n"
        "stream {\n  server {\n"
        f"    listen 127.0.0.1:{cache_port};\n"
        "    brix_root on;\n"
        f"    brix_export {export};\n"
        "    brix_auth none;\n"
        f"    brix_storage_backend root://127.0.0.1:{origin_port};\n"
        f"    brix_cache_store posix:{cache_root};\n"
        "    brix_cache_export /;\n"
        "    brix_cache_slice_size 1m;\n  }\n}\n")

    origin, cache = _start_servers(
        base, origin_cfg, cache_cfg, origin_port, cache_port)
    try:
        yield {"host": "127.0.0.1", "port": cache_port,
               "origin_data": origin_data, "cache_root": cache_root}
    finally:
        _kill(cache)
        _kill(origin)



from split_continuation import load as _load_continuation
_load_continuation(globals(), __file__, "_slice_cache_part2.py")
