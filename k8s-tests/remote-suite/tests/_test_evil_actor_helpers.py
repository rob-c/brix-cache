"""
test_evil_actor.py — adversarial worker-crash hunt for the root:// stream plane.

WHAT
    A malicious-client harness that fires byte-accurate hostile XRootD wire frames
    and concurrency races at a REAL master+worker nginx, then proves no worker
    process broke. Unlike the existing fuzz suites (which run against the shared
    fleet and only check "the session still answers"), this owns its own
    master_process-on server with >=2 workers, enumerates worker PIDs, and after
    each attack phase asserts: the master is alive, no worker exited on a fatal
    signal, the error log carries no SIGSEGV/SIGABRT/sanitizer report, and a
    legitimate request still returns correct bytes. A worker that SIGSEGVs and is
    silently respawned by the master is therefore caught (it would pass a
    login+ping health check).

THE ATTACK SURFACE (from a recon of the parsers/bounds):
    * frame/allocation gate   — lying/oversized/zero dlen, dlen at each per-opcode
                                cap and cap+1, truncated-body half-open frames.
    * fhandle out-of-range    — fhandle[0] in 16..255 (valid uchar cast, OOB for
                                the 16-slot table) on read/pgread/readv/write/
                                pgwrite/stat/close/truncate.
    * readv/writev segments   — bad seg counts, dlen not a multiple of 16, mixed
                                valid/invalid handles, huge per-seg rlen, long
                                contiguous coalesce runs, N-discovery confusion.
    * pgread/pgwrite math     — unaligned offsets + rlen near the cap, negative
                                offsets, rlen 0, bad CRC, edge dlens.
    * kXR_clone offsets       — negative/near-2^63 src/dst offsets (the one wire
                                offset path with no pre-validation).
    * fattr / query           — numattr 17/255, subcode 4..255, truncated nvec,
                                hostile query subcodes/paths.
    * login / open            — invalid usernames, path traversal/NUL/overlong.
    * THE HEADLINE — disconnect-mid-AIO: a large pgread/readv/write offloads to a
                     worker thread that pread/pwrites into ctx scratch buffers;
                     a hard RST then drives brix_on_disconnect to free those
                     buffers while the worker is still in the syscall (a classic
                     use-after-free with no thread-pool drain). Hammered from many
                     connections to widen the window.
    * endsess-then-pipelined-read + RST (post-teardown reuse / double-disconnect).
    * resource exhaustion (handle/session floods).

Strongest under an AddressSanitizer build (TEST_NGINX_BIN=<asan nginx>): a UAF
that only sometimes faults on a release build is a deterministic ASAN abort.

RUN
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_evil_actor.py -v -s
"""

import os
import random
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

import pytest

from settings import NGINX_BIN, REMOTE_SERVER, HOST, BIND_HOST

# tunables (env-overridable so CI can dial intensity)
AIO_ROUNDS   = int(os.environ.get("TEST_EVIL_AIO_ROUNDS", "600"))
AIO_THREADS  = int(os.environ.get("TEST_EVIL_AIO_THREADS", "8"))
FUZZ_REPEAT  = int(os.environ.get("TEST_EVIL_FUZZ_REPEAT", "3"))
BIGFILE_MB   = 48

# opcodes
kXR_query=3001; kXR_close=3003; kXR_dirlist=3004; kXR_login=3007; kXR_open=3010
kXR_ping=3011; kXR_read=3013; kXR_stat=3017; kXR_write=3019; kXR_fattr=3020
kXR_endsess=3023; kXR_bind=3024; kXR_readv=3025; kXR_pgwrite=3026
kXR_truncate=3028; kXR_pgread=3030; kXR_writev=3031; kXR_clone=3033

kXR_ok=0; kXR_error=4003; kXR_wait=4005; kXR_status=4007

CRASH_PATTERNS = ("signal 11", "signal 6", "signal 4", "signal 7", "signal 8",
                  "SIGSEGV", "SIGABRT", "core dumped", "segfault",
                  "AddressSanitizer", "runtime error:", "LeakSanitizer",
                  "heap-use-after-free", "heap-buffer-overflow",
                  "stack-buffer-overflow", "attempting double-free")


# ---------------------------------------------------------------------------
# process / liveness helpers (lifted from test_shm_fork_safety.py)
# ---------------------------------------------------------------------------

def _free_ports(n):
    socks, ports = [], []
    try:
        for _ in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((BIND_HOST, 0)); socks.append(s); ports.append(s.getsockname()[1])
    finally:
        for s in socks:
            s.close()
    return ports


def _reachable(port, timeout=0.5):
    try:
        with socket.create_connection((HOST, port), timeout=timeout):
            return True
    except OSError:
        return False


def _wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if _reachable(port):
            return True
        time.sleep(0.1)
    return False


def _master_pid(pidfile, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            return int(open(pidfile).read().strip())
        except (OSError, ValueError):
            time.sleep(0.1)
    return None


def _worker_pids(master):
    out = subprocess.run(["pgrep", "-P", str(master)], capture_output=True, text=True)
    return set(int(x) for x in out.stdout.split() if x.isdigit())


def _alive(pid):
    try:
        os.kill(pid, 0); return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# raw XRootD wire client
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise ConnectionError("closed")
        buf.extend(c)
    return bytes(buf)


def _read_response(sock):
    sid, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    body = _recv_exact(sock, dlen) if dlen else b""
    if status == kXR_status and dlen == 24 and len(body) == 24:
        extra = struct.unpack("!I", body[12:16])[0]
        if extra:
            body += _recv_exact(sock, extra)
    return status, body


def _connect(port, timeout=8):
    s = socket.create_connection((HOST, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def _login(s, user=b"evil\x00\x00\x00\x00"):
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    if _read_response(s)[0] != kXR_ok:
        raise ConnectionError("handshake rejected")
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0xFFFFFFFF, user, 0, 0, 5, 0, 0))
    if _read_response(s)[0] != kXR_ok:
        raise ConnectionError("login rejected")
    return s


def _session(port):
    return _login(_connect(port))


def _frame(opcode, body16, payload=b"", dlen=None, sid=b"\x00\x07"):
    """Build any request frame; dlen defaults to len(payload) but may LIE."""
    body16 = (body16 + b"\x00" * 16)[:16]
    if dlen is None:
        dlen = len(payload)
    return struct.pack("!2sH", sid, opcode) + body16 + struct.pack("!I", dlen & 0xFFFFFFFF) + payload


def _open(s, path, flags=0x0010, sid=b"\x00\x02"):
    p = (path.encode() if isinstance(path, str) else path)
    if not p.endswith(b"\x00"):
        p += b"\x00"
    body = struct.pack("!HH2s6s4s", 0o644, flags, b"\x00\x00", b"\x00" * 6, b"\x00" * 4)
    s.sendall(_frame(kXR_open, body, p, sid=sid))
    return _read_response(s)


def _rst_close(s):
    """Hard RST (SO_LINGER 0) — abrupt teardown to race in-flight AIO."""
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def _ping_ok(port):
    """True if a fresh session + ping round-trips (server is serving)."""
    try:
        s = _session(port)
        s.sendall(_frame(kXR_ping, b"", sid=b"\x00\x0f"))
        st, _ = _read_response(s)
        s.close()
        return st in (kXR_ok, kXR_error)   # any well-formed reply = alive
    except Exception:
        return False


def _load_continuation(filename):
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path, encoding="utf-8") as source:
        exec(compile(source.read(), path, "exec"), globals())


_load_continuation("_test_evil_actor_runtime.py")

