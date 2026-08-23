# brix-remote-ok
"""
test_evil_actor_v2.py — deeper adversarial worker-crash / data-race hunt.

Goes beyond test_evil_actor.py (single cleartext listener, per-connection attacks)
by targeting the surfaces the per-connection XRD_ST_AIO recv guard does NOT cover,
and by making the worker-vs-event-loop race windows DETERMINISTIC with a
worker-gated LD_PRELOAD syscall-slower shim (tests/race_shim.c):

  P1  cross-connection kXR_bind handle races — a secondary stream bound to a
      primary's session reads a primary-published handle while the file is
      close+unlink+recreate'd (inode swap) underneath it, with the shim holding
      the secondary's worker pread open across the swap. The single-connection
      AIO guard does not gate the PRIMARY's independent connection, so this is a
      genuine cross-thread race. Asserted for WORKER SAFETY (no crash/UAF/race).
  P2  cross-session bind security contract — confirms a secondary needs only a
      (captured) sessid to inherit the primary's identity and read its handles
      (the sessid is "Not a CSPRNG value": time|pid|ptr|ngx_random), and that a
      blind/forged sessid is rejected. Documents the bearer-token trust model.
  P3  disconnect-mid-AIO, shim-widened — large pgread/readv/write offloaded to a
      worker held mid-pread by the shim, then hard RST. Regression guard for the
      AIO-teardown / scratch-buffer lifetime guards.
  P4  pipelined scratch reuse — read->readv->pgread pipelined on one connection
      then RST (the historical read_scratch reuse window).
  P5  stateful / less-tested opcode fuzz — chkpoint/sigver/truncate/fattr/sync/
      endsess-during-AIO with malformed + state-confusing framing.
  P6  cross-protocol simultaneous assault — root write + WebDAV GET + S3 GET/DELETE
      + unlink/recreate on the SAME files concurrently (shared fd-cache / locks /
      write-through / SHM).
  P7  survival + integrity.

Server is a REAL master + 3 workers (a worker SIGSEGV is detected via pgrep churn
+ "signal 11/6"/sanitizer strings in the log, not masked by silent respawn).
Strongest under ASAN (heap-use-after-free) and TSan (data race) builds — point
TEST_NGINX_BIN at the sanitizer nginx and set TEST_EVIL_SHIM_SAN=address|thread so
the shim is built to match. The shim delay is XRD_RACE_DELAY_US (default 15000).

RUN: TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_evil_actor_v2.py -v -s
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

BIGFILE_MB = 32
SHIM_DELAY_US = int(os.environ.get("XRD_RACE_DELAY_US", "15000"))
SHIM_SAN = os.environ.get("TEST_EVIL_SHIM_SAN", "")          # ""|address|thread
ROUNDS = int(os.environ.get("TEST_EVIL_V2_ROUNDS", "120"))

# opcodes
kXR_close=3003; kXR_sync=3016; kXR_login=3007; kXR_open=3010; kXR_ping=3011
kXR_read=3013; kXR_stat=3017; kXR_write=3019; kXR_fattr=3020; kXR_truncate=3028
kXR_endsess=3023; kXR_bind=3024; kXR_readv=3025; kXR_pgwrite=3026; kXR_pgread=3030
kXR_writev=3031; kXR_chkpoint=3032
kXR_ok=0; kXR_error=4003; kXR_wait=4005; kXR_status=4007

CRASH_PATTERNS = ("signal 11", "signal 6", "signal 4", "signal 7", "signal 8",
                  "SIGSEGV", "SIGABRT", "core dumped", "segfault",
                  "AddressSanitizer", "heap-use-after-free", "heap-buffer-overflow",
                  "stack-buffer-overflow", "attempting double-free",
                  "runtime error:")
# TSan reports go to a separate log dir; scanned distinctly so benign atomic
# races (suppressed) don't fail the run — only module-frame races do.


# ----------------------------- process helpers ------------------------------

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


def _reachable(port, t=0.5):
    try:
        with socket.create_connection((HOST, port), timeout=t):
            return True
    except OSError:
        return False


def _wait_port(port, t=12.0):
    end = time.time() + t
    while time.time() < end:
        if _reachable(port):
            return True
        time.sleep(0.1)
    return False


def _master_pid(pidfile, t=8.0):
    end = time.time() + t
    while time.time() < end:
        try:
            return int(open(pidfile).read().strip())
        except (OSError, ValueError):
            time.sleep(0.1)
    return None


def _workers(master):
    out = subprocess.run(["pgrep", "-P", str(master)], capture_output=True, text=True)
    return set(int(x) for x in out.stdout.split() if x.isdigit())


def _alive(pid):
    try:
        os.kill(pid, 0); return True
    except OSError:
        return False


# ----------------------------- raw xrootd wire ------------------------------

def _recv_exact(s, n):
    b = bytearray()
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise ConnectionError("closed")
        b.extend(c)
    return bytes(b)


def _read_response(s):
    sid, status, dlen = struct.unpack("!2sHI", _recv_exact(s, 8))
    body = _recv_exact(s, dlen) if dlen else b""
    if status == kXR_status and dlen == 24 and len(body) == 24:
        extra = struct.unpack("!I", body[12:16])[0]
        if extra:
            body += _recv_exact(s, extra)
    return status, body


def _connect(port, t=8):
    s = socket.create_connection((HOST, port), timeout=t)
    s.settimeout(t)
    return s


def _handshake(s):
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    if _read_response(s)[0] != kXR_ok:
        raise ConnectionError("handshake rejected")


def _frame(op, body16, payload=b"", dlen=None, sid=b"\x00\x07"):
    body16 = (body16 + b"\x00" * 16)[:16]
    if dlen is None:
        dlen = len(payload)
    return struct.pack("!2sH", sid, op) + body16 + struct.pack("!I", dlen & 0xFFFFFFFF) + payload


def _login(s, user=b"evil\x00\x00\x00\x00"):
    """Returns the 16-byte sessid from the login reply."""
    _handshake(s)
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0xFFFFFFFF, user, 0, 0, 5, 0, 0))
    st, body = _read_response(s)
    if st != kXR_ok:
        raise ConnectionError("login rejected")
    return body[:16] if len(body) >= 16 else b"\x00" * 16


def _session(port):
    s = _connect(port)
    sid = _login(s)
    return s, sid


def _bind(s, sessid):
    """Attach a fresh connection to a primary's session via its sessid."""
    _handshake(s)
    s.sendall(_frame(kXR_bind, sessid, b"", sid=b"\x00\x09"))
    return _read_response(s)


def _open(s, path, flags=0x0010, sid=b"\x00\x02"):
    p = (path.encode() if isinstance(path, str) else path)
    if not p.endswith(b"\x00"):
        p += b"\x00"
    body = struct.pack("!HH2s6s4s", 0o644, flags, b"\x00\x00", b"\x00" * 6, b"\x00" * 4)
    s.sendall(_frame(kXR_open, body, p, sid=sid))
    return _read_response(s)


def _read(s, fh, off, rlen, sid=b"\x00\x03"):
    s.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, off, rlen), sid=sid))
    return _read_response(s)


def _rst(s):
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def _ping_ok(port):
    try:
        s, _ = _session(port)
        s.sendall(_frame(kXR_ping, b"", sid=b"\x00\x0f"))
        st, _ = _read_response(s)
        s.close()
        return st in (kXR_ok, kXR_error)
    except Exception:
        return False


# ------------------------------- the server ---------------------------------

class _Srv:
    def __init__(self, prefix, conf, pidfile, ports, datadir, tsandir):
        self.prefix = prefix; self.conf = conf; self.pidfile = pidfile
        self.root_port, self.http_port = ports
        self.s3_port = self.http_port
        self.webdav_port = self.http_port
        self.datadir = datadir; self.tsandir = tsandir
        self.master: "int | None" = None
        self._mark = 0

    @property
    def logfile(self):
        return os.path.join(self.prefix, "logs", "error.log")

    def mark(self):
        try:
            self._mark = os.path.getsize(self.logfile)
        except OSError:
            self._mark = 0

    def _delta(self):
        try:
            with open(self.logfile, errors="replace") as f:
                f.seek(self._mark); return f.read()
        except OSError:
            return ""

    @staticmethod
    def _module_race(text):
        markers = (
            "/src/core/aio/", "/src/protocols/root/read/",
            "/src/protocols/root/write/", "/src/fs/cache/",
            "/src/protocols/root/session/", "/src/protocols/root/connection/",
            "_aio_thread", "_aio_done", "read_scratch", "payload_to_free",
            "ctx->destroyed", "brix_",
        )
        return "data race" in text and any(marker in text for marker in markers)

    def _tsan_file_has_module_race(self, filename):
        try:
            with open(os.path.join(self.tsandir, filename), errors="replace") as source:
                text = source.read()
        except OSError:
            return False
        return self._module_race(text)

    def _tsan_module_races(self):
        if not self.tsandir or not os.path.isdir(self.tsandir):
            return ""
        hits = [name for name in os.listdir(self.tsandir)
                if self._tsan_file_has_module_race(name)]
        return ",".join(hits)

    def assert_healthy(self, phase):
        delta = self._delta()
        for pat in CRASH_PATTERNS:
            assert pat not in delta, (
                "WORKER BROKE during %s — %r in error log:\n%s"
                % (phase, pat, delta[-1800:]))
        races = self._tsan_module_races()
        assert not races, "TSan module-frame DATA RACE during %s: %s" % (phase, races)
        assert _alive(self.master), "master died during %s" % phase
        assert _workers(self.master), "no workers after %s" % phase
        assert _ping_ok(self.root_port), "server not serving after %s" % phase


def _build_shim(workdir):
    """Compile race_shim.c (matching the sanitizer of the binary under test)."""
    src = os.path.join(os.path.dirname(__file__), "race_shim.c")
    so = os.path.join(workdir, "librace.so")
    cmd = ["cc", "-shared", "-fPIC", "-O0", "-g", "-o", so, src, "-ldl", "-lpthread"]
    if SHIM_SAN in ("address", "thread"):
        cmd[1:1] = ["-fsanitize=" + SHIM_SAN]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr
    return so, ""


def _load_continuation(filename):
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path, encoding="utf-8") as source:
        exec(compile(source.read(), path, "exec"), globals())


_load_continuation("_test_evil_actor_v2_runtime.py")

