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
                     a hard RST then drives xrootd_on_disconnect to free those
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


# ---------------------------------------------------------------------------
# the server under attack: real master + workers, thread pool, big cold file
# ---------------------------------------------------------------------------

class _Srv:
    def __init__(self, prefix, conf, pidfile, root_port, http_port, datadir):
        self.prefix = prefix; self.conf = conf; self.pidfile = pidfile
        self.root_port = root_port; self.http_port = http_port
        self.datadir = datadir
        self.master: "int | None" = None
        self._log_mark = 0

    @property
    def logfile(self):
        return os.path.join(self.prefix, "logs", "error.log")

    def log_since_mark(self):
        try:
            with open(self.logfile, errors="replace") as f:
                f.seek(self._log_mark)
                return f.read()
        except OSError:
            return ""

    def mark_log(self):
        try:
            self._log_mark = os.path.getsize(self.logfile)
        except OSError:
            self._log_mark = 0

    def assert_healthy(self, phase):
        """The core verdict: no worker broke during `phase`."""
        delta = self.log_since_mark()
        for pat in CRASH_PATTERNS:
            assert pat not in delta, (
                "WORKER BROKE during %s — %r in error log:\n%s"
                % (phase, pat, delta[-1500:]))
        assert _alive(self.master), "master died during %s" % phase
        assert _worker_pids(self.master), "no workers alive after %s" % phase
        assert _ping_ok(self.root_port), "server not serving after %s" % phase


@pytest.fixture(scope="module")
def srv():
    if REMOTE_SERVER:
        pytest.skip("self-contained; not for REMOTE mode")
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built at %s" % NGINX_BIN)
    if shutil.which("pgrep") is None:
        pytest.skip("pgrep required")

    prefix = tempfile.mkdtemp(prefix="evil-")
    datadir = os.path.join(prefix, "data")
    for d in (os.path.join(prefix, "logs"), datadir):
        os.makedirs(d, exist_ok=True)

    # large, deterministic file so pgread/readv/write offload to the thread pool
    # and a happy-path read can be byte-verified.
    big = os.path.join(datadir, "big.bin")
    with open(big, "wb") as f:
        chunk = bytes((i * 31 + 7) & 0xFF for i in range(65536))
        for _ in range(BIGFILE_MB * 16):
            f.write(chunk)
    # a small writable scratch file
    open(os.path.join(datadir, "w.bin"), "wb").close()

    root_port, http_port = _free_ports(2)
    for p in (root_port, http_port):
        if _reachable(p):
            shutil.rmtree(prefix, ignore_errors=True)
            pytest.skip("port %d in use" % p)

    conf = ("""
worker_processes 3;
daemon on;
master_process on;
pid %s/logs/nginx.pid;
error_log %s/logs/error.log info;
thread_pool aiopool threads=4 max_queue=4096;
events { worker_connections 1024; }
stream {
    server {
        listen %s:%d;
        xrootd on;
        xrootd_storage_backend posix:%s;
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_thread_pool aiopool;
        xrootd_memory_budget 8m;
    }
}
http {
    access_log off;
    server {
        listen %s:%d;
        location = /metrics { xrootd_metrics on; }
    }
}
""" % (prefix, prefix, BIND_HOST, root_port, datadir, BIND_HOST, http_port))
    conf_path = os.path.join(prefix, "nginx.conf")
    open(conf_path, "w").write(conf)
    pidfile = os.path.join(prefix, "logs", "nginx.pid")

    chk = subprocess.run([NGINX_BIN, "-t", "-p", prefix, "-c", conf_path],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        tail = (chk.stderr or chk.stdout).strip()[-400:]
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("nginx rejected config: %s" % tail)
    run = subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path],
                         capture_output=True, text=True)
    if run.returncode != 0 or not _wait_port(root_port):
        tail = (run.stderr or run.stdout).strip()[-400:]
        subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path, "-s", "stop"],
                       capture_output=True)
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("nginx did not start: %s" % tail)

    s = _Srv(prefix, conf_path, pidfile, root_port, http_port, datadir)
    s.master = _master_pid(pidfile)
    if not s.master or not _alive(s.master):
        subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path, "-s", "stop"],
                       capture_output=True)
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("master pid never appeared")
    print("\n[evil] master=%d root=%d http=%d workers=%s"
          % (s.master, root_port, http_port, _worker_pids(s.master)))
    try:
        yield s
    finally:
        subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path, "-s", "stop"],
                       capture_output=True)
        time.sleep(0.3)
        if s.master and _alive(s.master):
            try:
                os.kill(s.master, 9)
            except OSError:
                pass
        shutil.rmtree(prefix, ignore_errors=True)


# ---------------------------------------------------------------------------
# helper: open the big file on a session, return its 4-byte fhandle
# ---------------------------------------------------------------------------

def _open_big(s):
    st, body = _open(s, "/big.bin", flags=0x0010)
    if st != kXR_ok or len(body) < 4:
        raise ConnectionError("open /big.bin failed: %r" % st)
    return body[:4]


def _open_w(s):
    st, body = _open(s, "/w.bin", flags=0x0010 | 0x0020)   # read|update
    if st != kXR_ok or len(body) < 4:
        raise ConnectionError("open /w.bin failed: %r" % st)
    return body[:4]


# ---------------------------------------------------------------------------
# Phase A — broad hostile-frame barrage (each on a fresh session; best-effort)
# ---------------------------------------------------------------------------

def _hostile_frames(fh_big, fh_w):
    """A list of (name, raw-bytes-to-send-after-login) hostile requests."""
    F = []
    bad = bytes([random.choice([15, 16, 17, 64, 200, 255])]) + b"\x00\x00\x00"

    # fhandle OOB (16..255) across every handle-indexed opcode
    for op, body in (
        (kXR_read,  struct.pack("!4sqi", bad, 0, 4096)),
        (kXR_pgread, struct.pack("!4sqi", bad, 0, 4096)),
        (kXR_close, bad + b"\x00" * 12),
        (kXR_stat,  struct.pack("!B11s4s", 0, b"\x00" * 11, bad)),
        (kXR_truncate, bad + struct.pack("!q", 4096) + b"\x00" * 4),
        (kXR_write, struct.pack("!4sqB3s", bad, 0, 0, b"\x00" * 3)),
        (kXR_pgwrite, struct.pack("!4sqBB2s", bad, 0, 0, 0, b"\x00\x00")),
    ):
        F.append(("fhandle_oob_%d" % op, _frame(op, body,
                  b"x" * 4096 if op in (kXR_write,) else b"")))

    # negative / overflow offsets
    F.append(("read_neg_off", _frame(kXR_read, struct.pack("!4sqi", fh_big, -1, 4096))))
    F.append(("read_huge_off", _frame(kXR_read, struct.pack("!4sQi", fh_big, 0x7FFFFFFFFFFFFFFF, 4096))))
    F.append(("read_huge_rlen", _frame(kXR_read, struct.pack("!4sqi", fh_big, 0, 0x7FFFFFFF))))
    F.append(("read_neg_rlen", _frame(kXR_read, struct.pack("!4sqi", fh_big, 0, -1))))
    F.append(("pgread_unaligned", _frame(kXR_pgread, struct.pack("!4sqi", fh_big, 1, 4097))))
    F.append(("pgread_neg_off", _frame(kXR_pgread, struct.pack("!4sqi", fh_big, -7, 8192))))

    # readv abuse
    seg_valid = lambda fh, off, rl: struct.pack("!4siq", fh, rl, off)
    F.append(("readv_dlen_not_mult16", _frame(kXR_readv, b"", b"\x00" * 17)))
    F.append(("readv_zero_segs", _frame(kXR_readv, b"", b"")))
    F.append(("readv_1025_segs", _frame(kXR_readv, b"", seg_valid(fh_big, 0, 16) * 1025)))
    F.append(("readv_oob_handle", _frame(kXR_readv, b"", seg_valid(bad, 0, 4096))))
    F.append(("readv_valid_then_oob", _frame(kXR_readv, b"",
              seg_valid(fh_big, 0, 4096) + seg_valid(bad, 0, 4096))))
    F.append(("readv_huge_rlen", _frame(kXR_readv, b"", seg_valid(fh_big, 0, 0x7FFFFFFF))))
    F.append(("readv_neg_off", _frame(kXR_readv, b"", struct.pack("!4siq", fh_big, 4096, -1))))
    # long contiguous coalesce run (stress the 64-iovec cap)
    contig = b"".join(seg_valid(fh_big, i * 4096, 4096) for i in range(200))
    F.append(("readv_long_contig", _frame(kXR_readv, b"", contig)))

    # pgwrite framing abuse (needs a writable handle)
    F.append(("pgwrite_bad_crc", _frame(kXR_pgwrite,
              struct.pack("!4sqBB2s", fh_w, 0, 0, 0, b"\x00\x00"),
              struct.pack("!I", 0xDEADBEEF) + b"z" * 4096)))
    F.append(("pgwrite_tiny", _frame(kXR_pgwrite,
              struct.pack("!4sqBB2s", fh_w, 0, 0, 0, b"\x00\x00"),
              struct.pack("!I", 0) + b"")))
    F.append(("pgwrite_unaligned", _frame(kXR_pgwrite,
              struct.pack("!4sqBB2s", fh_w, 4095, 0, 0, b"\x00\x00"),
              struct.pack("!I", 0xCAFEBABE) + b"q" * 10)))

    # writev N-discovery confusion: header count vs payload mismatch
    F.append(("writev_seg_mismatch", _frame(kXR_writev, b"",
              struct.pack("!4sii", fh_w, 0, 0x7FFFFFFF) + b"short")))

    # kXR_clone unvalidated offsets (negative + near 2^63)
    F.append(("clone_neg_off", _frame(kXR_clone,
              struct.pack("!4s4sq", fh_big, fh_w, -1),
              struct.pack("!qqQ", -1, -1, 0x7FFFFFFFFFFFFFFF))))

    # fattr abuse: numattr 17/255, bad subcode, truncated nvec
    F.append(("fattr_numattr_255", _frame(kXR_fattr,
              struct.pack("!4sBB10s", fh_big, 0, 255, b"\x00" * 10),
              b"\xff" + b"\x00" * 32)))
    F.append(("fattr_subcode_99", _frame(kXR_fattr,
              struct.pack("!4sBB10s", fh_big, 99, 1, b"\x00" * 10), b"\x00" * 8)))
    F.append(("fattr_trunc_nvec", _frame(kXR_fattr,
              struct.pack("!4sBB10s", fh_big, 0, 16, b"\x00" * 10), b"\x00\x02")))

    # query hostile subcodes / paths
    F.append(("query_bad_subcode", _frame(kXR_query,
              struct.pack("!H2s4s8s", 999, b"\x00\x00", b"\x00" * 4, b"\x00" * 8),
              b"/" + b"../" * 64 + b"\x00")))

    # path abuse on open
    F.append(("open_traversal", _open_frame("/" + "../" * 80 + "etc/passwd")))
    F.append(("open_nul", _open_frame(b"/big\x00.bin")))
    F.append(("open_overlong", _open_frame("/" + "A" * 9000)))

    # lying / oversized dlen (allocation gate)
    F.append(("read_lying_dlen", _frame(kXR_read,
              struct.pack("!4sqi", fh_big, 0, 4096), b"", dlen=0x40000000)))
    F.append(("write_oversize_dlen", _frame(kXR_write,
              struct.pack("!4sqB3s", fh_w, 0, 0, b"\x00" * 3), b"x" * 64, dlen=0x7FFFFFFF)))
    F.append(("stat_oversize_dlen", _frame(kXR_stat,
              struct.pack("!B11s4s", 0, b"\x00" * 11, b"\x00" * 4), b"", dlen=0x10000000)))

    # unknown / reserved opcodes
    for op in (2999, 3005, 3099, 4099, 65535, 0):
        F.append(("opcode_%d" % op, _frame(op, b"", b"")))

    return F


def _open_frame(path):
    p = (path.encode() if isinstance(path, str) else path)
    if not p.endswith(b"\x00"):
        p += b"\x00"
    body = struct.pack("!HH2s6s4s", 0o644, 0x0010, b"\x00\x00", b"\x00" * 6, b"\x00" * 4)
    return _frame(kXR_open, body, p, sid=b"\x00\x02")


def test_a_hostile_frame_barrage(srv):
    """Fire every hostile frame from fresh sessions, repeatedly; no worker may
    crash and the server must keep serving."""
    srv.mark_log()
    for _ in range(FUZZ_REPEAT):
        for name, raw in _build_attacks(srv):
            try:
                s = _session(srv.root_port)
            except Exception:
                continue                 # transient; server liveness checked below
            try:
                s.sendall(raw)
                s.settimeout(2.0)
                try:
                    _read_response(s)    # consume a reply if any (rejection)
                except Exception:
                    pass                 # clean close / no reply = a valid rejection
            finally:
                try:
                    s.close()
                except OSError:
                    pass
    srv.assert_healthy("Phase A hostile-frame barrage")


def _build_attacks(srv):
    """Open the two handles once per call to embed VALID fhandles in the frames
    (so handle-mixing attacks reach the per-segment validator)."""
    s = _session(srv.root_port)
    try:
        fh_big = _open_big(s)
        fh_w = _open_w(s)
    except Exception:
        fh_big = fh_w = b"\x00\x00\x00\x00"
    # the handles belong to session `s`; the attack frames are replayed on OTHER
    # sessions where those handles are NOT open — that is intentional (it makes
    # even the "valid" handle invalid on the attacker session, exercising the
    # not-open path), plus the OOB handles which are invalid everywhere.
    attacks = _hostile_frames(fh_big, fh_w)
    try:
        s.close()
    except OSError:
        pass
    return attacks


# ---------------------------------------------------------------------------
# Phase B — disconnect-mid-AIO torture (the headline use-after-free hunt)
# ---------------------------------------------------------------------------

def _aio_rst_worker(port, rounds, stop_at, counter):
    rng = random.Random(threading.get_ident())
    while time.time() < stop_at and counter[0] < rounds:
        counter[0] += 1
        s = None
        try:
            s = _connect(port, timeout=4)
            _login(s)
            fh = _open_big(s)
        except Exception:
            if s is not None:
                _rst_close(s)
            continue
        # pick a large-offload op and a big range so the worker thread is mid
        # pread/CRC-encode when the RST lands.
        op = rng.choice(("pgread", "readv", "read", "write"))
        off = rng.randrange(0, max(1, BIGFILE_MB * 1024 * 1024 - (32 << 20)))
        rlen = rng.choice((8 << 20, 24 << 20, 48 << 20))
        try:
            if op == "pgread":
                s.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, off, rlen)))
            elif op == "read":
                s.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, off, rlen)))
            elif op == "readv":
                segs = b"".join(struct.pack("!4siq", fh, 1 << 20, off + i * (1 << 20))
                                for i in range(16))
                s.sendall(_frame(kXR_readv, b"", segs))
            else:  # write: detached-payload pwrite from a buffer freed on RST
                try:
                    fw = _open_w(s)
                except Exception:
                    fw = fh
                s.sendall(_frame(kXR_write, struct.pack("!4sqB3s", fw, 0, 0, b"\x00" * 3),
                                 b"Z" * (1 << 20)))
        except OSError:
            pass
        # RST after a jittered delay spanning the post→pread window
        d = rng.choice((0, 0, 0.0005, 0.002, 0.008))
        if d:
            time.sleep(d)
        _rst_close(s)


def test_b_disconnect_mid_aio_uaf(srv):
    """Large offloaded read/pgread/readv/write + immediate hard RST, hammered from
    many connections. A use-after-free on the worker thread (freeing the scratch/
    payload buffer the worker is still pread/pwriting) surfaces as a SIGSEGV/ASAN
    abort in a worker — caught by the post-phase health check."""
    srv.mark_log()
    counter = [0]
    stop_at = time.time() + 90
    threads = [threading.Thread(target=_aio_rst_worker,
                                args=(srv.root_port, AIO_ROUNDS, stop_at, counter))
               for _ in range(AIO_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    print("\n[evil] AIO-RST rounds fired: %d" % counter[0])
    srv.assert_healthy("Phase B disconnect-mid-AIO")


# ---------------------------------------------------------------------------
# Phase C — endsess-then-pipelined-read + RST (post-teardown reuse / dbl-free)
# ---------------------------------------------------------------------------

def test_c_endsess_pipelined_then_rst(srv):
    srv.mark_log()
    for _ in range(200):
        s = None
        try:
            s = _connect(srv.root_port, timeout=4)
            _login(s)
            fh = _open_big(s)
        except Exception:
            if s is not None:
                _rst_close(s)
            continue
        # endsess + a pipelined large pgread in ONE segment, then RST
        pkt = _frame(kXR_endsess, b"\x00" * 16, sid=b"\x00\x05")
        pkt += _frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 16 << 20), sid=b"\x00\x06")
        try:
            s.sendall(pkt)
        except OSError:
            pass
        _rst_close(s)
    srv.assert_healthy("Phase C endsess+pipeline+RST")


# ---------------------------------------------------------------------------
# Phase D — resource exhaustion (handles / sessions) must shed, not crash
# ---------------------------------------------------------------------------

def test_d_resource_exhaustion(srv):
    srv.mark_log()
    # 1) exhaust the 16-slot handle table on one session, then keep opening
    s = _session(srv.root_port)
    try:
        for _ in range(64):
            _open(s, "/big.bin", flags=0x0010)   # >16 opens → must return errors
    except Exception:
        pass
    finally:
        try: s.close()
        except OSError: pass

    # 2) many concurrent sessions each flooding huge pgreads (budget shedding)
    def flood():
        try:
            s = _session(srv.root_port)
            fh = _open_big(s)
            for _ in range(20):
                s.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 48 << 20)))
            try: s.settimeout(1.0); _read_response(s)
            except Exception: pass
            _rst_close(s)
        except Exception:
            pass
    ts = [threading.Thread(target=flood) for _ in range(24)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=60)

    # 3) connect/disconnect storm (session registry churn)
    for _ in range(300):
        try:
            s = _connect(srv.root_port, timeout=2)
            _rst_close(s)
        except Exception:
            pass
    srv.assert_healthy("Phase D resource exhaustion")


# ---------------------------------------------------------------------------
# Phase E — final proof the server is intact and serves correct bytes
# ---------------------------------------------------------------------------

def test_e_server_intact_and_correct(srv):
    srv.mark_log()
    expected = bytes((i * 31 + 7) & 0xFF for i in range(65536))
    s = _session(srv.root_port)
    try:
        fh = _open_big(s)
        # a normal read of the first 64 KiB must return the exact bytes
        s.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, 0, 65536)))
        st, body = _read_response(s)
        assert st == kXR_ok, "post-attack read failed: %r" % st
        assert body == expected, "post-attack read returned wrong bytes"
        # a normal pgread must still verify (status framing intact)
        s.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 65536)))
        st, _ = _read_response(s)
        assert st in (kXR_ok, kXR_status), "post-attack pgread failed: %r" % st
    finally:
        try: s.close()
        except OSError: pass
    srv.assert_healthy("Phase E final integrity")
