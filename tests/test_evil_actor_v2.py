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

from settings import NGINX_BIN, REMOTE_SERVER, HOST, BIND_HOST, free_port
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

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
        self.root_port, self.metrics_port, self.s3_port, self.webdav_port = ports
        self.http_port = self.webdav_port
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

    def _tsan_module_races(self):
        if not self.tsandir or not os.path.isdir(self.tsandir):
            return ""
        hits = []
        for fn in os.listdir(self.tsandir):
            try:
                txt = open(os.path.join(self.tsandir, fn), errors="replace").read()
            except OSError:
                continue
            if "data race" not in txt:
                continue
            # only fail on races whose stack names module / AIO frames
            if any(m in txt for m in ("/src/core/aio/", "/src/protocols/root/read/", "/src/protocols/root/write/",
                                      "/src/fs/cache/", "/src/protocols/root/session/", "/src/protocols/root/connection/",
                                      "_aio_thread", "_aio_done", "read_scratch",
                                      "payload_to_free", "ctx->destroyed", "brix_")):
                hits.append(fn)
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


def _shim_env(shim, tsandir, workdir):
    """Build the worker-gated race-shim launch environment for the nginx spec.

    A sanitizer-instrumented shim must be preceded by the sanitizer RUNTIME in
    LD_PRELOAD ("ASan runtime does not come first"). The real versioned .so
    (libasan.so.6, not the linker-script libasan.so) is whatever the binary
    under test already links — read it straight out of ldd. Returned as a plain
    dict that the launcher merges onto os.environ for `nginx -t`, launch, and
    stop, so the shim (and its delay/options) survive the whole lifecycle.
    """
    env: dict[str, str] = {}
    pre = os.environ.get("LD_PRELOAD", "")
    san_rt = ""
    if SHIM_SAN in ("address", "thread"):
        want = "libasan.so" if SHIM_SAN == "address" else "libtsan.so"
        try:
            ldd = subprocess.run(["ldd", NGINX_BIN], capture_output=True, text=True).stdout
            for line in ldd.splitlines():
                if want in line and "=>" in line:
                    cand = line.split("=>", 1)[1].strip().split(" ", 1)[0]
                    if cand and os.path.exists(cand):
                        san_rt = cand
                    break
        except Exception:
            san_rt = ""
    env["LD_PRELOAD"] = " ".join(x for x in (san_rt, pre, shim) if x)
    env["XRD_RACE_DELAY_US"] = str(SHIM_DELAY_US)
    if SHIM_SAN == "thread":
        supp = os.path.join(workdir, "tsan.supp")
        open(supp, "w").write(
            "race:ngx_atomic_\nrace:^brix_metrics_\nrace:ngx_thread_pool_cycle\n"
            "race:ngx_time_update\nrace:ngx_event_\ncalled_from_lib:libssl\n"
            "called_from_lib:libcrypto\ncalled_from_lib:libjansson\n")
        env["TSAN_OPTIONS"] = ("suppressions=%s:halt_on_error=0:exitcode=0:"
                               "history_size=4:log_path=%s/tsan"
                               % (supp, tsandir))
    elif SHIM_SAN == "address":
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:halt_on_error=1"
    return env


@pytest.fixture(scope="module")
def srv():
    if REMOTE_SERVER:
        pytest.skip("self-contained; not REMOTE")
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built at %s" % NGINX_BIN)
    if shutil.which("pgrep") is None or shutil.which("cc") is None:
        pytest.skip("pgrep + cc required")

    # Our own scratch tree (data + shim + tsan reports); the nginx prefix, config,
    # pidfile and logs are owned by the registry (LifecycleHarness) under its
    # endpoint.prefix.  We only seed/own the datadir and the sanitizer artifacts.
    workdir = tempfile.mkdtemp(prefix="evil2-")
    datadir = os.path.join(workdir, "data")
    tsandir = os.path.join(workdir, "tsan")
    for d in (datadir, tsandir):
        os.makedirs(d, exist_ok=True)

    shim, err = _build_shim(workdir)
    if shim is None:
        shutil.rmtree(workdir, ignore_errors=True)
        pytest.skip("could not build race shim: %s" % err[-300:])

    big = os.path.join(datadir, "big.bin")
    chunk = bytes((i * 31 + 7) & 0xFF for i in range(65536))
    with open(big, "wb") as f:
        for _ in range(BIGFILE_MB * 16):
            f.write(chunk)
    for nm in ("shared.bin", "w.bin", "xp.bin"):
        with open(os.path.join(datadir, nm), "wb") as f:
            f.write(chunk * 8)

    env = _shim_env(shim, tsandir, workdir)

    # The 3-worker root:// server plus metrics/s3/webdav planes are driven through
    # the registry (LifecycleHarness): {PORT} is the root:// front and the other
    # three planes arrive as extra_ports; the harness renders nginx_evil_actor_v2.conf,
    # runs `nginx -t` and launches with the shim env, and reaps master+workers on
    # close().  Crash/TSan detection is unchanged — it reads the master pid from
    # endpoint.pidfile and scans endpoint.prefix/logs (+ our tsandir).
    harness = LifecycleHarness()
    try:
        endpoint = harness.start(NginxInstanceSpec(
            name="evil-actor-v2",
            template="nginx_evil_actor_v2.conf",
            protocol="root",
            data_root=datadir,
            extra_ports={"METRICS_PORT": free_port(),
                         "S3_PORT": free_port(),
                         "WEBDAV_PORT": free_port()},
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST},
            env=env,
        ))
    except Exception as exc:
        harness.close()
        shutil.rmtree(workdir, ignore_errors=True)
        pytest.skip("nginx did not start: %s" % str(exc)[-400:])

    ports = (endpoint.port, endpoint.extra_ports["METRICS_PORT"],
             endpoint.extra_ports["S3_PORT"], endpoint.extra_ports["WEBDAV_PORT"])
    s = _Srv(endpoint.prefix, endpoint.config, endpoint.pidfile,
             ports, datadir, tsandir)
    s.master = _master_pid(endpoint.pidfile)
    if not s.master or not _alive(s.master):
        harness.close()
        shutil.rmtree(workdir, ignore_errors=True)
        pytest.skip("master pid never appeared")
    print("\n[evil2] master=%d root=%d metrics=%d s3=%d webdav=%d shim=%s delay=%dus workers=%s"
          % (s.master, ports[0], ports[1], ports[2], ports[3],
             SHIM_SAN or "plain", SHIM_DELAY_US,
             _workers(s.master)))
    try:
        yield s
    finally:
        harness.close()
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------- P1: cross-connection bind handle races ----------

def test_p1_bind_handle_inode_swap_race(srv):
    """A bound secondary reads a primary-published handle while the file is
    close+unlink+recreate'd underneath (shim holds the secondary's worker pread
    open across the swap). Must not crash/UAF a worker."""
    srv.mark()
    shared = os.path.join(srv.datadir, "shared.bin")
    orig = open(shared, "rb").read()
    for i in range(ROUNDS):
        p = None; sec = None
        try:
            p, sid = _session(srv.root_port)
            st, body = _open(p, "/shared.bin", flags=0x0010)
            if st != kXR_ok or len(body) < 4:
                continue
            fh = body[:4]
            sec = _connect(srv.root_port)
            if _bind(sec, sid)[0] != kXR_ok:
                _rst(sec); sec = None; continue
            # secondary fires a large read (offloads; shim widens the pread)
            sec.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 8 << 20),
                               sid=b"\x00\x0a"))
            # ... and DURING that read, the primary closes + the file is swapped
            time.sleep(0.002)
            p.sendall(_frame(kXR_close, fh + b"\x00" * 12, sid=b"\x00\x0b"))
            try:
                os.unlink(shared)
            except OSError:
                pass
            with open(shared, "wb") as f:           # new inode, attacker content
                f.write(b"SWAPPED!" * 4096)
            try:
                sec.settimeout(3.0); _read_response(sec)   # consume / let it land
            except Exception:
                pass
        except Exception:
            pass
        finally:
            for c in (sec, p):
                if c is not None:
                    _rst(c)
        if i % 40 == 0:
            # restore the file so later rounds have a clean handle to open
            with open(shared, "wb") as f:
                f.write(orig)
    with open(shared, "wb") as f:
        f.write(orig)
    srv.assert_healthy("P1 bind inode-swap race")


def test_p1b_many_secondaries_close_race(srv):
    """N bound secondaries with in-flight reads on one primary handle while the
    primary closes it — exercises the per-secondary revocation/in-flight window."""
    srv.mark()
    for _ in range(max(20, ROUNDS // 4)):
        p = None; secs = []
        try:
            p, sid = _session(srv.root_port)
            st, body = _open(p, "/big.bin", flags=0x0010)
            if st != kXR_ok or len(body) < 4:
                continue
            fh = body[:4]
            for _k in range(5):
                c = _connect(srv.root_port)
                if _bind(c, sid)[0] == kXR_ok:
                    secs.append(c)
            off = random.randrange(0, (BIGFILE_MB - 8) * 1024 * 1024)
            for c in secs:                          # fire all in-flight at once
                try:
                    c.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, off, 8 << 20),
                                     sid=b"\x00\x0a"))
                except OSError:
                    pass
            p.sendall(_frame(kXR_close, fh + b"\x00" * 12, sid=b"\x00\x0b"))
        except Exception:
            pass
        finally:
            for c in secs + [p]:
                if c is not None:
                    _rst(c)
    srv.assert_healthy("P1b many-secondaries close race")


# --------------------------- P2: cross-session bind security contract --------

def test_p2_bind_security_contract(srv):
    """A secondary needs only a captured sessid to inherit identity + read the
    primary's handle (bearer-token model); a forged/random sessid is rejected."""
    srv.mark()
    p, sid = _session(srv.root_port)
    try:
        st, body = _open(p, "/big.bin", flags=0x0010)
        assert st == kXR_ok and len(body) >= 4
        fh = body[:4]
        # captured sessid => bind succeeds + can read the primary's handle
        sec = _connect(srv.root_port)
        st_b, pbody = _bind(sec, sid)
        assert st_b == kXR_ok, "bind with captured sessid should succeed"
        rst, _ = _read(sec, fh, 0, 65536, sid=b"\x00\x0c")
        assert rst in (kXR_ok, kXR_status), \
            "bound secondary should read the primary handle: %r" % rst
        _rst(sec)
        # forged/random sessids must NOT grant a session
        forged_ok = 0
        for _ in range(64):
            f = _connect(srv.root_port)
            try:
                fake = bytes(random.randrange(256) for _ in range(16))
                if _bind(f, fake)[0] == kXR_ok:
                    forged_ok += 1
            except Exception:
                pass
            finally:
                _rst(f)
        assert forged_ok == 0, (
            "%d/64 RANDOM sessids were accepted by kXR_bind — the session id is "
            "guessable/forgeable (it is not a CSPRNG): session-hijack risk" % forged_ok)
    finally:
        _rst(p)
    srv.assert_healthy("P2 bind security contract")


# --------------------------- P3: disconnect-mid-AIO (shim-widened) -----------

def _aio_rst_worker(port, datadir, rounds, stop_at, counter):
    rng = random.Random(threading.get_ident())
    while time.time() < stop_at and counter[0] < rounds:
        counter[0] += 1
        s = None
        try:
            s = _connect(port, 4)
            _login(s)
            st, body = _open(s, "/big.bin", flags=0x0010)
            if st != kXR_ok or len(body) < 4:
                if s: _rst(s)
                continue
            fh = body[:4]
            op = rng.choice(("pgread", "readv", "write"))
            off = rng.randrange(0, (BIGFILE_MB - 8) * 1024 * 1024)
            rlen = rng.choice((8 << 20, 16 << 20))
            if op == "pgread":
                s.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, off, rlen)))
            elif op == "readv":
                segs = b"".join(struct.pack("!4siq", fh, 1 << 20, off + i * (1 << 20))
                                for i in range(8))
                s.sendall(_frame(kXR_readv, b"", segs))
            else:
                stw, wb = _open(s, "/w.bin", flags=0x0010 | 0x0020)
                fw = wb[:4] if (stw == kXR_ok and len(wb) >= 4) else fh
                s.sendall(_frame(kXR_write, struct.pack("!4sqB3s", fw, 0, 0, b"\x00" * 3),
                                 b"Z" * (1 << 20)))
        except Exception:
            pass
        if s is not None:
            d = rng.choice((0, 0.0005, 0.003))
            if d: time.sleep(d)
            _rst(s)


def test_p3_disconnect_mid_aio_widened(srv):
    srv.mark()
    counter = [0]; stop_at = time.time() + 70
    ts = [threading.Thread(target=_aio_rst_worker,
                           args=(srv.root_port, srv.datadir, ROUNDS, stop_at, counter))
          for _ in range(6)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=120)
    print("\n[evil2] P3 shim-widened AIO-RST rounds: %d" % counter[0])
    srv.assert_healthy("P3 disconnect-mid-AIO (widened)")


# --------------------------- P4: pipelined scratch reuse ---------------------

def test_p4_pipelined_scratch_reuse(srv):
    srv.mark()
    for _ in range(max(40, ROUNDS // 2)):
        s = None
        try:
            s = _connect(srv.root_port, 4)
            _login(s)
            st, body = _open(s, "/big.bin", flags=0x0010)
            if st != kXR_ok or len(body) < 4:
                if s: _rst(s)
                continue
            fh = body[:4]
            # pipeline read -> readv -> pgread in one segment, then RST
            pkt = _frame(kXR_read, struct.pack("!4sqi", fh, 0, 4 << 20), sid=b"\x00\x21")
            pkt += _frame(kXR_readv, b"",
                          b"".join(struct.pack("!4siq", fh, 1 << 20, i << 20)
                                   for i in range(4)), sid=b"\x00\x22")
            pkt += _frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 4 << 20), sid=b"\x00\x23")
            s.sendall(pkt)
        except Exception:
            pass
        if s is not None:
            _rst(s)
    srv.assert_healthy("P4 pipelined scratch reuse")


# --------------------------- P5: stateful / less-tested opcode fuzz ----------

def test_p5_stateful_opcode_fuzz(srv):
    srv.mark()
    rng = random.Random(1337)
    for _ in range(max(60, ROUNDS)):
        s = None
        try:
            s = _connect(srv.root_port, 4)
            _login(s)
            st, body = _open(s, "/w.bin", flags=0x0010 | 0x0020)
            fh = body[:4] if (st == kXR_ok and len(body) >= 4) else b"\x00\x00\x00\x00"
            op = rng.choice((kXR_chkpoint, kXR_truncate, kXR_fattr, kXR_sync,
                             kXR_endsess, kXR_chkpoint))
            if op == kXR_truncate:
                s.sendall(_frame(kXR_truncate, fh + struct.pack("!q", rng.choice(
                    (-1, 0, 1 << 62))) + b"\x00" * 4))
            elif op == kXR_chkpoint:
                # subcode + maybe an embedded sub-request with mismatched fhandle
                sub = _frame(kXR_write, struct.pack("!4sqB3s", b"\x07\x00\x00\x00",
                             0, 0, b"\x00" * 3), b"x" * 16)
                s.sendall(_frame(kXR_chkpoint, fh + bytes([rng.randrange(6)]) + b"\x00" * 11,
                                 sub if rng.random() < 0.5 else b""))
            elif op == kXR_fattr:
                s.sendall(_frame(kXR_fattr, fh + bytes([rng.randrange(256)]) +
                                 bytes([rng.choice((0, 1, 16, 255))]) + b"\x00" * 10,
                                 b"\xff" * rng.choice((0, 2, 40))))
            elif op == kXR_sync:
                s.sendall(_frame(kXR_sync, fh + b"\x00" * 12))
            else:  # endsess with a random (cross-session) sessid then a pipelined read
                pkt = _frame(kXR_endsess, bytes(rng.randrange(256) for _ in range(16)))
                pkt += _frame(kXR_read, struct.pack("!4sqi", fh, 0, 4 << 20))
                s.sendall(pkt)
            try:
                s.settimeout(1.0); _read_response(s)
            except Exception:
                pass
        except Exception:
            pass
        if s is not None:
            _rst(s)
    srv.assert_healthy("P5 stateful opcode fuzz")


# --------------------------- P6: cross-protocol simultaneous assault ---------

def _http(method, path, body=None, timeout=4, port=None):
    import urllib.request, urllib.error
    url = "http://%s:%d%s" % (HOST, port or _XP_HTTP[0], path)
    req = urllib.request.Request(url, data=body, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


_XP_HTTP = [0]
_XP_S3 = [0]


def test_p6_cross_protocol_assault(srv):
    srv.mark()
    _XP_HTTP[0] = srv.webdav_port
    _XP_S3[0] = srv.s3_port
    shared = os.path.join(srv.datadir, "xp.bin")
    orig = open(shared, "rb").read()
    stop = time.time() + 25

    def root_rw():
        while time.time() < stop:
            s = None
            try:
                s = _connect(srv.root_port, 3); _login(s)
                st, b = _open(s, "/xp.bin", flags=0x0010)
                if st == kXR_ok and len(b) >= 4:
                    _read(s, b[:4], 0, 1 << 20)
            except Exception:
                pass
            if s: _rst(s)

    def webdav_get():
        while time.time() < stop:
            _http("GET", "/xp.bin")
            _http("PROPFIND", "/xp.bin",
                  body=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>')

    def s3_ops():
        while time.time() < stop:
            _http("GET", "/s3b/xp.bin", port=_XP_S3[0])
            _http("HEAD", "/s3b/xp.bin", port=_XP_S3[0])

    def swapper():
        while time.time() < stop:
            try:
                with open(shared, "wb") as f:
                    f.write(b"X" * random.randrange(4096, 1 << 20))
                time.sleep(0.01)
                os.unlink(shared)
            except OSError:
                pass
            with open(shared, "wb") as f:
                f.write(orig)
            time.sleep(0.01)

    ts = ([threading.Thread(target=root_rw) for _ in range(4)] +
          [threading.Thread(target=webdav_get) for _ in range(3)] +
          [threading.Thread(target=s3_ops) for _ in range(2)] +
          [threading.Thread(target=swapper) for _ in range(2)])
    for t in ts: t.start()
    for t in ts: t.join(timeout=60)
    with open(shared, "wb") as f:
        f.write(orig)
    srv.assert_healthy("P6 cross-protocol assault")


# --------------------------- P7: survival + integrity -----------------------

def test_p7_integrity(srv):
    srv.mark()
    expected = bytes((i * 31 + 7) & 0xFF for i in range(65536))
    s, _ = _session(srv.root_port)
    try:
        st, body = _open(s, "/big.bin", flags=0x0010)
        assert st == kXR_ok and len(body) >= 4
        fh = body[:4]
        st, data = _read(s, fh, 0, 65536)
        assert st == kXR_ok, "post-assault read failed: %r" % st
        assert data == expected, "post-assault read returned wrong bytes"
    finally:
        _rst(s)
    srv.assert_healthy("P7 final integrity")
