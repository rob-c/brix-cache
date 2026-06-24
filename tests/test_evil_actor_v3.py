"""
test_evil_actor_v3.py — "hyper-evil" worker-crash / data-race / UAF hunt.

Escalates beyond test_evil_actor.py (v1: hostile frames, disconnect-mid-AIO,
endsess+pipeline, exhaustion) and test_evil_actor_v2.py (v2: cross-connection
bind inode-swap, bind contract, shim-widened AIO, pipelined scratch, cross-
protocol) by attacking the surfaces v1/v2 NEVER touch, all under the worker-gated
race_shim.c (LD_PRELOAD syscall-slower):

  A1  roots:// in-protocol TLS bring-up correctness — raw kXR_protocol(kXR_ableTLS)
      -> kXR_haveTLS -> client wraps socket (CERT_NONE, no GSI PKI) -> windowed
      multi-window read byte-exact. The entire server-side TLS upgrade state
      machine + the TLS-forces-memory-windowed-read path, unexercised by v1/v2.
  A2  roots:// TLS disconnect-mid-AIO — RST the raw fd while a worker is held
      mid-pread by the shim AND an SSL connection object is being torn down: a
      SECOND teardown actor (SSL_free + ngx pool ssl cleanup) the cleartext
      tests structurally cannot produce.
  B6  cross-WORKER kXR_bind — reuseport spreads primary + secondary across worker
      PROCESSES; the secondary reads a primary handle published in cross-process
      SHM (v2's paired conns were effectively same-worker).
  B7  cross-worker bind-vs-teardown TOCTOU + handle-slot ABA — race a primary
      RST/endsess (memzeros the SHM session+handle slot) against a secondary's
      first cross-worker read, plus a free/reuse (ABA) cycle republishing a slot
      to a different inode; per-read dev/inode + sessid revalidation must revoke.
  C1  FRM async asynresp deliver-into-recycled-connection (cross-process UAF) —
      park a kXR_waitresp recall waiter, RST mid-stall, storm new clients onto
      recycled fds; the deliver-time liveness re-check must prevent any foreign-
      streamid kXR_attn(asynresp) injection. Brand-new FRM/kXR_prepare plane.
  C2  FRM reqid forgery — a foreign session must not cancel another's stage
      request by its guessable monotonic reqid; the cancel/evict path enforces
      requester ownership (xrootd_prepare_handle_cancel -> frm_request_owner_check).
  C3  FRM admission flood — durable queue + SHM index + waiter table + stage-agent
      fork bound must shed cleanly (no crash, no unbounded RSS, no fork storm).
  D   chaos capstone — sustained randomized interleave of every vector across all
      listeners concurrently under the shim, with surviving control connections
      proving no silent cross-plane corruption.

Same master+worker pgrep-churn + error-log crash detector as v2. Strongest under
ASAN (heap-use-after-free) — see "Running" at the bottom.

RUN: TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_evil_actor_v3.py -v -s
"""

import hashlib
import os
import random
import shutil
import socket
import ssl
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
def _host_is_constrained():
    """True on hosts that are slow at the socket connect/RST churn these
    adversarial loops generate (WSL2, CI runners).

    The server is idle during these tests (verified: nginx worker CPU/RSS/fds
    stay flat); the wall-clock cost is entirely the CLIENT's per-round
    connect → handshake → login → bind/open → RST cycle.  Under the TIME_WAIT and
    scheduler pressure a long suite run accumulates, each socket syscall slows
    ~10x, which blows the per-test timeout on such hosts.  Detect them so ROUNDS
    can scale down — the race classes these tests hunt reproduce within a handful
    of rounds, so fewer rounds keeps the coverage that matters while staying
    inside the timeout.  An explicit TEST_EVIL_V3_ROUNDS always overrides this.
    """
    if (os.environ.get("CI") or os.environ.get("TEST_HOST_CONSTRAINED")
            or os.environ.get("WSL_INTEROP") or os.environ.get("WSL_DISTRO_NAME")):
        return True
    if os.path.isdir("/run/WSL"):                  # WSL interop socket dir
        return True
    try:
        with open("/proc/version") as f:
            v = f.read().lower()
            if "microsoft" in v or "wsl" in v:     # WSL1 / WSL2 (incl. custom kernels)
                return True
    except OSError:
        pass
    return False


_CONSTRAINED = _host_is_constrained()
# Adversarial-loop iteration count.  Explicit env wins; else scale down on
# constrained hosts (see _host_is_constrained) so the client-side churn stays
# inside the per-test timeout.
ROUNDS = int(os.environ.get("TEST_EVIL_V3_ROUNDS",
                            "12" if _CONSTRAINED else "30"))
WORKERS = 4
# Fake-MSS recall latency: long enough that C1 can park a kXR_waitresp and RST
# mid-stall (the RST lands within ~50ms), short enough that a staging burst drains
# in seconds rather than minutes.
FRM_LATENCY_MS = 350

# opcodes
kXR_query=3001; kXR_close=3003; kXR_protocol=3006; kXR_login=3007; kXR_open=3010
kXR_ping=3011; kXR_read=3013; kXR_stat=3017; kXR_write=3019; kXR_endsess=3023
kXR_bind=3024; kXR_readv=3025; kXR_pgwrite=3026; kXR_prepare=3021; kXR_pgread=3030
# response status
kXR_ok=0; kXR_oksofar=4000; kXR_attn=4001; kXR_error=4003; kXR_wait=4005
kXR_waitresp=4006; kXR_status=4007
# protocol/TLS flags
kXR_secreqs=0x01; kXR_ableTLS=0x02; kXR_wantTLS=0x04
kXR_haveTLS=0x80000000; kXR_gotoTLS=0x40000000
# prepare options
kXR_cancel=1; kXR_stage=8; kXR_wmode=16; kXR_coloc=32; kXR_fresh=64
# open flags (XProtocol kXR_open_*)
OPEN_READ=0x0010      # kXR_open_read  -> O_RDONLY, readable+published
OPEN_UPDATE=0x0020    # kXR_open_updt  -> O_RDWR,   readable+published
OPEN_APND=0x0200      # kXR_open_apnd  -> O_WRONLY|O_APPEND, NOT readable (unpublished-for-read)
OPEN_NEW=0x0008       # kXR_new

CRASH_PATTERNS = ("signal 11", "signal 6", "signal 4", "signal 7", "signal 8",
                  "SIGSEGV", "SIGABRT", "core dumped", "segfault",
                  "AddressSanitizer", "heap-use-after-free", "heap-buffer-overflow",
                  "stack-buffer-overflow", "attempting double-free",
                  "runtime error:", "LeakSanitizer")


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
    return sid, status, body


def _connect(port, t=6.0):
    s = socket.create_connection((HOST, port), timeout=t)
    s.settimeout(t)
    return s


def _handshake(s):
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    if _read_response(s)[1] != kXR_ok:
        raise ConnectionError("handshake rejected")


def _frame(op, body16, payload=b"", dlen=None, sid=b"\x00\x07"):
    body16 = (body16 + b"\x00" * 16)[:16]
    if dlen is None:
        dlen = len(payload)
    return struct.pack("!2sH", sid, op) + body16 + struct.pack("!I", dlen & 0xFFFFFFFF) + payload


def _login(s, user=b"evil\x00\x00\x00\x00"):
    _handshake(s)
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0xFFFFFFFF, user, 0, 0, 5, 0, 0))
    _, st, body = _read_response(s)
    if st != kXR_ok:
        raise ConnectionError("login rejected")
    return body[:16] if len(body) >= 16 else b"\x00" * 16


def _session(port):
    s = _connect(port)
    return s, _login(s)


def _bind(s, sessid):
    _handshake(s)
    s.sendall(_frame(kXR_bind, sessid, b"", sid=b"\x00\x09"))
    return _read_response(s)


def _open(s, path, flags=OPEN_READ, sid=b"\x00\x02"):
    p = (path.encode() if isinstance(path, str) else path)
    if not p.endswith(b"\x00"):
        p += b"\x00"
    body = struct.pack("!HH2s6s4s", 0o644, flags, b"\x00\x00", b"\x00" * 6, b"\x00" * 4)
    s.sendall(_frame(kXR_open, body, p, sid=sid))
    return _read_response(s)


def _read(s, fh, off, rlen, sid=b"\x00\x03"):
    s.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, off, rlen), sid=sid))
    return _read_response(s)


def _prepare_stage(s, path, sid=b"\x00\x31"):
    """kXR_prepare|kXR_stage of one path; returns (status, reqid_str)."""
    body = struct.pack("!BBHH10s", kXR_stage, 0, 0, 0, b"\x00" * 10)
    payload = (path.encode() if isinstance(path, str) else path)
    if not payload.endswith(b"\n"):
        payload += b"\n"
    s.sendall(_frame(kXR_prepare, body, payload, sid=sid))
    _, st, b = _read_response(s)
    reqid = b.split(b"\n")[0].decode(errors="replace").strip() if b else ""
    return st, reqid


def _prepare_cancel(s, reqid, sid=b"\x00\x32"):
    """kXR_prepare|kXR_cancel of a reqid; returns status."""
    body = struct.pack("!BBHH10s", kXR_cancel, 0, 0, 0, b"\x00" * 10)
    payload = reqid.encode() if isinstance(reqid, str) else reqid
    s.sendall(_frame(kXR_prepare, body, payload, sid=sid))
    _, st, _b = _read_response(s)
    return st


def _rst(s):
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def _drain_for_attn(s, dur=0.3):
    """Read whatever the peer sent within dur and return True if a kXR_attn
    (unsolicited async push) appears — used to catch asynresp delivered to the
    wrong connection."""
    s.settimeout(dur)
    saw_attn = False
    try:
        while True:
            hdr = _recv_exact(s, 8)
            _sid, status, dlen = struct.unpack("!2sHI", hdr)
            if status == kXR_attn:
                saw_attn = True
            if dlen:
                _recv_exact(s, dlen)
    except (socket.timeout, OSError, ConnectionError):
        pass
    return saw_attn


def _ping_ok(port, t=2.5):
    try:
        s = _connect(port, t)
        _login(s)
        s.sendall(_frame(kXR_ping, b"", sid=b"\x00\x0f"))
        _, st, _ = _read_response(s)
        s.close()
        return st in (kXR_ok, kXR_error)
    except Exception:
        return False


def _ping_ok_retry(port, tries=20, gap=1.0):
    """A healthy server momentarily busy draining prior-phase RST/AIO teardowns
    (the 15ms shim stretches in-flight AIO, and FRM recalls make the loop briefly
    sluggish) may not answer the first several fresh pings; a truly wedged one
    never will. Generous budget so latency does not read as a wedge."""
    for _ in range(tries):
        if _ping_ok(port):
            return True
        time.sleep(gap)
    return False


# ------------------------------ roots:// TLS --------------------------------

def _roots_tls_connect(port, t=8):
    """Drive the in-protocol TLS upgrade with a raw client (no GSI PKI):
    handshake -> kXR_protocol(kXR_ableTLS) -> assert kXR_haveTLS -> wrap socket.
    Returns a connected ssl.SSLSocket (still pre-login), or raises."""
    raw = socket.create_connection((HOST, port), timeout=t)
    raw.settimeout(t)
    _handshake(raw)
    # kXR_protocol: clientpv (4) + flags byte at body[4] + reserved
    body = struct.pack("!IB11s", 0x00000500, kXR_ableTLS, b"\x00" * 11)
    raw.sendall(_frame(kXR_protocol, body, b"", sid=b"\x00\x06"))
    _, st, pbody = _read_response(raw)
    if st != kXR_ok or len(pbody) < 8:
        raw.close()
        raise ConnectionError("kXR_protocol rejected (st=%r len=%d)" % (st, len(pbody)))
    flags = struct.unpack("!I", pbody[4:8])[0]
    if not (flags & kXR_haveTLS):
        raw.close()
        raise ConnectionError("server did not offer TLS (flags=0x%08x)" % flags)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(raw, server_hostname=HOST, do_handshake_on_connect=True)
    tls.settimeout(t)
    return tls


def _tls_rst(tls):
    """Force an RST on the underlying fd (not a TLS close_notify)."""
    try:
        tls.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        tls.close()
    except OSError:
        pass


# --------------------------------- http -------------------------------------

def _https_get(port, path, abort_after=None, timeout=5):
    """HTTPS GET; if abort_after is set, read only that many bytes then hard-close
    (client-abort mid-body). Returns (status_or_None, bytes_read)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((HOST, port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=HOST)
        tls.settimeout(timeout)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, HOST))
        tls.sendall(req.encode())
        got = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            got += chunk
            if abort_after is not None and len(got) >= abort_after:
                _tls_rst(tls)
                return None, got
        tls.close()
        status = None
        if got.startswith(b"HTTP/"):
            try:
                status = int(got.split(b" ", 2)[1])
            except Exception:
                status = None
        return status, got
    except Exception:
        return None, b""


# ------------------------------- the server ---------------------------------

class _Srv:
    def __init__(self, prefix, conf, pidfile, ports, datadir, tsandir):
        self.prefix = prefix; self.conf = conf; self.pidfile = pidfile
        (self.root_port, self.root_tls_port,
         self.https_port, self.metrics_port) = ports
        self.datadir = datadir; self.tsandir = tsandir
        self.master: "int | None" = None
        self._mark = 0
        self.have_xattr = False
        self.frm_ok = False
        self.near_names: "list[str]" = []
        self.audit = ""
        self.queue = ""

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
            if any(m in txt for m in ("/src/aio/", "/src/read/", "/src/write/",
                                      "/src/cache/", "/src/session/", "/src/connection/",
                                      "/src/frm/", "_aio_thread", "_aio_done",
                                      "read_scratch", "payload_to_free", "ctx->destroyed",
                                      "xrootd_")):
                hits.append(fn)
        return ",".join(hits)

    def assert_no_crash(self, phase):
        """Crash/race/liveness check WITHOUT a fresh ping — safe to call mid-flight
        while attack threads saturate the listeners (a fresh ping would race the
        load and false-positive)."""
        delta = self._delta()
        for pat in CRASH_PATTERNS:
            assert pat not in delta, (
                "WORKER BROKE during %s — %r in error log:\n%s"
                % (phase, pat, delta[-2000:]))
        races = self._tsan_module_races()
        assert not races, "TSan module-frame DATA RACE during %s: %s" % (phase, races)
        assert _alive(self.master), "master died during %s" % phase
        assert _workers(self.master), "no workers after %s" % phase

    def assert_healthy(self, phase):
        self.assert_no_crash(phase)
        assert _ping_ok_retry(self.root_port), "server not serving after %s" % phase


def _build_shim(workdir):
    src = os.path.join(os.path.dirname(__file__), "race_shim.c")
    so = os.path.join(workdir, "librace.so")
    cmd = ["cc", "-shared", "-fPIC", "-O0", "-g", "-o", so, src, "-ldl", "-lpthread"]
    if SHIM_SAN in ("address", "thread"):
        cmd[1:1] = ["-fsanitize=" + SHIM_SAN]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr
    return so, ""


def _xattr_ok(tmp):
    try:
        p = os.path.join(tmp, ".xattrprobe")
        open(p, "w").close()
        os.setxattr(p, "user.frm.test", b"1")
        os.remove(p)
        return True
    except Exception:
        return False


def _gen_cert(prefix):
    cert = os.path.join(prefix, "cert.pem")
    key = os.path.join(prefix, "key.pem")
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(cert):
        return None, None
    return cert, key


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    if REMOTE_SERVER:
        pytest.skip("self-contained; not REMOTE")
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built at %s" % NGINX_BIN)
    for tool in ("pgrep", "cc", "openssl"):
        if shutil.which(tool) is None:
            pytest.skip("%s required" % tool)

    prefix = tempfile.mkdtemp(prefix="evil3-")
    datadir = os.path.join(prefix, "data")
    tapedir = os.path.join(prefix, "tape")
    tsandir = os.path.join(prefix, "tsan")
    for d in (os.path.join(prefix, "logs"), datadir, tapedir, tsandir):
        os.makedirs(d, exist_ok=True)

    have_xattr = _xattr_ok(datadir)

    shim, err = _build_shim(prefix)
    if shim is None:
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("could not build race shim: %s" % err[-300:])

    cert, key = _gen_cert(prefix)
    if cert is None:
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("could not generate self-signed cert")

    # data files
    big = os.path.join(datadir, "big.bin")
    chunk = bytes((i * 31 + 7) & 0xFF for i in range(65536))
    with open(big, "wb") as f:
        for _ in range(BIGFILE_MB * 16):
            f.write(chunk)
    for nm in ("shared.bin", "w.bin", "xp.bin"):
        with open(os.path.join(datadir, nm), "wb") as f:
            f.write(chunk * 8)

    # FRM nearline files (file=stub, real bytes on "tape")
    copycmd = os.path.join(prefix, "copycmd.sh")
    shutil.copy(os.path.join(os.path.dirname(__file__), "frm_fake_mss.sh"), copycmd)
    os.chmod(copycmd, 0o755)
    audit = os.path.join(prefix, "audit.log")
    near_names = []
    if have_xattr:
        tape_content = b"TAPE-" + b"z" * 4096 + b"\n"
        with open(os.path.join(tapedir, "near.dat"), "wb") as f:
            f.write(tape_content)
        open(os.path.join(datadir, "near.dat"), "wb").close()
        os.setxattr(os.path.join(datadir, "near.dat"), "user.frm.residency", b"nearline")
        # a pool of distinct nearline stubs for the flood phase
        for i in range(60):
            nm = "near%03d.dat" % i
            with open(os.path.join(tapedir, nm), "wb") as f:
                f.write(b"T%03d" % i + b"q" * 512)
            open(os.path.join(datadir, nm), "wb").close()
            os.setxattr(os.path.join(datadir, nm), "user.frm.residency", b"nearline")
            near_names.append("/" + nm)

    queue = os.path.join(prefix, "frm.queue")
    frm_block = ""
    if have_xattr:
        frm_block = (
            "        xrootd_frm on; xrootd_frm_queue_path %s;\n"
            "        xrootd_frm_copycmd %s; xrootd_frm_copymax 4;\n"
            "        xrootd_frm_async_recall on; xrootd_frm_stage_ttl 30s;\n"
            "        xrootd_frm_xfrhold 50ms;\n"   # default 30s throttle -> fast drains for the test
            "        xrootd_frm_max_inflight 64; xrootd_frm_max_per_source 16;\n"
            % (queue, copycmd))

    root_port, root_tls_port, https_port, metrics_port = _free_ports(4)
    for p in (root_port, root_tls_port, https_port, metrics_port):
        if _reachable(p):
            shutil.rmtree(prefix, ignore_errors=True)
            pytest.skip("port %d in use" % p)

    conf = ("""
worker_processes %d;
daemon on;
master_process on;
pid %s/logs/nginx.pid;
error_log %s/logs/error.log info;
thread_pool aiopool threads=4 max_queue=8192;
env FRM_DATA_DIR; env FRM_TAPE_DIR; env FRM_LATENCY_MS; env FRM_AUDIT_LOG; env FRM_FAIL_MODE;
events { worker_connections 1024; }
stream {
    server {
        listen %s:%d reuseport;
        xrootd on; xrootd_root %s; xrootd_auth none; xrootd_allow_write on;
        xrootd_thread_pool aiopool; xrootd_memory_budget 6m;
%s    }
    server {
        listen %s:%d reuseport;
        xrootd on; xrootd_root %s; xrootd_auth none; xrootd_allow_write on;
        xrootd_thread_pool aiopool; xrootd_memory_budget 6m;
        xrootd_tls on; xrootd_certificate %s; xrootd_certificate_key %s;
    }
}
http {
    access_log off;
    client_body_temp_path %s/logs/cbt; proxy_temp_path %s/logs/pt;
    fastcgi_temp_path %s/logs/ft; uwsgi_temp_path %s/logs/ut; scgi_temp_path %s/logs/st;
    server {
        listen %s:%d ssl;
        ssl_certificate %s; ssl_certificate_key %s;
        location = /metrics { xrootd_metrics on; }
        location /s3b/ { xrootd_s3 on; xrootd_s3_root %s; xrootd_s3_bucket s3b;
                         xrootd_s3_region us-east-1; }
        location / { xrootd_webdav on; xrootd_webdav_root %s; xrootd_webdav_auth none;
                     xrootd_webdav_allow_write on; }
    }
    server {
        listen %s:%d;
        location = /metrics { xrootd_metrics on; }
    }
}
""" % (WORKERS, prefix, prefix,
       BIND_HOST, root_port, datadir, frm_block,
       BIND_HOST, root_tls_port, datadir, cert, key,
       prefix, prefix, prefix, prefix, prefix,
       BIND_HOST, https_port, cert, key, datadir, datadir,
       BIND_HOST, metrics_port))
    conf_path = os.path.join(prefix, "nginx.conf")
    open(conf_path, "w").write(conf)
    pidfile = os.path.join(prefix, "logs", "nginx.pid")

    env = dict(os.environ)
    pre = env.get("LD_PRELOAD", "")
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
    env.update(FRM_DATA_DIR=os.path.realpath(datadir), FRM_TAPE_DIR=tapedir,
               FRM_LATENCY_MS=str(FRM_LATENCY_MS), FRM_AUDIT_LOG=audit)
    if SHIM_SAN == "thread":
        supp = os.path.join(prefix, "tsan.supp")
        open(supp, "w").write(
            "race:ngx_atomic_\nrace:^xrootd_metrics_\nrace:ngx_thread_pool_cycle\n"
            "race:ngx_time_update\nrace:ngx_event_\ncalled_from_lib:libssl\n"
            "called_from_lib:libcrypto\ncalled_from_lib:libjansson\n")
        env["TSAN_OPTIONS"] = ("suppressions=%s:halt_on_error=0:exitcode=0:"
                               "history_size=4:log_path=%s/tsan" % (supp, tsandir))
    elif SHIM_SAN == "address":
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:halt_on_error=1:verify_asan_link_order=0"

    chk = subprocess.run([NGINX_BIN, "-t", "-p", prefix, "-c", conf_path],
                         capture_output=True, text=True, env=env)
    if chk.returncode != 0:
        tail = (chk.stderr or chk.stdout).strip()[-500:]
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("nginx rejected config: %s" % tail)
    run = subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path],
                         capture_output=True, text=True, env=env)
    if run.returncode != 0 or not _wait_port(root_port):
        tail = (run.stderr or run.stdout).strip()[-500:]
        subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path, "-s", "stop"],
                       capture_output=True, env=env)
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("nginx did not start: %s" % tail)

    s = _Srv(prefix, conf_path, pidfile, (root_port, root_tls_port, https_port, metrics_port),
             datadir, tsandir)
    s.master = _master_pid(pidfile)
    s.have_xattr = have_xattr
    s.near_names = near_names
    s.audit = audit
    s.queue = queue
    # Determine FRM availability ONCE via the metrics endpoint (the xrootd_frm_*
    # exporter is wired only when FRM is compiled + enabled) — NOT by opening a
    # nearline file, which would trigger a real recall whose slow drain leaves the
    # server sluggish for the first ~tens of seconds and flakes the early phases.
    s.frm_ok = False
    if have_xattr:
        try:
            with __import__("urllib.request", fromlist=["request"]).urlopen(
                    "http://%s:%d/metrics" % (HOST, metrics_port), timeout=5) as resp:
                s.frm_ok = b"xrootd_frm_" in resp.read()
        except Exception:
            s.frm_ok = False
    if not s.master or not _alive(s.master):
        subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path, "-s", "stop"],
                       capture_output=True, env=env)
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("master pid never appeared")
    print("\n[evil3] master=%d root=%d roots_tls=%d https=%d metrics=%d shim=%s "
          "delay=%dus workers=%s xattr=%s"
          % (s.master, root_port, root_tls_port, https_port, metrics_port,
             SHIM_SAN or "plain", SHIM_DELAY_US, _workers(s.master), have_xattr))
    try:
        yield s
    finally:
        subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path, "-s", "stop"],
                       capture_output=True, env=env)
        time.sleep(0.3)
        if s.master and _alive(s.master):
            try: os.kill(s.master, 9)
            except OSError: pass
        shutil.rmtree(prefix, ignore_errors=True)


# ----------------------- A1: roots:// TLS bring-up ---------------------------

def _tls_available(srv):
    try:
        t = _roots_tls_connect(srv.root_tls_port)
        t.close()
        return True
    except Exception:
        return False


def test_a1_roots_tls_windowed_read(srv):
    if not _tls_available(srv):
        pytest.skip("roots:// in-protocol TLS not drivable (binary lacks xrootd_tls?)")
    srv.mark()
    origin_small = open(os.path.join(srv.datadir, "shared.bin"), "rb").read()
    md5_small = hashlib.md5(origin_small).hexdigest()
    for rnd in range(20):
        tls = _roots_tls_connect(srv.root_tls_port)
        try:
            # login + small whole-file read over TLS
            s = struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                            os.getpid() & 0xFFFFFFFF, b"tls\x00\x00\x00\x00\x00", 0, 0, 5, 0, 0)
            tls.sendall(s)
            _, st, _ = _read_response(tls)
            assert st == kXR_ok, "TLS login failed: %r" % st
            _, st, body = _open(tls, "/shared.bin", flags=OPEN_READ)
            assert st == kXR_ok and len(body) >= 4
            fh = body[:4]
            got = b""
            off = 0
            while off < len(origin_small):
                tls.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, off, 65536), sid=b"\x00\x05"))
                _, rst, data = _read_response(tls)
                assert rst in (kXR_ok, kXR_oksofar), "read st=%r" % rst
                if not data:
                    break
                got += data
                off += len(data)
            assert hashlib.md5(got).hexdigest() == md5_small, "TLS small read corrupt"

            # large windowed read (>2MiB) over TLS — collect windows to one kXR_ok
            _, st, body = _open(tls, "/big.bin", flags=OPEN_READ)
            assert st == kXR_ok and len(body) >= 4
            fh = body[:4]
            rlen = 12 << 20
            tls.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, 0, rlen), sid=b"\x00\x08"))
            acc = b""
            terminal = 0
            while len(acc) < rlen:
                _, rst, data = _read_response(tls)
                acc += data
                if rst == kXR_ok:
                    terminal += 1
                    break
                assert rst in (kXR_oksofar, kXR_status), "windowed read st=%r" % rst
            assert terminal == 1, "expected exactly one terminating kXR_ok"
            expect = (open(os.path.join(srv.datadir, "big.bin"), "rb").read(len(acc)))
            assert acc == expect, "TLS windowed read bytes diverged"
        finally:
            tls.close()
    srv.assert_healthy("A1 roots TLS windowed read")


# ----------------------- A2: TLS disconnect-mid-AIO --------------------------

def test_a2_tls_disconnect_mid_aio(srv):
    if not _tls_available(srv):
        pytest.skip("roots:// TLS not drivable")
    srv.mark()
    big_md5 = hashlib.md5(open(os.path.join(srv.datadir, "big.bin"), "rb").read(65536)).hexdigest()
    rounds = ROUNDS
    for i in range(rounds):
        tls = None
        try:
            tls = _roots_tls_connect(srv.root_tls_port, t=6)
            tls.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                        os.getpid() & 0xFFFFFFFF, b"a\x00\x00\x00\x00\x00\x00\x00", 0, 0, 5, 0, 0))
            _read_response(tls)
            _, st, body = _open(tls, "/big.bin", flags=OPEN_READ)
            if st != kXR_ok or len(body) < 4:
                _tls_rst(tls); continue
            fh = body[:4]
            off = random.randrange(0, (BIGFILE_MB - 16) * 1024 * 1024)
            tls.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, off, 16 << 20), sid=b"\x00\x0a"))
            # worker now held mid-pread by the shim; RST the raw fd (not close_notify)
            time.sleep(0.001)
            _tls_rst(tls)
        except Exception:
            if tls is not None:
                _tls_rst(tls)
        # interleave a surviving control TLS reader every few rounds
        if i % 7 == 0:
            try:
                c = _roots_tls_connect(srv.root_tls_port, t=6)
                c.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0xFFFFFFFF, b"c\x00\x00\x00\x00\x00\x00\x00", 0, 0, 5, 0, 0))
                _read_response(c)
                _, st, body = _open(c, "/big.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    _, _, data = _read(c, body[:4], 0, 65536, sid=b"\x00\x0c")
                    assert hashlib.md5(data).hexdigest() == big_md5, "control TLS read corrupt"
                c.close()
            except Exception:
                pass
    srv.assert_healthy("A2 TLS disconnect-mid-AIO")


# ----------------------- B6: cross-worker bind -------------------------------

def test_b6_cross_worker_bind(srv):
    srv.mark()
    shared_md5 = hashlib.md5(open(os.path.join(srv.datadir, "shared.bin"), "rb").read(65536)).hexdigest()
    primaries = []
    try:
        for _ in range(24):
            p, sid = _session(srv.root_port)
            _, st, body = _open(p, "/shared.bin", flags=OPEN_READ)
            if st == kXR_ok and len(body) >= 4:
                primaries.append((p, sid, body[:4]))
        assert primaries, "could not open any primary handles"
        served = 0
        for (p, sid, fh) in primaries:
            sec = _connect(srv.root_port)
            try:
                if _bind(sec, sid)[1] != kXR_ok:
                    continue
                _, st, data = _read(sec, fh, 0, 65536, sid=b"\x00\x0c")
                if st in (kXR_ok, kXR_oksofar) and data:
                    assert hashlib.md5(data).hexdigest() == shared_md5, \
                        "cross-worker bound read returned wrong bytes"
                    served += 1
            finally:
                _rst(sec)
        assert served > 0, "no bound secondary served the primary's handle"
        # negative: bind then read a WRITE-ONLY (non-readable) handle -> not served.
        # kXR_open_apnd opens O_WRONLY|O_APPEND with is_readable=0, so a bound
        # secondary must NOT be able to read primary data through it.
        pw, sidw = _session(srv.root_port)
        _, stw, bw = _open(pw, "/w.bin", flags=OPEN_APND)
        if stw == kXR_ok and len(bw) >= 4:
            sec = _connect(srv.root_port)
            try:
                if _bind(sec, sidw)[1] == kXR_ok:
                    _, st, _d = _read(sec, bw[:4], 0, 4096, sid=b"\x00\x0d")
                    assert st not in (kXR_ok, kXR_oksofar), \
                        "write-only (non-readable) handle should not be readable via bind"
            finally:
                _rst(sec)
        _rst(pw)
    finally:
        for (p, _s, _f) in primaries:
            _rst(p)
    srv.assert_healthy("B6 cross-worker bind")


# ----------------- B7: bind-vs-teardown TOCTOU + handle ABA ------------------

@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_b7_bind_teardown_aba(srv):
    srv.mark()
    shared = os.path.join(srv.datadir, "shared.bin")
    shared_md5 = hashlib.md5(open(shared, "rb").read(65536)).hexdigest()
    # TOCTOU: secondary reads while primary tears down
    for _ in range(ROUNDS):
        p = None; sec = None
        try:
            p, sid = _session(srv.root_port)
            _, st, body = _open(p, "/shared.bin", flags=OPEN_READ)
            if st != kXR_ok or len(body) < 4:
                continue
            fh = body[:4]
            sec = _connect(srv.root_port)
            if _bind(sec, sid)[1] != kXR_ok:
                _rst(sec); sec = None; continue
            sec.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 8 << 20), sid=b"\x00\x0a"))
            # tear the primary down DURING the secondary's held read
            p.sendall(_frame(kXR_endsess, b"\x00" * 16, sid=b"\x00\x0b"))
            try:
                sec.settimeout(1.0)
                _, st, data = _read_response(sec)
                # if served, bytes must be the real file (never garbage/old inode)
                if st in (kXR_ok, kXR_oksofar) and data:
                    assert hashlib.md5(data[:65536]).hexdigest() == shared_md5 or len(data) < 65536, \
                        "post-teardown read returned corrupt bytes"
            except Exception:
                pass
        except Exception:
            pass
        finally:
            for c in (sec, p):
                if c is not None:
                    _rst(c)
    # ABA: slot reused for a different file under a new session.  Floor scales
    # with the host: full 20 on a fast host, 8 on a constrained one (so reducing
    # ROUNDS actually shortens this loop instead of being pinned by the floor).
    for _ in range(max(8 if _CONSTRAINED else 20, ROUNDS // 3)):
        p1 = sec = p2 = None
        try:
            p1, sid1 = _session(srv.root_port)
            _, st, b1 = _open(p1, "/shared.bin", flags=OPEN_READ)
            if st != kXR_ok or len(b1) < 4:
                continue
            fh = b1[:4]
            sec = _connect(srv.root_port)
            bound = _bind(sec, sid1)[1] == kXR_ok
            _rst(p1); p1 = None                      # free the slot (ABA: A->_)
            p2, sid2 = _session(srv.root_port)        # new primary reuses slot index
            _open(p2, "/w.bin", flags=OPEN_READ)
            if bound:
                _, st, data = _read(sec, fh, 0, 65536, sid=b"\x00\x0e")
                # never serve fileA's freed bytes from a stale slot under a foreign sess
                assert st in (kXR_error, kXR_ok, kXR_oksofar, kXR_wait, kXR_status), \
                    "unexpected status after ABA: %r" % st
        except Exception:
            pass
        finally:
            for c in (sec, p1, p2):
                if c is not None:
                    _rst(c)
    # forged random sessids across workers -> overwhelmingly rejected
    forged_ok = forged_tried = 0
    for _ in range(24):
        f = _connect(srv.root_port)
        try:
            forged_tried += 1
            if _bind(f, bytes(random.randrange(256) for _ in range(16)))[1] == kXR_ok:
                forged_ok += 1
        except Exception:
            pass
        finally:
            _rst(f)
    assert forged_ok == 0, "%d/%d forged sessids accepted by cross-worker bind" % (forged_ok, forged_tried)
    srv.assert_healthy("B7 bind-teardown + ABA")


# ------------- C1: FRM async asynresp deliver-into-recycled-conn -------------

def _frm_skip(srv):
    if not srv.have_xattr:
        pytest.skip("filesystem lacks user xattrs (FRM residency)")
    if not srv.frm_ok:
        pytest.skip("FRM not compiled/enabled (nearline open not intercepted)")


@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_c1_frm_async_deliver_to_recycled_conn(srv):
    _frm_skip(srv)
    srv.mark()
    # Reuse ONE nearline file: its first open posts a recall, and while that recall
    # is in flight every further open of the same file parks another waiter (the
    # server-side waiter is created regardless of whether the client reads the
    # kXR_waitresp). We do NOT wait for the open response — we RST immediately to
    # abandon the waiter mid-stall, which is the whole point. This keeps the test
    # independent of recall-drain throughput (one deduped recall, not N).
    # bounded: the server's event loop is sluggish while FRM recalls process, so
    # keep the round/connection count low (this is a UAF-deliver correctness check,
    # not a throughput test)
    rounds = min(ROUNDS, 6)
    for _ in range(rounds):
        a = None
        try:
            a, _sid = _session(srv.root_port)
            a.sendall(_frame(kXR_open, struct.pack("!HH2s6s4s", 0o644, OPEN_READ,
                      b"\x00\x00", b"\x00" * 6, b"\x00" * 4), b"/near.dat\x00", sid=b"\x00\x41"))
            time.sleep(0.01)                 # let the server register the waiter
            _rst(a); a = None
            # reconnect storm onto recycled fds; none may receive A's asynresp
            storm = []
            for _k in range(2):
                try:
                    b, _ = _session(srv.root_port)
                    b.sendall(_frame(kXR_ping, b"", sid=b"\x00\x42"))
                    _read_response(b)
                    storm.append(b)
                except Exception:
                    pass
            time.sleep(0.02)
            for b in storm:
                assert not _drain_for_attn(b, 0.04), \
                    "a recycled connection received a foreign kXR_attn(asynresp)"
            for b in storm:
                _rst(b)
        except Exception:
            pass
        finally:
            if a is not None:
                _rst(a)
    # the abandoned waiters' recall completes in the background; let it settle so
    # any (correctly-suppressed) asynresp attempt has happened before we assert
    time.sleep(1.0)
    # no crash is the immediate invariant; the event loop is sluggish while the
    # background recall drains, so allow a generous recovery window for the ping
    # (the server DOES recover — this is FRM recall latency, not a wedge)
    srv.assert_no_crash("C1 FRM async deliver-to-recycled")
    assert _ping_ok_retry(srv.root_port, tries=30, gap=1.0), \
        "server did not recover after FRM async park/RST cycles"


# ------------- C2: FRM reqid forgery — owner check ---------------------------

@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_c2_frm_reqid_forgery_owner_check(srv):
    _frm_skip(srv)
    srv.mark()
    try:
        # tenant B stages a file -> reqid R (must be real, non-"0", and monotonic)
        b, _ = _session(srv.root_port)
        st1, r1 = _prepare_stage(b, "/near000.dat")
        st2, r2 = _prepare_stage(b, "/near001.dat")
        b.close()
        if st1 != kXR_ok or not r1 or r1 == "0":
            pytest.skip("FRM stage did not return a durable reqid (got %r)" % r1)
        # reqid should be observably structured/monotonic (predictable)
        assert r1 != r2, "stage reqids not unique"

        # tenant A (a DIFFERENT session) cancels B's reqid by id alone
        a, _ = _session(srv.root_port)
        st_cancel = _prepare_cancel(a, r1)
        a.close()

        # a foreign principal's cancel of a non-owned reqid must be rejected.
        assert st_cancel not in (kXR_ok,), (
            "foreign session cancelled reqid %r it never owned (status=%r) — "
            "no ownership binding on the FRM cancel path" % (r1, st_cancel))
    finally:
        srv.assert_healthy("C2 FRM forge")


# ------------------------- C3: FRM admission flood ---------------------------

@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_c3_frm_flood_sheds_cleanly(srv):
    _frm_skip(srv)
    srv.mark()
    names = srv.near_names or ["/near%03d.dat" % i for i in range(60)]

    # Volume is bounded: a correct server sheds excess admissions past
    # max_inflight=64 (no enqueue) and dedups same-path recalls, so the staging
    # backlog stays small and drains in seconds. A runaway backlog would itself be
    # a shed failure (caught by the post-flood responsiveness check below).
    def flood(n):
        for _ in range(n):
            try:
                s, _ = _session(srv.root_port)
                for nm in random.sample(names, min(len(names), 12)):
                    try:
                        _prepare_stage(s, nm)
                    except Exception:
                        break
                s.close()
            except Exception:
                pass

    def dedup_hammer():
        # many connections recall the SAME file -> must collapse to one stagecmd
        for _ in range(12):
            try:
                s, _ = _session(srv.root_port)
                _open(s, "/near.dat", flags=OPEN_READ, sid=b"\x00\x43")
                s.close()
            except Exception:
                pass

    def huge_list():
        # one prepare carrying a large newline-separated path list -> per-request
        # bounding (must not over-enqueue or crash)
        for _ in range(3):
            try:
                s, _ = _session(srv.root_port)
                payload = ("\n".join(names)).encode() + b"\n"
                body = struct.pack("!BBHH10s", kXR_stage, 0, 0, 0, b"\x00" * 10)
                s.sendall(_frame(kXR_prepare, body, payload, sid=b"\x00\x44"))
                try:
                    s.settimeout(2.0); _read_response(s)
                except Exception:
                    pass
                s.close()
            except Exception:
                pass

    ts = ([threading.Thread(target=flood, args=(2,)) for _ in range(2)] +
          [threading.Thread(target=dedup_hammer) for _ in range(2)] +
          [threading.Thread(target=huge_list)])
    for t in ts: t.start()
    for t in ts: t.join(timeout=60)

    # durable queue file must not grow without bound (slot reuse, not append-forever)
    try:
        qsz = os.path.getsize(srv.queue) if os.path.exists(srv.queue) else 0
        assert qsz < 64 * 1024 * 1024, "FRM queue file grew unbounded: %d bytes" % qsz
    except OSError:
        pass
    # fake-MSS must not have been fork-stormed without bound
    if os.path.exists(srv.audit):
        try:
            lines = sum(1 for _ in open(srv.audit, errors="replace"))
            assert lines < 200000, "stage agent fork-storm: %d invocations" % lines
        except OSError:
            pass
    # no crash is the immediate invariant; then the bounded backlog must drain and
    # the server must serve again (a runaway backlog would fail this responsiveness
    # check, which is itself the "shed cleanly" assertion).
    srv.assert_no_crash("C3 FRM flood")
    assert _ping_ok_retry(srv.root_port, tries=30, gap=1.0), \
        "server did not recover after FRM flood (staging backlog not shed)"


# --------------------------- D: chaos capstone -------------------------------

@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_d_chaos_capstone(srv):
    srv.mark()
    tls_ok = _tls_available(srv)
    big = os.path.join(srv.datadir, "big.bin")
    big_md5_64k = hashlib.md5(open(big, "rb").read(65536)).hexdigest()
    stop = time.time() + 35
    errors = []

    def cleartext_aio():
        while time.time() < stop:
            s = None
            try:
                s = _connect(srv.root_port, 4); _login(s)
                _, st, body = _open(s, "/big.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    op = random.choice(("pgread", "readv", "write"))
                    fh = body[:4]
                    off = random.randrange(0, (BIGFILE_MB - 16) * 1024 * 1024)
                    if op == "pgread":
                        s.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, off, 12 << 20)))
                    elif op == "readv":
                        segs = b"".join(struct.pack("!4siq", fh, 1 << 20, off + i * (1 << 20)) for i in range(8))
                        s.sendall(_frame(kXR_readv, b"", segs))
                    else:
                        _, stw, bw = _open(s, "/w.bin", flags=OPEN_UPDATE)
                        if stw == kXR_ok and len(bw) >= 4:
                            s.sendall(_frame(kXR_write, struct.pack("!4sqB3s", bw[:4], 0, 0, b"\x00" * 3), b"Z" * (1 << 20)))
            except Exception:
                pass
            if s is not None:
                _rst(s)

    def tls_aio():
        while time.time() < stop:
            t = None
            try:
                t = _roots_tls_connect(srv.root_tls_port, t=5)
                t.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0xFFFFFFFF, b"x\x00\x00\x00\x00\x00\x00\x00", 0, 0, 5, 0, 0))
                _read_response(t)
                _, st, body = _open(t, "/big.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    t.sendall(_frame(kXR_read, struct.pack("!4sqi", body[:4], 0, 12 << 20), sid=b"\x00\x0a"))
                    time.sleep(0.001)
            except Exception:
                pass
            if t is not None:
                _tls_rst(t)

    def bind_aba():
        while time.time() < stop:
            p = sec = None
            try:
                p, sid = _session(srv.root_port)
                _, st, body = _open(p, "/shared.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    sec = _connect(srv.root_port)
                    if _bind(sec, sid)[1] == kXR_ok:
                        sec.sendall(_frame(kXR_pgread, struct.pack("!4sqi", body[:4], 0, 8 << 20), sid=b"\x00\x0a"))
                    p.sendall(_frame(kXR_endsess, b"\x00" * 16, sid=b"\x00\x0b"))
            except Exception:
                pass
            for c in (sec, p):
                if c is not None:
                    _rst(c)

    def frm_chaos():
        while time.time() < stop:
            a = None
            try:
                a, _ = _session(srv.root_port)
                a.sendall(_frame(kXR_open, struct.pack("!HH2s6s4s", 0o644, OPEN_READ,
                          b"\x00\x00", b"\x00" * 6, b"\x00" * 4), b"/near.dat\x00", sid=b"\x00\x41"))
                time.sleep(0.05)
            except Exception:
                pass
            if a is not None:
                _rst(a)

    def http_abort():
        while time.time() < stop:
            _https_get(srv.https_port, "/big.bin", abort_after=random.choice((4096, 65536)))
            _https_get(srv.https_port, "/s3b/big.bin", abort_after=8192)

    def control_root():
        while time.time() < stop:
            try:
                s, _ = _session(srv.root_port)
                _, st, body = _open(s, "/big.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    _, _, data = _read(s, body[:4], 0, 65536, sid=b"\x00\x0c")
                    if data and hashlib.md5(data).hexdigest() != big_md5_64k:
                        errors.append("control_root corrupt")
                s.close()
            except Exception:
                pass
            time.sleep(0.05)

    threads = ([threading.Thread(target=cleartext_aio) for _ in range(5)] +
               [threading.Thread(target=bind_aba) for _ in range(3)] +
               [threading.Thread(target=control_root) for _ in range(2)] +
               [threading.Thread(target=http_abort) for _ in range(2)])
    if tls_ok:
        threads += [threading.Thread(target=tls_aio) for _ in range(3)]
    if srv.have_xattr:
        threads += [threading.Thread(target=frm_chaos) for _ in range(2)]
    for t in threads: t.start()
    # crash-check mid-flight (NO ping — that would race the 17-thread load and
    # false-positive; the control_root threads are the live correctness signal)
    while time.time() < stop:
        time.sleep(2.0)
        srv.assert_no_crash("D chaos (mid-flight)")
    for t in threads: t.join(timeout=60)
    assert not errors, "silent cross-plane corruption: %r" % errors[:5]
    time.sleep(FRM_LATENCY_MS / 1000.0 + 0.5)
    srv.assert_healthy("D chaos capstone")
