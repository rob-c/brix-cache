# _test_evil_actor_v3_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_evil_actor_v3.py.  `from _test_evil_actor_v3_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


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
      requester ownership (brix_prepare_handle_cancel -> frm_request_owner_check).
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
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

# Fixed-port target (evil-actor-v3 ledger, 30357 + TLS/HTTPS/metrics extras): one
# driver at a time.  serial because the client-side flood exhausts ephemeral fds.
pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("evil-actor-v3")]

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

# Re-export from split helpers
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_evil_actor_v3_helpers_b")
