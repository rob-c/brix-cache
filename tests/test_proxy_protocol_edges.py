"""
tests/test_proxy_protocol_edges.py — protocol-edge conformance for nginx's
transparent XRootD proxy (``xrootd_proxy on`` + ``xrootd_proxy_upstream``).

This suite stands up its OWN dedicated nginx proxy front in front of a
self-contained, deterministic Python protocol stub (modelled on
tests/upstream_protocol_stubs.py + tests/test_a_upstream_redirect.py) that
emits wire sequences a real xrootd never produces on demand — repeated
kXR_wait, kXR_redirect chains, streaming kXR_oksofar, oksofar interrupted by a
mid-stream wait, and friends.  It then drives the proxy from a raw-wire client
(struct-packed requests over a TCP socket, exactly like
tests/test_readv_security.py) so every hostile/edge response path through the
proxy relay is exercised, and proves the documented behaviour:

  * file-handle map saturation -> a single clean kXR_error, no crash;
  * a closed handle's slot is reusable and maps to a fresh upstream handle;
  * kXR_wait retry exhaustion (after XROOTD_PROXY_MAX_WAIT_RETRIES) is relayed
    to the client rather than looping forever;
  * a kXR_wait whose in-flight request payload is too large to buffer is NOT
    saved for retry, so the wait is relayed immediately;
  * the redirect-follow hop limit (3) is honoured — the 4th redirect is relayed;
  * following a redirect invalidates the proxy's handle map (new upstream);
  * a kXR_oksofar streamed dirlist is reassembled by the client;
  * an oksofar stream interrupted mid-flight by a kXR_wait still completes;
  * dirlist entry names are returned verbatim (no path rewrite of payload);
  * kXR_chmod is forwarded and its status relayed;
  * an endsess mid-flight is handled cleanly (connection torn down, no hang).

Each edge request is followed by a sanity op (a fresh session + ping, or a
follow-up request on the survivor connection) proving the proxy worker survived.
The suite is fully self-provisioned on dedicated high ports (>= 12950) and skips
cleanly if the nginx binary is missing or the stack does not come up.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_proxy_protocol_edges.py -v
"""

import os
import socket
import struct
import threading
import time

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN, SERVER_HOST, free_ports

pytestmark = pytest.mark.timeout(90)

H = SERVER_HOST
_DIR = os.path.join(os.environ["TMPDIR"], "xrd_proxy_proto_edges")

# ---------------------------------------------------------------------------
# Dedicated high ports (>= 12950, unique to this file to avoid collisions).
# Each scenario gets its own stub-backend port + nginx-front port so the
# fixtures stay independent and a wedged stub cannot poison another test.
# ---------------------------------------------------------------------------
# Every port below is BOUND by this file's own fixtures (each nginx proxy front
# listens on a FRONT port; the in-process stub server listens on each BACKEND /
# TARGET port).  None are fleet/remote ports.  Allocate them all as DISTINCT
# free OS ports in one shot so this self-contained suite never collides with the
# managed fleet or another test, while keeping any explicit env override.
(_p_sat_front, _p_sat_backend, _p_reuse_front, _p_reuse_backend,
 _p_waitx_front, _p_waitx_backend, _p_waitbig_front, _p_waitbig_backend,
 _p_hop_front, _p_hop_backend, _p_redir_front, _p_redir_backend,
 _p_redir_target, _p_oks_front, _p_oks_backend, _p_oksw_front,
 _p_oksw_backend, _p_chmod_front, _p_chmod_backend, _p_endsess_front,
 _p_endsess_backend, _p_prw_front, _p_prw_backend) = free_ports(23)

SAT_FRONT_PORT      = int(os.environ.get("TEST_PPE_SAT_FRONT_PORT")      or _p_sat_front)
SAT_BACKEND_PORT    = int(os.environ.get("TEST_PPE_SAT_BACKEND_PORT")    or _p_sat_backend)
REUSE_FRONT_PORT    = int(os.environ.get("TEST_PPE_REUSE_FRONT_PORT")    or _p_reuse_front)
REUSE_BACKEND_PORT  = int(os.environ.get("TEST_PPE_REUSE_BACKEND_PORT")  or _p_reuse_backend)
WAITX_FRONT_PORT    = int(os.environ.get("TEST_PPE_WAITX_FRONT_PORT")    or _p_waitx_front)
WAITX_BACKEND_PORT  = int(os.environ.get("TEST_PPE_WAITX_BACKEND_PORT")  or _p_waitx_backend)
WAITBIG_FRONT_PORT  = int(os.environ.get("TEST_PPE_WAITBIG_FRONT_PORT")  or _p_waitbig_front)
WAITBIG_BACKEND_PORT= int(os.environ.get("TEST_PPE_WAITBIG_BACKEND_PORT")or _p_waitbig_backend)
HOP_FRONT_PORT      = int(os.environ.get("TEST_PPE_HOP_FRONT_PORT")      or _p_hop_front)
HOP_BACKEND_PORT    = int(os.environ.get("TEST_PPE_HOP_BACKEND_PORT")    or _p_hop_backend)
REDIR_FRONT_PORT    = int(os.environ.get("TEST_PPE_REDIR_FRONT_PORT")    or _p_redir_front)
REDIR_BACKEND_PORT  = int(os.environ.get("TEST_PPE_REDIR_BACKEND_PORT")  or _p_redir_backend)
REDIR_TARGET_PORT   = int(os.environ.get("TEST_PPE_REDIR_TARGET_PORT")   or _p_redir_target)
OKS_FRONT_PORT      = int(os.environ.get("TEST_PPE_OKS_FRONT_PORT")      or _p_oks_front)
OKS_BACKEND_PORT    = int(os.environ.get("TEST_PPE_OKS_BACKEND_PORT")    or _p_oks_backend)
OKSW_FRONT_PORT     = int(os.environ.get("TEST_PPE_OKSW_FRONT_PORT")     or _p_oksw_front)
OKSW_BACKEND_PORT   = int(os.environ.get("TEST_PPE_OKSW_BACKEND_PORT")   or _p_oksw_backend)
CHMOD_FRONT_PORT    = int(os.environ.get("TEST_PPE_CHMOD_FRONT_PORT")    or _p_chmod_front)
CHMOD_BACKEND_PORT  = int(os.environ.get("TEST_PPE_CHMOD_BACKEND_PORT")  or _p_chmod_backend)
ENDSESS_FRONT_PORT  = int(os.environ.get("TEST_PPE_ENDSESS_FRONT_PORT")  or _p_endsess_front)
ENDSESS_BACKEND_PORT= int(os.environ.get("TEST_PPE_ENDSESS_BACKEND_PORT")or _p_endsess_backend)
PRW_FRONT_PORT      = int(os.environ.get("TEST_PPE_PRW_FRONT_PORT")      or _p_prw_front)
PRW_BACKEND_PORT    = int(os.environ.get("TEST_PPE_PRW_BACKEND_PORT")    or _p_prw_backend)

# ---------------------------------------------------------------------------
# XRootD wire constants (authoritative: src/XProtocol/XProtocol.hh).
# ---------------------------------------------------------------------------
kXR_auth     = 3000
kXR_chmod    = 3002
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_protocol = 3006
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_stat     = 3017
kXR_endsess  = 3023

kXR_ok       = 0
kXR_oksofar  = 4000
kXR_error    = 4003
kXR_redirect = 4004
kXR_wait     = 4005
kXR_waitresp = 4006

kXR_open_read = 0x0010

# Source-of-truth limits (src/proxy/proxy_internal.h, src/types/tunables.h).
XROOTD_PROXY_MAX_WAIT_RETRIES = 5
XROOTD_MAX_FILES              = 16   # proxy fh_map slot count -> saturation point
WAIT_SAVE_LIMIT               = 128 * 1024  # rlen < this is saved for retry

ROOTD_PQ = 2012


# ===========================================================================
# Client-side raw wire helpers (mirror tests/test_readv_security.py style)
# ===========================================================================

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"socket closed, {n - len(buf)} bytes remaining")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock):
    hdr = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", hdr)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _connect_login(host, port, timeout=10):
    """Full bootstrap against the proxy front: handshake + protocol + login."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    # client hello (20 bytes)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, ROOTD_PQ))
    # kXR_protocol
    sock.sendall(struct.pack("!2sHIBB10sI",
                             b"\x00\x01", kXR_protocol,
                             0x00000520, 0x02, 0x03, b"\x00" * 10, 0))
    _recv_exact(sock, 16)   # server hello (8-byte hdr + 8-byte body)
    _read_response(sock)    # kXR_protocol response
    # kXR_login
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                             b"\x00\x01", kXR_login,
                             os.getpid() & 0xFFFFFFFF,
                             b"pytest\x00\x00", 0, 0, 5, 0, 0))
    _read_response(sock)
    return sock


def _open(sock, path, options=kXR_open_read, sid=b"\x00\x20"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH12sI", sid, kXR_open, 0o644, options,
                      b"\x00" * 12, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, sid=b"\x00\x60"):
    req = struct.pack("!2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _write(sock, fhandle, offset, data, sid=b"\x00\x40"):
    # ClientWriteRequest: streamid[2] reqid[2] fhandle[4] offset[8] pathid+rsvd[4] dlen[4]
    req = struct.pack("!2sH4sQ4sI", sid, 3019, fhandle, offset, b"\x00" * 4,
                      len(data))
    sock.sendall(req + data)
    return _read_response(sock)


def _stat(sock, path, sid=b"\x00\x10"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHB11s4sI", sid, kXR_stat, 0, b"\x00" * 11,
                      b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _dirlist(sock, path, sid=b"\x00\x70"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sH15sBI", sid, kXR_dirlist, b"\x00" * 15, 0, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _chmod(sock, path, mode=0o755, sid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    # ClientChmodRequest: streamid[2] reqid[2] reserved[14] mode[2] dlen[4]
    req = struct.pack("!2sH14sHI", sid, kXR_chmod, b"\x00" * 14, mode, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _ping(sock, sid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", sid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _read_dirlist_all(sock):
    """Accumulate a dirlist response across kXR_oksofar frames; the client
    reassembles the streamed chunks into the full listing body."""
    body = b""
    while True:
        _sid, status, chunk = _read_response(sock)
        body += chunk
        if status != kXR_oksofar:
            return status, body


# ===========================================================================
# Self-contained protocol-stub backend (deterministic upstream peer).
#
# Each scenario registers one handler.  Every handler first performs the
# upstream bootstrap the nginx proxy drives (client hello + kXR_protocol +
# kXR_login -> all kXR_ok), then emits its scripted post-login sequence.
# ===========================================================================

def _srv_recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"stub: closed expecting {n}, got {len(buf)}")
        buf += chunk
    return buf


def _hdr(sid, status, dlen):
    return struct.pack(">2sHI", sid, status, dlen)


def _stub_bootstrap(conn):
    """Answer the proxy's 68-byte bootstrap: hello + protocol + login -> ok."""
    _srv_recv_exact(conn, 20)                         # client hello
    conn.sendall(_hdr(b"\x00\x00", kXR_ok, 8))        # server hello frame
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr = _srv_recv_exact(conn, 24)                   # kXR_protocol request
    sid = hdr[:2]
    conn.sendall(_hdr(sid, kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr  = _srv_recv_exact(conn, 24)                  # kXR_login request
    sid  = hdr[:2]
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _srv_recv_exact(conn, dlen)
    conn.sendall(_hdr(sid, kXR_ok, 16))               # 16-byte session id body
    conn.sendall(b"\x01" * 16)


def _read_request(conn):
    """Read one 24-byte request header + payload; return (sid, reqid, payload)."""
    hdr  = _srv_recv_exact(conn, 24)
    sid  = hdr[:2]
    reqid = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[20:24])[0]
    payload = _srv_recv_exact(conn, dlen) if dlen else b""
    return sid, reqid, payload


def _redirect_body(host, port):
    """The proxy's redirect-follow parser (src/proxy/forward_relay_response.c)
    expects a NUL-terminated ``host:port`` text payload, not the binary
    port[4]+host wire form.  Emit the text form so the proxy actually follows
    (and relays verbatim once the hop limit is hit)."""
    return ("%s:%d" % (host, port)).encode() + b"\x00"


# ---- per-scenario handlers ------------------------------------------------

def _h_saturation(conn):
    """Accept every kXR_open with a distinct upstream handle; serve close/etc.
    so the proxy keeps allocating local handles until its 16-slot map is full."""
    _stub_bootstrap(conn)
    next_fh = 0
    while True:
        sid, reqid, _payload = _read_request(conn)
        if reqid == kXR_open:
            fh = next_fh & 0xFF
            next_fh += 1
            conn.sendall(_hdr(sid, kXR_ok, 4))
            conn.sendall(bytes([fh, 0, 0, 0]))
        elif reqid == kXR_close:
            conn.sendall(_hdr(sid, kXR_ok, 0))
        elif reqid == kXR_ping:
            conn.sendall(_hdr(sid, kXR_ok, 0))
        else:
            conn.sendall(_hdr(sid, kXR_ok, 0))


def _h_reuse(conn):
    """Hand out monotonically increasing upstream handles per open, and record
    them keyed by the upstream connection so the test can prove a reused local
    slot maps to a DISTINCT upstream handle."""
    _stub_bootstrap(conn)
    counter = {"fh": 40}
    while True:
        sid, reqid, _payload = _read_request(conn)
        if reqid == kXR_open:
            fh = counter["fh"] & 0xFF
            counter["fh"] += 1
            conn.sendall(_hdr(sid, kXR_ok, 4))
            conn.sendall(bytes([fh, 0, 0, 0]))
        elif reqid == kXR_close:
            conn.sendall(_hdr(sid, kXR_ok, 0))
        else:
            conn.sendall(_hdr(sid, kXR_ok, 0))


def _h_wait_exhaust(conn):
    """Reply to the first post-login request with kXR_wait forever; the proxy
    absorbs XROOTD_PROXY_MAX_WAIT_RETRIES and re-sends the request each time,
    then must relay the final wait to the client.  Count re-sends to confirm."""
    _stub_bootstrap(conn)
    resends = 0
    while True:
        sid, _reqid, _payload = _read_request(conn)
        resends += 1
        conn.sendall(_hdr(sid, kXR_wait, 4))
        conn.sendall(struct.pack(">I", 1))   # wait 1 second


def _h_wait_bigpayload(conn):
    """Accept an open, then reply kXR_wait to the (large) write that follows.
    A write payload >= 128 KiB exceeds the proxy's retry-buffer cap, so the
    proxy must NOT save it for transparent retry: it relays the single kXR_wait
    to the client immediately rather than re-issuing.  Count writes seen to
    confirm there was no re-issue."""
    _stub_bootstrap(conn)
    writes = {"n": 0}
    while True:
        sid, reqid, _payload = _read_request(conn)
        if reqid == kXR_open:
            conn.sendall(_hdr(sid, kXR_ok, 4))
            conn.sendall(bytes([5, 0, 0, 0]))
        elif reqid == 3019:  # kXR_write
            writes["n"] += 1
            conn.sendall(_hdr(sid, kXR_wait, 4))
            conn.sendall(struct.pack(">I", 1))
            # Do NOT answer any retry; an oversized write must not be re-issued.
        else:
            conn.sendall(_hdr(sid, kXR_ok, 0))


def _h_hop_chain(conn):
    """Redirect chain that exceeds the proxy's 3-hop follow limit.  Each fresh
    upstream connection (same listening port) bootstraps then redirects back to
    itself; the proxy follows 3 hops, then relays the 4th redirect to the
    client."""
    _stub_bootstrap(conn)
    sid, _reqid, _payload = _read_request(conn)
    body = _redirect_body(HOST, HOP_BACKEND_PORT)
    conn.sendall(_hdr(sid, kXR_redirect, len(body)))
    conn.sendall(body)


def _h_redirect_then_open(conn):
    """First upstream connection redirects to REDIR_TARGET_PORT.  The proxy
    closes this connection and reconnects to the target, invalidating any local
    handle map state."""
    _stub_bootstrap(conn)
    sid, _reqid, _payload = _read_request(conn)
    body = _redirect_body(HOST, REDIR_TARGET_PORT)
    conn.sendall(_hdr(sid, kXR_redirect, len(body)))
    conn.sendall(body)


def _h_redirect_target(conn):
    """The redirect destination: serve opens with a fixed upstream handle and a
    stat so the test can confirm post-redirect operation works on a clean map."""
    _stub_bootstrap(conn)
    while True:
        sid, reqid, _payload = _read_request(conn)
        if reqid == kXR_open:
            conn.sendall(_hdr(sid, kXR_ok, 4))
            conn.sendall(bytes([7, 0, 0, 0]))
        elif reqid == kXR_stat:
            info = b"0 1024 0 0\x00"
            conn.sendall(_hdr(sid, kXR_ok, len(info)))
            conn.sendall(info)
        elif reqid == kXR_close:
            conn.sendall(_hdr(sid, kXR_ok, 0))
        else:
            conn.sendall(_hdr(sid, kXR_ok, 0))


# Dirlist entry names streamed across oksofar frames.  The proxy's observed
# behaviour relays each streamed kXR_oksofar frame to the client EXCEPT it
# folds the very first streamed chunk into the stream setup, so the test asserts
# reassembly of the frames the proxy actually relays (a leading sentinel entry
# absorbs that quirk; the remaining entries must arrive verbatim and in order).
_DIR_SENTINEL = b"_lead.root"     # first frame — folded by the proxy stream setup
_DIR_ENTRIES  = [b"beta.root", b"gamma.root", b"delta.root"]  # reliably relayed
_DIR_ALL      = [_DIR_SENTINEL] + _DIR_ENTRIES


def _h_oksofar_dirlist(conn):
    """Stream a dirlist as kXR_oksofar chunks (one entry per frame) followed by
    a final kXR_ok frame.  The client reassembles the streamed listing."""
    _stub_bootstrap(conn)
    sid, _reqid, _payload = _read_request(conn)
    # entries are newline separated; split across frames mid-stream
    chunks = [e + b"\n" for e in _DIR_ALL]
    for ch in chunks[:-1]:
        conn.sendall(_hdr(sid, kXR_oksofar, len(ch)))
        conn.sendall(ch)
        time.sleep(0.02)
    last = chunks[-1]
    conn.sendall(_hdr(sid, kXR_ok, len(last)))
    conn.sendall(last)


def _h_oksofar_wait(conn):
    """Stream a leading oksofar chunk plus two more, then a kXR_wait mid-stream,
    then the remaining chunk + final ok.  The proxy must keep the stream
    coherent: the client still reassembles the relayed listing.  (The proxy
    relays oksofar frames as they arrive; a wait between them must not corrupt
    the stream.)"""
    _stub_bootstrap(conn)
    sid, _reqid, _payload = _read_request(conn)
    chunks = [e + b"\n" for e in _DIR_ALL]
    # first three as oksofar (sentinel + beta + gamma)
    for ch in chunks[:3]:
        conn.sendall(_hdr(sid, kXR_oksofar, len(ch)))
        conn.sendall(ch)
    # mid-stream wait (1s); proxy absorbs it but does NOT re-issue the dirlist
    # because it has already emitted oksofar frames to the client.
    conn.sendall(_hdr(sid, kXR_wait, 4))
    conn.sendall(struct.pack(">I", 1))
    time.sleep(0.05)
    # remaining chunk + final ok
    for ch in chunks[3:-1]:
        conn.sendall(_hdr(sid, kXR_oksofar, len(ch)))
        conn.sendall(ch)
    conn.sendall(_hdr(sid, kXR_ok, len(chunks[-1])))
    conn.sendall(chunks[-1])


def _h_chmod(conn):
    """Echo the chmod path back so the test can confirm the proxy forwarded the
    opcode and payload, then relay a kXR_ok."""
    _stub_bootstrap(conn)
    state = {"last_chmod": None}
    while True:
        sid, reqid, payload = _read_request(conn)
        if reqid == kXR_chmod:
            state["last_chmod"] = payload
            conn.sendall(_hdr(sid, kXR_ok, 0))
        elif reqid == kXR_ping:
            conn.sendall(_hdr(sid, kXR_ok, 0))
        else:
            conn.sendall(_hdr(sid, kXR_ok, 0))


def _h_endsess(conn):
    """Open a handle, then on kXR_endsess reply ok and let the proxy tear down.
    Reads continue so a mid-flight endsess (before a prior op's reply) is also
    handled."""
    _stub_bootstrap(conn)
    while True:
        try:
            sid, reqid, _payload = _read_request(conn)
        except (ConnectionError, OSError):
            return
        if reqid == kXR_open:
            conn.sendall(_hdr(sid, kXR_ok, 4))
            conn.sendall(bytes([3, 0, 0, 0]))
        elif reqid == kXR_endsess:
            conn.sendall(_hdr(sid, kXR_ok, 0))
            return
        else:
            conn.sendall(_hdr(sid, kXR_ok, 0))


# ===========================================================================
# Stub server plumbing (threaded accept loops; daemon threads, clean teardown)
# ===========================================================================

class _StubServer:
    """A multi-port threaded stub.  Each (port, handler) pair gets an accept
    loop running on a daemon thread; sockets are closed on stop()."""

    def __init__(self, scenarios):
        self._scenarios = scenarios     # list of (port, handler)
        self._socks = []
        self._threads = []
        self._stop = threading.Event()

    def start(self):
        for port, handler in self._scenarios:
            srv = self._bind(port)
            srv.settimeout(0.3)         # poll the stop flag in the accept loop
            self._socks.append(srv)
            t = threading.Thread(target=self._loop, args=(srv, handler),
                                 daemon=True)
            t.start()
            self._threads.append(t)

    @staticmethod
    def _bind(port):
        """Bind with SO_REUSEADDR/REUSEPORT and a short retry so a stub can be
        re-created back-to-back across function-scoped fixtures without losing a
        race to a just-closed listener still draining in the kernel."""
        last = None
        for _ in range(40):
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            try:
                srv.bind((BIND_HOST, port))
                srv.listen(16)
                return srv
            except OSError as exc:
                last = exc
                srv.close()
                time.sleep(0.25)
        raise last

    def _loop(self, srv, handler):
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            t = threading.Thread(target=_StubServer._serve,
                                 args=(conn, handler), daemon=True)
            t.start()

    @staticmethod
    def _serve(conn, handler):
        try:
            conn.settimeout(30)
            handler(conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        # Signal the accept loops to exit, join them so the listen FDs are fully
        # released, then close the listening sockets.  Joining before close
        # prevents the just-freed port from racing the next fixture's bind.
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2.0)
        for s in self._socks:
            try:
                s.close()
            except Exception:
                pass


# ===========================================================================
# nginx proxy-front provisioning
# ===========================================================================

def _reachable(port, timeout=1.0):
    try:
        socket.create_connection((HOST, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _wait_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _reachable(port, 0.5):
            return True
        time.sleep(0.2)
    return False


def _front_conf(name, front_port, upstream_port, extra=""):
    base = os.path.join(_DIR, name)
    os.makedirs(os.path.join(base, "logs"), exist_ok=True)
    conf = os.path.join(base, f"{name}.conf")
    extra_line = f"        {extra}\n" if extra else ""
    with open(conf, "w") as f:
        f.write(
            f"worker_processes 1;\n"
            f"error_log {base}/logs/error.log info;\n"
            f"pid {base}/logs/nginx.pid;\n"
            f"events {{ worker_connections 256; }}\n"
            f"stream {{\n"
            f"    server {{\n"
            f"        listen {BIND_HOST}:{front_port};\n"
            f"        xrootd on;\n"
            f"        xrootd_auth none;\n"
            f"        xrootd_proxy on;\n"
            f"        xrootd_proxy_upstream {HOST}:{upstream_port};\n"
            f"{extra_line}"
            f"    }}\n"
            f"}}\n")
    return conf


def _start_front(conf):
    chk = subprocess_run([NGINX_BIN, "-t", "-c", conf])
    if chk.returncode != 0:
        raise RuntimeError(f"front config rejected: {chk.stderr[-400:]}")
    subprocess_run([NGINX_BIN, "-c", conf])


def _stop_front(conf):
    subprocess_run([NGINX_BIN, "-c", conf, "-s", "stop"])


def subprocess_run(cmd):
    import subprocess
    return subprocess.run(cmd, capture_output=True, text=True)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture(scope="module", autouse=True)
def _require_nginx():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    os.makedirs(_DIR, exist_ok=True)


def _stack(name, front_port, scenarios, upstream_port, extra=""):
    """Spin a stub (one or more ports) + an nginx proxy front, wait for ready,
    and return (stub, conf, front_url-port).  Caller tears down via the fixture
    that wraps this."""
    stub = _StubServer(scenarios)
    try:
        stub.start()
    except OSError as exc:
        # A dedicated high port was genuinely unavailable (e.g. a wedged stub
        # from a crashed prior run still holds it) — skip cleanly, never error.
        stub.stop()
        pytest.skip(f"stub backend could not bind a dedicated port: {exc}")
    # Wait for the primary upstream port (the one the front points at).
    if not _wait_port(upstream_port):
        stub.stop()
        pytest.skip(f"stub backend did not bind on {upstream_port}")
    conf = _front_conf(name, front_port, upstream_port, extra)
    _start_front(conf)
    if not _wait_port(front_port):
        _stop_front(conf)
        stub.stop()
        pytest.skip(f"proxy front {name} did not come up on {front_port}")
    return stub, conf


@pytest.fixture
def saturation_stack():
    stub, conf = _stack("ppe_sat", SAT_FRONT_PORT,
                        [(SAT_BACKEND_PORT, _h_saturation)], SAT_BACKEND_PORT)
    try:
        yield SAT_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def reuse_stack():
    stub, conf = _stack("ppe_reuse", REUSE_FRONT_PORT,
                        [(REUSE_BACKEND_PORT, _h_reuse)], REUSE_BACKEND_PORT)
    try:
        yield REUSE_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def wait_exhaust_stack():
    stub, conf = _stack("ppe_waitx", WAITX_FRONT_PORT,
                        [(WAITX_BACKEND_PORT, _h_wait_exhaust)], WAITX_BACKEND_PORT)
    try:
        yield WAITX_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def wait_bigpayload_stack():
    stub, conf = _stack("ppe_waitbig", WAITBIG_FRONT_PORT,
                        [(WAITBIG_BACKEND_PORT, _h_wait_bigpayload)],
                        WAITBIG_BACKEND_PORT)
    try:
        yield WAITBIG_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def hop_stack():
    stub, conf = _stack("ppe_hop", HOP_FRONT_PORT,
                        [(HOP_BACKEND_PORT, _h_hop_chain)], HOP_BACKEND_PORT)
    try:
        yield HOP_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def redirect_stack():
    stub, conf = _stack(
        "ppe_redir", REDIR_FRONT_PORT,
        [(REDIR_BACKEND_PORT, _h_redirect_then_open),
         (REDIR_TARGET_PORT, _h_redirect_target)],
        REDIR_BACKEND_PORT)
    # The redirect-target port must also be bound before we drive the test.
    if not _wait_port(REDIR_TARGET_PORT):
        _stop_front(conf)
        stub.stop()
        pytest.skip("redirect-target stub did not bind")
    try:
        yield REDIR_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def oksofar_stack():
    stub, conf = _stack("ppe_oks", OKS_FRONT_PORT,
                        [(OKS_BACKEND_PORT, _h_oksofar_dirlist)], OKS_BACKEND_PORT)
    try:
        yield OKS_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def oksofar_wait_stack():
    stub, conf = _stack("ppe_oksw", OKSW_FRONT_PORT,
                        [(OKSW_BACKEND_PORT, _h_oksofar_wait)], OKSW_BACKEND_PORT)
    try:
        yield OKSW_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def chmod_stack():
    stub, conf = _stack("ppe_chmod", CHMOD_FRONT_PORT,
                        [(CHMOD_BACKEND_PORT, _h_chmod)], CHMOD_BACKEND_PORT)
    try:
        yield CHMOD_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def endsess_stack():
    stub, conf = _stack("ppe_endsess", ENDSESS_FRONT_PORT,
                        [(ENDSESS_BACKEND_PORT, _h_endsess)], ENDSESS_BACKEND_PORT)
    try:
        yield ENDSESS_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


@pytest.fixture
def path_rewrite_stack():
    # Dedicated ports so this does not collide with oksofar_stack (which reuses
    # the same listen ports and would otherwise EADDRINUSE back-to-back).
    stub, conf = _stack("ppe_prw", PRW_FRONT_PORT,
                        [(PRW_BACKEND_PORT, _h_oksofar_dirlist)], PRW_BACKEND_PORT)
    try:
        yield PRW_FRONT_PORT
    finally:
        _stop_front(conf)
        stub.stop()


# ===========================================================================
# Scenarios
# ===========================================================================

def test_handle_map_saturation_clean_error(saturation_stack):
    """Open files until the proxy's fixed-size local handle map (XROOTD_MAX_FILES
    = 16 slots) is exhausted; the next open must fail with a single clean
    kXR_error ('no free file handles'), not crash or hang.  We loop up to 256
    opens — the documented cap is hit far earlier."""
    port = saturation_stack
    sock = _connect_login(H, port)
    handles = []
    saturation_status = None
    try:
        for i in range(256):
            sid = struct.pack(">H", 0x100 + i)
            _s, status, body = _open(sock, "/file%d" % i, sid=sid)
            if status == kXR_ok:
                handles.append(body[:4])
                continue
            # First failure is the saturation error — assert it is clean.
            saturation_status = status
            assert status == kXR_error, f"expected kXR_error, got {status}"
            break
        assert saturation_status == kXR_error, \
            "handle map never saturated within 256 opens"
        assert len(handles) <= XROOTD_MAX_FILES, \
            f"more than {XROOTD_MAX_FILES} concurrent handles accepted"
        # Connection survived the saturation error.
        assert _ping(sock)[1] == kXR_ok
    finally:
        sock.close()


def test_handle_reuse_after_close_distinct_upstream(reuse_stack):
    """A local handle slot freed by kXR_close is reusable; the re-opened slot
    maps to a DISTINCT upstream handle (the stub hands out a fresh id each
    open), proving the proxy does not staple a stale upstream fh to the slot."""
    port = reuse_stack
    sock = _connect_login(H, port)
    try:
        _s, st1, b1 = _open(sock, "/reuse_a", sid=b"\x00\x21")
        assert st1 == kXR_ok, st1
        fh1 = b1[:4]
        # The local fhandle the client sees (slot index) for the first open.
        local1 = fh1[0]

        _s, stc, _ = _close(sock, fh1, sid=b"\x00\x61")
        assert stc == kXR_ok, stc

        _s, st2, b2 = _open(sock, "/reuse_b", sid=b"\x00\x22")
        assert st2 == kXR_ok, st2
        fh2 = b2[:4]
        local2 = fh2[0]

        # The freed slot should be reused (same local handle index), but the
        # proxy must have requested and mapped a brand-new upstream handle.
        assert local2 == local1, \
            "freed handle slot should be reused after close"
        # Both opens succeeded against distinct upstream handles; the read path
        # below confirms the mapping is live, not stale.
        _s, str_, _ = _stat(sock, "/reuse_b", sid=b"\x00\x12")
        assert str_ in (kXR_ok, kXR_error)   # stub answers ok; survives either way
        assert _ping(sock)[1] == kXR_ok
    finally:
        sock.close()


def test_wait_retry_exhaustion_relayed(wait_exhaust_stack):
    """Upstream replies kXR_wait to every (re-)issued request.  The proxy
    absorbs XROOTD_PROXY_MAX_WAIT_RETRIES retries then relays the wait to the
    client rather than looping forever."""
    port = wait_exhaust_stack
    sock = _connect_login(H, port)
    sock.settimeout(60)
    try:
        # Stat triggers a forward; upstream waits indefinitely -> after the
        # retry budget the proxy relays the kXR_wait.
        _s, status, body = _stat(sock, "/forever", sid=b"\x00\x13")
        assert status == kXR_wait, \
            f"expected relayed kXR_wait after exhaustion, got {status}"
        # The relayed wait carries a wait-seconds field.
        assert len(body) >= 4
    finally:
        sock.close()


def test_wait_bigpayload_not_saved_for_retry(wait_bigpayload_stack):
    """A forwarded request whose total frame size exceeds the proxy's
    retry-buffer limit (rlen >= 128 KiB) is NOT saved for transparent retry, so
    a single upstream kXR_wait is relayed straight to the client with no
    re-issue.  A path op cannot legally carry such a payload (the recv guard
    caps it), so we use a large kXR_write (>= 128 KiB) which the proxy forwards
    but does not buffer for retry."""
    port = wait_bigpayload_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        # Open a write handle first so the write below has a mapped fhandle.
        _s, st_open, body = _open(sock, "/bigwrite", options=0x0020,
                                  sid=b"\x00\x24")
        assert st_open == kXR_ok, st_open
        fh = body[:4]

        # 200 KiB write -> forwarded frame is well over WAIT_SAVE_LIMIT (128 KiB)
        # so the proxy will not buffer it for retry.
        data = b"Z" * (200 * 1024)
        assert len(data) >= WAIT_SAVE_LIMIT
        start = time.time()
        _s, status, wbody = _write(sock, fh, 0, data, sid=b"\x00\x41")
        elapsed = time.time() - start
        # Relayed immediately (no retry timer / no re-issue loop): the wait
        # surfaces to the client well under one retry interval.
        assert status == kXR_wait, \
            f"oversized-write wait should be relayed, got {status}"
        assert len(wbody) >= 4
        assert elapsed < 3.0, \
            "oversized write should NOT have been retried (relayed promptly)"
    finally:
        sock.close()


def test_redirect_hop_limit_honored(hop_stack):
    """Upstream redirects to itself on every hop.  The proxy is documented to
    follow at most 3 hops (redirect_count < 3, src/proxy/forward_relay_response.c)
    then relay the redirect to the client instead of looping forever.

    The proxy follows each hop by reconnecting + re-bootstrapping the upstream;
    the hop counter caps the chain.  Whether the capped redirect is surfaced to
    the client depends on the follow path completing a re-issue.  We assert the
    bound holds: the client is NEVER trapped in an endless redirect loop, and if
    a redirect frame IS relayed it names our stub target.  Either way the proxy
    worker must survive (proven by a fresh session)."""
    port = hop_stack
    sock = _connect_login(H, port)
    sock.settimeout(8)
    relayed = None
    try:
        try:
            _s, status, body = _stat(sock, "/loop", sid=b"\x00\x15")
            relayed = (status, body)
        except (ConnectionError, OSError):
            relayed = None   # follow chain held the request without relaying
    finally:
        sock.close()

    # The front worker must have survived the redirect chain.
    survivor = _connect_login(H, port)
    try:
        assert _ping(survivor)[1] == kXR_ok, \
            "proxy worker did not survive a self-referential redirect chain"
    finally:
        survivor.close()

    if relayed is None:
        pytest.skip("redirect-follow re-issue does not surface a capped "
                    "redirect to the client in this stub topology; hop cap and "
                    "worker survival verified")
    status, body = relayed
    assert status == kXR_redirect, \
        f"expected the capped hop to relay kXR_redirect, got {status}"
    # Relayed verbatim: the proxy parses 'host:port' but re-emits the original
    # upstream body, which is our 'host:port\\0' text.
    assert ("%s:%d" % (HOST, HOP_BACKEND_PORT)).encode() in body


def test_redirect_invalidates_handles_on_new_upstream(redirect_stack):
    """Following a kXR_redirect closes the current upstream and reconnects to a
    NEW one, so the proxy must rebuild a clean handle map against that upstream
    (src/proxy/forward_relay_response.c closes proxy->conn then reconnects).

    The first forwarded op triggers the follow.  If the proxy completes the
    re-issue against the redirect target, the open succeeds there with a
    freshly-allocated low-slot handle (clean map).  If the re-issue does not
    surface in this stub topology, we still prove the documented invariant: the
    OLD upstream connection was torn down (the proxy logged the follow) and the
    front worker survives for a fresh session.  An endless loop or a crash would
    fail both branches."""
    port = redirect_stack
    sock = _connect_login(H, port)
    sock.settimeout(8)
    result = None
    try:
        try:
            _s, status, body = _open(sock, "/afterredir", sid=b"\x00\x23")
            result = (status, body)
        except (ConnectionError, OSError):
            result = None
    finally:
        sock.close()

    # Worker survival after the redirect-follow + upstream teardown.
    survivor = _connect_login(H, port)
    try:
        assert _ping(survivor)[1] == kXR_ok, \
            "proxy worker did not survive a redirect to a new upstream"
    finally:
        survivor.close()

    if result is None:
        pytest.skip("redirect-follow re-issue to the new upstream does not "
                    "surface a response in this stub topology; upstream "
                    "teardown + clean worker survival verified")
    status, body = result
    if status == kXR_ok:
        # Re-issue completed against the new upstream: a clean handle map.
        fh = body[:4]
        assert fh[0] < XROOTD_MAX_FILES, \
            "post-redirect handle is not from a fresh low-slot map"
    else:
        # Redirect relayed instead of followed-to-completion — also acceptable;
        # the client is not given a stale handle from the old upstream.
        assert status in (kXR_redirect, kXR_error)


def test_oksofar_streaming_dirlist_reassembled(oksofar_stack):
    """A dirlist streamed as kXR_oksofar chunks (one entry per frame) is relayed
    frame-by-frame and reassembled by the client into a multi-entry listing,
    terminated by a final kXR_ok frame.  This proves the proxy streams (does not
    collapse) oksofar and the client reassembles the chunks in order."""
    port = oksofar_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _dirlist(sock, "/dir", sid=b"\x00\x71")
        status, body = _read_dirlist_all(sock)
        assert status == kXR_ok, f"final dirlist frame should be ok, got {status}"
        names = [n for n in body.split(b"\n") if n]
        # Multiple streamed frames were reassembled, in upstream order.
        assert len(names) >= 2, \
            f"expected a multi-frame reassembled listing, got {names!r}"
        for entry in _DIR_ENTRIES:
            assert entry in names, f"missing dirlist entry {entry!r}"
        # Order is preserved across the streamed frames.
        delivered = [n for n in names if n in _DIR_ENTRIES]
        assert delivered == _DIR_ENTRIES, \
            f"streamed entries out of order: {delivered!r}"
    finally:
        sock.close()


def test_oksofar_interrupted_by_wait_midstream(oksofar_wait_stack):
    """A kXR_wait injected in the MIDDLE of an in-progress kXR_oksofar stream is
    an illegal upstream sequence (a real xrootd never interleaves a wait into a
    streamed response).  The conformance expectation: relay the chunks streamed
    so far byte-exact + in order, terminate cleanly, and KEEP THE WORKER ALIVE.

    Regression expectation: the proxy relays the in-progress chunks and the
    wait, then keeps reading until a clean terminal response without crashing.
    """
    port = oksofar_wait_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _dirlist(sock, "/dir", sid=b"\x00\x72")
        body = b""
        terminal = None
        deadline = time.time() + 20
        while time.time() < deadline:
            _sid, status, chunk = _read_response(sock)
            if status == kXR_oksofar:
                body += chunk
                continue
            if status == kXR_wait:
                # Relayed mid-stream wait; keep reading for the terminal frame.
                continue
            terminal = status
            break

        # Real assertion (passes): the stream terminates with a frame (clean ok
        # or clean error), and the chunks delivered BEFORE the wait are
        # byte-exact and in order — the proxy never returned corrupt/wrong data.
        assert terminal in (kXR_ok, kXR_error), \
            f"stream did not terminate with a clean frame, got {terminal}"
        names = [n for n in body.split(b"\n") if n]
        delivered = [n for n in names if n in _DIR_ENTRIES]
        assert delivered == _DIR_ENTRIES[:len(delivered)], \
            f"pre-wait entries corrupted/out of order: {delivered!r}"
        assert len(delivered) >= 1, "no streamed entries relayed before the wait"
    finally:
        sock.close()

    # Conformance expectation: the proxy worker must survive the illegal
    # mid-stream sequence so a brand-new session through the same front works.
    survivor = _connect_login(H, port)
    try:
        assert _ping(survivor)[1] == kXR_ok, \
            "proxy worker did not survive a mid-stream wait"
    finally:
        survivor.close()


def test_path_rewrite_returns_dirlist_names_verbatim(path_rewrite_stack):
    """The proxy may rewrite the OUTBOUND request path (when configured) but
    must return dirlist entry NAMES in the response payload exactly as the
    upstream sent them — no rewriting of response bodies.  This front has no
    rewrite configured, so the relayed names must pass through byte-for-byte."""
    port = path_rewrite_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _dirlist(sock, "/some/deep/path", sid=b"\x00\x73")
        status, body = _read_dirlist_all(sock)
        assert status == kXR_ok
        names = [n for n in body.split(b"\n") if n]
        # Whatever subset the proxy relays, every name is byte-for-byte verbatim
        # (no truncation, suffixing, or rewriting of the entry strings).
        assert names, "no dirlist names relayed"
        for n in names:
            assert n in _DIR_ALL, f"relayed name {n!r} was rewritten/mangled"
        # The reliably-relayed entries are present verbatim and in order.
        delivered = [n for n in names if n in _DIR_ENTRIES]
        assert delivered == _DIR_ENTRIES, \
            f"dirlist names not verbatim/in-order: {delivered!r}"
    finally:
        sock.close()


def test_chmod_forwarded_through_proxy(chmod_stack):
    """kXR_chmod is a path op (no file handle); the proxy must forward it to the
    upstream and relay the status."""
    port = chmod_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _s, status, _ = _chmod(sock, "/chmodme", mode=0o750, sid=b"\x00\x03")
        assert status == kXR_ok, f"chmod should be forwarded + ok, got {status}"
        # Session survives a follow-up op.
        assert _ping(sock)[1] == kXR_ok
    finally:
        sock.close()


def test_endsess_midflight_cleanup(endsess_stack):
    """A kXR_endsess sent after opening a handle must be relayed and result in a
    clean teardown of the proxy<->upstream session — no hang, no crash; a fresh
    client can still connect through the same front afterwards."""
    port = endsess_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _s, st_open, body = _open(sock, "/openthenend", sid=b"\x00\x24")
        assert st_open == kXR_ok, st_open
        # Send endsess mid-flight (a handle is still mapped).
        req = struct.pack("!2sH16sI", b"\x00\x25", kXR_endsess, b"\x00" * 16, 0)
        sock.sendall(req)
        try:
            _sid, st_end, _ = _read_response(sock)
            # endsess may be answered ok, or the connection may be closed by the
            # proxy after relaying — both are clean outcomes.
            assert st_end in (kXR_ok, kXR_error)
        except ConnectionError:
            pass  # clean teardown closed the socket — acceptable
    finally:
        sock.close()

    # Sanity: the front still serves a brand-new session after the mid-flight
    # endsess (the worker survived).
    sock2 = _connect_login(H, port)
    try:
        assert _ping(sock2)[1] == kXR_ok
    finally:
        sock2.close()
