# _test_proxy_protocol_edges_stub.py - continuation shard of
# _test_proxy_protocol_edges_helpers.py: the deterministic protocol-stub
# upstream every scenario in test_proxy_protocol_edges.py is driven against.
#
# split_continuation.load() execs this file into that module's namespace, so the
# wire constants, the per-scenario port constants and the client-side helpers are
# already bound here.  It is NOT importable on its own and nothing imports it:
# re-running the parent's module body would re-run its free_ports() allocation
# and hand out a second, different set of ports.

import functools
import socket
import struct
import threading
import time

from settings import BIND_HOST, HOST

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
    """The proxy's redirect-follow parser (src/net/proxy/forward_relay_response.c)
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
    absorbs BRIX_PROXY_MAX_WAIT_RETRIES and re-sends the request each time,
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


def _stat_ok(conn, sid):
    info = b"0 1024 0 0\x00"
    conn.sendall(_hdr(sid, kXR_ok, len(info)))
    conn.sendall(info)


def _hop_chain_handler(conn, seen, lock):
    _stub_bootstrap(conn)
    while True:
        try:
            sid, _reqid, payload = _read_request(conn)
        except (ConnectionError, OSError):
            return
        path = payload.split(b"\x00", 1)[0]
        with lock:
            seen[path] = seen.get(path, 0) + 1
            first_sighting = seen[path] == 1
        hop = path == b"/loop" or (path.startswith(b"/__ppe_hop_hop")
                                   and first_sighting)
        if hop:
            body = _redirect_body(HOST, HOP_BACKEND_PORT)
            conn.sendall(_hdr(sid, kXR_redirect, len(body)))
            conn.sendall(body)
        else:
            _stat_ok(conn, sid)


def _make_hop_chain():
    """Self-referential redirect chain used to exercise the proxy's 3-hop follow
    cap.  The connection-driving client (via _connect_login) first walks the
    redirect counter up to the cap with three followed hops (the ``/__ppe_hop_hopN__``
    warm-ups), then the scenario stat on ``/loop`` is the redirect the proxy must
    relay to the client instead of following.

    Redirect target is always this same listening port, so every followed hop
    lands back here on a fresh connection + bootstrap.  A per-stub sighting map
    keyed on the request path lets a warm-up hop redirect on its first sighting
    (driving one follow) yet answer the proxy's re-issue (second sighting) with a
    plain stat, so each warm-up contributes exactly one hop.  ``/loop`` always
    redirects; the proxy relays it once the counter is at the cap."""
    seen = {}
    lock = threading.Lock()
    return functools.partial(_hop_chain_handler, seen=seen, lock=lock)


def _h_redirect_then_open(conn):
    """Redirect the scenario open on ``/afterredir`` to REDIR_TARGET_PORT: the
    proxy closes this connection and reconnects to the target, rebuilding a clean
    handle map there.  The redirect-front warm-up stat (which brings the upstream
    session to IDLE so the open travels the real re-issue path) is answered
    directly."""
    _stub_bootstrap(conn)
    while True:
        try:
            sid, reqid, payload = _read_request(conn)
        except (ConnectionError, OSError):
            return
        path = payload.split(b"\x00", 1)[0]
        if reqid == kXR_open and b"afterredir" in path:
            body = _redirect_body(HOST, REDIR_TARGET_PORT)
            conn.sendall(_hdr(sid, kXR_redirect, len(body)))
            conn.sendall(body)
        elif reqid == kXR_stat:
            _stat_ok(conn, sid)
        else:
            conn.sendall(_hdr(sid, kXR_ok, 0))


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
