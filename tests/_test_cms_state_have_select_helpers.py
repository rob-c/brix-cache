"""
tests/test_cms_state_have_select.py — CMS on-demand selection wire conformance.

This suite drives the nginx CMS *client* (a data-server / sub-manager that
connects OUT to a CMS manager, src/net/cms/recv.c + src/net/cms/send.c) and the nginx
CMS *server* (a manager that accepts data-node registrations,
src/net/cms/server_recv.c) using a self-contained Python CMS peer over raw sockets.
It exercises the real XrdCms on-demand selection handshake the way a live cmsd
manager does: after nginx logs in, the peer sends kYR_state ("do you hold
<path>?") and verifies nginx replies kYR_have for a held path with the matching
streamid, stays silent for path-traversal / symlink-escape / malformed
requests, and that the kYR_select / kYR_try redirect-reply parsers handle short
payloads, big-endian ports, unknown streamids and malformed try-lists without
desyncing or crashing the connection.  Every hostile frame is followed by a
sanity ping/pong (client side) or a benign frame + liveness probe (server side)
to prove the CMS connection survived intact.

nginx connects to the manager on a per-worker timer with exponential backoff, so
the peer LISTENS on a dedicated high port and waits for nginx to dial in.  The
whole stack (nginx + python peer) is provisioned on dedicated ports (>=12950)
with module-scoped fixtures and pidfile/`nginx -s stop` teardown; it skips
cleanly if the nginx binary is missing, if the build lacks the CMS directives,
if a port is occupied, or if nginx never dials in.

Wire framing was validated against src/net/cms/cms_internal.h, src/net/cms/frame_io.c
(header = streamid[4] code[1] modifier[1] dlen[2], all big-endian) and the real
nginx handlers in src/net/cms/recv.c / src/net/cms/server_recv.c, and end-to-end against
the built binary (kYR_state /held.bin -> kYR_have modifier 0x21, streamid echo).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_state_have_select.py -v
"""

import os
import socket
import struct
import threading
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import SERVER_HOST, HOST, BIND_HOST
from ephemeral_port import free_port

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-state")]

H = SERVER_HOST

_DIR = os.path.join(os.environ["TMPDIR"], "xrd_cms_state_have_select")


# ---------------------------------------------------------------------------
# CMS wire constants (from src/net/cms/cms_internal.h — do not renumber)
# ---------------------------------------------------------------------------

CMS_RR_LOGIN   = 0
CMS_RR_LOCATE  = 2
CMS_RR_AVAIL   = 12
CMS_RR_GONE    = 14
CMS_RR_HAVE    = 15
CMS_RR_LOAD    = 16
CMS_RR_SELECT  = 10
CMS_RR_PING    = 17
CMS_RR_PONG    = 18
CMS_RR_SPACE   = 19
CMS_RR_STATE   = 20
CMS_RR_STATUS  = 22
CMS_RR_TRY     = 24

# Pup type tags (src/net/cms/cms_internal.h: CMS_PT_SHORT / CMS_PT_INT).
CMS_PT_SHORT   = 0x80
CMS_PT_INT     = 0xA0

# Modifier bits (src/net/cms/cms_internal.h).
CMS_MOD_RAW     = 0x20
CMS_HAVE_ONLINE = 0x01

HDR_LEN = 8


# ---------------------------------------------------------------------------
# Raw CMS frame helpers (header = streamid[4] code[1] modifier[1] dlen[2], BE).
# Matches brix_cms_send_frame() in src/net/cms/frame_io.c byte-for-byte.
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"socket closed, {n - len(buf)} of {n} bytes remaining")
        buf.extend(chunk)
    return bytes(buf)


def _recv_frame(sock):
    """Read one CMS frame -> (streamid, code, modifier, payload)."""
    hdr = _recv_exact(sock, HDR_LEN)
    streamid, code, modifier, dlen = struct.unpack(">IBBH", hdr)
    payload = _recv_exact(sock, dlen) if dlen else b""
    return streamid, code, modifier, payload


def _send_frame(sock, streamid, code, modifier=0, payload=b""):
    sock.sendall(struct.pack(">IBBH", streamid, code, modifier, len(payload))
                 + payload)


def _select_payload(host, port):
    """kYR_select / single kYR_try entry: NUL-terminated host + BE uint16 port."""
    return host.encode() + b"\x00" + struct.pack(">H", port)


def _try_payload(*entries):
    return b"".join(_select_payload(h, p) for h, p in entries)


def _drain_until(sock, want_code, deadline, *, allow_codes=()):
    """Read frames until one with `want_code` arrives (returns it) or the
    deadline passes (returns None).  Frames whose code is in `allow_codes`
    (heartbeat noise: LOAD / STATUS / AVAIL / GONE) are skipped.  An unexpected
    code is returned so the caller can assert on it."""
    while time.time() < deadline:
        remaining = max(0.2, deadline - time.time())
        sock.settimeout(remaining)
        try:
            sid, code, mod, payload = _recv_frame(sock)
        except (socket.timeout, ConnectionError, OSError):
            return None
        if code == want_code:
            return (sid, code, mod, payload)
        if code in allow_codes:
            continue
        # Unexpected but non-fatal frame — return it for inspection.
        return (sid, code, mod, payload)
    return None


# Heartbeat / housekeeping codes nginx (as CMS client) emits unprompted after
# login.  Verified end-to-end: the client sends kYR_status (22) and kYR_load
# (16); kYR_avail/kYR_gone may also appear depending on configuration.
_NOISE = (CMS_RR_LOAD, CMS_RR_STATUS, CMS_RR_AVAIL, CMS_RR_GONE)


# ===========================================================================
# Python CMS MANAGER peer — accepts nginx's outbound CMS-client connection
# ===========================================================================

class _ManagerPeer:
    """Listens on MGR_PORT, accepts the single nginx CMS-client connection,
    reads its LOGIN, and exposes the live socket for the test to drive
    kYR_state / kYR_select / kYR_try / kYR_ping against."""

    def __init__(self, port):
        self.port = port
        self._srv = None
        self._conn = None
        self._login = None
        self._thread = None
        self._ready = threading.Event()
        self._err = None

    def start(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, self.port))
        self._srv.listen(4)
        self._srv.settimeout(40)
        self._thread = threading.Thread(target=self._accept_one, daemon=True)
        self._thread.start()

    def _accept_one(self):
        try:
            conn, _ = self._srv.accept()
            conn.settimeout(30)
            # First frame from nginx is the LOGIN (streamid 0, code 0).
            sid, code, mod, payload = _recv_frame(conn)
            self._login = (sid, code, mod, payload)
            self._conn = conn
            self._ready.set()
        except Exception as exc:  # pragma: no cover - diagnostic
            self._err = exc
            self._ready.set()

    def wait_login(self, timeout=35):
        """Block until nginx has connected and sent LOGIN.  Returns the conn or
        None (test should skip if nginx never dialled in)."""
        if not self._ready.wait(timeout):
            return None
        if self._conn is None:
            return None
        return self._conn

    def stop(self):
        for s in (self._conn, self._srv):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def client_stack(lifecycle):
    """nginx CMS-client subscribed to a python manager peer.  Yields the live
    accepted manager-side socket (after nginx LOGIN), plus the data dir."""
    mgr_port = free_port()
    data_dir = os.path.join(_DIR, "client_data")
    os.makedirs(data_dir, exist_ok=True)
    # A real, in-root file the manager can probe with kYR_state.
    with open(os.path.join(data_dir, "held.bin"), "wb") as f:
        f.write(b"held-file-contents")

    # A symlink that escapes the export root (-> /etc) to prove RESOLVE_BENEATH
    # makes nginx stay silent rather than answering kYR_have for an outside file.
    escape = os.path.join(data_dir, "escape")
    try:
        if os.path.islink(escape) or os.path.exists(escape):
            os.unlink(escape)
        os.symlink("/etc", escape)
    except OSError:
        pass  # symlink-escape test will skip if we couldn't plant it

    peer = _ManagerPeer(mgr_port)
    peer.start()

    try:
        lifecycle.start(NginxInstanceSpec(
            name="lc-cms-state-client",
            template="nginx_cms_state_client.conf",
            protocol="root",
            readiness="tcp",
            data_root=data_dir,
            template_values={"MANAGER_PORT": mgr_port},
            reason="CMS state/have/select: client-side wire conformance.",
        ))
    except Exception:
        peer.stop()
        raise
    try:
        conn = peer.wait_login()
        if conn is None:
            pytest.skip("nginx never dialled in to the CMS manager peer "
                        f"(err={peer._err})")
        yield {"conn": conn, "data_dir": data_dir, "peer": peer}
    finally:
        peer.stop()


@pytest.fixture
def server_stack(lifecycle):
    """nginx CMS-server (manager).  Yields the listen port for data-node
    sockets to dial into."""
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-cms-state-server",
        template="nginx_cms_state_server.conf",
        protocol="root",
        readiness="tcp",
        reason="CMS state/have/select: server-side kYR_gone conformance.",
    ))
    return {"port": ep.port}


def _ping_sanity(conn, deadline_s=6.0):
    """Sanity op (client side): send kYR_ping, expect kYR_pong back -> the CMS
    connection survived the preceding hostile/edge frame intact."""
    streamid = 0xABCD1234
    _send_frame(conn, streamid, CMS_RR_PING)
    got = _drain_until(conn, CMS_RR_PONG, time.time() + deadline_s,
                       allow_codes=_NOISE)
    assert got is not None, "no kYR_pong — CMS connection did not survive"
    assert got[1] == CMS_RR_PONG, f"expected pong, got code={got[1]}"
    # nginx echoes the request streamid back in the pong.
    assert got[0] == streamid, f"pong streamid {got[0]} != request {streamid}"


# ===========================================================================
# Class 1 — kYR_state -> kYR_have (CMS client / src/net/cms/recv.c)
# ===========================================================================

def _login_payload():
    """A minimal-but-valid CmsLoginData payload the nginx CMS-server parser
    (cms_srv_parse_login) accepts: PT_SHORT/PT_INT scalars in wire order then
    SID + Paths Pup strings.  We advertise dPort and an export path '/' so the
    node registers; the exact values don't matter for the gone tests, only that
    LOGIN is accepted and the node becomes logged_in.

    Wire format verified against src/net/cms/server_recv.c:
      tlv_read_next()      — PT_SHORT (0x80)+BE u16  |  PT_INT (0xa0)+BE u32
      cms_srv_read_string()— BE u16 length prefix then that many bytes
    """
    def pshort(v):
        return bytes([CMS_PT_SHORT]) + struct.pack(">H", v)

    def pint(v):
        return bytes([CMS_PT_INT]) + struct.pack(">I", v)

    def pstr(s):
        if not s:
            return struct.pack(">H", 0)
        b = s.encode()
        return struct.pack(">H", len(b) + 1) + b + b"\x00"

    body = b"".join([
        pshort(3),          # Version
        pint(0x08),         # Mode (kYR_server)
        pint(300),          # HoldTime
        pint(0),            # tSpace
        pint(10000),        # fSpace (free_mb)
        pint(100),          # mSpace
        pshort(1),          # fsNum
        pshort(5),          # fsUtil (util_pct)
        pshort(1094),       # dPort
        pshort(0),          # sPort
        pstr("nodeA:1094"),  # SID
        pstr("w /"),         # Paths ("<type> <path>")
        pstr(""),            # ifList
        pstr(""),            # envCGI
    ])
    return body


def _server_login(conn):
    """Drive the LOGIN handshake against the nginx CMS-server.  Returns True.

    cms_srv_parse_login() is lenient (it always returns success and registers
    the node) and the server sends NO immediate reply — it arms a ping timer.
    There is therefore no reply frame to assert on here; admission is proven by
    the subsequent _server_alive() liveness probe in each test.  A follow-up
    benign LOAD frame is sent to confirm the post-login dispatch path accepts
    data-node traffic without tearing the connection down."""
    _send_frame(conn, 0, CMS_RR_LOGIN, payload=_login_payload())
    # Benign LOAD: PT_SHORT count + 6 raw CPU bytes + PT_INT free_mb.  The
    # server's parser is lenient about a malformed count tag, so this never
    # closes the connection (verified against cms_srv_parse_load_free_mb).
    _send_frame(conn, 0, CMS_RR_LOAD,
                payload=bytes([CMS_PT_SHORT]) + struct.pack(">H", 6)
                + b"\x00" * 6
                + bytes([CMS_PT_INT]) + struct.pack(">I", 9000))
    return True


def _server_alive(conn):
    """Liveness probe (server side): the nginx CMS-server only emits frames on
    its own ping timer (kYR_ping) and never replies to data-node frames, so we
    prove survival by sending a benign LOAD and confirming the socket is still
    writable and not closed (no RST/FIN)."""
    try:
        _send_frame(conn, 0, CMS_RR_LOAD,
                    payload=bytes([CMS_PT_SHORT]) + struct.pack(">H", 6)
                    + b"\x00" * 6
                    + bytes([CMS_PT_INT]) + struct.pack(">I", 8000))
    except OSError as exc:
        pytest.fail(f"CMS-server closed the connection: {exc}")
    # A short read: nginx may send a ping; anything other than a clean
    # closed-socket (b"") proves the connection is alive.
    conn.settimeout(1.0)
    try:
        data = conn.recv(64)
        # Empty read == peer closed the connection -> server tore us down.
        assert data != b"", "CMS-server closed the connection after the frame"
    except socket.timeout:
        pass  # silence == still connected, which is the expected case
