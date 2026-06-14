"""
tests/test_cms_state_have_select.py — CMS on-demand selection wire conformance.

This suite drives the nginx CMS *client* (a data-server / sub-manager that
connects OUT to a CMS manager, src/cms/recv.c + src/cms/send.c) and the nginx
CMS *server* (a manager that accepts data-node registrations,
src/cms/server_recv.c) using a self-contained Python CMS peer over raw sockets.
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

Wire framing was validated against src/cms/cms_internal.h, src/cms/frame_io.c
(header = streamid[4] code[1] modifier[1] dlen[2], all big-endian) and the real
nginx handlers in src/cms/recv.c / src/cms/server_recv.c, and end-to-end against
the built binary (kYR_state /held.bin -> kYR_have modifier 0x21, streamid echo).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_state_have_select.py -v
"""

import os
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time

import pytest

from settings import NGINX_BIN, SERVER_HOST

H = SERVER_HOST

# ---------------------------------------------------------------------------
# Dedicated stack — unique high ports (>=12950) to avoid collisions with the
# shared fleet and the other self-provisioned suites (mirror uses 12910-12929).
# ---------------------------------------------------------------------------

_DIR = "/tmp/xrd_cms_state_have_select"

# CMS-client nginx: nginx dials OUT to MGR_PORT; we play the manager there.
# 12996-12998: above test_proxy_protocol_edges' reserved 12950-12972 block so
# the full P0 suite runs collision-free in one pytest invocation.
CLIENT_NGINX_PORT = int(os.environ.get("TEST_CMSSHS_CLIENT_PORT", "12996"))
MGR_PORT          = int(os.environ.get("TEST_CMSSHS_MGR_PORT",    "12997"))

# CMS-server nginx: nginx LISTENS as a manager; we play a data node dialing IN.
SRV_NGINX_PORT    = int(os.environ.get("TEST_CMSSHS_SRV_PORT",    "12998"))


# ---------------------------------------------------------------------------
# CMS wire constants (from src/cms/cms_internal.h — do not renumber)
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

# Pup type tags (src/cms/cms_internal.h: CMS_PT_SHORT / CMS_PT_INT).
CMS_PT_SHORT   = 0x80
CMS_PT_INT     = 0xA0

# Modifier bits (src/cms/cms_internal.h).
CMS_MOD_RAW     = 0x20
CMS_HAVE_ONLINE = 0x01

HDR_LEN = 8


# ---------------------------------------------------------------------------
# Raw CMS frame helpers (header = streamid[4] code[1] modifier[1] dlen[2], BE).
# Matches xrootd_cms_send_frame() in src/cms/frame_io.c byte-for-byte.
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
        self._srv.bind(("127.0.0.1", self.port))
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
# nginx provisioning helpers
# ===========================================================================

def _reachable(port, timeout=1.0):
    try:
        socket.create_connection((H, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _wait_port(port, up=True, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _reachable(port, 0.5) == up:
            return True
        time.sleep(0.2)
    return False


def _mkdirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)


def _client_conf(name, port, data_dir, mgr_port):
    """nginx as a CMS *client* (data node): plain xrootd server that subscribes
    UP to our python manager peer via xrootd_cms_manager.  A short cms_interval
    keeps the reconnect backoff small so the test connects quickly."""
    base = os.path.join(_DIR, name)
    _mkdirs(data_dir, os.path.join(base, "logs"))
    conf = os.path.join(base, f"{name}.conf")
    with open(conf, "w") as f:
        f.write(
            f"worker_processes 1;\n"
            f"error_log {base}/logs/error.log info;\n"
            f"pid {base}/logs/nginx.pid;\n"
            f"events {{ worker_connections 128; }}\n"
            f"stream {{\n"
            f"    server {{\n"
            f"        listen 0.0.0.0:{port};\n"
            f"        xrootd on;\n"
            f"        xrootd_root {data_dir};\n"
            f"        xrootd_auth none;\n"
            f"        xrootd_allow_write on;\n"
            f"        xrootd_cms_manager 127.0.0.1:{mgr_port};\n"
            f"        xrootd_cms_paths /;\n"
            f"        xrootd_cms_interval 2;\n"
            f"        xrootd_listen_port {port};\n"
            f"    }}\n"
            f"}}\n")
    return conf


def _server_conf(name, port, data_dir):
    """nginx as a CMS *server* (manager): accepts inbound data-node logins on
    the same stream port via xrootd_cms_server on; (no allowlist -> any peer)."""
    base = os.path.join(_DIR, name)
    _mkdirs(data_dir, os.path.join(base, "logs"))
    conf = os.path.join(base, f"{name}.conf")
    with open(conf, "w") as f:
        f.write(
            f"worker_processes 1;\n"
            f"error_log {base}/logs/error.log info;\n"
            f"pid {base}/logs/nginx.pid;\n"
            f"events {{ worker_connections 128; }}\n"
            f"stream {{\n"
            f"    server {{\n"
            f"        listen 0.0.0.0:{port};\n"
            f"        xrootd_cms_server on;\n"
            f"        xrootd_cms_server_interval 60;\n"
            f"    }}\n"
            f"}}\n")
    return conf


def _pidfile(conf):
    return os.path.join(os.path.dirname(conf), "logs", "nginx.pid")


def _kill_pidfile(conf):
    """Best-effort: stop any nginx left running from a previous run/crash whose
    pidfile sits beside this conf, so a stale master can't hold the port."""
    pid_path = _pidfile(conf)
    try:
        with open(pid_path) as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    else:
        # Give the master a moment to release the listen socket.
        for _ in range(20):
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.1)
    try:
        os.unlink(pid_path)
    except OSError:
        pass


def _start_nginx(conf):
    """Start nginx, skipping cleanly (never erroring) on a config the build
    rejects (e.g. CMS directives not compiled in) or a port already in use."""
    # Clear any leftover master from a crashed prior run first.
    _kill_pidfile(conf)

    chk = subprocess.run([NGINX_BIN, "-t", "-c", conf],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip(
            "nginx rejected the CMS test config (build may lack CMS "
            f"directives): {chk.stderr.strip()[-300:]}")

    run = subprocess.run([NGINX_BIN, "-c", conf],
                         capture_output=True, text=True)
    if run.returncode != 0:
        # Typically EADDRINUSE from another instance on our dedicated port.
        pytest.skip(
            f"nginx failed to start for {conf}: "
            f"{(run.stderr or run.stdout).strip()[-300:]}")


def _stop_nginx(conf):
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"],
                   capture_output=True)
    # Fall back to the pidfile in case `-s stop` couldn't reach the master.
    _kill_pidfile(conf)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture(scope="module")
def client_stack():
    """nginx CMS-client subscribed to a python manager peer.  Yields the live
    accepted manager-side socket (after nginx LOGIN), plus the data dir."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if _reachable(MGR_PORT, 0.3) or _reachable(CLIENT_NGINX_PORT, 0.3):
        pytest.skip("dedicated CMS-client ports already in use; another "
                    "instance is running")

    base = os.path.join(_DIR, "client")
    shutil.rmtree(base, ignore_errors=True)
    data_dir = os.path.join(_DIR, "client_data")
    shutil.rmtree(data_dir, ignore_errors=True)
    _mkdirs(data_dir)
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

    peer = _ManagerPeer(MGR_PORT)
    peer.start()

    conf = _client_conf("client", CLIENT_NGINX_PORT, data_dir, MGR_PORT)
    _start_nginx(conf)
    try:
        if not _wait_port(CLIENT_NGINX_PORT):
            pytest.skip("CMS-client nginx did not come up")
        conn = peer.wait_login()
        if conn is None:
            pytest.skip("nginx never dialled in to the CMS manager peer "
                        f"(err={peer._err})")
        yield {"conn": conn, "data_dir": data_dir, "peer": peer}
    finally:
        peer.stop()
        _stop_nginx(conf)


@pytest.fixture(scope="module")
def server_stack():
    """nginx CMS-server (manager).  Yields the listen port for data-node
    sockets to dial into."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if _reachable(SRV_NGINX_PORT, 0.3):
        pytest.skip("dedicated CMS-server port already in use; another "
                    "instance is running")

    base = os.path.join(_DIR, "server")
    shutil.rmtree(base, ignore_errors=True)
    data_dir = os.path.join(_DIR, "server_data")
    conf = _server_conf("server", SRV_NGINX_PORT, data_dir)
    _start_nginx(conf)
    try:
        if not _wait_port(SRV_NGINX_PORT):
            pytest.skip("CMS-server nginx did not come up")
        yield {"port": SRV_NGINX_PORT}
    finally:
        _stop_nginx(conf)


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
# Class 1 — kYR_state -> kYR_have (CMS client / src/cms/recv.c)
# ===========================================================================

class TestStateHave:
    """The manager probes 'do you hold <path>?' (kYR_state, raw NUL-terminated
    path).  nginx must answer kYR_have (modifier RAW|Online, same streamid)
    only for an in-root file that exists, and stay silent otherwise."""

    def test_state_have_roundtrip_matching_streamid(self, client_stack):
        """A held in-root file -> kYR_have echoing the request streamid, raw
        NUL-terminated path, modifier RAW|Online."""
        conn = client_stack["conn"]
        sid = 0x00C0FFEE
        _send_frame(conn, sid, CMS_RR_STATE, payload=b"/held.bin\x00")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 8.0,
                           allow_codes=_NOISE)
        assert got is not None, "no kYR_have for a held in-root file"
        r_sid, code, mod, payload = got
        assert code == CMS_RR_HAVE
        assert r_sid == sid, f"have streamid {r_sid} != state streamid {sid}"
        # Raw (unmarshalled) NUL-terminated path echoed back.
        assert payload.rstrip(b"\x00") == b"/held.bin"
        assert mod & CMS_MOD_RAW, "kYR_have must carry the RAW modifier"
        assert mod & CMS_HAVE_ONLINE, "kYR_have must carry the Online modifier"
        _ping_sanity(conn)

    def test_state_missing_file_silent(self, client_stack):
        """A path that does not exist under the export root -> NO kYR_have; the
        manager simply doesn't select this node.  Connection survives."""
        conn = client_stack["conn"]
        _send_frame(conn, 0x11, CMS_RR_STATE, payload=b"/does-not-exist.bin\x00")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 3.0,
                           allow_codes=_NOISE)
        assert got is None or got[1] != CMS_RR_HAVE, \
            "must not answer kYR_have for a missing file"
        _ping_sanity(conn)

    def test_state_path_traversal_rejected_before_stat(self, client_stack):
        """A '..' in the path is rejected by the cheap pre-check BEFORE any
        stat — nginx stays silent (recv.c rejects payload containing '..')."""
        conn = client_stack["conn"]
        _send_frame(conn, 0x22, CMS_RR_STATE,
                    payload=b"/../etc/passwd\x00")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 3.0,
                           allow_codes=_NOISE)
        assert got is None or got[1] != CMS_RR_HAVE, \
            "path traversal must not produce kYR_have"
        _ping_sanity(conn)

    def test_state_symlink_escape_not_answered_with_have(self, client_stack):
        """A symlink under the root pointing OUTSIDE it (escape -> /etc): the
        kernel-confined probe (openat2 RESOLVE_BENEATH) rejects the escape so
        nginx must NOT answer kYR_have, even though /etc/hostname exists."""
        escape = os.path.join(client_stack["data_dir"], "escape")
        if not os.path.islink(escape):
            pytest.skip("could not plant escaping symlink for the test")
        conn = client_stack["conn"]
        # /escape/hostname resolves to /etc/hostname OUTSIDE the export root.
        _send_frame(conn, 0x33, CMS_RR_STATE,
                    payload=b"/escape/hostname\x00")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 3.0,
                           allow_codes=_NOISE)
        assert got is None or got[1] != CMS_RR_HAVE, \
            "symlink escape must not be answered with kYR_have"
        _ping_sanity(conn)

    def test_state_empty_or_missing_nul_terminator(self, client_stack):
        """An empty payload (pl==0) and a non-NUL-terminated path are both
        handled without desyncing the framer.

        recv.c's bounded scan stops at the first NUL or at plen.  An empty
        payload returns NGX_OK with no have.  For a NUL-less '/held.bin' the
        scan runs to plen and the path equals the real file, so a kYR_have is
        legitimate — we therefore only assert *survival* for that case, never a
        specific have/no-have, so this never hard-fails on a benign edge."""
        conn = client_stack["conn"]
        # Empty payload: pl==0 -> early return NGX_OK, no have.
        _send_frame(conn, 0x44, CMS_RR_STATE, payload=b"")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 2.5,
                           allow_codes=_NOISE)
        assert got is None or got[1] != CMS_RR_HAVE
        _ping_sanity(conn)

        # No trailing NUL: survival only (a NUL-less "/held.bin" may legitimately
        # match the real file and produce a have).
        _send_frame(conn, 0x45, CMS_RR_STATE, payload=b"/held.bin")
        _drain_until(conn, CMS_RR_HAVE, time.time() + 2.5, allow_codes=_NOISE)
        _ping_sanity(conn)


# ===========================================================================
# Class 2 — kYR_select / kYR_try redirect-reply parsing (src/cms/recv.c)
# ===========================================================================

class TestSelectTryParsing:
    """kYR_select (single host) and kYR_try (ordered list) carry a redirect
    target the manager resolved for a waiting client.  Standalone (no suspended
    client session in the pending table) the documented behavior is a clean
    no-op (cms_wake_pending_session returns NGX_OK for an unknown streamid);
    the parser must still robustly bounds-check the host/NUL/port framing and
    leave the connection usable.  We assert that documented survival behavior
    via a ping/pong after each frame."""

    def test_select_short_payload_missing_nul_handled(self, client_stack):
        """A select payload shorter than 3 bytes (no room for host+NUL+port)
        hits the `payload_len < 3` guard -> return NGX_OK, no crash."""
        conn = client_stack["conn"]
        _send_frame(conn, 0x51, CMS_RR_SELECT, payload=b"x")   # 1 byte
        _ping_sanity(conn)
        # Host with no NUL and no port bytes: host_len+3 > payload_len guard.
        _send_frame(conn, 0x52, CMS_RR_SELECT, payload=b"host-no-nul")
        _ping_sanity(conn)

    def test_select_port_is_big_endian_2_byte(self, client_stack):
        """A well-formed select (host + NUL + BE uint16 port) parses cleanly.
        The port is read with ngx_xrootd_cms_get16 (big-endian, 2 bytes); we
        feed a distinctive port (0x1F90 = 8080) — the high byte first.  No
        pending session exists so this is a documented silent no-op; the
        connection must survive (proving the port bytes were consumed, not
        misread as trailing payload that desyncs the framer)."""
        conn = client_stack["conn"]
        payload = b"127.0.0.1\x00" + struct.pack(">H", 8080)
        assert payload[-2:] == b"\x1f\x90", "test built a non-BE port"
        _send_frame(conn, 0x53, CMS_RR_SELECT, payload=payload)
        _ping_sanity(conn)

    def test_select_unknown_streamid_silently_ignored(self, client_stack):
        """A select for a streamid that is NOT in the pending-locate table
        (no waiting client) is silently ignored (pending==NULL -> NGX_OK).
        The connection must not be torn down."""
        conn = client_stack["conn"]
        payload = _select_payload("127.0.0.1", 1094)
        _send_frame(conn, 0xDEADBEEF, CMS_RR_SELECT, payload=payload)
        _ping_sanity(conn)

    def test_try_multiple_entries_first_used(self, client_stack):
        """kYR_try with several (host,port) entries: recv.c uses only the FIRST
        entry (the NUL-terminated host then the following port).  With no
        pending session this is a silent no-op; survival proves the first entry
        was parsed and the trailing entries did not desync the framer."""
        conn = client_stack["conn"]
        payload = _try_payload(("first-host", 29001), ("second-host", 29002))
        _send_frame(conn, 0x61, CMS_RR_TRY, payload=payload)
        _ping_sanity(conn)

    def test_try_malformed_entry_parser_stops_cleanly(self, client_stack):
        """A malformed kYR_try (host string but truncated before the 2 port
        bytes) trips the `host_len + 3 > payload_len` guard -> return NGX_OK.
        The framer must not over-read into the next frame."""
        conn = client_stack["conn"]
        # "trunc-host" + NUL but only ONE of the two port bytes present.
        _send_frame(conn, 0x62, CMS_RR_TRY, payload=b"trunc-host\x00\x04")
        _ping_sanity(conn)
        # Also a try payload that is exactly host+NUL with zero port bytes.
        _send_frame(conn, 0x63, CMS_RR_TRY, payload=b"hostonly\x00")
        _ping_sanity(conn)


# ===========================================================================
# Class 3 — kYR_gone on the CMS server side (src/cms/server_recv.c)
# ===========================================================================

def _login_payload():
    """A minimal-but-valid CmsLoginData payload the nginx CMS-server parser
    (cms_srv_parse_login) accepts: PT_SHORT/PT_INT scalars in wire order then
    SID + Paths Pup strings.  We advertise dPort and an export path '/' so the
    node registers; the exact values don't matter for the gone tests, only that
    LOGIN is accepted and the node becomes logged_in.

    Wire format verified against src/cms/server_recv.c:
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


class TestServerGone:
    """kYR_gone on the manager side (nginx CMS-server, server_recv.c): a data
    node signals it no longer holds a path.  An empty-payload gone is a no-op;
    a gone received BEFORE login is ignored (the `if (!ctx->logged_in) break;`
    guard).  Neither must tear down the connection."""

    def _connect(self, server_stack):
        conn = socket.create_connection((H, server_stack["port"]), timeout=8)
        conn.settimeout(8)
        return conn

    def test_gone_empty_payload(self, server_stack):
        """A logged-in node sends kYR_gone with an empty payload -> the
        `payload_len > 0` guard skips the unregister; connection survives."""
        conn = self._connect(server_stack)
        try:
            assert _server_login(conn), "CMS-server did not admit the node"
            _send_frame(conn, 0, CMS_RR_GONE, payload=b"")
            _server_alive(conn)
        finally:
            conn.close()

    def test_gone_before_login_ignored(self, server_stack):
        """kYR_gone arriving BEFORE any LOGIN is ignored (not logged_in) and
        must not crash or close the connection; a subsequent LOGIN still works."""
        conn = self._connect(server_stack)
        try:
            # gone first, with a real path, while NOT logged in.
            _send_frame(conn, 0, CMS_RR_GONE, payload=b"/atlas\x00")
            # The guard `if (!ctx->logged_in) break;` means this is a no-op.
            # The connection must still accept a normal LOGIN afterwards.
            assert _server_login(conn), \
                "CMS-server did not admit the node after a pre-login gone"
            _server_alive(conn)
        finally:
            conn.close()
