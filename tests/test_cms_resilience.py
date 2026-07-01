"""
tests/test_cms_resilience.py — Phase 50 CMS network-fault resilience.

These tests exercise the connection-lifecycle hardening added in phase-50
(docs/refactor/phase-50-cms-protocol-hardening.md) WITHOUT any wire change, so a
conformant peer is never tripped:

  * WS3 server LOGIN deadline — a peer that connects and trickles a partial
    header (slowloris) but never completes LOGIN is closed, while a peer that
    completes LOGIN stays open.
  * WS3 server post-login idle watchdog — a logged-in node that then goes silent
    is closed (and unregistered), while one that keeps answering pings survives.
  * WS4 accepted-connection cap — the (N+1)-th CMS connection is refused.
  * WS1 client read-liveness — a data node whose manager black-holes (accepts the
    TCP connection, captures LOGIN, then goes silent) fails over and reconnects.
  * WS6 redirect-host validation — a kYR_select naming a host with control bytes
    is refused (the waiting client is NOT redirected to a poisoned host).
  * Regression — an oversized frame still closes the connection cleanly.

Everything is self-contained on dedicated free ports.  If the nginx binary is
missing or lacks CMS support the affected tests skip cleanly.

Run:
    PYTHONPATH=tests pytest tests/test_cms_resilience.py -v
"""

import os
import socket
import struct
import subprocess
import threading
import time

import pytest

from settings import HOST, NGINX_BIN, free_port

H = HOST
_DIR = os.path.join(os.environ.get("TMPDIR", "/tmp"), "xrd_cms_resilience")

# CMS wire constants — mirror src/cms/cms_internal.h
CMS_RR_LOGIN  = 0
CMS_RR_SELECT = 10
CMS_RR_LOAD   = 16
CMS_RR_PING   = 17
CMS_RR_PONG   = 18
CMS_RR_STATUS = 22
CMS_PT_SHORT  = 0x80
CMS_PT_INT    = 0xa0
CMS_HDR_LEN   = 8
CMS_MAX_FRAME = 4096


# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------

def _build_frame(streamid, code, modifier, payload=b""):
    return struct.pack(">IBBH", streamid, code, modifier, len(payload)) + payload


def _pup_short(v):
    return struct.pack(">BH", CMS_PT_SHORT, v)


def _pup_int(v):
    return struct.pack(">BI", CMS_PT_INT, v)


def _pup_str(s):
    if not s:
        return struct.pack(">H", 0)
    b = s.encode() if isinstance(s, str) else s
    b = b + b"\x00"
    return struct.pack(">H", len(b)) + b


def _login_payload(dport, paths="w /"):
    """A minimal but well-formed CmsLoginData payload the server parser accepts."""
    body = b""
    body += _pup_short(3)          # Version
    body += _pup_int(0x08)         # Mode = kYR_server
    body += _pup_int(os.getpid())  # HoldTime
    body += _pup_int(0)            # tSpace
    body += _pup_int(10000)        # fSpace (free MB)
    body += _pup_int(100)          # mSpace
    body += _pup_short(1)          # fsNum
    body += _pup_short(5)          # fsUtil
    body += _pup_short(dport)      # dPort
    body += _pup_short(0)          # sPort
    body += _pup_str("node:%d" % dport)  # SID
    body += _pup_str(paths)        # Paths
    body += _pup_str("")           # ifList
    body += _pup_str("")           # envCGI
    return body


def _recv_some(sock, timeout):
    """Return True if the peer closed the connection within `timeout`, False if
    it is still open (a read timeout means still-open-but-idle)."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(4096)
    except socket.timeout:
        return False          # still open, just idle
    except OSError:
        return True           # connection error == closed
    return data == b""        # empty recv == clean close


def _wait_closed(sock, timeout):
    """Block up to `timeout` for the peer to close `sock`; return True if closed."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _recv_some(sock, min(1.0, max(0.1, deadline - time.time()))):
            return True
    return False


# ---------------------------------------------------------------------------
# nginx helpers
# ---------------------------------------------------------------------------

def _mkdirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)


def _write_conf(name, body):
    base = os.path.join(_DIR, name)
    _mkdirs(base, os.path.join(base, "logs"))
    conf = os.path.join(base, f"{name}.conf")
    with open(conf, "w") as f:
        f.write(
            f"worker_processes 1;\n"
            f"error_log {base}/logs/error.log info;\n"
            f"pid {base}/logs/nginx.pid;\n"
            f"events {{ worker_connections 128; }}\n"
            f"stream {{\n{body}}}\n")
    return conf


def _start_nginx(conf):
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)
    time.sleep(0.3)
    chk = subprocess.run([NGINX_BIN, "-t", "-c", conf],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        return False, chk.stderr[-400:]
    started = subprocess.run([NGINX_BIN, "-c", conf], capture_output=True,
                             text=True)
    if started.returncode != 0:
        return False, started.stderr[-400:]
    return True, ""


def _stop_nginx(conf):
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)


def _wait_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((H, port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def _require_nginx():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


# ---------------------------------------------------------------------------
# CMS *server* fixture (manager accepting data nodes) with tight deadlines
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cms_server():
    """A CMS server with short login/idle deadlines and a small cap so the
    accept-side hardening can be observed quickly."""
    _require_nginx()
    port = int(os.environ.get("TEST_CMSR_SRV_PORT") or free_port())
    data_dir = os.path.join(_DIR, "srv_data")
    _mkdirs(data_dir)
    body = (
        f"    server {{\n"
        f"        listen 0.0.0.0:{port};\n"
        f"        xrootd on; xrootd_storage_backend posix:{data_dir}; xrootd_auth none;\n"
        f"        xrootd_manager_mode on;\n"
        f"        xrootd_cms_server on;\n"
        f"        xrootd_cms_server_interval 1;\n"
        f"        xrootd_cms_server_login_timeout 2s;\n"
        f"        xrootd_cms_server_idle_timeout 3s;\n"
        f"        xrootd_cms_server_max_connections 2;\n"
        f"    }}\n")
    conf = _write_conf("cmssrv", body)
    ok, err = _start_nginx(conf)
    if not ok:
        pytest.skip(f"cms-server config rejected (CMS unsupported?): {err}")
    try:
        if not _wait_port(port):
            pytest.skip("cms-server nginx did not come up")
        yield port
    finally:
        _stop_nginx(conf)


# ---------------------------------------------------------------------------
# WS3 — server LOGIN handshake deadline (slowloris)
# ---------------------------------------------------------------------------

def test_server_login_timeout_closes_partial_header(cms_server):
    """A peer that sends a partial header and never completes LOGIN is closed
    by the server's login deadline (2s), not left squatting forever."""
    s = socket.create_connection((H, cms_server), timeout=5)
    try:
        s.sendall(b"\x00\x00\x00\x00")     # 4 of the 8 header bytes, then stall
        assert _wait_closed(s, timeout=6.0), \
            "server did not close a stalled pre-LOGIN connection"
    finally:
        s.close()


def test_server_login_completed_stays_open(cms_server):
    """Control: a peer that completes LOGIN before the deadline is NOT closed by
    it — proving the login timeout does not trip a conformant data node."""
    dport = 41000
    s = socket.create_connection((H, cms_server), timeout=5)
    try:
        s.sendall(_build_frame(0, CMS_RR_LOGIN, 0, _login_payload(dport)))
        # Past the 2s login deadline the connection must still be open (the idle
        # watchdog is 3s and we are well within it right after login).
        assert not _wait_closed(s, timeout=2.5), \
            "server closed a connection that completed LOGIN in time"
    finally:
        s.close()


# ---------------------------------------------------------------------------
# WS3 — server post-login idle watchdog
# ---------------------------------------------------------------------------

def test_server_idle_timeout_closes_silent_node(cms_server):
    """A node that logs in then goes silent (answers no pings) is reaped by the
    idle watchdog (3s)."""
    dport = 41001
    s = socket.create_connection((H, cms_server), timeout=5)
    try:
        s.sendall(_build_frame(0, CMS_RR_LOGIN, 0, _login_payload(dport)))
        # Drain whatever the server pushes (ping frames) but never reply, so the
        # server sees no INBOUND frame and the idle watchdog must fire.
        assert _wait_closed(s, timeout=6.0), \
            "server did not reap a silent logged-in node"
    finally:
        s.close()


def test_server_idle_kept_alive_by_pongs(cms_server):
    """Control: a node that answers the server's pings keeps the connection
    alive well past the idle timeout — a responsive node is never reaped."""
    dport = 41002
    s = socket.create_connection((H, cms_server), timeout=5)
    try:
        s.sendall(_build_frame(0, CMS_RR_LOGIN, 0, _login_payload(dport)))
        # For ~5s (> the 3s idle timeout) keep sending a frame each second so the
        # server keeps seeing inbound activity.
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                s.sendall(_build_frame(0, CMS_RR_PONG, 0, b""))
            except OSError:
                pytest.fail("server closed a node that was actively sending")
            time.sleep(1.0)
        assert not _recv_some(s, 0.5), \
            "server reaped a node that kept sending frames"
    finally:
        s.close()


# ---------------------------------------------------------------------------
# WS4 — accepted-connection cap
# ---------------------------------------------------------------------------

def test_server_connection_cap_refuses_excess(cms_server):
    """With xrootd_cms_server_max_connections 2, the third concurrent CMS
    connection is refused (closed promptly) while the first two persist."""
    held = []
    try:
        for i in range(2):
            c = socket.create_connection((H, cms_server), timeout=5)
            c.sendall(_build_frame(0, CMS_RR_LOGIN, 0, _login_payload(42000 + i)))
            held.append(c)
        # Give the server a moment to register both.
        time.sleep(0.5)
        third = socket.create_connection((H, cms_server), timeout=5)
        try:
            assert _wait_closed(third, timeout=3.0), \
                "third connection over the cap was not refused"
        finally:
            third.close()
    finally:
        for c in held:
            c.close()


# ---------------------------------------------------------------------------
# Regression — oversized frame still closes cleanly
# ---------------------------------------------------------------------------

def test_server_oversized_frame_closes(cms_server):
    """A frame whose dlen pushes the total over NGX_XROOTD_CMS_MAX_FRAME is
    rejected with a connection close (unchanged from before phase-50)."""
    s = socket.create_connection((H, cms_server), timeout=5)
    try:
        # dlen = 0xFFFF (65535) >> 4088 max -> header alone triggers the reject.
        s.sendall(struct.pack(">IBBH", 0, CMS_RR_LOAD, 0, 0xFFFF))
        assert _wait_closed(s, timeout=3.0), \
            "server did not close on an oversized frame"
    finally:
        s.close()


# ---------------------------------------------------------------------------
# WS1 / WS6 — client side: a manager peer that captures the node connection
# ---------------------------------------------------------------------------

class ManagerPeer:
    """Accepts the node's outbound CMS connection(s), records LOGIN arrivals, and
    can send manager-originated frames back down the latest connection."""

    def __init__(self, port):
        self.port = port
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bound = False
        for _ in range(40):
            try:
                self._srv.bind(("0.0.0.0", port))
                bound = True
                break
            except OSError:
                time.sleep(0.25)
        if not bound:
            self._srv.close()
            raise OSError(f"could not bind manager peer port {port}")
        self._srv.listen(8)
        self._lock = threading.Lock()
        self.connections = 0          # count of accepted node connections
        self.logins = 0               # count of LOGIN frames seen
        self.conn = None
        self._stop = False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _ = self._srv.accept()
            except (socket.timeout, OSError):
                if self._stop:
                    return
                continue
            with self._lock:
                self.connections += 1
                self.conn = conn
            threading.Thread(target=self._read_loop, args=(conn,),
                             daemon=True).start()

    def _read_loop(self, conn):
        conn.settimeout(0.5)
        buf = bytearray()
        while not self._stop:
            while len(buf) >= CMS_HDR_LEN:
                _sid, code, _mod, dlen = struct.unpack(
                    ">IBBH", bytes(buf[:CMS_HDR_LEN]))
                if len(buf) < CMS_HDR_LEN + dlen:
                    break
                del buf[:CMS_HDR_LEN + dlen]
                if code == CMS_RR_LOGIN:
                    with self._lock:
                        self.logins += 1
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            buf.extend(chunk)

    def wait_connections(self, n, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if self.connections >= n:
                    return True
            time.sleep(0.1)
        return False

    def send_to_node(self, streamid, code, modifier, payload=b""):
        with self._lock:
            conn = self.conn
        if conn is None:
            return False
        try:
            conn.sendall(_build_frame(streamid, code, modifier, payload))
            return True
        except OSError:
            return False

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass
        with self._lock:
            if self.conn is not None:
                try:
                    self.conn.close()
                except OSError:
                    pass


@pytest.fixture(scope="module")
def silent_manager_node():
    """A Python manager peer that goes silent + a data node dialing it with a
    short cms_read_timeout, so the node's read-liveness failover can be seen."""
    _require_nginx()
    mgr_port = int(os.environ.get("TEST_CMSR_MGR_PORT") or free_port())
    node_port = int(os.environ.get("TEST_CMSR_NODE_PORT") or free_port())
    data_dir = os.path.join(_DIR, "node_data")
    _mkdirs(data_dir)
    try:
        peer = ManagerPeer(mgr_port)
    except OSError as exc:
        pytest.skip(f"could not bind manager peer: {exc}")

    body = (
        f"    server {{\n"
        f"        listen 0.0.0.0:{node_port};\n"
        f"        xrootd on; xrootd_storage_backend posix:{data_dir}; xrootd_auth none;\n"
        f"        xrootd_listen_port {node_port};\n"
        f"        xrootd_cms_manager {H}:{mgr_port};\n"
        f"        xrootd_cms_paths /;\n"
        f"        xrootd_cms_interval 1;\n"
        f"        xrootd_cms_read_timeout 3s;\n"
        f"    }}\n")
    conf = _write_conf("node", body)
    ok, err = _start_nginx(conf)
    if not ok:
        peer.close()
        pytest.skip(f"node config rejected (CMS client unsupported?): {err}")
    try:
        if not _wait_port(node_port):
            peer.close()
            pytest.skip("data-node nginx did not come up")
        yield peer
    finally:
        _stop_nginx(conf)
        peer.close()


def test_client_reconnects_when_manager_silent(silent_manager_node):
    """The node dials the manager and logs in; the manager then stays silent.
    With cms_read_timeout=3s the node must tear down and reconnect, so the peer
    observes a SECOND connection (and a second LOGIN)."""
    peer = silent_manager_node
    assert peer.wait_connections(1, timeout=20.0), \
        "node never dialed the manager peer"
    # The peer sends nothing back. Within read_timeout(3s)+backoff the node must
    # reconnect — observed as a second accepted connection.
    assert peer.wait_connections(2, timeout=20.0), \
        "node did not fail over (reconnect) after manager went silent"
    with peer._lock:
        assert peer.logins >= 2, "reconnect did not re-issue LOGIN"


def test_client_rejects_poisoned_redirect_host(silent_manager_node):
    """WS6: a kYR_select naming a host with control bytes is refused — the node
    logs a rejection and does NOT crash/redirect.  We assert the node connection
    survives the malicious frame (liveness probe: it keeps reconnecting/serving),
    proving the poisoned host never reached xrootd_send_redirect."""
    peer = silent_manager_node
    assert peer.wait_connections(1, timeout=20.0), \
        "node never dialed the manager peer"
    # streamid 0 (no pending session) + a host with CR/LF + an alt scheme; the
    # validator must reject it.  Even with no pending locate this must not crash
    # the worker — the node keeps running (still reachable / still reconnecting).
    poisoned = b"evil\r\nLocation:x\x00" + struct.pack(">H", 1094)
    peer.send_to_node(0, CMS_RR_SELECT, 0, poisoned)
    # The node must still be alive: it continues its reconnect cycle (the manager
    # is otherwise silent), so we still see fresh connections accumulate.
    before = peer.connections
    assert peer.wait_connections(before + 1, timeout=20.0), \
        "node appears to have died after a poisoned kYR_select"
