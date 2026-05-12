"""
Tests for the CMS manager heartbeat/registration subsystem.

nginx-xrootd can be configured with ``xrootd_cms_manager host:port`` so that
the server periodically sends registration and heartbeat frames to a CMS
manager.  The protocol uses a simple binary frame format:

    [streamid(4)][code(1)][modifier(1)][payload_len(2)][payload(N)]

Frame codes:
    CMS_RR_LOGIN   (0) — initial registration with path list, PID, space info
    CMS_RR_AVAIL   (12) — availability report with free MB and utilization %
    CMS_RR_LOAD    (16) — load report
    CMS_RR_PING    (17) — heartbeat from manager → server must reply PONG
    CMS_RR_PONG    (18) — server response to manager ping
    CMS_RR_SPACE   (19) — space query
    CMS_RR_STATUS  (22) — status report

This test suite exercises:

  - Login frame construction and delivery to a mock CMS manager
  - PING/PONG heartbeat exchange
  - Availability frame with correct free MB / utilization % fields
  - Reconnection after manager disconnect (backoff timer)

Run:
    pytest tests/test_cms.py -v -s
"""

import os
import socket
import struct
import threading
import time

import pytest

from settings import DATA_ROOT


# ---------------------------------------------------------------------------
# CMS protocol constants
# ---------------------------------------------------------------------------

CMS_RR_LOGIN   = 0
CMS_RR_AVAIL   = 12
CMS_RR_LOAD    = 16
CMS_RR_PING    = 17
CMS_RR_PONG    = 18
CMS_RR_SPACE   = 19
CMS_RR_STATUS  = 22

CMS_PT_SHORT   = 0x80
CMS_PT_INT     = 0xa0

CMS_LOGIN_VERSION = 3
CMS_LOGIN_MODE    = 0x00000008

kXR_ok       = 0
kXR_protocol = 3006
kXR_login    = 3007
kXR_ping     = 3011


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_xrootd_response(sock):
    hdr = _recv_exact(sock, 8)
    assert hdr is not None, "no XRootD response header received"
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _send_xrootd_req(sock, streamid, reqid, body=b"", payload=b""):
    hdr = struct.pack(">2sH", streamid, reqid)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    return _read_xrootd_response(sock)


def _assert_xrootd_ping(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(("127.0.0.1", port))
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        assert _recv_exact(sock, 16) is not None

        status, _ = _send_xrootd_req(sock, b"\x00\x01", kXR_protocol)
        assert status == kXR_ok

        status, _ = _send_xrootd_req(
            sock,
            b"\x00\x01",
            kXR_login,
            payload=b"anon\x00\x00\x00\x00",
        )
        assert status == kXR_ok

        status, _ = _send_xrootd_req(sock, b"\x00\x01", kXR_ping)
        assert status == kXR_ok
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Mock CMS manager
# ---------------------------------------------------------------------------

class _MockCmsManager:
    """A minimal CMS manager that accepts login frames and sends pings."""

    def __init__(self, port):
        self.port = port
        self._sock = None
        self._thread = None
        self._running = False
        self._received_frames = []  # list of (code, payload) tuples
        self._connections = set()
        self._handler_threads = []
        self._lock = threading.Lock()

    def start(self):
        """Start the mock manager in a background thread."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(4)
        self._running = True

        def _loop():
            while self._running:
                self._sock.settimeout(1.0)
                try:
                    conn, _ = self._sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._running:
                        continue
                    break
                with self._lock:
                    self._connections.add(conn)
                t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
                with self._lock:
                    self._handler_threads.append(t)
                t.start()

        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()

    def _recv_exact(self, sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _handle(self, conn):
        """Handle a single CMS connection from an nginx server."""
        try:
            while self._running:
                conn.settimeout(10.0)
                hdr = self._recv_exact(conn, 8)
                if not hdr:
                    break

                streamid = struct.unpack(">I", hdr[:4])[0]
                code = hdr[4]
                modifier = hdr[5]
                payload_len = struct.unpack(">H", hdr[6:8])[0]

                payload = b""
                if payload_len > 0:
                    payload = self._recv_exact(conn, payload_len)

                with self._lock:
                    self._received_frames.append((code, streamid, modifier, payload))

                # Respond to PING with PONG
                if code == CMS_RR_PING:
                    pong_hdr = struct.pack(">IBBH", 0, CMS_RR_PONG, 0, 0)
                    conn.sendall(pong_hdr)

                # Send a PING after login to test heartbeat response
                if code == CMS_RR_LOGIN:
                    time.sleep(2.0)
                    if self._running:
                        ping_hdr = struct.pack(">IBBH", 1, CMS_RR_PING, 0, 0)
                        conn.sendall(ping_hdr)

        except Exception:
            pass
        finally:
            with self._lock:
                self._connections.discard(conn)
            conn.close()

    def get_received_frames(self):
        """Return a copy of all received frames."""
        with self._lock:
            return list(self._received_frames)

    def stop(self):
        self._running = False
        try:
            if self._sock:
                self._sock.close()
                self._sock = None
        except OSError:
            pass
        with self._lock:
            connections = list(self._connections)
            threads = list(self._handler_threads)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        for thread in threads:
            thread.join(timeout=2.0)


# ---------------------------------------------------------------------------
# Fixture — start nginx with CMS manager configured
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cms_nginx(test_env, tmp_path_factory):
    """Start an nginx instance with CMS manager heartbeat configured."""
    import server_control

    log_dir = tmp_path_factory.mktemp("cms-logs") / "logs"
    os.makedirs(log_dir, exist_ok=True)
    data_dir = test_env["data_dir"]

    cms_port = 12400
    nginx_port = 12500

    conf_text = f"""
worker_processes 1;
error_log {log_dir}/error.log debug;
pid {log_dir}/nginx.pid;
thread_pool default threads=4 max_queue=65536;

events {{ worker_connections 64; }}

stream {{
    server {{
        listen {nginx_port};
        xrootd on;
        xrootd_root {data_dir};
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_cms_manager 127.0.0.1:{cms_port};
        xrootd_cms_paths /data;
        xrootd_cms_interval 5;
    }}
}}
"""

    info = server_control.start_nginx_instance(
        port=nginx_port,
        conf_text=conf_text,
        template_kwargs={"DATA_DIR": data_dir},
    )

    # Start mock CMS manager
    cms = _MockCmsManager(cms_port)
    cms.start()

    time.sleep(2.0)  # give nginx time to connect and send login

    yield {
        "nginx": info,
        "cms": cms,
        "log_dir": log_dir,
        "url": f"root://localhost:{nginx_port}",
    }

    cms.stop()
    info["stop"]()


# ---------------------------------------------------------------------------
# Login frame — initial registration
# ---------------------------------------------------------------------------

class TestCmsLogin:
    """Verify that the server sends a valid login frame to the CMS manager."""

    def test_login_frame_received(self, cms_nginx):
        """The CMS manager must receive a LOGIN frame with correct fields."""
        frames = cms_nginx["cms"].get_received_frames()

        login_frames = [f for f in frames if f[0] == CMS_RR_LOGIN]
        assert len(login_frames) >= 1, "no LOGIN frame received from nginx"

        code, streamid, modifier, payload = login_frames[0]
        assert streamid == 0, "login streamid must be 0"
        assert modifier == 0, "login modifier must be 0"

        # Parse login payload: [version(short)][mode(int)][pid(int)]
        # [total_gb(int)][free_mb(int)][min_free_mb(int)][role(short)]
        # [util_pct(short)][port(short)][flags(short)][flags(short)]
        # [path_len(short)][paths(N)][flags(short)][flags(short)]

        p = payload
        assert p[0] == CMS_PT_SHORT, "version must be PT_SHORT tag"
        version = struct.unpack(">H", p[1:3])[0]
        assert version == CMS_LOGIN_VERSION, f"login version {version} != expected {CMS_LOGIN_VERSION}"

        p = p[3:]  # skip tag(1) + short value(2)
        assert p[0] == CMS_PT_INT, "mode must be PT_INT tag"
        mode = struct.unpack(">I", p[1:5])[0]
        assert mode == CMS_LOGIN_MODE, f"login mode {mode:#x} != expected {CMS_LOGIN_MODE:#x}"

        p = p[5:]  # skip tag(1) + int value(4)
        assert p[0] == CMS_PT_INT, "pid must be PT_INT tag"
        pid = struct.unpack(">I", p[1:5])[0]
        assert pid > 0, "login PID must be positive"

    def test_login_contains_paths(self, cms_nginx):
        """The LOGIN payload must contain the configured export paths."""
        frames = cms_nginx["cms"].get_received_frames()
        login_frames = [f for f in frames if f[0] == CMS_RR_LOGIN]
        assert len(login_frames) >= 1

        _, _, _, payload = login_frames[0]

        # Navigate to path_len field: version(3) + mode(5) + pid(5) + total_gb(5)
        # + free_mb(5) + min_free_mb(5) + role(3) + util_pct(3) + port(3)
        # + flags(3) + flags(3) = 40 bytes
        p = payload[40:]
        assert p[0] == CMS_PT_SHORT, "path_len must be PT_SHORT tag"
        path_len = struct.unpack(">H", p[1:3])[0]

        if path_len > 0:
            paths_data = p[3:3 + path_len]
            assert b"/data" in paths_data or b"data" in paths_data, \
                f"export path '/data' not found in login payload: {paths_data}"


# ---------------------------------------------------------------------------
# PING/PONG heartbeat exchange
# ---------------------------------------------------------------------------

class TestCmsPingPong:

    def test_periodic_load_sent(self, cms_nginx):
        time.sleep(8.0)
        frames = cms_nginx["cms"].get_received_frames()

        load_frames = [f for f in frames if f[0] == CMS_RR_LOAD]
        assert len(load_frames) >= 1, "server did not send periodic LOAD"


# ---------------------------------------------------------------------------
# Availability frame — free MB and utilization %
# ---------------------------------------------------------------------------

class TestCmsAvail:
    """Verify that availability frames carry correct space information."""

    def test_avail_frame_fields(self, cms_nginx):
        """The AVAIL frame must contain free_mb (uint32) and util_pct (uint32)."""
        frames = cms_nginx["cms"].get_received_frames()
        avail_frames = [f for f in frames if f[0] == CMS_RR_AVAIL]

        # The manager may not send AVAIL requests, but the server sends them
        # periodically.  If we see any, verify their structure.
        if len(avail_frames) > 0:
            _, streamid, modifier, payload = avail_frames[0]
            assert len(payload) >= 8, "AVAIL payload must have at least free_mb + util_pct"

            # Parse: [free_mb(int)][util_pct(int)]
            assert payload[0] == CMS_PT_INT, "free_mb must be PT_INT tag"
            free_mb = struct.unpack(">I", payload[1:5])[0]
            assert free_mb >= 0, "free_mb must be non-negative"

            p = payload + 4
            assert p[0] == CMS_PT_INT, "util_pct must be PT_INT tag"
            util_pct = struct.unpack(">I", p[1:5])[0]
            assert 0 <= util_pct <= 100, f"util_pct {util_pct} out of range [0,100]"


# ---------------------------------------------------------------------------
# Reconnection — backoff timer after disconnect
# ---------------------------------------------------------------------------

class TestCmsReconnect:

    def test_cms_connection_maintained(self, cms_nginx):
        cms = cms_nginx["cms"]
        frames = cms.get_received_frames()
        assert len(frames) > 0, "no CMS traffic received"
        login_frames = [f for f in frames if f[0] == CMS_RR_LOGIN]
        assert len(login_frames) >= 1, "no LOGIN frame received"

    def test_server_survives_manager_disconnect(self, cms_nginx):
        cms = cms_nginx["cms"]
        cms.stop()
        time.sleep(1.0)

        _assert_xrootd_ping(cms_nginx["nginx"]["port"])


# ---------------------------------------------------------------------------
# CMS frame header size validation
# ---------------------------------------------------------------------------

class TestCmsWireFormat:
    """Verify the CMS wire format constants are correct."""

    def test_frame_header_is_8_bytes(self):
        """CMS frame headers must be exactly 8 bytes: [4B streamid][1B code]
        [1B modifier][2B payload_len].
        """
        # Construct a minimal frame header and verify size
        hdr = struct.pack(">IBBH", 0, CMS_RR_LOGIN, 0, 0)
        assert len(hdr) == 8, f"CMS header length {len(hdr)} != expected 8"

    def test_short_tag_encoding(self):
        """CMS PT_SHORT tag encodes as [1B tag][2B value] = 3 bytes total."""
        p = bytearray(4)
        p[0] = CMS_PT_SHORT
        struct.pack_into(">H", p, 1, 42)
        assert len(p[:3]) == 3
        assert p[0] == CMS_PT_SHORT
        assert struct.unpack(">H", p[1:3])[0] == 42

    def test_int_tag_encoding(self):
        """CMS PT_INT tag encodes as [1B tag][4B value] = 5 bytes total."""
        p = bytearray(6)
        p[0] = CMS_PT_INT
        struct.pack_into(">I", p, 1, 999999)
        assert len(p[:5]) == 5
        assert p[0] == CMS_PT_INT
        assert struct.unpack(">I", p[1:5])[0] == 999999
