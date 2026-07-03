"""
Tests for manager-mode XRootD redirector functionality:

  Part 1 — Static brix_manager_map: a fixed path-prefix → backend mapping
            that returns kXR_redirect for matching kXR_locate requests.

  Part 2 — Dynamic cluster mode (brix_manager_mode + brix_cms_server):
            data servers register via the CMS protocol; kXR_locate and
            kXR_open on the redirector return kXR_redirect to the best
            registered data server.

Both parts use raw sockets so we can assert wire-level response contents
without a PyXRootD dependency.
"""

import os
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

from settings import (
    CLUSTER_3T_LEAF_PORT,
    CLUSTER_3T_META_CMS_PORT,
    CLUSTER_3T_META_PORT,
    CLUSTER_3T_SUB_CMS_PORT,
    CLUSTER_3T_SUB_PORT,
    CLUSTER_CMS_PORT,
    CLUSTER_DS_DATA_ROOT,
    CLUSTER_DS_PORT,
    CLUSTER_ESC_LEAF_DATA_ROOT,
    CLUSTER_ESC_LEAF_PORT,
    CLUSTER_ESC_SUB_PORT,
    CLUSTER_GONE_DS_PORT,
    CLUSTER_GONE_DS_PORT_A,
    CLUSTER_GONE_DS_PORT_B,
    CLUSTER_MP_CMS_PORT,
    CLUSTER_MP_DS_PORT,
    CLUSTER_MP_REDIR_PORT,
    CLUSTER_MS_CMS_PORT,
    CLUSTER_MS_DS1_DATA_ROOT,
    CLUSTER_MS_DS1_PORT,
    CLUSTER_MS_DS2_DATA_ROOT,
    CLUSTER_MS_DS2_PORT,
    CLUSTER_MS_REDIR_PORT,
    CLUSTER_MW_CMS_PORT,
    CLUSTER_MW_PORT,
    CLUSTER_REDIR_PORT,
    CLUSTER_SELECT_PORT,
    CLUSTER_SELECT_REDIRECT_PORT,
    CLUSTER_SLOTS_DS1_DATA_ROOT,
    CLUSTER_SLOTS_DS1_PORT,
    CLUSTER_SLOTS_DS2_DATA_ROOT,
    CLUSTER_SLOTS_DS2_PORT,
    CLUSTER_SLOTS_DS3_DATA_ROOT,
    CLUSTER_SLOTS_DS3_PORT,
    CLUSTER_SLOTS_DS4_DATA_ROOT,
    CLUSTER_SLOTS_DS4_PORT,
    CLUSTER_SLOTS_METRICS_PORT,
    CLUSTER_SLOTS_REDIR_PORT,
    CLUSTER_TRY_FIRST_PORT,
    CLUSTER_TRY_PORT,
    CLUSTER_TRY_SECOND_PORT,
    HOST,
    MANAGER_PORT,
    NGINX_BIN,
    TEST_ROOT,
    url_host,
)


def _kill_nginx_dedicated(name: str) -> None:
    """Send SIGTERM to the pre-launched dedicated nginx instance by name."""
    import signal
    pidfile = os.path.join(TEST_ROOT, "dedicated", name, "logs", "nginx.pid")
    if os.path.exists(pidfile):
        try:
            pid = int(open(pidfile).read().strip())
            os.kill(pid, signal.SIGTERM)
        except (ValueError, ProcessLookupError):
            pass


def _wait_port(port: int, label: str = "", timeout: float = 20.0, host: str = HOST):
    """Block until host:port accepts a TCP connection or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    pytest.fail(f"Port {port} ({label}) not ready after {timeout}s")


def _wait_for_redirect(redir_port: int, path: str, expected_ds_port: int,
                       timeout: float = 25.0, host: str = HOST):
    """Connect to redir_port, send kXR_locate for path, retry until we get
    a kXR_redirect (4004) pointing at expected_ds_port, or timeout."""
    deadline = time.monotonic() + timeout
    last_status = None
    while time.monotonic() < deadline:
        try:
            sock = _xrd_handshake_and_login(host, redir_port)
            try:
                status, body = _send_locate_and_recv(sock, path)
                last_status = status
                if status == 4004 and len(body) >= 4:
                    redirect_port = struct.unpack(">I", body[:4])[0]
                    if redirect_port == expected_ds_port:
                        return
            finally:
                sock.close()
        except OSError:
            pass
        time.sleep(0.5)
    pytest.fail(
        f"Redirector on {redir_port} never redirected {path!r} to port "
        f"{expected_ds_port} within {timeout}s (last status={last_status})"
    )


@pytest.fixture(scope="session", autouse=True)
def manager_nginx():
    """Use the pre-launched dedicated manager nginx at MANAGER_PORT.

    nginx_manager.conf uses MAP_A defaults of 127.0.0.1:11098 and
    127.0.0.1:11099 (REF_PORT and REF_PORT+1).
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    _wait_port(MANAGER_PORT, "manager_nginx")

    yield {
        "port":  MANAGER_PORT,
        "map_a": (HOST, 11098),
        "map_b": (HOST, 11099),
    }


def _xrd_handshake_and_login(host: str, port: int):
    """Establish an XRootD session: handshake, protocol, login.

    Returns a connected socket ready to send requests.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))

    # 1. Initial handshake (20 bytes)
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))

    # 2. kXR_protocol
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, 3006, 0x00000520, 0x02, 0x03, 0))

    # Read handshake response (8 + 8 per server code path)
    # The server replies with an 8-byte ServerResponseHdr then 8-byte body
    _ = sock.recv(16)

    # Next protocol response (ServerResponseHdr + body)
    hdr = sock.recv(8)
    if len(hdr) < 8:
        raise RuntimeError("short protocol response header")
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        _ = sock.recv(dlen)

    # 3. kXR_login — send a minimal login (username "test")
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, 3007, 0,
                             b"test\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))

    # read login response
    hdr = sock.recv(8)
    if len(hdr) < 8:
        raise RuntimeError("short login response header")
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        _ = sock.recv(dlen)

    return sock


def _send_locate_and_recv(sock: socket.socket, path: str):
    # Build ClientLocateRequest header: streamid[2]=0,1; requestid=3027; options=0; reserved=14 zeros; dlen=payload length
    payload = path.encode("utf-8") + b"\x00"
    hdr = struct.pack(">BBHH14sI", 0, 1, 3027, 0, b"\x00" * 14, len(payload))
    sock.sendall(hdr + payload)

    # Read response header (8 bytes) then body
    resp_hdr = sock.recv(8)
    if len(resp_hdr) < 8:
        raise RuntimeError("short response header")
    status = struct.unpack(">H", resp_hdr[2:4])[0]
    dlen = struct.unpack(">I", resp_hdr[4:8])[0]
    body = b""
    while len(body) < dlen:
        chunk = sock.recv(dlen - len(body))
        if not chunk:
            raise RuntimeError("connection closed while reading body")
        body += chunk

    return status, body


def test_locate_redirect_basic(manager_nginx):
    info = manager_nginx
    host = HOST
    port = info["port"]

    sock = _xrd_handshake_and_login(host, port)

    try:
        status, body = _send_locate_and_recv(sock, "/maps/somefile.bin")
        # Expect kXR_redirect (4004)
        assert status == 4004, f"expected redirect status, got {status}"

        # Body = 4-byte BE port followed by host bytes
        assert len(body) >= 4
        port_be = struct.unpack(">I", body[:4])[0]
        host_str = body[4:].decode("utf-8")

        assert port_be == info["map_a"][1]
        assert host_str == info["map_a"][0]

        # Now test longest-prefix: /maps/prefix should match map_b
        status2, body2 = _send_locate_and_recv(sock, "/maps/prefix/xyz")
        assert status2 == 4004
        pb = struct.unpack(">I", body2[:4])[0]
        hb = body2[4:].decode("utf-8")
        assert pb == info["map_b"][1]
        assert hb == info["map_b"][0]

    finally:
        sock.close()


# ═══════════════════════════════════════════════════════════════════════════
# Part 2 — Dynamic cluster mode (brix_manager_mode + brix_cms_server)
# ═══════════════════════════════════════════════════════════════════════════

# Additional wire constants for Part 2
kXR_ok        = 0
kXR_redirect  = 4004

kXR_open      = 3010
kXR_locate    = 3027

kXR_open_read = 0x0010   # open for reading
kXR_isManager = 0x00000002  # flags in kXR_protocol response body


def _cluster_recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _cluster_read_response(sock):
    hdr    = _cluster_recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen   = struct.unpack(">I", hdr[4:8])[0]
    body   = _cluster_recv_exact(sock, dlen) if dlen else b""
    return status, body


def _cluster_handshake_login(host, port):
    """Full XRootD bootstrap: handshake + kXR_protocol + kXR_login."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
    _cluster_recv_exact(sock, 16)
    _cluster_read_response(sock)
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, 3007, 0, b"anon\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    _cluster_read_response(sock)
    return sock


def _cluster_send_locate(sock, path):
    payload = path.encode() + b"\x00"
    sock.sendall(
        struct.pack(">BB H H 14x I", 0, 1, kXR_locate, 0, len(payload)) + payload
    )


def _cluster_send_open(sock, path, options=kXR_open_read):
    payload = path.encode() + b"\x00"
    sock.sendall(
        struct.pack(">BB H H H 12x I", 0, 1, kXR_open, options, 0, len(payload))
        + payload
    )


# ── nginx config templates ────────────────────────────────────────────────

@pytest.fixture(scope="module")
def cluster():
    """Use the pre-launched cluster-redir + cluster-ds instances.

    TestClusterUnregister.test_no_redirect_after_dataserver_stops calls
    cluster["ds"]["stop"]() to permanently kill the DS; that's intentional
    and it must run last (it appears last in this file).
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    os.makedirs(CLUSTER_DS_DATA_ROOT, exist_ok=True)
    Path(CLUSTER_DS_DATA_ROOT, "test.txt").write_text("hello from data server")

    _wait_port(CLUSTER_REDIR_PORT, "cluster-redir")
    _wait_for_redirect(CLUSTER_REDIR_PORT, "/test.txt", CLUSTER_DS_PORT)

    yield {
        "redir_port": CLUSTER_REDIR_PORT,
        "ds_port":    CLUSTER_DS_PORT,
        "cms_port":   CLUSTER_CMS_PORT,
        "data_dir":   CLUSTER_DS_DATA_ROOT,
        "ds":         {"stop": lambda: _kill_nginx_dedicated("cluster-ds")},
    }

    # test_no_redirect_after_dataserver_stops permanently kills cluster-ds;
    # restart it so the next test run finds port 11162 alive.
    import subprocess
    _script = os.path.join(os.path.dirname(__file__), "manage_test_servers.sh")
    subprocess.run(
        [_script, "start-dedicated", "cluster-ds"],
        capture_output=True,
        timeout=30,
    )


class TestClusterProtocol:
    """kXR_protocol response advertises kXR_isManager when manager_mode is on."""

    def test_protocol_flags_include_is_manager(self, cluster):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, cluster["redir_port"]))
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
        _cluster_recv_exact(sock, 16)
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_ok, f"kXR_protocol failed with status {status}"
        assert len(body) >= 8, f"protocol body too short: {len(body)} bytes"
        flags = struct.unpack(">I", body[4:8])[0]
        assert flags & kXR_isManager, (
            f"kXR_isManager (0x{kXR_isManager:08x}) not set in flags {flags:#010x}"
        )


class TestClusterLocate:
    """kXR_locate on the redirector returns kXR_redirect to the registered data server."""

    def test_locate_returns_redirect(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect ({kXR_redirect}), got {status}"
        )
        assert len(body) >= 4, f"redirect body too short: {len(body)} bytes"
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster["ds_port"], (
            f"redirect port {got_port} != data server port {cluster['ds_port']}"
        )

    def test_locate_redirect_host_is_loopback(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect
        host = body[4:].rstrip(b"\x00").decode(errors="replace")
        assert host == HOST, f"unexpected redirect host: {host!r}"


class TestClusterOpen:
    """kXR_open (read) on the redirector returns kXR_redirect to the data server."""

    def test_open_read_returns_redirect(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_open(sock, "/test.txt", kXR_open_read)
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect ({kXR_redirect}), got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster["ds_port"]


kXR_mkdir = 3008
kXR_rm    = 3014


def _cluster_send_mkdir(sock, path, mode=0o755):
    """ClientMkdirRequest: streamid[2] requestid options[1] reserved[13]
    mode(u16) dlen — path in the body."""
    payload = path.encode() + b"\x00"
    sock.sendall(
        struct.pack(">BB H B 13x H I", 0, 1, kXR_mkdir, 0, mode, len(payload))
        + payload
    )


def _cluster_send_rm(sock, path):
    """ClientRmRequest: streamid[2] requestid reserved[16] dlen — path body."""
    payload = path.encode() + b"\x00"
    sock.sendall(
        struct.pack(">BB H 16x I", 0, 1, kXR_rm, len(payload)) + payload
    )


class TestClusterMutationRedirect:
    """Plane B manager orchestration: in manager mode a path-based namespace
    mutation (mkdir/rm) is redirected to the registered data node — it must NOT
    be executed against the redirector's own (empty) export."""

    def test_mkdir_returns_redirect(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        try:
            _cluster_send_mkdir(sock, "/mgr_made_dir")
            status, body = _cluster_read_response(sock)
        finally:
            sock.close()
        assert status == kXR_redirect, (
            f"mkdir must be redirected in manager mode, got status {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster["ds_port"], (
            f"mkdir redirect port {got_port} != data server {cluster['ds_port']}"
        )

    def test_rm_returns_redirect(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        try:
            _cluster_send_rm(sock, "/test.txt")
            status, body = _cluster_read_response(sock)
        finally:
            sock.close()
        assert status == kXR_redirect, (
            f"rm must be redirected in manager mode, got status {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster["ds_port"]


class TestClusterUnregister:
    """After the data server disconnects, the redirector stops redirecting.

    NOTE: This class stops the data server permanently — it must be last.
    """

    def test_no_redirect_after_dataserver_stops(self, cluster):
        cluster["ds"]["stop"]()
        time.sleep(2.0)   # let nginx detect the dropped CMS connection

        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, _body = _cluster_read_response(sock)
        sock.close()

        assert status != kXR_redirect, (
            "redirector still returned kXR_redirect after data server disconnected"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 3 — Multi-token path list routing (srv_path_matches edge cases)
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def cluster_multi_path():
    """Use the pre-launched cluster-mp-redir + cluster-mp-ds instances."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    mp_data = os.path.join(TEST_ROOT, "data-cluster-mp-ds")
    os.makedirs(os.path.join(mp_data, "data"), exist_ok=True)
    os.makedirs(os.path.join(mp_data, "atlas"), exist_ok=True)
    Path(mp_data, "data", "test.txt").write_text("data area file")
    Path(mp_data, "atlas", "test.txt").write_text("atlas area file")

    _wait_port(CLUSTER_MP_REDIR_PORT, "cluster-mp-redir")
    _wait_for_redirect(CLUSTER_MP_REDIR_PORT, "/data/test.txt", CLUSTER_MP_DS_PORT)

    yield {
        "redir_port": CLUSTER_MP_REDIR_PORT,
        "ds_port":    CLUSTER_MP_DS_PORT,
        "cms_port":   CLUSTER_MP_CMS_PORT,
        "data_dir":   mp_data,
    }


class TestClusterMultiPath:
    """srv_path_matches handles colon-delimited multi-token path lists.

    Exercises the colon-split logic in registry.c: a data server that
    exports '/data:/atlas' must redirect requests under both prefixes but
    reject requests for '/physics' (not in the list).
    """

    def test_locate_first_prefix_redirects(self, cluster_multi_path):
        """locate /data/test.txt must return kXR_redirect."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/data/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect for /data prefix, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster_multi_path["ds_port"], (
            f"redirected to wrong port {got_port}"
        )

    def test_locate_second_prefix_redirects(self, cluster_multi_path):
        """locate /atlas/test.txt must also return kXR_redirect."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/atlas/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect for /atlas prefix, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster_multi_path["ds_port"]

    def test_locate_exact_prefix_token_redirects(self, cluster_multi_path):
        """locate /data (exactly the token without trailing slash) must redirect."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/data")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"exact-token locate /data expected redirect, got {status}"
        )

    def test_locate_unregistered_path_no_redirect(self, cluster_multi_path):
        """locate /physics/test.txt must NOT redirect (path not in /data:/atlas)."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/physics/test.txt")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status != kXR_redirect, (
            "redirector incorrectly redirected /physics which is not a registered prefix"
        )

    def test_locate_prefix_partial_match_not_redirected(self, cluster_multi_path):
        """/dataextended must NOT match the /data prefix (boundary check)."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/dataextended/file.txt")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status != kXR_redirect, (
            "/dataextended incorrectly matched the /data prefix token"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 4 — Multi-server registration and brix_srv_select
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def cluster_multi_server():
    """Use the pre-launched cluster-ms-redir + cluster-ms-ds1 + cluster-ms-ds2."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    os.makedirs(CLUSTER_MS_DS1_DATA_ROOT, exist_ok=True)
    os.makedirs(CLUSTER_MS_DS2_DATA_ROOT, exist_ok=True)
    Path(CLUSTER_MS_DS1_DATA_ROOT, "shared.txt").write_text("server 1 copy")
    Path(CLUSTER_MS_DS2_DATA_ROOT, "shared.txt").write_text("server 2 copy")

    _wait_port(CLUSTER_MS_REDIR_PORT, "cluster-ms-redir")
    _wait_for_redirect(CLUSTER_MS_REDIR_PORT, "/shared.txt", CLUSTER_MS_DS1_PORT)

    yield {
        "redir_port": CLUSTER_MS_REDIR_PORT,
        "ds1_port":   CLUSTER_MS_DS1_PORT,
        "ds2_port":   CLUSTER_MS_DS2_PORT,
        "cms_port":   CLUSTER_MS_CMS_PORT,
    }


class TestClusterMultiServer:
    """Two registered data servers — locate must return one of them."""

    def test_locate_returns_valid_server(self, cluster_multi_server):
        """locate /shared.txt must redirect to one of the two data servers."""
        c = cluster_multi_server
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        _cluster_send_locate(sock, "/shared.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect with two registered servers, got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port in (c["ds1_port"], c["ds2_port"]), (
            f"redirected to unknown port {got_port}; "
            f"expected one of {c['ds1_port']} or {c['ds2_port']}"
        )

    def test_repeated_locates_stay_valid(self, cluster_multi_server):
        """Multiple locate calls must all redirect to valid servers."""
        c = cluster_multi_server
        valid_ports = {c["ds1_port"], c["ds2_port"]}

        for _ in range(5):
            sock = _cluster_handshake_login(HOST, c["redir_port"])
            _cluster_send_locate(sock, "/shared.txt")
            status, body = _cluster_read_response(sock)
            sock.close()

            assert status == kXR_redirect, f"unexpected status {status}"
            got_port = struct.unpack(">I", body[:4])[0]
            assert got_port in valid_ports, (
                f"redirected to unexpected port {got_port}"
            )

    def test_open_redirects_to_valid_server(self, cluster_multi_server):
        """kXR_open on the redirector with two servers must also redirect correctly."""
        c = cluster_multi_server
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        _cluster_send_open(sock, "/shared.txt", kXR_open_read)
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect for open with two servers, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port in (c["ds1_port"], c["ds2_port"])


# ═══════════════════════════════════════════════════════════════════════════
# Part 3 — Per-worker CMS connections
#
# Each nginx worker process must open its own independent CMS connection to
# the parent manager.  With N workers configured, the manager must receive
# exactly N connections.  This ensures that when a worker sends kYR_locate
# the kYR_select reply arrives on the same worker's event loop as the waiting
# XRootD client session — no cross-worker IPC is required.
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="class")
def cluster_multi_worker():
    """Verify both nginx workers at CLUSTER_MW_PORT connect to the real CMS manager.

    The pre-started cluster-mw-mgr nginx at CLUSTER_MW_CMS_PORT acts as the
    real CMS server.  With worker_processes 2 and brix_cms_interval 2, both
    workers open independent TCP connections to the manager.  We verify by
    counting ESTABLISHED connections to CLUSTER_MW_CMS_PORT via ss(8).
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    def _count_cms_connections():
        result = subprocess.run(["ss", "-tn"], capture_output=True, text=True)
        return sum(
            1 for line in result.stdout.splitlines()
            if f":{CLUSTER_MW_CMS_PORT}" in line and "ESTAB" in line
        )

    # Wait up to 30s for both workers to establish their CMS connections.
    deadline = time.monotonic() + 30.0
    count = 0
    while time.monotonic() < deadline:
        count = _count_cms_connections()
        if count >= 2:
            break
        time.sleep(0.5)

    yield {
        "redir_port":       CLUSTER_MW_PORT,
        "cms_port":         CLUSTER_MW_CMS_PORT,
        "connection_count": [count],
    }


class TestPerWorkerCMS:
    """Each nginx worker must open its own independent CMS connection."""

    def test_each_worker_connects_independently(self, cluster_multi_worker):
        """With worker_processes 2 and one CMS manager, expect 2 connections.

        Each worker forks from the master with cms_ctx == NULL and runs its own
        init_process hook, so both workers call ngx_brix_cms_start and open
        an independent TCP connection to the CMS manager.
        """
        count = cluster_multi_worker["connection_count"][0]
        assert count >= 2, (
            f"expected >= 2 CMS connections (one per worker), got {count}; "
            "check that ngx_brix_cms_start is not guarded to a single worker"
        )


# ═══════════════════════════════════════════════════════════════════════════
# CMS wire helpers (shared by Parts 6 and 8)
# ═══════════════════════════════════════════════════════════════════════════

#   CMS frame: 8-byte header
#     [0..3]  streamid  BE uint32
#     [4]     opcode
#     [5]     modifier
#     [6..7]  dlen      BE uint16
#   Payload of dlen bytes follows immediately.

CMS_RR_LOGIN  = 0
CMS_RR_LOCATE = 2
CMS_RR_SELECT = 10
CMS_RR_GONE   = 14
CMS_RR_PING   = 17
CMS_RR_PONG   = 18

CMS_PT_SHORT = 0x80
CMS_PT_INT   = 0xa0


def _cms_frame(streamid: int, opcode: int, payload: bytes = b"",
               modifier: int = 0) -> bytes:
    return struct.pack(">IBBH", streamid, opcode, modifier, len(payload)) + payload


def _cms_put_short(v: int) -> bytes:
    return bytes([CMS_PT_SHORT]) + struct.pack(">H", v)


def _cms_put_int(v: int) -> bytes:
    return bytes([CMS_PT_INT]) + struct.pack(">I", v)


def _cms_put_string(data: bytes = b"") -> bytes:
    """An XrdOucPup string: a 2-byte big-endian length (which INCLUDES the
    trailing NUL) followed by the bytes and a NUL.  An empty string is just a
    zero length with no bytes.  Matches ngx_brix_cms_put_string in cms/wire.c
    and the reader in cms/server_recv.c (cms_srv_read_string)."""
    if not data:
        return struct.pack(">H", 0)
    return struct.pack(">H", len(data) + 1) + data + b"\x00"


def _cms_login_payload(port: int, path: str = "/") -> bytes:
    """Build the LOGIN payload in the real XrdCms CmsLoginData wire order
    (XrdOucPup), matching cms/send.c: ten type-tagged scalars (version, mode,
    holdtime, tSpace, fSpace, mSpace, fsNum, fsUtil, dPort, sPort) followed by
    four strings (SID, Paths, ifList, envCGI).  Paths is a newline-separated
    list of "<type> <namespace-path>" entries; server_recv.c strips the leading
    type token, so "w /gone-test" registers the bare path "/gone-test"."""
    paths_str = ("w " + path).encode()
    return (
        _cms_put_short(3)            # version
        + _cms_put_int(0x00000008)   # mode = DataServer
        + _cms_put_int(0)            # holdtime
        + _cms_put_int(0)            # tSpace (total GB)
        + _cms_put_int(1024)         # fSpace ← free_mb
        + _cms_put_int(100)          # mSpace (min free MB)
        + _cms_put_short(1)          # fsNum
        + _cms_put_short(0)          # fsUtil ← util_pct
        + _cms_put_short(port)       # dPort ← registered XRootD port
        + _cms_put_short(0)          # sPort
        + _cms_put_string(b"test-ds")  # SID (ignored by the server)
        + _cms_put_string(paths_str)   # Paths "<type> <path>"
        + _cms_put_string(b"")         # ifList (empty)
        + _cms_put_string(b"")         # envCGI (empty)
    )


def _cms_recv_frame(sock: socket.socket):
    """Read one complete CMS frame; return (streamid, opcode, payload)."""
    hdr = _cluster_recv_exact(sock, 8)
    streamid, opcode, _modifier, dlen = struct.unpack(">IBBH", hdr)
    payload = _cluster_recv_exact(sock, dlen) if dlen else b""
    return streamid, opcode, payload


# ═══════════════════════════════════════════════════════════════════════════
# Part 5 — Three-tier topology
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def three_tier():
    """Use the pre-launched cluster-3t-meta + cluster-3t-sub + cluster-3t-leaf."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    t3_data = os.path.join(TEST_ROOT, "data-cluster-3t-leaf")
    os.makedirs(t3_data, exist_ok=True)
    Path(t3_data, "test.txt").write_text("three-tier test file")

    _wait_port(CLUSTER_3T_META_PORT, "cluster-3t-meta")
    _wait_for_redirect(CLUSTER_3T_META_PORT, "/test.txt", CLUSTER_3T_SUB_PORT)

    yield {
        "meta_port":     CLUSTER_3T_META_PORT,
        "sub_port":      CLUSTER_3T_SUB_PORT,
        "leaf_port":     CLUSTER_3T_LEAF_PORT,
        "meta_cms_port": CLUSTER_3T_META_CMS_PORT,
        "sub_cms_port":  CLUSTER_3T_SUB_CMS_PORT,
    }


class TestThreeTierTopology:
    """Two-hop locate chain: client → meta → sub → leaf."""

    def test_locate_follows_redirect_chain_to_sub(self, three_tier):
        """First locate at meta-manager must redirect to the sub-manager."""
        tt = three_tier
        sock = _cluster_handshake_login(HOST, tt["meta_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"meta-manager: expected kXR_redirect, got {status}"
        )
        assert len(body) >= 4
        hop1_port = struct.unpack(">I", body[:4])[0]
        assert hop1_port == tt["sub_port"], (
            f"expected redirect to sub-manager port {tt['sub_port']}, got {hop1_port}"
        )

    def test_locate_follows_redirect_chain_to_leaf(self, three_tier):
        """Second locate at sub-manager must redirect to the leaf data server."""
        tt = three_tier
        sock = _cluster_handshake_login(HOST, tt["sub_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"sub-manager: expected kXR_redirect, got {status}"
        )
        assert len(body) >= 4
        leaf_port = struct.unpack(">I", body[:4])[0]
        assert leaf_port == tt["leaf_port"], (
            f"expected redirect to leaf port {tt['leaf_port']}, got {leaf_port}"
        )

    def test_full_two_hop_chain(self, three_tier):
        """Client follows both hops and lands at the leaf port."""
        tt = three_tier

        # Hop 1: meta → sub
        sock = _cluster_handshake_login(HOST, tt["meta_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()
        assert status == kXR_redirect
        hop1_port = struct.unpack(">I", body[:4])[0]

        # Hop 2: sub → leaf
        sock2 = _cluster_handshake_login(HOST, hop1_port)
        _cluster_send_locate(sock2, "/test.txt")
        status2, body2 = _cluster_read_response(sock2)
        sock2.close()
        assert status2 == kXR_redirect
        final_port = struct.unpack(">I", body2[:4])[0]
        assert final_port == tt["leaf_port"], (
            f"two-hop chain ended at {final_port}, expected leaf {tt['leaf_port']}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 6 — kYR_select flow (CMS-assisted locate suspension + wake)
# ═══════════════════════════════════════════════════════════════════════════

# nginx at CLUSTER_SELECT_PORT has no local registry; it escalates kXR_locate
# to its parent CMS (cms_parent_stubs.py at CLUSTER_SELECT_CMS_PORT), which
# replies with kYR_select pointing at CLUSTER_SELECT_REDIRECT_PORT.


@pytest.fixture(scope="module")
def cms_select():
    """Pre-started cluster-select nginx at CLUSTER_SELECT_PORT backed by CMS stub."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")
    _wait_port(CLUSTER_SELECT_PORT, "cluster-select")
    yield {
        "redir_port":    CLUSTER_SELECT_PORT,
        "redirect_port": CLUSTER_SELECT_REDIRECT_PORT,
    }


class TestCmsSelectWake:
    """nginx suspends a client kXR_locate, escalates kYR_locate to the CMS stub,
    and resumes the client with a kXR_redirect once kYR_select arrives."""

    def test_locate_wakes_on_cms_select(self, cms_select):
        """kXR_locate must return kXR_redirect to the port advertised by kYR_select."""
        c = cms_select

        sock = _cluster_handshake_login(HOST, c["redir_port"])
        sock.settimeout(15)  # generous — allows for CMS round-trip
        _cluster_send_locate(sock, "/cms-select-test/file.dat")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect after kYR_select, got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == c["redirect_port"], (
            f"redirect to port {got_port}, expected {c['redirect_port']}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 7 — Registry-full counter (brix_registry_slots + Prometheus)
# ═══════════════════════════════════════════════════════════════════════════

import urllib.request

@pytest.fixture(scope="module")
def cluster_full_registry():
    """Use pre-launched cluster-slots-redir + 4 cluster-slots-ds instances."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    ds_data_roots = [
        CLUSTER_SLOTS_DS1_DATA_ROOT,
        CLUSTER_SLOTS_DS2_DATA_ROOT,
        CLUSTER_SLOTS_DS3_DATA_ROOT,
        CLUSTER_SLOTS_DS4_DATA_ROOT,
    ]
    ds_ports = [
        CLUSTER_SLOTS_DS1_PORT,
        CLUSTER_SLOTS_DS2_PORT,
        CLUSTER_SLOTS_DS3_PORT,
        CLUSTER_SLOTS_DS4_PORT,
    ]
    for i, dr in enumerate(ds_data_roots):
        os.makedirs(dr, exist_ok=True)
        Path(dr, "file.txt").write_text(f"server {i}")

    _wait_port(CLUSTER_SLOTS_REDIR_PORT, "cluster-slots-redir")
    # Give all 4 data servers time to attempt CMS registration.
    time.sleep(5.0)

    yield {
        "redir_port":   CLUSTER_SLOTS_REDIR_PORT,
        "metrics_port": CLUSTER_SLOTS_METRICS_PORT,
        "ds_ports":     ds_ports,
    }


class TestRegistryFullCounter:
    """brix_registry_full_total increments when a data server cannot register."""

    def test_registry_full_counter_nonzero(self, cluster_full_registry):
        """Prometheus metrics must show registry_full_total > 0 after overflow."""
        c = cluster_full_registry
        url = f"http://{url_host(HOST)}:{c['metrics_port']}/metrics"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode()
        except Exception as exc:
            pytest.fail(f"Could not fetch metrics from {url}: {exc}")

        counter_value = None
        for line in body.splitlines():
            if line.startswith("brix_registry_full_total "):
                counter_value = float(line.split()[1])
                break

        assert counter_value is not None, (
            "brix_registry_full_total not present in Prometheus output"
        )
        assert counter_value > 0, (
            f"brix_registry_full_total is {counter_value}; "
            "expected > 0 after 4 servers tried to register into 3 slots"
        )

    def test_registry_accepts_up_to_slot_limit(self, cluster_full_registry):
        """At most 3 slots filled → at least one server's locate succeeds."""
        c = cluster_full_registry
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        _cluster_send_locate(sock, "/file.txt")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect (at least 3 servers should have registered), got {status}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 8 — kYR_gone: path deregistration via CMS
# ═══════════════════════════════════════════════════════════════════════════

def _cms_connect_and_register(cms_port: int, xrd_port: int,
                                   path: str) -> socket.socket:
    """Connect to the nginx CMS server port and send a LOGIN frame for the
    given XRootD port and path.  Returns the open TCP socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, cms_port))
    payload = _cms_login_payload(xrd_port, path)
    sock.sendall(_cms_frame(1, CMS_RR_LOGIN, payload))
    return sock


class TestKyrGone:
    """kYR_gone removes a path from the registry without disconnecting.

    A raw TCP socket registers as a data server via the CMS protocol:
      1. Connects to the redirector's CMS server port and sends LOGIN
         (which registers the path "/gone-test").
      2. Confirms locate returns kXR_redirect.
      3. Sends kYR_gone with the registered path.
      4. Confirms locate no longer redirects to that server.
    """

    def test_path_unregistered_after_gone(self, cluster):
        """After kYR_gone for /gone-test, locate must stop redirecting there."""
        gone_port = CLUSTER_GONE_DS_PORT

        # Register a raw TCP socket as a CMS data server for /gone-test.
        cms_conn = _cms_connect_and_register(
            cluster["cms_port"], gone_port, "/gone-test"
        )
        time.sleep(1.5)  # let nginx process LOGIN and register the path

        # Verify the path is reachable.
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/gone-test/file.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect before kYR_gone, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == gone_port

        # Send kYR_gone — payload is the raw path bytes (no TLV encoding).
        cms_conn.sendall(
            _cms_frame(2, CMS_RR_GONE, b"/gone-test")
        )
        time.sleep(1.5)  # let nginx process the GONE frame

        # The path must no longer redirect to gone_port.
        sock2 = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock2, "/gone-test/file.txt")
        status2, body2 = _cluster_read_response(sock2)
        sock2.close()
        cms_conn.close()

        # After GONE the slot may either be gone entirely (no redirect) or
        # the server is still registered but the path token removed.
        # Either way the port must not be gone_port any more.
        if status2 == kXR_redirect:
            redirect_port = struct.unpack(">I", body2[:4])[0]
            assert redirect_port != gone_port, (
                f"redirector still sends to gone_port {gone_port} after kYR_gone"
            )

    def test_other_paths_unaffected_by_gone(self, cluster):
        """kYR_gone for /gone-test2 must not remove /gone-other."""
        port_a = CLUSTER_GONE_DS_PORT_A
        port_b = CLUSTER_GONE_DS_PORT_B

        conn_a = _cms_connect_and_register(cluster["cms_port"], port_a, "/gone-other")
        conn_b = _cms_connect_and_register(cluster["cms_port"], port_b, "/gone-test2")
        time.sleep(1.5)

        # Send GONE only for /gone-test2.
        conn_b.sendall(_cms_frame(2, CMS_RR_GONE, b"/gone-test2"))
        time.sleep(1.5)

        # /gone-other must still redirect.
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/gone-other/x.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        conn_a.close()
        conn_b.close()

        assert status == kXR_redirect, (
            f"expected /gone-other to still redirect after GONE for /gone-test2, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == port_a, (
            f"expected redirect to port_a {port_a}, got {got_port}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 9 — kYR_try: manager replies with ordered alternative list
# ═══════════════════════════════════════════════════════════════════════════

# kYR_try differs from kYR_select: the payload contains multiple host:port
# entries in priority order.  nginx picks the FIRST entry and wakes the
# suspended client with a redirect to that host:port.
#
# Wire format for kYR_try payload (src/net/cms/cms_internal.h CMS_RR_TRY=24):
#   entry_0: NUL-terminated hostname + 2-byte big-endian port
#   entry_1: NUL-terminated hostname + 2-byte big-endian port
#   ...

CMS_RR_TRY = 24  # kYR_try opcode


@pytest.fixture(scope="module")
def cms_try():
    """Pre-started CMS-try cluster at CLUSTER_TRY_PORT backed by cms_parent_stubs.py."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")
    _wait_port(CLUSTER_TRY_PORT, "cms-try")
    yield {
        "redir_port":  CLUSTER_TRY_PORT,
        "first_port":  CLUSTER_TRY_FIRST_PORT,
        "second_port": CLUSTER_TRY_SECOND_PORT,
    }


class TestCmsKyrTry:
    """kYR_try: nginx must redirect the client to the first entry in the list."""

    def test_locate_redirects_to_first_try_entry(self, cms_try):
        """kXR_locate returns kXR_REDIRECT pointing at the FIRST kYR_try entry.

        Wire path: client → nginx XRD_ST_WAITING_CMS → CMS stub replies
        kYR_try[first_port, second_port] → nginx wakes with kXR_REDIRECT to
        first_port only.
        """
        c = cms_try
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        sock.settimeout(20)
        _cluster_send_locate(sock, "/kyr-try-test/file.dat")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_REDIRECT after kYR_try wake, got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == c["first_port"], (
            f"nginx redirected to port {got_port}; expected first_port "
            f"{c['first_port']}, not second_port {c['second_port']}"
        )

    def test_second_entry_ignored(self, cms_try):
        """The second kYR_try entry must not be used for the redirect."""
        c = cms_try
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        sock.settimeout(20)
        _cluster_send_locate(sock, "/kyr-try-second-entry/file.dat")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, f"expected kXR_REDIRECT, got {status}"
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port != c["second_port"], (
            f"nginx used the second kYR_try entry (port {got_port}) "
            "instead of the first"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 10 — True CMS escalation: sub-manager asks parent on registry miss
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def cms_escalation():
    """Pre-started escalation cluster backed by cms_parent_stubs.py."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    leaf_file = Path(CLUSTER_ESC_LEAF_DATA_ROOT, "escalate", "file.dat")
    leaf_file.parent.mkdir(parents=True, exist_ok=True)
    leaf_file.write_text("cms escalation target")

    _wait_port(CLUSTER_ESC_SUB_PORT, "cms-escalation-sub")
    yield {
        "sub_port":  CLUSTER_ESC_SUB_PORT,
        "leaf_port": CLUSTER_ESC_LEAF_PORT,
    }


class TestCmsEscalation:
    """Registry miss -> kYR_locate to parent -> kYR_select -> kXR_redirect."""

    def test_three_tier_escalation_redirects_to_leaf(self, cms_escalation):
        c = cms_escalation

        sock = _cluster_handshake_login(HOST, c["sub_port"])
        sock.settimeout(15)
        _cluster_send_locate(sock, "/escalate/file.dat")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect after CMS escalation, got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == c["leaf_port"], (
            f"expected redirect to leaf port {c['leaf_port']}, got {got_port}"
        )

        leaf_sock = _cluster_handshake_login(HOST, c["leaf_port"])
        leaf_sock.settimeout(10)
        _cluster_send_open(leaf_sock, "/escalate/file.dat", kXR_open_read)
        open_status, _open_body = _cluster_read_response(leaf_sock)
        leaf_sock.close()

        assert open_status == kXR_ok, (
            f"leaf data-server did not open escalated file, got {open_status}"
        )
