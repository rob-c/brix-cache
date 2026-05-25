"""
Tests for manager-mode XRootD redirector functionality:

  Part 1 — Static xrootd_manager_map: a fixed path-prefix → backend mapping
            that returns kXR_redirect for matching kXR_locate requests.

  Part 2 — Dynamic cluster mode (xrootd_manager_mode + xrootd_cms_server):
            data servers register via the CMS protocol; kXR_locate and
            kXR_open on the redirector return kXR_redirect to the best
            registered data server.

Both parts use raw sockets so we can assert wire-level response contents
without a PyXRootD dependency.
"""

import os
import shutil
import socket
import struct
import time
from pathlib import Path

import pytest

import server_control
from settings import MANAGER_PORT, NGINX_BIN

WORKDIR = "/tmp/xrd-manager-mode-test"


@pytest.fixture(scope="session", autouse=True)
def manager_nginx():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    # Prepare workspace
    shutil.rmtree(WORKDIR, ignore_errors=True)
    import server_control

    port = MANAGER_PORT

    # Two mappings to exercise longest-prefix matching
    map_a_host = "backend.example.org"
    map_a_port = 54321
    map_b_host = "backend2.example.org"
    map_b_port = 12345

    conf_text = f"""\
worker_processes 1;
error_log {{LOG_DIR}}/error.log info;
pid       {{LOG_DIR}}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{port};
        xrootd on;
        xrootd_manager_map /maps {map_a_host}:{map_a_port};
        xrootd_manager_map /maps/prefix {map_b_host}:{map_b_port};
    }}
}}
"""

    info = server_control.start_nginx_instance(
        port=port, nginx_bin=NGINX_BIN,
        conf_file="nginx_manager.conf",
        template_kwargs={
            "MAP_A_HOST": map_a_host,
            "MAP_A_PORT": map_a_port,
            "MAP_B_HOST": map_b_host,
            "MAP_B_PORT": map_b_port,
        },
    )

    try:
        yield {
            "proc": None,
            "port": info["port"],
            "map_a": (map_a_host, map_a_port),
            "map_b": (map_b_host, map_b_port),
            "stop": info["stop"],
        }
    finally:
        try:
            info["stop"]()
        except Exception:
            pass


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
    host = "127.0.0.1"
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
# Part 2 — Dynamic cluster mode (xrootd_manager_mode + xrootd_cms_server)
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

# Redirector: XRootD with manager_mode on  + CMS server on a separate port.
# Placeholders: {PORT}=XRootD port (auto), {CMS_PORT}=CMS management port
_REDIRECTOR_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_auth none;
        xrootd_manager_mode on;
    }}
    server {{
        listen 127.0.0.1:{CMS_PORT};
        xrootd_cms_server on;
    }}
}}
"""

# Data server: serves files and CMS-registers with the redirector.
# Placeholders: {PORT}=XRootD port, {CMS_PORT}=redirector CMS port, {DATA_DIR}
_DATASERVER_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth none;
        xrootd_cms_manager 127.0.0.1:{CMS_PORT};
        xrootd_cms_paths /;
        xrootd_cms_interval 5;
        xrootd_listen_port {PORT};
    }}
}}
"""


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    """Two-tier cluster: redirector (manager_mode) + one data server.

    Yields a dict with redir_port, ds_port, cms_port, data_dir, and stop
    callables for each instance.  Tests that stop the data server early
    (TestClusterUnregister) must run last — they appear last in this file.
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    cms_port   = server_control._free_port()
    redir_port = server_control._free_port()
    ds_port    = server_control._free_port()

    data_dir = tmp_path_factory.mktemp("cluster-data")
    (data_dir / "test.txt").write_text("hello from data server")

    redir = server_control.start_nginx_instance(
        port=redir_port,
        conf_text=_REDIRECTOR_CONF,
        template_kwargs={"CMS_PORT": cms_port},
    )

    ds = server_control.start_nginx_instance(
        port=ds_port,
        conf_text=_DATASERVER_CONF,
        template_kwargs={"CMS_PORT": cms_port, "DATA_DIR": str(data_dir)},
    )

    # Give the data server's CMS client time to connect and send LOGIN.
    time.sleep(3.0)

    yield {
        "redir_port": redir_port,
        "ds_port":    ds_port,
        "cms_port":   cms_port,
        "data_dir":   str(data_dir),
        "redir":      redir,
        "ds":         ds,
    }

    ds["stop"]()
    redir["stop"]()


class TestClusterProtocol:
    """kXR_protocol response advertises kXR_isManager when manager_mode is on."""

    def test_protocol_flags_include_is_manager(self, cluster):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", cluster["redir_port"]))
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
        sock = _cluster_handshake_login("127.0.0.1", cluster["redir_port"])
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
        sock = _cluster_handshake_login("127.0.0.1", cluster["redir_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect
        host = body[4:].rstrip(b"\x00").decode(errors="replace")
        assert host == "127.0.0.1", f"unexpected redirect host: {host!r}"


class TestClusterOpen:
    """kXR_open (read) on the redirector returns kXR_redirect to the data server."""

    def test_open_read_returns_redirect(self, cluster):
        sock = _cluster_handshake_login("127.0.0.1", cluster["redir_port"])
        _cluster_send_open(sock, "/test.txt", kXR_open_read)
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect ({kXR_redirect}), got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster["ds_port"]


class TestClusterUnregister:
    """After the data server disconnects, the redirector stops redirecting.

    NOTE: This class stops the data server permanently — it must be last.
    """

    def test_no_redirect_after_dataserver_stops(self, cluster):
        cluster["ds"]["stop"]()
        time.sleep(2.0)   # let nginx detect the dropped CMS connection

        sock = _cluster_handshake_login("127.0.0.1", cluster["redir_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, _body = _cluster_read_response(sock)
        sock.close()

        assert status != kXR_redirect, (
            "redirector still returned kXR_redirect after data server disconnected"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 3 — Multi-token path list routing (srv_path_matches edge cases)
# ═══════════════════════════════════════════════════════════════════════════

# Data server with two export path prefixes.
_MULTIPATH_DATASERVER_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth none;
        xrootd_cms_manager 127.0.0.1:{CMS_PORT};
        xrootd_cms_paths /data:/atlas;
        xrootd_cms_interval 5;
        xrootd_listen_port {PORT};
    }}
}}
"""


@pytest.fixture(scope="module")
def cluster_multi_path(tmp_path_factory):
    """Redirector + one data server advertising two export path prefixes.

    The data server registers with xrootd_cms_paths /data:/atlas so that
    srv_path_matches must match both tokens but NOT other paths.
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    cms_port   = server_control._free_port()
    redir_port = server_control._free_port()
    ds_port    = server_control._free_port()

    data_dir = tmp_path_factory.mktemp("mp-data")
    (data_dir / "data").mkdir()
    (data_dir / "atlas").mkdir()
    (data_dir / "data" / "test.txt").write_text("data area file")
    (data_dir / "atlas" / "test.txt").write_text("atlas area file")

    redir = server_control.start_nginx_instance(
        port=redir_port,
        conf_text=_REDIRECTOR_CONF,
        template_kwargs={"CMS_PORT": cms_port},
    )

    ds = server_control.start_nginx_instance(
        port=ds_port,
        conf_text=_MULTIPATH_DATASERVER_CONF,
        template_kwargs={"CMS_PORT": cms_port, "DATA_DIR": str(data_dir)},
    )

    time.sleep(3.0)

    yield {
        "redir_port": redir_port,
        "ds_port":    ds_port,
        "cms_port":   cms_port,
        "data_dir":   str(data_dir),
        "redir":      redir,
        "ds":         ds,
    }

    ds["stop"]()
    redir["stop"]()


class TestClusterMultiPath:
    """srv_path_matches handles colon-delimited multi-token path lists.

    Exercises the colon-split logic in registry.c: a data server that
    exports '/data:/atlas' must redirect requests under both prefixes but
    reject requests for '/physics' (not in the list).
    """

    def test_locate_first_prefix_redirects(self, cluster_multi_path):
        """locate /data/test.txt must return kXR_redirect."""
        sock = _cluster_handshake_login("127.0.0.1", cluster_multi_path["redir_port"])
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
        sock = _cluster_handshake_login("127.0.0.1", cluster_multi_path["redir_port"])
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
        sock = _cluster_handshake_login("127.0.0.1", cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/data")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"exact-token locate /data expected redirect, got {status}"
        )

    def test_locate_unregistered_path_no_redirect(self, cluster_multi_path):
        """locate /physics/test.txt must NOT redirect (path not in /data:/atlas)."""
        sock = _cluster_handshake_login("127.0.0.1", cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/physics/test.txt")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status != kXR_redirect, (
            "redirector incorrectly redirected /physics which is not a registered prefix"
        )

    def test_locate_prefix_partial_match_not_redirected(self, cluster_multi_path):
        """/dataextended must NOT match the /data prefix (boundary check)."""
        sock = _cluster_handshake_login("127.0.0.1", cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/dataextended/file.txt")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status != kXR_redirect, (
            "/dataextended incorrectly matched the /data prefix token"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 4 — Multi-server registration and xrootd_srv_select
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def cluster_multi_server(tmp_path_factory):
    """Redirector + two data servers, both registering the same path prefix.

    Exercises xrootd_srv_select: when multiple data servers match the
    requested path, the redirector must redirect to one of them (not return
    an error) and the chosen server must be a valid registered member.
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    cms_port    = server_control._free_port()
    redir_port  = server_control._free_port()
    ds1_port    = server_control._free_port()
    ds2_port    = server_control._free_port()

    data_dir1 = tmp_path_factory.mktemp("ms-data1")
    data_dir2 = tmp_path_factory.mktemp("ms-data2")
    (data_dir1 / "shared.txt").write_text("server 1 copy")
    (data_dir2 / "shared.txt").write_text("server 2 copy")

    redir = server_control.start_nginx_instance(
        port=redir_port,
        conf_text=_REDIRECTOR_CONF,
        template_kwargs={"CMS_PORT": cms_port},
    )

    ds1 = server_control.start_nginx_instance(
        port=ds1_port,
        conf_text=_DATASERVER_CONF,
        template_kwargs={"CMS_PORT": cms_port, "DATA_DIR": str(data_dir1)},
    )

    ds2 = server_control.start_nginx_instance(
        port=ds2_port,
        conf_text=_DATASERVER_CONF,
        template_kwargs={"CMS_PORT": cms_port, "DATA_DIR": str(data_dir2)},
    )

    time.sleep(4.0)   # both servers need time to connect and send LOGIN

    yield {
        "redir_port": redir_port,
        "ds1_port":   ds1_port,
        "ds2_port":   ds2_port,
        "cms_port":   cms_port,
        "redir":      redir,
        "ds1":        ds1,
        "ds2":        ds2,
    }

    ds1["stop"]()
    ds2["stop"]()
    redir["stop"]()


class TestClusterMultiServer:
    """Two registered data servers — locate must return one of them."""

    def test_locate_returns_valid_server(self, cluster_multi_server):
        """locate /shared.txt must redirect to one of the two data servers."""
        c = cluster_multi_server
        sock = _cluster_handshake_login("127.0.0.1", c["redir_port"])
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
            sock = _cluster_handshake_login("127.0.0.1", c["redir_port"])
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
        sock = _cluster_handshake_login("127.0.0.1", c["redir_port"])
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

import threading


_MULTI_WORKER_CONF = """\
worker_processes 2;
error_log {LOG_DIR}/error.log info;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 64; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root /tmp;
        xrootd_auth none;
        xrootd_cms_manager 127.0.0.1:{CMS_PORT};
        xrootd_cms_paths /;
        xrootd_cms_interval 3600;
        xrootd_listen_port {PORT};
    }}
}}
"""


@pytest.fixture(scope="class")
def cluster_multi_worker(tmp_path_factory):
    """nginx with 2 workers pointing to a mock CMS listener.

    The mock TCP server accepts connections and tracks the count.  Because
    each worker's CMS client connects independently after its init delay,
    the mock must see one connection per worker.
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    cms_port = server_control._free_port()
    redir_port = server_control._free_port()

    connection_count = [0]
    accepted_conns = []
    count_lock = threading.Lock()
    stop_event = threading.Event()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", cms_port))
    server_sock.listen(8)
    server_sock.settimeout(0.2)

    def _mock_cms_listener():
        while not stop_event.is_set():
            try:
                conn, _ = server_sock.accept()
                with count_lock:
                    connection_count[0] += 1
                    accepted_conns.append(conn)
            except socket.timeout:
                continue
        for c in accepted_conns:
            try:
                c.close()
            except Exception:
                pass
        server_sock.close()

    listener_thread = threading.Thread(target=_mock_cms_listener, daemon=True)
    listener_thread.start()

    redir = server_control.start_nginx_instance(
        port=redir_port,
        conf_text=_MULTI_WORKER_CONF,
        template_kwargs={"CMS_PORT": cms_port},
    )

    # NGX_XROOTD_CMS_INITIAL_DELAY is 1 s; allow extra slack for both workers.
    time.sleep(2.5)

    yield {
        "redir_port": redir_port,
        "cms_port": cms_port,
        "connection_count": connection_count,
        "redir": redir,
    }

    redir["stop"]()
    stop_event.set()
    listener_thread.join(timeout=2.0)


class TestPerWorkerCMS:
    """Each nginx worker must open its own independent CMS connection."""

    def test_each_worker_connects_independently(self, cluster_multi_worker):
        """With worker_processes 2 and one CMS manager, expect 2 connections.

        Each worker forks from the master with cms_ctx == NULL and runs its own
        init_process hook, so both workers call ngx_xrootd_cms_start and open
        an independent TCP connection to the CMS manager.
        """
        count = cluster_multi_worker["connection_count"][0]
        assert count >= 2, (
            f"expected >= 2 CMS connections (one per worker), got {count}; "
            "check that ngx_xrootd_cms_start is not guarded to a single worker"
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


def _cms_login_payload(port: int, path: str = "/") -> bytes:
    """Build the TLV-encoded LOGIN payload matching cms/send.c."""
    path_bytes = path.encode()
    return (
        _cms_put_short(3)            # version
        + _cms_put_int(0x00000008)   # mode = DataServer
        + _cms_put_int(os.getpid())  # pid
        + _cms_put_int(0)            # total_gb
        + _cms_put_int(1024)         # free_mb
        + _cms_put_int(100)          # min_free_mb
        + _cms_put_short(1)          # num_cpus
        + _cms_put_short(0)          # util_pct
        + _cms_put_short(port)       # ← registered XRootD port
        + _cms_put_short(0)          # flags1
        + _cms_put_short(0)          # flags2
        + _cms_put_short(len(path_bytes))
        + path_bytes
        + _cms_put_short(0)          # sentinel
        + _cms_put_short(0)          # sentinel
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

# Sub-manager: acts as both a manager (for the leaf data server) and as a
# data-server client (connecting to the meta-manager's CMS port).
_SUB_MANAGER_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_auth none;
        xrootd_manager_mode on;
    }}
    server {{
        listen 127.0.0.1:{CMS_PORT};
        xrootd_cms_server on;
    }}
    server {{
        listen 127.0.0.1:{SELF_REGISTER_PORT};
        xrootd on;
        xrootd_root /tmp;
        xrootd_auth none;
        xrootd_cms_manager 127.0.0.1:{META_CMS_PORT};
        xrootd_cms_paths /;
        xrootd_cms_interval 5;
        xrootd_listen_port {PORT};
    }}
}}
"""


@pytest.fixture(scope="module")
def three_tier(tmp_path_factory):
    """Three-tier: meta-manager → sub-manager → leaf data server."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    meta_cms_port        = server_control._free_port()
    meta_redir_port      = server_control._free_port()
    sub_cms_port         = server_control._free_port()
    sub_redir_port       = server_control._free_port()
    sub_self_reg_port    = server_control._free_port()  # dummy listener for sub-manager's CMS login port field
    leaf_ds_port         = server_control._free_port()

    data_dir = tmp_path_factory.mktemp("three-tier-data")
    (data_dir / "test.txt").write_text("three-tier test file")

    # Tier 1: meta-manager (plain redirector)
    meta = server_control.start_nginx_instance(
        port=meta_redir_port,
        conf_text=_REDIRECTOR_CONF,
        template_kwargs={"CMS_PORT": meta_cms_port},
    )

    # Tier 2: sub-manager (redirector + registers with meta)
    sub = server_control.start_nginx_instance(
        port=sub_redir_port,
        conf_text=_SUB_MANAGER_CONF,
        template_kwargs={
            "CMS_PORT":           sub_cms_port,
            "META_CMS_PORT":      meta_cms_port,
            "SELF_REGISTER_PORT": sub_self_reg_port,
        },
    )

    # Tier 3: leaf data server (registers with sub-manager's CMS)
    leaf = server_control.start_nginx_instance(
        port=leaf_ds_port,
        conf_text=_DATASERVER_CONF,
        template_kwargs={"CMS_PORT": sub_cms_port, "DATA_DIR": str(data_dir)},
    )

    # Allow both CMS registration chains to complete.
    time.sleep(4.0)

    yield {
        "meta_port":      meta_redir_port,
        "sub_port":       sub_redir_port,
        "leaf_port":      leaf_ds_port,
        "meta_cms_port":  meta_cms_port,
        "sub_cms_port":   sub_cms_port,
        "meta":           meta,
        "sub":            sub,
        "leaf":           leaf,
    }

    leaf["stop"]()
    sub["stop"]()
    meta["stop"]()


class TestThreeTierTopology:
    """Two-hop locate chain: client → meta → sub → leaf."""

    def test_locate_follows_redirect_chain_to_sub(self, three_tier):
        """First locate at meta-manager must redirect to the sub-manager."""
        tt = three_tier
        sock = _cluster_handshake_login("127.0.0.1", tt["meta_port"])
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
        sock = _cluster_handshake_login("127.0.0.1", tt["sub_port"])
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
        sock = _cluster_handshake_login("127.0.0.1", tt["meta_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()
        assert status == kXR_redirect
        hop1_port = struct.unpack(">I", body[:4])[0]

        # Hop 2: sub → leaf
        sock2 = _cluster_handshake_login("127.0.0.1", hop1_port)
        _cluster_send_locate(sock2, "/test.txt")
        status2, body2 = _cluster_read_response(sock2)
        sock2.close()
        assert status2 == kXR_redirect
        final_port = struct.unpack(">I", body2[:4])[0]
        assert final_port == tt["leaf_port"], (
            f"two-hop chain ended at {final_port}, expected leaf {tt['leaf_port']}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 6 — kYR_select mock flow (CMS-assisted locate suspension + wake)
# ═══════════════════════════════════════════════════════════════════════════

# Manager that has no local registry but forwards locate requests to a mock
# CMS manager (Python), which replies with kYR_select.
_MOCK_CMS_MANAGER_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_auth none;
        xrootd_manager_mode on;
        xrootd_cms_manager 127.0.0.1:{CMS_PORT};
        xrootd_cms_paths /;
        xrootd_cms_interval 3600;
        xrootd_cms_locate_timeout 10s;
        xrootd_listen_port {PORT};
    }}
}}
"""


def _run_mock_cms_select_server(cms_port: int, redirect_host: str,
                                redirect_port: int, stop_event: threading.Event,
                                locate_paths: list, select_sent: threading.Event):
    """Accept one nginx CMS connection and serve kYR_login + kYR_locate → kYR_select."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", cms_port))
    srv.listen(4)
    srv.settimeout(0.3)

    try:
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue

            conn.settimeout(10)
            try:
                # Read and discard the LOGIN frame from nginx.
                streamid, opcode, _payload = _cms_recv_frame(conn)
                if opcode != CMS_RR_LOGIN:
                    conn.close()
                    continue

                # Wait for a kYR_locate frame.
                while not stop_event.is_set():
                    locate_streamid, opcode, payload = _cms_recv_frame(conn)
                    if opcode == CMS_RR_LOCATE:
                        path = payload.rstrip(b"\x00").decode(errors="replace")
                        locate_paths.append(path)
                        # Send kYR_select: NUL-terminated host + BE uint16 port.
                        select_payload = (
                            redirect_host.encode() + b"\x00"
                            + struct.pack(">H", redirect_port)
                        )
                        conn.sendall(
                            _cms_frame(locate_streamid, CMS_RR_SELECT, select_payload)
                        )
                        select_sent.set()
                    # Absorb any follow-up frames (PING etc.) without replying.
            except Exception:
                pass
            finally:
                conn.close()
    finally:
        srv.close()


@pytest.fixture(scope="module")
def cluster_mock_cms(tmp_path_factory):
    """nginx manager pointing to a Python mock CMS that returns kYR_select."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    cms_port         = server_control._free_port()
    redir_port       = server_control._free_port()
    redirect_port    = server_control._free_port()  # the port select will advertise

    stop_event   = threading.Event()
    select_sent  = threading.Event()
    locate_paths = []

    mock_thread = threading.Thread(
        target=_run_mock_cms_select_server,
        args=(cms_port, "127.0.0.1", redirect_port,
              stop_event, locate_paths, select_sent),
        daemon=True,
    )
    mock_thread.start()

    redir = server_control.start_nginx_instance(
        port=redir_port,
        conf_text=_MOCK_CMS_MANAGER_CONF,
        template_kwargs={"CMS_PORT": cms_port},
    )

    time.sleep(2.5)

    yield {
        "redir_port":     redir_port,
        "redirect_port":  redirect_port,
        "locate_paths":   locate_paths,
        "select_sent":    select_sent,
        "stop_event":     stop_event,
        "redir":          redir,
    }

    redir["stop"]()
    stop_event.set()
    mock_thread.join(timeout=3.0)


class TestCmsSelectWake:
    """nginx suspends a client kXR_locate, forwards kYR_locate to CMS, and
    resumes the client with a kXR_redirect once kYR_select arrives."""

    def test_locate_wakes_on_cms_select(self, cluster_mock_cms):
        """kXR_locate must return kXR_redirect to the port advertised by kYR_select."""
        c = cluster_mock_cms

        sock = _cluster_handshake_login("127.0.0.1", c["redir_port"])
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

    def test_cms_received_locate_path(self, cluster_mock_cms):
        """The mock CMS must have received the locate path forwarded by nginx."""
        c = cluster_mock_cms
        # Wait up to 5 s for the select to have been sent.
        c["select_sent"].wait(timeout=5)
        assert c["locate_paths"], "mock CMS never received a kYR_locate frame"
        assert any("cms-select-test" in p for p in c["locate_paths"]), (
            f"expected locate path to contain 'cms-select-test', got {c['locate_paths']}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 7 — Registry-full counter (xrootd_registry_slots + Prometheus)
# ═══════════════════════════════════════════════════════════════════════════

import urllib.request

_REDIRECTOR_SLOTS_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_auth none;
        xrootd_manager_mode on;
        xrootd_registry_slots 3;
    }}
    server {{
        listen 127.0.0.1:{CMS_PORT};
        xrootd_cms_server on;
    }}
}}

http {{
    server {{
        listen 127.0.0.1:{METRICS_PORT};
        location /metrics {{
            xrootd_metrics on;
        }}
    }}
}}
"""


@pytest.fixture(scope="module")
def cluster_full_registry(tmp_path_factory):
    """Redirector with 3 registry slots + 4 data servers → overflow on the 4th."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    cms_port     = server_control._free_port()
    redir_port   = server_control._free_port()
    metrics_port = server_control._free_port()

    redir = server_control.start_nginx_instance(
        port=redir_port,
        conf_text=_REDIRECTOR_SLOTS_CONF,
        template_kwargs={"CMS_PORT": cms_port, "METRICS_PORT": metrics_port},
    )

    data_servers = []
    ds_ports = []
    for i in range(4):
        ds_port = server_control._free_port()
        ds_ports.append(ds_port)
        data_dir = tmp_path_factory.mktemp(f"full-reg-data{i}")
        (data_dir / "file.txt").write_text(f"server {i}")
        ds = server_control.start_nginx_instance(
            port=ds_port,
            conf_text=_DATASERVER_CONF,
            template_kwargs={"CMS_PORT": cms_port, "DATA_DIR": str(data_dir)},
        )
        data_servers.append(ds)

    # Allow all data servers time to connect and attempt LOGIN.
    time.sleep(5.0)

    yield {
        "redir_port":   redir_port,
        "metrics_port": metrics_port,
        "ds_ports":     ds_ports,
        "redir":        redir,
        "data_servers": data_servers,
    }

    for ds in data_servers:
        ds["stop"]()
    redir["stop"]()


class TestRegistryFullCounter:
    """xrootd_registry_full_total increments when a data server cannot register."""

    def test_registry_full_counter_nonzero(self, cluster_full_registry):
        """Prometheus metrics must show registry_full_total > 0 after overflow."""
        c = cluster_full_registry
        url = f"http://127.0.0.1:{c['metrics_port']}/metrics"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode()
        except Exception as exc:
            pytest.fail(f"Could not fetch metrics from {url}: {exc}")

        counter_value = None
        for line in body.splitlines():
            if line.startswith("xrootd_registry_full_total "):
                counter_value = float(line.split()[1])
                break

        assert counter_value is not None, (
            "xrootd_registry_full_total not present in Prometheus output"
        )
        assert counter_value > 0, (
            f"xrootd_registry_full_total is {counter_value}; "
            "expected > 0 after 4 servers tried to register into 3 slots"
        )

    def test_registry_accepts_up_to_slot_limit(self, cluster_full_registry):
        """At most 3 slots filled → at least one server's locate succeeds."""
        c = cluster_full_registry
        sock = _cluster_handshake_login("127.0.0.1", c["redir_port"])
        _cluster_send_locate(sock, "/file.txt")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect (at least 3 servers should have registered), got {status}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 8 — kYR_gone: path deregistration via CMS
# ═══════════════════════════════════════════════════════════════════════════

def _mock_cms_connect_and_register(cms_port: int, xrd_port: int,
                                   path: str) -> socket.socket:
    """Connect to the nginx CMS server port and send a LOGIN frame for the
    given XRootD port and path.  Returns the open TCP socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("127.0.0.1", cms_port))
    payload = _cms_login_payload(xrd_port, path)
    sock.sendall(_cms_frame(1, CMS_RR_LOGIN, payload))
    return sock


class TestKyrGone:
    """kYR_gone removes a path from the registry without disconnecting.

    A Python socket acts as the mock data server.  It:
      1. Connects to the redirector's CMS server port and sends LOGIN
         (which registers the path "/gone-test").
      2. Confirms locate returns kXR_redirect.
      3. Sends kYR_gone with the registered path.
      4. Confirms locate no longer redirects to that server.
    """

    def test_path_unregistered_after_gone(self, cluster):
        """After kYR_gone for /gone-test, locate must stop redirecting there."""
        gone_port = server_control._free_port()

        # Register a mock data server for /gone-test.
        mock_conn = _mock_cms_connect_and_register(
            cluster["cms_port"], gone_port, "/gone-test"
        )
        time.sleep(1.5)  # let nginx process LOGIN and register the path

        # Verify the path is reachable.
        sock = _cluster_handshake_login("127.0.0.1", cluster["redir_port"])
        _cluster_send_locate(sock, "/gone-test/file.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect before kYR_gone, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == gone_port

        # Send kYR_gone — payload is the raw path bytes (no TLV encoding).
        mock_conn.sendall(
            _cms_frame(2, CMS_RR_GONE, b"/gone-test")
        )
        time.sleep(1.5)  # let nginx process the GONE frame

        # The path must no longer redirect to gone_port.
        sock2 = _cluster_handshake_login("127.0.0.1", cluster["redir_port"])
        _cluster_send_locate(sock2, "/gone-test/file.txt")
        status2, body2 = _cluster_read_response(sock2)
        sock2.close()
        mock_conn.close()

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
        port_a = server_control._free_port()
        port_b = server_control._free_port()

        conn_a = _mock_cms_connect_and_register(cluster["cms_port"], port_a, "/gone-other")
        conn_b = _mock_cms_connect_and_register(cluster["cms_port"], port_b, "/gone-test2")
        time.sleep(1.5)

        # Send GONE only for /gone-test2.
        conn_b.sendall(_cms_frame(2, CMS_RR_GONE, b"/gone-test2"))
        time.sleep(1.5)

        # /gone-other must still redirect.
        sock = _cluster_handshake_login("127.0.0.1", cluster["redir_port"])
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
# Wire format for kYR_try payload (src/cms/cms_internal.h CMS_RR_TRY=24):
#   entry_0: NUL-terminated hostname + 2-byte big-endian port
#   entry_1: NUL-terminated hostname + 2-byte big-endian port
#   ...

CMS_RR_TRY = 24  # kYR_try opcode


def _run_mock_cms_try_server(cms_port, first_host, first_port,
                             second_host, second_port,
                             stop_event, locate_paths, try_sent):
    """Accept nginx CMS connection; reply to kYR_locate with kYR_try (2 entries).

    Follows the same frame-reading loop as _run_mock_cms_select_server: read
    LOGIN first, then loop consuming all frames and acting only on LOCATE.
    PONG and LOAD frames are consumed by the loop and ignored.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", cms_port))
    srv.listen(4)
    srv.settimeout(0.3)
    try:
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            conn.settimeout(15)
            try:
                sid, op, _pl = _cms_recv_frame(conn)
                if op != CMS_RR_LOGIN:
                    conn.close()
                    continue
                # Loop reading all frames; act only on kYR_locate
                while not stop_event.is_set():
                    loc_sid, op, payload = _cms_recv_frame(conn)
                    if op == CMS_RR_LOCATE:
                        path = payload.rstrip(b"\x00").decode(errors="replace")
                        locate_paths.append(path)
                        try_payload = (
                            first_host.encode()  + b"\x00"
                            + struct.pack(">H", first_port)
                            + second_host.encode() + b"\x00"
                            + struct.pack(">H", second_port)
                        )
                        conn.sendall(_cms_frame(loc_sid, CMS_RR_TRY, try_payload))
                        try_sent.set()
            except Exception:
                pass
            finally:
                conn.close()
    finally:
        srv.close()


@pytest.fixture(scope="module")
def cluster_cms_try(tmp_path_factory):
    """nginx manager whose mock CMS parent replies to kYR_locate with kYR_try."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    cms_port    = server_control._free_port()
    redir_port  = server_control._free_port()
    first_port  = server_control._free_port()   # nginx must redirect here
    second_port = server_control._free_port()   # must be ignored

    stop_event   = threading.Event()
    try_sent     = threading.Event()
    locate_paths = []

    threading.Thread(
        target=_run_mock_cms_try_server,
        args=(cms_port,
              "127.0.0.1", first_port,
              "127.0.0.1", second_port,
              stop_event, locate_paths, try_sent),
        daemon=True,
    ).start()

    redir = server_control.start_nginx_instance(
        port=redir_port,
        conf_text=_MOCK_CMS_MANAGER_CONF,
        template_kwargs={"CMS_PORT": cms_port},
    )
    time.sleep(2.5)

    yield {
        "redir_port":   redir_port,
        "first_port":   first_port,
        "second_port":  second_port,
        "locate_paths": locate_paths,
        "try_sent":     try_sent,
        "stop_event":   stop_event,
        "redir":        redir,
    }
    redir["stop"]()
    stop_event.set()


class TestCmsKyrTry:
    """kYR_try: nginx must redirect the client to the first entry in the list."""

    def test_locate_redirects_to_first_try_entry(self, cluster_cms_try):
        """kXR_locate returns kXR_REDIRECT pointing at the FIRST kYR_try entry.

        Wire path: client → nginx XRD_ST_WAITING_CMS → mock CMS replies
        kYR_try[first_port, second_port] → nginx wakes with kXR_REDIRECT to
        first_port only.
        """
        c = cluster_cms_try
        sock = _cluster_handshake_login("127.0.0.1", c["redir_port"])
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

    def test_second_entry_ignored(self, cluster_cms_try):
        """The second kYR_try entry must not be used for the redirect."""
        c = cluster_cms_try
        sock = _cluster_handshake_login("127.0.0.1", c["redir_port"])
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

    def test_mock_cms_received_escalated_locate(self, cluster_cms_try):
        """The mock CMS must have received at least one kYR_locate frame."""
        c = cluster_cms_try
        c["try_sent"].wait(timeout=10)
        assert c["locate_paths"], "mock CMS never received a kYR_locate frame"
        assert any("kyr-try" in p for p in c["locate_paths"]), (
            f"expected path containing 'kyr-try', got {c['locate_paths']}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 10 — True CMS escalation: sub-manager asks parent on registry miss
# ═══════════════════════════════════════════════════════════════════════════

_LEAF_STANDALONE_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth none;
    }}
}}
"""


@pytest.fixture(scope="module")
def cluster_cms_escalation(tmp_path_factory):
    """Sub-manager with an empty registry escalates kYR_locate to a mock parent."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    cms_port   = server_control._free_port()
    sub_port   = server_control._free_port()
    leaf_port  = server_control._free_port()
    data_dir   = tmp_path_factory.mktemp("cms-escalation-leaf")
    leaf_file  = data_dir / "escalate" / "file.dat"
    leaf_file.parent.mkdir(parents=True, exist_ok=True)
    leaf_file.write_text("cms escalation target")

    stop_event   = threading.Event()
    select_sent  = threading.Event()
    locate_paths = []

    mock_thread = threading.Thread(
        target=_run_mock_cms_select_server,
        args=(cms_port, "127.0.0.1", leaf_port,
              stop_event, locate_paths, select_sent),
        daemon=True,
    )
    mock_thread.start()

    leaf = server_control.start_nginx_instance(
        port=leaf_port,
        conf_text=_LEAF_STANDALONE_CONF,
        template_kwargs={"DATA_DIR": str(data_dir)},
    )
    sub = server_control.start_nginx_instance(
        port=sub_port,
        conf_text=_MOCK_CMS_MANAGER_CONF,
        template_kwargs={"CMS_PORT": cms_port},
    )

    time.sleep(2.5)

    yield {
        "sub_port": sub_port,
        "leaf_port": leaf_port,
        "locate_paths": locate_paths,
        "select_sent": select_sent,
        "leaf": leaf,
        "sub": sub,
    }

    sub["stop"]()
    leaf["stop"]()
    stop_event.set()
    mock_thread.join(timeout=3.0)


class TestCmsEscalation:
    """Registry miss -> kYR_locate to parent -> kYR_select -> kXR_redirect."""

    def test_three_tier_escalation_redirects_to_leaf(self, cluster_cms_escalation):
        c = cluster_cms_escalation

        sock = _cluster_handshake_login("127.0.0.1", c["sub_port"])
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

        c["select_sent"].wait(timeout=5)
        assert any("escalate/file.dat" in p for p in c["locate_paths"]), (
            f"mock meta-manager did not receive escalated path: {c['locate_paths']}"
        )

        leaf_sock = _cluster_handshake_login("127.0.0.1", c["leaf_port"])
        leaf_sock.settimeout(10)
        _cluster_send_open(leaf_sock, "/escalate/file.dat", kXR_open_read)
        open_status, _open_body = _cluster_read_response(leaf_sock)
        leaf_sock.close()

        assert open_status == kXR_ok, (
            f"leaf data-server did not open escalated file, got {open_status}"
        )
