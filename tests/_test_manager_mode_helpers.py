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
    REGISTRY_ROOT,
    TEST_ROOT,
    url_host,
)

kXR_ok = 0
kXR_redirect = 4004
kXR_mkdir = 3008
kXR_open = 3010
kXR_rm = 3014
kXR_locate = 3027
kXR_open_read = 0x0010
kXR_isManager = 0x00000002

# CMS wire constants (used by the _cms_* builders below and re-exported to
# the test modules; see src/net/cms/cms_internal.h).
CMS_RR_LOGIN  = 0
CMS_RR_LOCATE = 2
CMS_RR_SELECT = 10
CMS_RR_GONE   = 14
CMS_RR_PING   = 17
CMS_RR_PONG   = 18

CMS_PT_SHORT = 0x80
CMS_PT_INT   = 0xa0


def _kill_nginx_dedicated(name: str) -> None:
    """Send SIGTERM to the pre-launched dedicated nginx instance by name."""
    import signal
    # The registry launcher writes each instance's pidfile under its own prefix
    # (REGISTRY_ROOT/<name>/logs/nginx.pid) — the retired bash "dedicated/<name>"
    # path never exists, so the SIGTERM was a no-op and the data server stayed up
    # (redirector kept returning kXR_redirect after the "stop").
    pidfile = os.path.join(REGISTRY_ROOT, name, "logs", "nginx.pid")
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


def _wait_for_redirect(redir_port, path, expected_ds_ports,
                       timeout: float = 25.0, host: str = HOST):
    """Connect to redir_port, send kXR_locate for path, retry until we get
    a kXR_redirect (4004) pointing at one of expected_ds_ports, or timeout.

    expected_ds_ports may be a single port or a collection: multi-server
    clusters must accept ANY registered data server — selection tie-breaks
    by registration order, so insisting on one specific server races the
    fleet's parallel bring-up.
    """
    if isinstance(expected_ds_ports, int):
        expected_ds_ports = {expected_ds_ports}
    else:
        expected_ds_ports = set(expected_ds_ports)
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
                    if redirect_port in expected_ds_ports:
                        return
            finally:
                sock.close()
        except OSError:
            pass
        time.sleep(0.5)
    pytest.fail(
        f"Redirector on {redir_port} never redirected {path!r} to any of "
        f"{sorted(expected_ds_ports)} within {timeout}s (last status={last_status})"
    )


@pytest.fixture(scope="session")
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
    import sys
    subprocess.run(
        [sys.executable, "-m", "cmdscripts.manage_test_servers", "start-dedicated", "cluster-ds"],
        cwd=os.path.dirname(__file__),
        capture_output=True,
        timeout=30,
    )



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
    _wait_for_redirect(CLUSTER_MS_REDIR_PORT, "/shared.txt",
                       (CLUSTER_MS_DS1_PORT, CLUSTER_MS_DS2_PORT))

    yield {
        "redir_port": CLUSTER_MS_REDIR_PORT,
        "ds1_port":   CLUSTER_MS_DS1_PORT,
        "ds2_port":   CLUSTER_MS_DS2_PORT,
        "cms_port":   CLUSTER_MS_CMS_PORT,
    }



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

# Re-export from split helpers
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_manager_mode_helpers_b")
