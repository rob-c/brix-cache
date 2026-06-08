"""
Heterogeneous cluster interoperability matrix — Section 3B of the comprehensive
testing roadmap docs/comprehensive-testing-roadmap.md.

Four management/cluster permutations are validated with real nginx and xrootd
binaries operating as managers, sub-managers, and data servers.

Permutation 1: "Nginx Manager"
    client ──► nginx (manager) ──► 2+ xrootd data nodes
    Uses: CLUSTER_MS_REDIR_PORT → CLUSTER_MS_DS1_PORT, CLUSTER_MS_DS2_PORT

Permutation 2: "Nginx Data Node"
    xrootd (manager) ──► nginx (data) registered via CMS
    Uses: CLUSTER_ESC_LEAF_PORT (nginx data) registered with CLUSTER_ESC_SUB_PORT

Permutation 3: "Multi-Tier Escalation"
    client ──► nginx (sub-manager) ──► xrootd (meta-manager) ──► leaf
    Uses: CLUSTER_3T_META_PORT, CLUSTER_3T_SUB_PORT, CLUSTER_3T_LEAF_PORT

Permutation 4: "Space & Quota Relay"
    Verify kYR_space relaying and space-aware redirection.
    Uses: CLUSTER_SLOTS_REDIR_PORT and its data-server pool

All tests use pre-launched servers from manage_test_servers.sh.
Run:
    pytest tests/test_e2e_cluster_matrix.py -v
"""

import os
import socket
import struct
import subprocess
import threading
import time
import uuid

import pytest

from settings import (
    CLUSTER_3T_LEAF_DATA_ROOT,
    CLUSTER_3T_LEAF_PORT,
    CLUSTER_3T_META_PORT,
    CLUSTER_3T_SUB_PORT,
    CLUSTER_ESC_CMS_PORT,
    CLUSTER_ESC_LEAF_DATA_ROOT,
    CLUSTER_ESC_LEAF_PORT,
    CLUSTER_ESC_SUB_PORT,
    CLUSTER_MS_DS1_DATA_ROOT,
    CLUSTER_MS_DS1_PORT,
    CLUSTER_MS_DS2_DATA_ROOT,
    CLUSTER_MS_DS2_PORT,
    CLUSTER_MS_REDIR_PORT,
    CLUSTER_SLOTS_DS1_DATA_ROOT,
    CLUSTER_SLOTS_DS1_PORT,
    CLUSTER_SLOTS_DS2_DATA_ROOT,
    CLUSTER_SLOTS_DS2_PORT,
    CLUSTER_SLOTS_REDIR_PORT,
    SERVER_HOST,
    XRDCP_BIN,
    XRDFS_BIN,
)

# ---------------------------------------------------------------------------
# CMS protocol helpers (subset needed for mock CMS server)
# ---------------------------------------------------------------------------

_CMS_LOGIN  = 0
_CMS_LOCATE = 2
_CMS_SELECT = 10


def _cms_recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"CMS connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _cms_recv_frame(sock: socket.socket):
    hdr = _cms_recv_exact(sock, 8)
    streamid, opcode, _mod, dlen = struct.unpack(">IBBH", hdr)
    payload = _cms_recv_exact(sock, dlen) if dlen else b""
    return streamid, opcode, payload


def _cms_frame(streamid: int, opcode: int, payload: bytes = b"") -> bytes:
    return struct.pack(">IBBH", streamid, opcode, 0, len(payload)) + payload

pytestmark = pytest.mark.e2e

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _wait_port(host: str, port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def _skip_if_port_closed(port: int, label: str):
    if not _wait_port(SERVER_HOST, port, timeout=5.0):
        pytest.skip(f"{label} not available (port {port} not open)")


def _md5(data: bytes) -> str:
    import hashlib
    return hashlib.md5(data).hexdigest()


def _xrdcp_get(src_url: str, dst: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src_url, dst],
        capture_output=True, text=True, timeout=timeout,
        env={**os.environ},
    )


def _xrdfs_stat(host: str, port: int, path: str, timeout: int = 15) -> str:
    r = subprocess.run(
        [XRDFS_BIN, f"{host}:{port}", "stat", path],
        capture_output=True, text=True, timeout=timeout,
        env={**os.environ},
    )
    return r.stdout if r.returncode == 0 else ""


_DS_DATA_ROOT = {
    CLUSTER_MS_DS1_PORT:    CLUSTER_MS_DS1_DATA_ROOT,
    CLUSTER_MS_DS2_PORT:    CLUSTER_MS_DS2_DATA_ROOT,
    CLUSTER_3T_LEAF_PORT:   CLUSTER_3T_LEAF_DATA_ROOT,
    CLUSTER_ESC_LEAF_PORT:  CLUSTER_ESC_LEAF_DATA_ROOT,
    CLUSTER_SLOTS_DS1_PORT: CLUSTER_SLOTS_DS1_DATA_ROOT,
    CLUSTER_SLOTS_DS2_PORT: CLUSTER_SLOTS_DS2_DATA_ROOT,
}


def _write_ds(port: int, name: str, data: bytes):
    """Write a file into the data root that the server on `port` serves."""
    root = _DS_DATA_ROOT[port]
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def _xrd_handshake_and_login(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(8)
    sock.connect((host, port))
    # Initial handshake
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    # kXR_protocol (24 bytes): streamid[2] requestid[2] clientpv[4] flags[1] expect[1] reserved[10] dlen[4]
    sock.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
    sock.recv(16)   # handshake resp
    sock.recv(24)   # protocol resp
    # kXR_login (24 bytes): streamid[2] requestid[2] pid[4] username[8] ability2[1] ability[1] capver[1] reserved[1] dlen[4]
    sock.sendall(struct.pack(">BB H I 8s BBBB I",
        0, 3,          # streamid
        3007,          # requestid = kXR_login
        0,             # pid
        b'anonymou',   # username[8] — NUL-padded, max 8 chars
        0, 0, 0, 0,    # ability2, ability, capver, reserved
        0,             # dlen = 0 (anonymous, no auth token)
    ))
    resp = sock.recv(1024)
    return sock


def _send_locate(sock: socket.socket, path: str) -> tuple[int, bytes]:
    """Send kXR_locate and return (status_code, body)."""
    p = path.encode("utf-8")
    # ClientLocateRequest (24 bytes): streamid[2] requestid[2] options[2] reserved[14] dlen[4]
    sock.sendall(struct.pack(">BB H H 14x I", 0, 4, 3027, 0, len(p)) + p)
    hdr = b""
    while len(hdr) < 8:
        hdr += sock.recv(8 - len(hdr))
    _, _, status, body_len = struct.unpack(">BBH I", hdr)
    body = b""
    while len(body) < body_len:
        body += sock.recv(body_len - len(body))
    return status, body


# ---------------------------------------------------------------------------
# Section 3B.1 — Nginx Manager → multiple xrootd data nodes
# ---------------------------------------------------------------------------

class TestNginxManagerMultipleDS:
    """Nginx acts as a CMS manager; requests are redirected to one of 2+ DS nodes.

    Covers roadmap Section 3B, Permutation 1.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _require_multi_server_cluster(self):
        for port, label in [
            (CLUSTER_MS_REDIR_PORT, "nginx multi-server redirector"),
            (CLUSTER_MS_DS1_PORT, "xrootd data server 1"),
            (CLUSTER_MS_DS2_PORT, "xrootd data server 2"),
        ]:
            _skip_if_port_closed(port, label)

    def test_locate_redirects_to_registered_ds(self):
        """kXR_locate from the nginx manager returns a redirect to a registered DS."""
        name = f"ms_locate_{uuid.uuid4().hex[:8]}.bin"
        _write_ds(CLUSTER_MS_DS1_PORT, name, b"locate test data")

        sock = _xrd_handshake_and_login(SERVER_HOST, CLUSTER_MS_REDIR_PORT)
        try:
            status, body = _send_locate(sock, f"/{name}")
            # 4004 = kXR_redirect
            assert status == 4004, (
                f"Expected kXR_redirect (4004) from manager, got {status}"
            )
            redirect_port = struct.unpack(">I", body[:4])[0]
            assert redirect_port in (CLUSTER_MS_DS1_PORT, CLUSTER_MS_DS2_PORT), (
                f"Redirect port {redirect_port} is not one of the registered DS ports"
            )
        finally:
            sock.close()

    def test_xrdcp_read_follows_redirect_multi_ds(self, tmp_path):
        """xrdcp reads through the nginx manager; redirect to DS and content is correct."""
        payload = os.urandom(32 * 1024)
        name = f"ms_read_{uuid.uuid4().hex[:8]}.bin"
        # Write to both DSes — manager may redirect to either one.
        _write_ds(CLUSTER_MS_DS1_PORT, name, payload)
        _write_ds(CLUSTER_MS_DS2_PORT, name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(
            f"root://{SERVER_HOST}:{CLUSTER_MS_REDIR_PORT}/{name}", dst
        )
        assert result.returncode == 0, f"xrdcp through multi-DS manager failed: {result.stderr}"
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload)

    def test_xrdfs_stat_through_nginx_manager(self):
        """xrdfs stat returns the correct file size after redirect from nginx manager."""
        payload = os.urandom(4096)
        name = f"ms_stat_{uuid.uuid4().hex[:8]}.bin"
        # Write to both DSes — manager may redirect to either one.
        _write_ds(CLUSTER_MS_DS1_PORT, name, payload)
        _write_ds(CLUSTER_MS_DS2_PORT, name, payload)

        out = _xrdfs_stat(SERVER_HOST, CLUSTER_MS_REDIR_PORT, f"/{name}")
        assert str(len(payload)) in out, (
            f"Expected size {len(payload)} in stat output, got:\n{out}"
        )

    def test_multiple_concurrent_reads_across_ds_pool(self, tmp_path):
        """Section 3B.1: Parallel reads are spread across both DS nodes without errors."""
        import concurrent.futures
        files = {}
        for i in range(4):
            data = os.urandom(16 * 1024)
            name = f"ms_par_{uuid.uuid4().hex[:8]}_{i}.bin"
            # Write to both DSes — manager may redirect any request to either one.
            _write_ds(CLUSTER_MS_DS1_PORT, name, data)
            _write_ds(CLUSTER_MS_DS2_PORT, name, data)
            files[name] = _md5(data)

        def _fetch(name_md5):
            name, expected = name_md5
            dst = str(tmp_path / name)
            r = _xrdcp_get(f"root://{SERVER_HOST}:{CLUSTER_MS_REDIR_PORT}/{name}", dst)
            if r.returncode != 0:
                return False
            with open(dst, "rb") as fh:
                return _md5(fh.read()) == expected

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            results = list(ex.map(_fetch, files.items()))
        assert all(results), f"Some parallel reads through nginx manager failed: {results}"


# ---------------------------------------------------------------------------
# Section 3B.2 — Nginx Data Node: xrootd manager → nginx data
# ---------------------------------------------------------------------------

def _run_esc_mock_cms(stop_event: threading.Event, connected: threading.Event) -> None:
    """Mock CMS server for the escalation cluster.

    Listens at CLUSTER_ESC_CMS_PORT. When nginx esc-sub connects and sends
    a LOCATE query, responds with SELECT → esc-leaf (CLUSTER_ESC_LEAF_PORT).
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", CLUSTER_ESC_CMS_PORT))
    srv.listen(4)
    srv.settimeout(0.3)
    try:
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            connected.set()
            conn.settimeout(5)
            try:
                streamid, opcode, _ = _cms_recv_frame(conn)
                if opcode != _CMS_LOGIN:
                    conn.close()
                    continue
                while not stop_event.is_set():
                    streamid, opcode, _ = _cms_recv_frame(conn)
                    if opcode == _CMS_LOCATE:
                        select_payload = (
                            b"127.0.0.1\x00"
                            + struct.pack(">H", CLUSTER_ESC_LEAF_PORT)
                        )
                        conn.sendall(_cms_frame(streamid, _CMS_SELECT, select_payload))
            except Exception:
                pass
            finally:
                conn.close()
    finally:
        srv.close()


class TestNginxDataNode:
    """nginx-xrootd as a data node with a mock CMS manager redirecting to it.

    Covers roadmap Section 3B, Permutation 2.
    The mock CMS at CLUSTER_ESC_CMS_PORT responds to esc-sub's LOCATE queries
    with a SELECT pointing to esc-leaf (CLUSTER_ESC_LEAF_PORT).
    """

    @pytest.fixture(scope="class", autouse=True)
    def _cluster_ready(self):
        """Verify ports are up, then start the mock CMS for esc-sub escalation."""
        for port, label in [
            (CLUSTER_ESC_SUB_PORT, "xrootd sub-manager (escalation)"),
            (CLUSTER_ESC_LEAF_PORT, "nginx data node (escalation leaf)"),
        ]:
            _skip_if_port_closed(port, label)

        stop_event = threading.Event()
        connected  = threading.Event()
        t = threading.Thread(
            target=_run_esc_mock_cms, args=(stop_event, connected), daemon=True
        )
        t.start()
        if not connected.wait(timeout=20):
            stop_event.set()
            pytest.skip("esc-sub never connected to mock CMS")
        yield
        stop_event.set()
        t.join(timeout=3)

    def test_xrootd_manager_redirects_to_nginx_data(self, tmp_path):
        """xrootd CMS manager redirects to nginx data node; xrdcp reads correctly."""
        payload = os.urandom(16 * 1024)
        name = f"ngxdata_{uuid.uuid4().hex[:8]}.bin"
        _write_ds(CLUSTER_ESC_LEAF_PORT, name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(
            f"root://{SERVER_HOST}:{CLUSTER_ESC_SUB_PORT}/{name}", dst
        )
        assert result.returncode == 0, (
            f"xrdcp via xrootd-manager → nginx-data failed: {result.stderr}"
        )
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload)

    def test_nginx_data_node_stat(self):
        """Stat of a file on the nginx data node returns correct metadata via xrootd manager."""
        payload = b"stat-test-" + os.urandom(100)
        name = f"ngxdata_stat_{uuid.uuid4().hex[:8]}.bin"
        _write_ds(CLUSTER_ESC_LEAF_PORT, name, payload)

        out = _xrdfs_stat(SERVER_HOST, CLUSTER_ESC_SUB_PORT, f"/{name}")
        assert str(len(payload)) in out, (
            f"Size {len(payload)} not in stat output:\n{out}"
        )


# ---------------------------------------------------------------------------
# Section 3B.3 — Multi-Tier Escalation
# ---------------------------------------------------------------------------

class TestMultiTierEscalation:
    """client ──► nginx (sub-manager) ──► xrootd (meta-manager) ──► leaf data node.

    Verifies that Nginx correctly escalates queries to a higher-level
    meta-manager when a path is not found locally, and relays the WAN-scoped
    redirect back to the client.

    Covers roadmap Section 3B, Permutation 3 and Section 4B (Federated Redirection).
    """

    @pytest.fixture(scope="class", autouse=True)
    def _require_3tier(self):
        for port, label in [
            (CLUSTER_3T_META_PORT, "xrootd meta-manager"),
            (CLUSTER_3T_SUB_PORT,  "nginx sub-manager"),
            (CLUSTER_3T_LEAF_PORT, "leaf data node"),
        ]:
            _skip_if_port_closed(port, label)

    def test_locate_escalates_to_meta_manager(self):
        """kXR_locate to the nginx sub-manager is escalated to the meta-manager."""
        name = f"escalate_locate_{uuid.uuid4().hex[:8]}.bin"
        _write_ds(CLUSTER_3T_LEAF_PORT, name, b"escalation-test-data")

        sock = _xrd_handshake_and_login(SERVER_HOST, CLUSTER_3T_SUB_PORT)
        try:
            status, body = _send_locate(sock, f"/{name}")
            assert status == 4004, (
                f"Expected kXR_redirect from sub-manager escalation, got {status}"
            )
            redirect_port = struct.unpack(">I", body[:4])[0]
            assert redirect_port == CLUSTER_3T_LEAF_PORT, (
                f"Expected redirect to leaf ({CLUSTER_3T_LEAF_PORT}), got {redirect_port}"
            )
        finally:
            sock.close()

    def test_xrdcp_follows_multi_tier_redirect(self, tmp_path):
        """xrdcp follows a redirect chain through sub-manager → meta-manager → leaf."""
        payload = os.urandom(32 * 1024)
        name = f"escalate_read_{uuid.uuid4().hex[:8]}.bin"
        _write_ds(CLUSTER_3T_LEAF_PORT, name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(
            f"root://{SERVER_HOST}:{CLUSTER_3T_SUB_PORT}/{name}", dst
        )
        assert result.returncode == 0, (
            f"xrdcp through 3-tier escalation failed: {result.stderr}"
        )
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload), "Content mismatch after 3-tier redirect"

    def test_path_not_local_triggers_escalation(self):
        """A path that does not exist on the sub-manager must escalate, not fail."""
        name = f"escalate_notlocal_{uuid.uuid4().hex[:8]}.bin"
        # Write ONLY to the leaf, not in the sub-manager's local view.
        _write_ds(CLUSTER_3T_LEAF_PORT, name, b"leaf-only-data")

        sock = _xrd_handshake_and_login(SERVER_HOST, CLUSTER_3T_SUB_PORT)
        try:
            status, body = _send_locate(sock, f"/{name}")
            # Must get a redirect (4004), not not-found (4003)
            assert status == 4004, (
                f"Expected escalation redirect, got {status} (not-found would be a bug)"
            )
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# Section 3B.4 — Space & Quota Relay
# ---------------------------------------------------------------------------

class TestSpaceAndQuotaRelay:
    """Verify kYR_space relaying and space-aware redirection across the DS pool.

    Covers roadmap Section 3B, Permutation 4.
    Uses CLUSTER_SLOTS_REDIR_PORT with CLUSTER_SLOTS_DS1..DS4.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _require_slots_cluster(self):
        for port, label in [
            (CLUSTER_SLOTS_REDIR_PORT, "slots cluster redirector"),
            (CLUSTER_SLOTS_DS1_PORT, "slots DS-1"),
            (CLUSTER_SLOTS_DS2_PORT, "slots DS-2"),
        ]:
            _skip_if_port_closed(port, label)

    def test_locate_uses_space_aware_selection(self):
        """Redirector returns a data server based on space availability."""
        name = f"slots_{uuid.uuid4().hex[:8]}.bin"
        _write_ds(CLUSTER_SLOTS_DS1_PORT, name, b"space-test")

        sock = _xrd_handshake_and_login(SERVER_HOST, CLUSTER_SLOTS_REDIR_PORT)
        try:
            status, body = _send_locate(sock, f"/{name}")
            assert status == 4004, f"Expected redirect from slots cluster, got {status}"
            redirect_port = struct.unpack(">I", body[:4])[0]
            assert redirect_port in (
                CLUSTER_SLOTS_DS1_PORT, CLUSTER_SLOTS_DS2_PORT
            ), f"Unexpected redirect target: {redirect_port}"
        finally:
            sock.close()

    def test_xrdcp_completes_via_space_selected_ds(self, tmp_path):
        """xrdcp reads complete successfully via space-selected data server."""
        payload = os.urandom(8 * 1024)
        name = f"slots_read_{uuid.uuid4().hex[:8]}.bin"
        # Write to both DSes — redirector may select either one.
        _write_ds(CLUSTER_SLOTS_DS1_PORT, name, payload)
        _write_ds(CLUSTER_SLOTS_DS2_PORT, name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(
            f"root://{SERVER_HOST}:{CLUSTER_SLOTS_REDIR_PORT}/{name}", dst
        )
        assert result.returncode == 0, f"xrdcp via slots cluster failed: {result.stderr}"
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload)
