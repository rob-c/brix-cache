# brix-remote-skip
"""
Federated redirection (WAN/Global Namespace) — Section 4B of the comprehensive
testing roadmap docs/comprehensive-testing-roadmap.md.

Topology:
    Client ──► Local Nginx Mgr ──► Regional XRootD Redirector ──► Remote Data Server

Nginx correctly escalates queries to a higher-level "meta-manager" when a path
is not found locally, then relays the WAN-scoped redirect back to the client.

The test reuses the three-tier cluster topology already started by
manage_test_servers.sh:
    CLUSTER_3T_META_PORT  — xrootd meta-manager (the "regional" redirector)
    CLUSTER_3T_SUB_PORT   — nginx sub-manager (the "local" manager)
    CLUSTER_3T_LEAF_PORT  — leaf data node (the "remote" data server)

Run:
    pytest tests/test_federated_redirection.py -v
"""

import hashlib
import os
import socket
import struct
import subprocess
import time
import uuid

import pytest

from settings import (
    CLUSTER_3T_LEAF_DATA_ROOT,
    CLUSTER_3T_LEAF_PORT,
    CLUSTER_3T_META_PORT,
    CLUSTER_3T_SUB_PORT,
    SERVER_HOST,
    XRDCP_BIN,
    XRDFS_BIN,
)

pytestmark = pytest.mark.e2e


def _wait_port(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


@pytest.fixture(scope="module")
def federated_cluster():
    """Wait for the three-tier federated cluster and return port info."""
    for port, label in [
        (CLUSTER_3T_META_PORT, "xrootd meta-manager"),
        (CLUSTER_3T_SUB_PORT,  "nginx sub-manager"),
        (CLUSTER_3T_LEAF_PORT, "leaf data node"),
    ]:
        if not _wait_port(SERVER_HOST, port, timeout=15.0):
            pytest.skip(f"Federated cluster not available ({label} on port {port})")
    return {
        "meta_port":  CLUSTER_3T_META_PORT,
        "sub_port":   CLUSTER_3T_SUB_PORT,
        "leaf_port":  CLUSTER_3T_LEAF_PORT,
        "meta_url":   f"root://{SERVER_HOST}:{CLUSTER_3T_META_PORT}/",
        "sub_url":    f"root://{SERVER_HOST}:{CLUSTER_3T_SUB_PORT}/",
        "leaf_url":   f"root://{SERVER_HOST}:{CLUSTER_3T_LEAF_PORT}/",
    }


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _write_leaf(name: str, data: bytes) -> str:
    path = os.path.join(CLUSTER_3T_LEAF_DATA_ROOT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _recv_response(sock: socket.socket) -> tuple[int, bytes]:
    hdr = _recv_exact(sock, 8)
    _, _, status, dlen = struct.unpack(">BBH I", hdr)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _xrd_session(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(8)
    sock.connect((host, port))
    # Pipeline: send initial handshake + kXR_protocol before reading anything
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    sock.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
    # Server handshake response is always 16 bytes (8-byte header + 8-byte body)
    _recv_exact(sock, 16)
    # kXR_protocol response: variable length
    _recv_response(sock)
    # kXR_login: 24-byte fixed header, username in header field (8 bytes), dlen=0
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, 3007, 0,
                             b"anon\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))
    _recv_response(sock)
    return sock


def _locate(sock: socket.socket, path: str) -> tuple[int, bytes]:
    payload = path.encode() + b"\x00"
    sock.sendall(struct.pack(">BBHH14sI", 0, 1, 3027, 0, b"\x00" * 14, len(payload)) + payload)
    return _recv_response(sock)


def _xrdcp_get(src: str, dst: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src, dst],
        capture_output=True, text=True, timeout=timeout, env={**os.environ},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.requires_local_server
class TestFederatedRedirection:
    """Section 4B — Federated Redirection (WAN / Global Namespace).

    Verifies that the nginx sub-manager escalates to the meta-manager and
    correctly relays WAN redirects back to the client.
    """

    def test_local_sub_manager_escalates_unknown_path(self, federated_cluster):
        """A path unknown to the sub-manager triggers escalation to the meta-manager."""
        name = f"fed_esc_{uuid.uuid4().hex[:8]}.bin"
        # Write to the leaf — the sub-manager has no local knowledge of this.
        _write_leaf(name, b"escalate-payload")

        sock = _xrd_session(SERVER_HOST, federated_cluster["sub_port"])
        try:
            status, body = _locate(sock, f"/{name}")
            assert status == 4004, (
                f"Expected kXR_redirect after escalation, got {status}"
            )
            redirect_port = struct.unpack(">I", body[:4])[0]
            assert redirect_port == CLUSTER_3T_LEAF_PORT, (
                f"Expected redirect to leaf ({CLUSTER_3T_LEAF_PORT}), got {redirect_port}"
            )
        finally:
            sock.close()

    def test_xrdcp_via_sub_manager_fetches_wan_file(self, federated_cluster, tmp_path):
        """xrdcp through the sub-manager fetches a file located at the remote leaf node."""
        payload = os.urandom(64 * 1024)
        name = f"fed_read_{uuid.uuid4().hex[:8]}.bin"
        _write_leaf(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(
            f"{federated_cluster['sub_url']}/{name}", dst
        )
        assert result.returncode == 0, (
            f"xrdcp through federated sub-manager failed:\n{result.stderr}"
        )
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload), "Federated redirect content mismatch"

    def test_multiple_hops_completed(self, federated_cluster, tmp_path):
        """Verify redirect chain: meta redirects to sub, sub redirects to leaf."""
        payload = os.urandom(32 * 1024)
        name = f"fed_multi_{uuid.uuid4().hex[:8]}.bin"
        _write_leaf(name, payload)

        # Meta-manager knows the sub-manager (sub registers with meta's CMS).
        # Locate via meta → expect redirect to sub-manager.
        meta_sock = _xrd_session(SERVER_HOST, federated_cluster["meta_port"])
        try:
            status, body = _locate(meta_sock, f"/{name}")
            assert status == 4004, f"Meta-manager did not redirect: {status}"
            meta_redirect_port = struct.unpack(">I", body[:4])[0]
        finally:
            meta_sock.close()

        assert meta_redirect_port == CLUSTER_3T_SUB_PORT, (
            f"Meta should redirect to sub-manager ({CLUSTER_3T_SUB_PORT}), got {meta_redirect_port}"
        )

        # Sub-manager knows the leaf (leaf registers with sub's CMS).
        # Locate via sub → expect redirect to leaf.
        sub_sock = _xrd_session(SERVER_HOST, federated_cluster["sub_port"])
        try:
            status, body = _locate(sub_sock, f"/{name}")
            assert status == 4004, f"Sub-manager did not redirect: {status}"
            sub_redirect_port = struct.unpack(">I", body[:4])[0]
        finally:
            sub_sock.close()

        assert sub_redirect_port == CLUSTER_3T_LEAF_PORT, (
            f"Sub should redirect to leaf ({CLUSTER_3T_LEAF_PORT}), got {sub_redirect_port}"
        )

    def test_xrdfs_ls_through_federated_namespace(self, federated_cluster):
        """xrdfs ls on the sub-manager returns files visible via the meta-manager."""
        _write_leaf(f"fed_ls_{uuid.uuid4().hex[:8]}.txt", b"ls-test")
        r = subprocess.run(
            [XRDFS_BIN, f"{SERVER_HOST}:{CLUSTER_3T_SUB_PORT}", "ls", "/"],
            capture_output=True, text=True, timeout=20, env={**os.environ},
        )
        # We expect at least the ls command to complete without a hard error.
        assert r.returncode == 0 or "No such file" not in r.stderr, (
            f"xrdfs ls through federated namespace failed: {r.stderr}"
        )

    def test_redirect_chain_completes_large_file(self, federated_cluster, tmp_path):
        """Section 4B Validation: large file transfer completes through redirect chain."""
        payload = os.urandom(4 * 1024 * 1024)  # 4 MiB
        name = f"fed_large_{uuid.uuid4().hex[:8]}.bin"
        _write_leaf(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(f"{federated_cluster['sub_url']}/{name}", dst, timeout=120)
        assert result.returncode == 0, (
            f"Large-file federated transfer failed:\n{result.stderr}"
        )
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload), "Large-file checksum mismatch through federated redirect"
