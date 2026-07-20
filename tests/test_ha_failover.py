"""
Site-Entry High-Availability (HA) Stack — Section 4E of the comprehensive
testing roadmap docs/comprehensive-testing-roadmap.md.

Topology:
    Client ──► Load Balancer (HAProxy) ──► {Nginx-1, Nginx-2} ──► XRootD DS pool

Validation (per roadmap Section 4E):
  1. Both Nginx instances serve reads correctly.
  2. Force Nginx-1 to stop mid-transfer.
  3. Verify new connections are handled by Nginx-2 seamlessly.
  4. Verify zero "orphaned" handles in /proc/net/tcp after 1000 operations.

Requirements:
  - HAProxy listening on HA_HAPROXY_PORT (default 11210).
  - Two nginx instances: HA_NGINX1_PORT (11211) and HA_NGINX2_PORT (11212).
  - Both nginx instances configured with the same XRootD data root.
  - haproxy binary available on PATH.

These tests are SKIPPED when HAProxy is not detected on HA_HAPROXY_PORT.
They require the ha-failover server group to be started:
    manage_test_servers.sh start-ha

To add this group, configure in manage_test_servers.sh:
    - haproxy with round-robin to HA_NGINX1_PORT and HA_NGINX2_PORT
    - two nginx instances each serving DATA_ROOT

Run:
    pytest tests/test_ha_failover.py -v
"""

# --- Python 3.9 compat (EL9 system python) --------------------------------
# This suite uses PEP 604 unions (`X | None`) in annotations. On Python 3.9
# those are evaluated at def-time and raise TypeError; PEP 604 only works at
# runtime on Python >= 3.10. `from __future__ import annotations` (PEP 563)
# makes ALL annotations in this module lazy strings, so 3.9 imports cleanly.
# DROP this block (and the import) once the minimum supported Python is >=3.10.
from __future__ import annotations
# --------------------------------------------------------------------------


import hashlib
import os
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from settings import (
    DATA_ROOT,
    HA_HAPROXY_PORT,
    HA_NGINX1_PORT,
    HA_NGINX2_PORT,
    SERVER_HOST,
    TEST_ROOT,
    XRDCP_BIN,
    XRDFS_BIN,
)
from server_launcher import launch_fleet_nginx

# The HA group is a standing fleet (haproxy + two fixed-port nginx, brought up by
# `manage_test_servers.sh start-ha`), not a per-test harness; the only nginx the
# test starts itself is the restart of the member it kills, routed through the
# registry's fleet-relaunch seam.  The marker keeps this out of the direct-launch
# lint scope.
pytestmark = [pytest.mark.e2e, pytest.mark.uses_lifecycle_harness]


def _wait_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def ha_cluster():
    """Wait for HAProxy + both nginx instances; skip if HA not configured."""
    if not shutil.which("haproxy"):
        pytest.skip("haproxy binary not found on PATH — HA tests require haproxy")

    for port, label in [
        (HA_HAPROXY_PORT, "HAProxy load balancer"),
        (HA_NGINX1_PORT, "nginx HA instance 1"),
        (HA_NGINX2_PORT, "nginx HA instance 2"),
    ]:
        if not _wait_port(SERVER_HOST, port, timeout=10.0):
            pytest.skip(
                f"HA cluster not available ({label} on port {port}). "
                "Run: manage_test_servers.sh start-ha"
            )
    return {
        "haproxy_port": HA_HAPROXY_PORT,
        "nginx1_port":  HA_NGINX1_PORT,
        "nginx2_port":  HA_NGINX2_PORT,
        "haproxy_url":  f"root://{SERVER_HOST}:{HA_HAPROXY_PORT}/",
        "nginx1_url":   f"root://{SERVER_HOST}:{HA_NGINX1_PORT}/",
        "nginx2_url":   f"root://{SERVER_HOST}:{HA_NGINX2_PORT}/",
        "data_root":    DATA_ROOT,
    }


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _write_shared(name: str, data: bytes) -> str:
    path = os.path.join(DATA_ROOT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _xrdcp_get(src: str, dst: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src, dst],
        capture_output=True, text=True, timeout=timeout, env={**os.environ},
    )


def _orphaned_handles() -> int:
    """Count CLOSE_WAIT TCP connections on our HA ports.

    CLOSE_WAIT is the leak signal: the peer closed and our process still
    holds the descriptor.  TIME_WAIT deliberately does NOT count — it holds
    no fd (kernel-only state, lingering ~60s whenever our side closes
    first), so any earlier test on these shared ports would trip a
    TIME_WAIT-based check for a minute afterwards.
    """
    xrd_ports = {HA_HAPROXY_PORT, HA_NGINX1_PORT, HA_NGINX2_PORT}
    count = 0
    try:
        with open("/proc/net/tcp", "r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 4 or ":" not in parts[1]:
                    continue  # skip header and malformed lines
                local_hex = parts[1].split(":")[1]
                state = parts[3]
                local_port = int(local_hex, 16)
                if local_port in xrd_ports and state == "08":  # CLOSE_WAIT
                    count += 1
    except FileNotFoundError:
        pass
    return count


# ---------------------------------------------------------------------------
# Section 4E.1 — Both Nginx instances serve reads correctly
# ---------------------------------------------------------------------------

class TestHABothInstancesServe:
    """Verify both HA nginx instances can independently serve reads."""

    @pytest.mark.registry_servers("ha-haproxy", "ha-nginx1", "ha-nginx2")
    def test_nginx1_serves_file(self, ha_cluster, tmp_path):
        """Nginx instance 1 serves a file directly."""
        payload = os.urandom(8 * 1024)
        name = f"ha_n1_{uuid.uuid4().hex[:8]}.bin"
        _write_shared(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(f"{ha_cluster['nginx1_url']}{name}", dst)
        assert result.returncode == 0, f"nginx-1 direct read failed: {result.stderr}"
        with open(dst, "rb") as fh:
            assert _md5(fh.read()) == _md5(payload)

    @pytest.mark.registry_servers("ha-haproxy", "ha-nginx1", "ha-nginx2")
    def test_nginx2_serves_file(self, ha_cluster, tmp_path):
        """Nginx instance 2 serves a file directly."""
        payload = os.urandom(8 * 1024)
        name = f"ha_n2_{uuid.uuid4().hex[:8]}.bin"
        _write_shared(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(f"{ha_cluster['nginx2_url']}{name}", dst)
        assert result.returncode == 0, f"nginx-2 direct read failed: {result.stderr}"
        with open(dst, "rb") as fh:
            assert _md5(fh.read()) == _md5(payload)

    @pytest.mark.registry_servers("ha-haproxy", "ha-nginx1", "ha-nginx2")
    def test_haproxy_balances_across_both(self, ha_cluster, tmp_path):
        """HAProxy distributes reads across both nginx instances without error."""
        import concurrent.futures

        payload = os.urandom(16 * 1024)
        name = f"ha_bal_{uuid.uuid4().hex[:8]}.bin"
        _write_shared(name, payload)
        expected = _md5(payload)

        def _fetch(idx: int) -> bool:
            dst = str(tmp_path / f"{name}_{idx}")
            r = _xrdcp_get(f"{ha_cluster['haproxy_url']}{name}", dst)
            if r.returncode != 0:
                return False
            with open(dst, "rb") as fh:
                return _md5(fh.read()) == expected

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            results = list(ex.map(_fetch, range(6)))
        assert all(results), f"Some HA reads failed: {results}"


# ---------------------------------------------------------------------------
# Section 4E.2 — Handle leak detection
# ---------------------------------------------------------------------------

class TestHAHandleLeaks:
    """Section 4E Validation: /proc/net/tcp shows zero orphaned handles after
    operations.  Covers roadmap Section 14.4.
    """

    @pytest.mark.skipif(not os.path.exists("/proc/net/tcp"),
                        reason="/proc/net/tcp not available (not Linux)")
    @pytest.mark.registry_servers("ha-haproxy", "ha-nginx1", "ha-nginx2")
    def test_no_orphaned_handles_after_100_operations(self, ha_cluster, tmp_path):
        """After 100 xrdcp reads through HAProxy, no CLOSE_WAIT sockets remain
        for our ports.  Each xrdcp creates one TCP connection; a CLOSE_WAIT
        left behind means the server still holds the fd after the client
        closed (Section 5A / roadmap Section 14.4).
        """
        payload = os.urandom(4096)
        name = f"ha_leak_{uuid.uuid4().hex[:8]}.bin"
        _write_shared(name, payload)

        for i in range(100):
            dst = str(tmp_path / f"{name}_{i}")
            result = _xrdcp_get(f"{ha_cluster['haproxy_url']}{name}", dst)
            assert result.returncode == 0, f"xrdcp #{i} failed: {result.stderr}"

        # Give the OS a moment to close connections.
        time.sleep(1)
        orphans = _orphaned_handles()
        assert orphans == 0, (
            f"Found {orphans} orphaned TCP connections after 100 operations — "
            "possible handle leak in HA path"
        )


# ---------------------------------------------------------------------------
# Section 4E.3 — Failover: Nginx-1 stops mid-transfer
# ---------------------------------------------------------------------------

class TestHAFailover:
    """Force one nginx instance down; verify new connections go to the other.

    Roadmap Section 4E: "Force Nginx-1 to stop mid-transfer and ensure the
    client can resume via Nginx-2."
    """

    def _get_nginx1_pid(self) -> int | None:
        """Return the PID of the nginx master process on HA_NGINX1_PORT."""
        try:
            r = subprocess.run(
                ["ss", "-tlnp", f"sport = :{HA_NGINX1_PORT}"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                if "pid=" in line:
                    pid_part = [p for p in line.split(",") if "pid=" in p][0]
                    return int(pid_part.split("pid=")[1].split(",")[0].rstrip(")"))
        except Exception:
            pass
        return None

    @pytest.mark.registry_servers("ha-haproxy", "ha-nginx1", "ha-nginx2")
    def test_new_connections_handled_after_nginx1_stop(self, ha_cluster, tmp_path):
        """After nginx-1 stops, new connections through HAProxy still succeed.

        This validates the "seamless failover" requirement in Section 4E.
        Note: existing in-flight connections will fail; only NEW connections
        after the restart are tested here.
        """
        payload = os.urandom(8 * 1024)
        name = f"ha_fail_{uuid.uuid4().hex[:8]}.bin"
        _write_shared(name, payload)

        # Verify baseline: haproxy works before stopping nginx-1.
        dst0 = str(tmp_path / f"{name}_pre")
        assert _xrdcp_get(
            f"{ha_cluster['haproxy_url']}{name}", dst0
        ).returncode == 0, "Baseline HA read failed before failover test"

        pid1 = self._get_nginx1_pid()
        if pid1 is None:
            pytest.skip("Could not determine nginx-1 PID — skipping stop test")

        try:
            os.kill(pid1, signal.SIGTERM)
            time.sleep(0.5)  # allow haproxy to detect the down backend

            # New connections through HAProxy must still succeed via nginx-2.
            dst1 = str(tmp_path / f"{name}_post")
            result = _xrdcp_get(
                f"{ha_cluster['haproxy_url']}{name}", dst1, timeout=30
            )
            assert result.returncode == 0, (
                f"HAProxy did not failover to nginx-2 after nginx-1 stop:\n"
                f"{result.stderr}"
            )
            with open(dst1, "rb") as fh:
                assert _md5(fh.read()) == _md5(payload), (
                    "Content mismatch after HA failover"
                )
        finally:
            # Restart nginx-1 (the fleet member this test killed) so subsequent
            # tests are not affected — through the registry's standing-fleet
            # relaunch seam, into the member's own fixed prefix tree.
            nginx_prefix = os.path.join(TEST_ROOT, "dedicated", "ha-nginx1")
            launch_fleet_nginx("conf/nginx.conf", prefix=nginx_prefix)
