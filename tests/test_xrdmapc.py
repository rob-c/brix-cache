"""
xrdmapc (phase-37 §14.5 / §15.4): cluster-map tool + ghost-replica detector.

`xrdmapc root://host[:port][//path] [--verify]` asks the endpoint which data
servers hold a path (locate), prints them with read/write flag + free space, and
with --verify probes each advertised holder to flag GHOST replicas (advertised
but not serving) and UNREACHABLE nodes.

Self-contained: a single anon nginx on a free loopback port stands in for a
one-server "cluster" (locate returns the server itself); the cluster redirector
(:11160) is additionally exercised when the fleet is up.

Run (serial):
    PYTHONPATH=tests pytest tests/test_xrdmapc.py -v -p no:xdist
"""

import os
import shutil
import socket
import subprocess

import pytest

from settings import BIND_HOST, CLUSTER_REDIR_PORT, HOST, NGINX_BIN, SERVER_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDMAPC = os.path.join(CLIENT_DIR, "bin", "xrdmapc")


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def _client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdmapc"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDMAPC):
        pytest.skip(f"xrdmapc build failed:\n{proc.stdout}\n{proc.stderr}")


@pytest.fixture()
def anon(lifecycle, _client_built, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"hello\n")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-xrdmapc",
        template="nginx_lc_stream_posix_anon.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="xrdmapc cluster-map tool against a single writable anon root server"))
    return ep.port


def _run(*args, timeout=40):
    return subprocess.run([XRDMAPC, *args], capture_output=True, text=True, timeout=timeout)


# --------------------------------------------------------------------------
# success
# --------------------------------------------------------------------------

def test_map_lists_holder_and_space(anon):
    p = _run(f"root://{HOST}:{anon}//probe.txt")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "Holders:" in p.stdout, p.stdout
    assert f"{BIND_HOST}:{anon}" in p.stdout, p.stdout
    assert "oss.free=" in p.stdout, "space line missing: " + p.stdout
    assert "Total: 1 holder(s)" in p.stdout, p.stdout


def test_map_verify_pass(anon):
    p = _run(f"root://{HOST}:{anon}//probe.txt", "--verify")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "PASS" in p.stdout and "all serving" in p.stdout, p.stdout
    assert "GHOST" not in p.stdout, p.stdout


# --------------------------------------------------------------------------
# error
# --------------------------------------------------------------------------

def test_map_nonexistent_clean_fail(anon):
    p = _run(f"root://{HOST}:{anon}//does-not-exist.bin")
    assert p.returncode != 0, p.stdout
    assert "NotFound" in (p.stdout + p.stderr), p.stderr


# --------------------------------------------------------------------------
# security-neg: --verify probes ONLY advertised holders
# --------------------------------------------------------------------------

def test_map_verify_only_advertised(anon):
    """Every host --verify probes must be one the locate set advertised — the
    tool must never reach outside the returned holder list."""
    p = _run(f"root://{HOST}:{anon}//probe.txt", "--verify")
    assert p.returncode == 0, p.stderr
    for line in p.stdout.splitlines():
        line = line.strip()
        if any(v in line for v in ("PASS", "GHOST", "UNREACHABLE")):
            assert line.startswith(f"{BIND_HOST}:{anon}"), \
                f"probed a non-advertised host: {line}"


# --------------------------------------------------------------------------
# cluster redirector (optional — skips when the fleet is down)
# --------------------------------------------------------------------------

@pytest.mark.registry_server("cluster-redir")
def test_map_cluster_redirector(anon):
    if not _port_up(SERVER_HOST, CLUSTER_REDIR_PORT):
        pytest.skip("cluster redirector not running")
    p = _run(f"root://{SERVER_HOST}:{CLUSTER_REDIR_PORT}/", timeout=40)
    # The redirector should resolve to at least one data-server holder.
    assert p.returncode in (0, 1), f"{p.stdout}\n{p.stderr}"
    assert "Holders:" in p.stdout, p.stdout


# --------------------------------------------------------------------------
# WS-J: --redirect-trace per-hop trace (cluster-gated; skips when fleet down)
# --------------------------------------------------------------------------

XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")


def test_redirect_trace_accepted_no_op(anon):
    """--redirect-trace is a recognized flag and is a no-op on a non-redirecting
    (single) server — runnable without the cluster."""
    if not os.path.exists(XRDFS):
        subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"], capture_output=True, timeout=180)
    if not os.path.exists(XRDFS):
        pytest.skip("xrdfs not built")
    p = subprocess.run([XRDFS, "--redirect-trace", f"root://{HOST}:{anon}",
                        "stat", "/probe.txt"], capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "unknown" not in p.stderr.lower(), p.stderr
    assert "Size:" in p.stdout, p.stdout
    # no redirect happened → no hop lines, and the trace never leaks onto stdout
    assert "redirect[" not in p.stdout, p.stdout


@pytest.mark.registry_server("cluster-redir")
def test_redirect_trace_hops_via_cluster(anon):
    """Through the cluster redirector, --redirect-trace emits a per-hop line on
    stderr (the data server) without disturbing stdout."""
    if not _port_up(SERVER_HOST, CLUSTER_REDIR_PORT):
        pytest.skip("cluster redirector not running")
    if not os.path.exists(XRDFS):
        pytest.skip("xrdfs not built")
    # locate a path the redirector resolves; ls / through it with the trace on.
    p = subprocess.run([XRDFS, "--redirect-trace",
                        f"root://{SERVER_HOST}:{CLUSTER_REDIR_PORT}", "ls", "/"],
                       capture_output=True, text=True, timeout=30)
    # the op may succeed or NotFound, but a redirect hop must have been traced
    assert "redirect[" in p.stderr, f"no hop traced:\n{p.stderr}"
    assert "redirect[" not in p.stdout, "trace leaked onto stdout"
