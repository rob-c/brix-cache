"""
test_cms_fast_settle.py — guards the CMS mesh fast cold-start settling work.

Self-contained: each test provisions its OWN nginx-xrootd CMS *data node* (own
prefix, high ports) pointed at a stand-in "manager" and drives the freshly-built
objs/nginx directly — no dependency on the real-cmsd mesh fleet.

Why a plain TCP listener is a valid manager stand-in: the CMS client marks itself
registered (sets ever_logged_in and logs its settle time) the moment the TCP connect
succeeds and the login frame is sent — which is exactly the cold-start cost the
fast-retry optimizes. So a socket that merely accepts is enough to measure
time-to-register and prove the fast-retry/backoff behaviour, without standing up a
full cmsd.

Covered:
  * loopback fast-retry actually engages — a node started before its manager retries
    on the short interval and registers within tens of ms of the manager appearing
    (many connect attempts, not one lucky try after a multi-second backoff);
  * the happy path (manager already up) registers near-instantly;
  * a dead manager is bounded: fast-retry is confined to the window, then falls back
    to sparse exponential backoff — it never busy-spins (no 0ms-timer footgun);
  * the tunables (brix_cms_initial_delay / _connect_retry) are accepted.

Real mesh interop/correctness is covered by test_cms_mesh_interop.py /
test_conformance_topologies.py against the cmsd fleet.
"""

import os
import re
import socket
import threading
import time

import pytest

NGINX_BIN = os.environ.get("LIFECYCLE_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

pytestmark = pytest.mark.skipif(
    not os.path.isfile(NGINX_BIN),
    reason=f"nginx binary not built at {NGINX_BIN}",
)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class StubManager:
    """A loopback TCP listener that accepts and holds CMS-node connections."""

    def __init__(self, port):
        self.port = port
        self._sock = None
        self._conns = []
        self._thread = None
        self._stop = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self):
        while not self._stop:
            try:
                c, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            c.setblocking(False)
            self._conns.append(c)  # hold open; drain lazily so the node stays "up"

    def stop(self):
        self._stop = True
        if self._thread:
            self._thread.join(timeout=1)
        for c in self._conns:
            try:
                c.close()
            except OSError:
                pass
        if self._sock:
            self._sock.close()


class Node:
    """A self-provisioned nginx-xrootd CMS data node pointed at a manager port."""

    def __init__(self, prefix, mgr_port, log_level="notice", extra=""):
        self.prefix = prefix
        self.mgr_port = mgr_port
        self.conf = os.path.join(prefix, "conf", "nginx.conf")
        self.elog = os.path.join(prefix, "logs", "error.log")
        self.listen = _free_port()
        for sub in ("conf", "logs", "data"):
            os.makedirs(os.path.join(prefix, sub), exist_ok=True)
        # nginx master runs as root here, so the worker drops to the built-in
        # 'nobody' user. The checkpoint-recovery lock is created INSIDE the
        # export, so the export dir must be writable by that worker user (the
        # fleet exports are 0777 for the same reason). Without this the worker
        # fails the recovery lock with EACCES and exits fatally before it can
        # register with the CMS manager.
        os.chmod(os.path.join(prefix, "data"), 0o777)
        with open(self.conf, "w") as fh:
            fh.write(f"""\
worker_processes 1;
daemon on;
pid {prefix}/logs/nginx.pid;
error_log {self.elog} {log_level};
events {{ worker_connections 256; }}
stream {{
    server {{
        listen {self.listen};
        brix_root on;
        brix_storage_backend posix:{prefix}/data;
        brix_auth none;
        brix_cms_manager 127.0.0.1:{mgr_port};
{extra}    }}
}}
""")

    def start(self):
        import subprocess
        subprocess.run([NGINX_BIN, "-p", self.prefix, "-c", self.conf], check=True)

    def stop(self):
        import subprocess
        subprocess.run([NGINX_BIN, "-p", self.prefix, "-c", self.conf, "-s", "stop"],
                       stderr=subprocess.DEVNULL)

    def read_log(self):
        try:
            with open(self.elog) as fh:
                return fh.read()
        except FileNotFoundError:
            return ""

    def wait_registered(self, timeout=8.0):
        """Return the parsed 'CMS registered ... after N ms (K attempt(s), prof)'."""
        rx = re.compile(
            r"CMS registered with \S+ after (\d+) ms "
            r"\((\d+) connect attempt\(s\), (\w+)\)")
        deadline = time.time() + timeout
        while time.time() < deadline:
            m = rx.search(self.read_log())
            if m:
                return int(m.group(1)), int(m.group(2)), m.group(3)
            time.sleep(0.02)
        return None


@pytest.fixture
def node_factory(tmp_path):
    nodes, mgrs = [], []

    def _make(mgr_port=None, start_manager=False, **kw):
        port = mgr_port if mgr_port is not None else _free_port()
        mgr = None
        if start_manager:
            mgr = StubManager(port)
            mgr.start()
            mgrs.append(mgr)
        node = Node(str(tmp_path / f"node{len(nodes)}"), port, **kw)
        nodes.append(node)
        return node, port, mgr

    yield _make
    for n in nodes:
        n.stop()
    for m in mgrs:
        m.stop()


def test_happy_path_registers_fast(node_factory):
    """Manager already listening: the node registers near-instantly."""
    node, _, _ = node_factory(start_manager=True)
    node.start()
    res = node.wait_registered()
    assert res is not None, "node never registered\n" + node.read_log()
    ms, attempts, profile = res
    assert profile == "loopback"
    assert ms < 500, f"loopback registration took {ms} ms"


def test_fast_retry_engages_for_late_manager(node_factory):
    """Node started before its manager fast-retries and registers right as it appears."""
    node, port, _ = node_factory(start_manager=False)
    node.start()
    time.sleep(0.4)            # node fast-retries on the 10ms loopback interval
    mgr = StubManager(port)    # manager finally comes up
    mgr.start()
    try:
        res = node.wait_registered()
        assert res is not None, "node never registered\n" + node.read_log()
        ms, attempts, profile = res
        assert profile == "loopback"
        # Many attempts during the 0.4s gap => fast-retry really engaged (the old
        # behaviour waited 1s then connected on attempt 1).
        assert attempts >= 2, f"expected fast-retry (multiple attempts), got {attempts}"
        # Registered close to when the manager appeared, not after a multi-second backoff.
        assert ms < 1500, f"settled in {ms} ms — slower than fast-retry should allow"
    finally:
        mgr.stop()


def test_dead_manager_is_bounded_then_backs_off(node_factory):
    """Fast-retry is confined to the window, then falls back to sparse backoff.

    Fast-retry is intentionally quiet (debug, compiled out in release builds), so we
    observe it indirectly: the actionable "cannot reach" WARN fires only when the
    fast-retry window EXPIRES.  Its timing proves fast-retry engaged and is bounded
    (it does not back off immediately, but it does eventually); its sparsity proves
    there is no busy-spin.
    """
    node, _, _ = node_factory(start_manager=False)   # manager never comes up
    node.start()
    t0 = time.time()

    # Poll for the first backoff WARN.
    first = None
    while time.time() - t0 < 6:
        if "cannot reach cluster manager" in node.read_log():
            first = time.time() - t0
            break
        time.sleep(0.02)
    assert first is not None, "node never emitted the backoff WARN\n" + node.read_log()

    # The WARN only appears AFTER the ~2s loopback fast-retry window: fast-retry held
    # off the multi-second backoff for the whole bounded window, then gave up.
    assert 1.2 <= first <= 3.5, f"backoff WARN at {first:.2f}s (expected ~2s window)"

    # After the window, retries are sparse exponential backoff — never a tight loop.
    time.sleep(1.5)
    warns = node.read_log().count("cannot reach cluster manager")
    assert warns <= 3, f"too many backoff WARNs ({warns}) — not sparse (spinning?)"


def test_tunables_accepted(node_factory):
    """brix_cms_initial_delay / _connect_retry are accepted and the node settles."""
    node, _, _ = node_factory(
        start_manager=True,
        extra="        brix_cms_initial_delay 0;\n"
              "        brix_cms_connect_retry 25;\n")
    node.start()
    res = node.wait_registered()
    assert res is not None, "node never registered with custom tunables\n" + node.read_log()
