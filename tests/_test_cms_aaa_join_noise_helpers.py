"""
test_cms_aaa_join_noise.py — can BriX join a CMS-AAA-style redirector mesh over
a *bad* WAN link, and stay serving while that link misbehaves?

CMS AAA is a wide-area federation: a site data node registers UP to a regional
redirector over a link it does not control, then keeps that registration alive
with heartbeats for months.  Every existing CMS suite here drives the node over
loopback, where the link is perfect — so the two failure modes an AAA site
actually hits were untested:

  * the JOIN itself crossing an impaired link (latency, jitter, tiny segments,
    reordering) — does the LOGIN frame survive segmentation, does the node
    settle at all;
  * the link going bad AFTER the join (silence, refusal, mid-stream sever,
    corruption) — does the node notice, back off without busy-spinning, rejoin
    when the link heals, and above all KEEP SERVING DATA while out of the mesh.

Topology (all loopback, unprivileged, no root, no netem):

    raw kXR client ─► BriX node :{PORT}          (data plane — must stay up)
                          │ upward CMS leg
                          ▼
                   brix-fault-proxy  ──►  ManagerPeer  (AAA redirector stand-in,
                   (the impaired WAN)     counts LOGIN/LOAD frames)
                          ▲
                     ctl port: live toxics (latency/chunk/lossy/hang/block/...)

    scrape ─► BriX node :{METRICS_PORT}/metrics  (federation-join counters)

The oracles are the phase-98 join counters — `brix_cms_logins_total`,
`brix_cms_connect_failures_total` and the `brix_cms_registered_links` gauge —
cross-checked against what the redirector stand-in actually received, so a
counter that lies about registration cannot pass.

House 3-test ritual, across the classes below:
  SUCCESS       — joins and heartbeats through latency/jitter/segmentation;
  ERROR         — silent, refusing and severing redirectors are all survived,
                  with bounded retries and a clean rejoin when the link heals;
  SECURITY/NEG  — a corrupting/oversized-framing redirector on the far side of
                  the link never crashes the node or wedges its data plane.

Run:
    PYTHONPATH=tests pytest tests/test_cms_aaa_join_noise.py -v
"""

import os
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from ephemeral_port import free_port
from server_registry import NginxInstanceSpec
from settings import HOST
from test_cms_resilience import (
    CMS_RR_LOAD,
    CMS_RR_LOGIN,
    ManagerPeer,
    _build_frame,
)

# Every test here waits out at least one real reconnect/backoff cycle against a
# deliberately broken link, so the 30s house default is far too tight.
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-aaa-node"),
              pytest.mark.timeout(180)]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAULT_PROXY = os.path.join(REPO, "client", "bin", "brix-fault-proxy")

# The node's heartbeat is 1s and its read deadline 3s (nginx_cms_aaa_node.conf),
# so every wait below is a generous multiple of those, never a bare sleep.
JOIN_TIMEOUT = 25.0
REJOIN_TIMEOUT = 30.0


# --------------------------------------------------------------------------- #
# Link + node harness                                                          #
# --------------------------------------------------------------------------- #

class ImpairedLink:
    """A brix-fault-proxy standing in for the WAN between node and redirector.

    Toxics are applied live over the control port, so one node instance can be
    walked through join → degradation → rejoin without a restart.  ``down()``
    /``up()`` model the harder outage — nothing listening at all, i.e. the
    ECONNREFUSED a site sees when its redirector or the path to it is gone —
    which the ``block`` lever deliberately does NOT reproduce (that one accepts
    and then closes, a different and separately-tested failure).
    """

    def __init__(self, target_port):
        self.target_port = target_port
        self.listen = free_port()
        self.control = free_port()
        self.proc = None
        self.up()

    def up(self):
        """(Re)start the proxy on the same listen port the node is configured for."""
        if self.proc is not None:
            return
        self.proc = subprocess.Popen(
            [FAULT_PROXY,
             "--listen", str(self.listen),
             "--target", f"{HOST}:{self.target_port}",
             "--control", str(self.control),
             "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for port in (self.control, self.listen):
            if not _wait_port(port, timeout=10.0):
                self.close()
                raise RuntimeError(f"fault proxy port {port} never came up")

    def down(self):
        """Take the link away entirely — connects to it now get ECONNREFUSED."""
        self.close()

    def ctl(self, cmd):
        """Send one control command; return the proxy's reply text."""
        with socket.create_connection((HOST, self.control), timeout=3) as s:
            s.sendall((cmd + "\n").encode())
            return s.recv(4096).decode()

    def close(self):
        if self.proc is None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.proc = None


def _wait_port(port, timeout=10.0, host=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host or HOST, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.1)
    return False


class AaaSite:
    """The whole site under test: redirector stand-in, impaired link, node."""

    def __init__(self, peer, link, endpoint):
        self.peer = peer
        self.link = link
        self.endpoint = endpoint
        self.port = endpoint.port
        self.metrics_port = endpoint.extra_ports["METRICS_PORT"]

    # -- oracles ---------------------------------------------------------- #

    def metrics(self):
        """Scrape /metrics off the node; return the raw exposition text."""
        url = f"http://{HOST}:{self.metrics_port}/metrics"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode()

    def counter(self, name):
        """Value of an unlabelled series, or -1 when the series is absent."""
        for line in self.metrics().splitlines():
            if line.startswith(name + " "):
                return int(line.split()[-1])
        return -1

    def wait_counter(self, name, at_least, timeout):
        """Block until `name` reaches `at_least`; return its final value."""
        deadline = time.monotonic() + timeout
        value = self.counter(name)
        while value < at_least and time.monotonic() < deadline:
            time.sleep(0.25)
            value = self.counter(name)
        return value

    def wait_registered(self, registered, timeout):
        """Block until the join gauge reads 1 (registered) or 0 (out)."""
        want = 1 if registered else 0
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.counter("brix_cms_registered_links") == want:
                return True
            time.sleep(0.25)
        return self.counter("brix_cms_registered_links") == want

    def data_plane_alive(self):
        """True when the root:// data plane still completes a kXR handshake.

        This is the "stay up" assertion: whatever the federation leg is doing,
        a physics client reading from this site must be unaffected.
        """
        try:
            with socket.create_connection((HOST, self.port), timeout=5) as s:
                s.sendall(struct.pack(">5i", 0, 0, 0, 4, 2012))
                s.settimeout(5)
                return len(s.recv(64)) >= 8
        except OSError:
            return False

    def worker_crashes(self):
        """Lines in the node's error log that indicate a worker died badly."""
        log = os.path.join(self.endpoint.prefix, "logs", "error.log")
        if not os.path.exists(log):
            return []
        with open(log, "r", errors="replace") as fh:
            body = fh.read()
        return [ln for ln in body.splitlines()
                if "exited on signal" in ln or "SIGSEGV" in ln
                or "Assertion" in ln]


@pytest.fixture
def site(lifecycle):
    """A BriX AAA node joined to a redirector stand-in across an impaired link.

    The peer and the proxy take ephemeral ports (they are test-side mocks, not
    registry servers — the same exemption test_cms_resilience.py's ManagerPeer
    uses); the node's own data and metrics listens come from the fixed ledger.
    """
    if not os.path.exists(FAULT_PROXY):
        pytest.skip("brix-fault-proxy not built (make -C client)")

    peer_port = free_port()
    try:
        peer = ManagerPeer(peer_port)
    except OSError as exc:
        pytest.skip(f"could not bind redirector stand-in: {exc}")

    link = None
    try:
        link = ImpairedLink(peer_port)
        endpoint = lifecycle.start(NginxInstanceSpec(
            name="lc-cms-aaa-node",
            template="nginx_cms_aaa_node.conf",
            protocol="root",
            readiness="tcp",
            template_values={"MANAGER_PORT": link.listen},
            reason="CMS AAA: federation join + stay-up over an impaired WAN link.",
        ))
        yield AaaSite(peer, link, endpoint)
    finally:
        if link is not None:
            link.close()
        peer.close()


# --------------------------------------------------------------------------- #
# SUCCESS — joining the federation across a bad link                           #
# --------------------------------------------------------------------------- #
