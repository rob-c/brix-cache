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

class TestJoinAcrossImpairedWan:

    def test_joins_through_latency_and_jitter(self, site):
        """A WAN-like link (120ms base + up to 80ms jitter) must not stop the
        join: the redirector receives a LOGIN and the node reports itself in."""
        site.link.ctl("latency 120")
        site.link.ctl("jitter 80")

        assert site.peer.wait_connections(1, timeout=JOIN_TIMEOUT), \
            "node never dialed the redirector across the impaired link"
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT), \
            "no LOGIN frame reached the redirector"
        assert site.wait_registered(True, timeout=JOIN_TIMEOUT), \
            "node did not report itself registered after a successful LOGIN"
        assert site.counter("brix_cms_logins_total") >= 1

    def test_login_survives_segmentation_and_reordering(self, site):
        """The LOGIN frame chopped into 4-byte segments, half of them held back
        and delivered late, must still parse as ONE well-formed frame upstream —
        the redirector's parser is the oracle, so a desynced stream would show
        up as a missing or garbage-coded frame, not a passing test."""
        site.link.ctl("chunk 4")
        site.link.ctl("reorder 50 40")

        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT), \
            "segmented + reordered LOGIN never reassembled upstream"
        # Nothing ahead of the LOGIN: a desync would surface as a bogus code
        # parsed out of misaligned bytes before it.
        assert site.peer.frame_codes[0] == CMS_RR_LOGIN, \
            f"stream desynced: first frame code was {site.peer.frame_codes[0]}"

    def test_heartbeats_continue_under_sustained_noise(self, site):
        """Staying joined is the hard part: with the link still degrading every
        chunk, the 1s LOAD heartbeat must keep arriving and the gauge must not
        flap back to 0."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.ctl("latency 60")
        site.link.ctl("chunk 8")

        assert site.peer.wait_frames(CMS_RR_LOAD, 3, timeout=JOIN_TIMEOUT), \
            "heartbeats stopped once the link started degrading every chunk"
        assert site.counter("brix_cms_registered_links") == 1, \
            "node dropped out of the mesh while merely slow (not disconnected)"


# --------------------------------------------------------------------------- #
# ERROR — outage, refusal, sever; and the data plane through all of it         #
# --------------------------------------------------------------------------- #

class TestOutageAndRejoin:

    def test_silent_redirector_drops_gauge_and_keeps_data_plane(self, site):
        """A black-holed redirector (accepts, never answers) must be caught by
        the read deadline: the join gauge falls to 0 — the node knows it is OUT
        of the mesh — while physics clients keep getting served."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.ctl("hang")

        assert site.wait_registered(False, timeout=REJOIN_TIMEOUT), \
            "black-holed redirector never dropped the registration gauge"
        assert site.counter("brix_cms_read_timeouts_total") >= 1, \
            "read-liveness never fired against a silent redirector"
        assert site.data_plane_alive(), \
            "a silent redirector took the data plane down with it"

    def test_refused_link_counts_failures_without_busy_spin(self, site):
        """With nothing listening, the node must keep trying — but on a backoff,
        not a hot loop.  Ten seconds of outage may legitimately produce a
        handful of attempts; hundreds would mean a 0ms-timer footgun burning a
        core at every AAA site in the federation."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.down()

        before = site.counter("brix_cms_connect_failures_total")
        assert site.wait_registered(False, timeout=REJOIN_TIMEOUT), \
            "refused link never dropped the registration gauge"
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            time.sleep(0.5)
        after = site.counter("brix_cms_connect_failures_total")
        attempts = after - before

        assert attempts >= 1, \
            f"a refused dial produced no connect failures ({before} -> {after})"
        assert attempts < 100, \
            f"{attempts} dial attempts in 10s — retry is busy-spinning, not backing off"
        assert site.data_plane_alive(), \
            "a refused federation leg took the data plane down with it"

    def test_accept_then_close_redirector_is_bounded(self, site):
        """A redirector that accepts and instantly closes — an overloaded cmsd,
        or a load balancer with no live backend behind it — is the nastiest
        outage shape, because every cycle looks like a fresh successful login
        and so resets the backoff.  The reconnect rate must still stay bounded
        by the heartbeat interval rather than becoming a hot loop."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.ctl("block")          # accept-then-close, not refuse

        before = site.counter("brix_cms_logins_total")
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            time.sleep(0.5)
        cycles = site.counter("brix_cms_logins_total") - before

        assert cycles < 100, \
            f"{cycles} login cycles in 10s against a closing redirector — hot loop"
        assert site.data_plane_alive(), \
            "an accept-then-close redirector took the data plane down with it"
        assert not site.worker_crashes(), \
            f"worker died against a closing redirector: {site.worker_crashes()}"

    def test_rejoins_when_the_link_heals(self, site):
        """The whole point of the retry loop: when the WAN comes back the site
        must re-register itself without operator action."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        logins_before = site.counter("brix_cms_logins_total")
        site.link.down()
        assert site.wait_registered(False, timeout=REJOIN_TIMEOUT), \
            "link outage never dropped the registration gauge"

        site.link.up()
        assert site.wait_registered(True, timeout=REJOIN_TIMEOUT), \
            "node never rejoined after the link healed"
        assert site.counter("brix_cms_logins_total") > logins_before, \
            "rejoin did not re-issue a LOGIN"
        assert site.peer.wait_frames(CMS_RR_LOGIN, 2, timeout=REJOIN_TIMEOUT), \
            "the redirector never saw the second registration"

    def test_midstream_sever_reregisters(self, site):
        """A link that severs established connections (the classic WAN reset)
        must be recovered from in-place, not just at cold start."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        conns_before = site.peer.connections
        site.link.ctl("lossy 100")

        deadline = time.monotonic() + 15.0
        while site.peer.connections <= conns_before and time.monotonic() < deadline:
            time.sleep(0.25)
        assert site.peer.connections > conns_before, \
            "severing link never forced a reconnect"

        site.link.ctl("clear")
        assert site.wait_registered(True, timeout=REJOIN_TIMEOUT), \
            "node did not re-register after the severing stopped"
        assert not site.worker_crashes(), \
            f"worker died during sever/recover: {site.worker_crashes()}"


# --------------------------------------------------------------------------- #
# SECURITY / NEG — a hostile redirector on the far side of a noisy link        #
# --------------------------------------------------------------------------- #

class TestHostileRedirectorAcrossLink:

    def test_corrupted_downstream_bytes_never_crash_the_node(self, site):
        """Bit-flipped manager→node traffic is indistinguishable from a MITM.
        The node must treat it as garbage — drop/recycle the link — and never
        fault, and must keep serving data throughout."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        site.link.ctl("corrupt 25 down")

        for _ in range(20):
            site.peer.send_to_node(0, CMS_RR_LOAD, 0, b"\x00" * 32)
            time.sleep(0.1)

        assert site.data_plane_alive(), \
            "corrupted federation traffic wedged the data plane"
        assert not site.worker_crashes(), \
            f"worker died on corrupted CMS input: {site.worker_crashes()}"

    def test_oversized_downstream_frame_is_refused_not_buffered(self, site):
        """A redirector claiming a 64KiB frame body (past the 4KiB CMS ceiling)
        must be refused rather than believed: the node recycles the link and
        rejoins, with no unbounded read behind it."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        conns_before = site.peer.connections

        # Header advertises 0xFFFF bytes; only a few follow — a node that
        # trusted dlen would block forever waiting for the rest.
        site.peer.send_to_node(0, CMS_RR_LOAD, 0, b"")
        with site.peer._lock:
            conn = site.peer.conn
        if conn is not None:
            try:
                conn.sendall(struct.pack(">IBBH", 0, CMS_RR_LOAD, 0, 0xFFFF)
                             + b"\x41" * 16)
            except OSError:
                pass

        assert site.peer.wait_connections(conns_before + 1, timeout=REJOIN_TIMEOUT), \
            "node neither refused nor recycled the oversized-framing link"
        assert site.data_plane_alive(), \
            "an oversized CMS frame wedged the data plane"
        assert not site.worker_crashes(), \
            f"worker died on an oversized CMS frame: {site.worker_crashes()}"

    def test_unsolicited_frame_storm_does_not_starve_the_data_plane(self, site):
        """Phase-61 proved a flood cannot wedge the CMS leg itself.  The AAA
        question is the other direction: a redirector spraying frames must not
        starve the worker that physics clients share with it."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)

        for i in range(400):
            site.peer.send_to_node(i, CMS_RR_LOAD, 0, _build_frame(0, 0, 0)[:4])

        assert site.data_plane_alive(), \
            "a redirector frame storm starved the data plane"
        assert not site.worker_crashes(), \
            f"worker died under a redirector frame storm: {site.worker_crashes()}"


# --------------------------------------------------------------------------- #
# NOISE — heavy data-plane activity must not cost the site its registration    #
# --------------------------------------------------------------------------- #

class TestDataPlaneNoise:

    def test_connection_storm_keeps_the_site_registered(self, site):
        """The realistic AAA noise case: a job burst opens hundreds of client
        connections at once.  The single worker that carries them ALSO carries
        the federation leg — if the storm starves it, the redirector times the
        site out and the site silently leaves the mesh.  Heartbeats must keep
        flowing straight through the storm."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)
        loads_before = site.peer.count_frames(CMS_RR_LOAD)

        socks = []
        try:
            for _ in range(200):
                try:
                    s = socket.create_connection((HOST, site.port), timeout=5)
                    s.sendall(struct.pack(">5i", 0, 0, 0, 4, 2012))
                    socks.append(s)
                except OSError:
                    break
            assert len(socks) >= 50, \
                f"only {len(socks)} of 200 storm connections were accepted"

            assert site.peer.wait_frames(CMS_RR_LOAD, loads_before + 3,
                                         timeout=JOIN_TIMEOUT), \
                "heartbeats stalled under a client connection storm — the site " \
                "would be timed out of the federation"
            assert site.counter("brix_cms_registered_links") == 1, \
                "site dropped out of the mesh under data-plane load"
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass

        assert site.data_plane_alive(), \
            "node stopped accepting clients after the storm drained"
        assert not site.worker_crashes(), \
            f"worker died under a connection storm: {site.worker_crashes()}"

    def test_storm_churn_does_not_leak_the_registration(self, site):
        """Repeated connect/abort churn (jobs dying on the batch farm) must
        leave the join gauge at exactly 1 — not incremented per churn cycle,
        which would make the fleet-wide 'sites in the mesh' panel meaningless."""
        assert site.peer.wait_frames(CMS_RR_LOGIN, 1, timeout=JOIN_TIMEOUT)

        for _ in range(150):
            try:
                s = socket.create_connection((HOST, site.port), timeout=3)
                s.sendall(struct.pack(">5i", 0, 0, 0, 4, 2012))
                s.close()          # abort without a graceful close
            except OSError:
                pass

        assert site.wait_registered(True, timeout=JOIN_TIMEOUT), \
            "connection churn cost the site its registration"
        assert site.counter("brix_cms_registered_links") == 1, \
            "registration gauge drifted above 1 — the login/teardown pair leaks"
