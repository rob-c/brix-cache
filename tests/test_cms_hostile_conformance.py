"""
CMS hostile-network conformance — brix as a CMSD MITM between a site cluster
and a remote cluster over an untrusted link.

The design goal these tests defend: brix must stay ROCK SOLID with a hostile
peer on EITHER leg, and — the headline property — abuse on one leg must never
stall the other.  A misbehaving remote manager must not be able to wedge the
downward service to site data nodes, and a flooding/garbage-spewing site node
must not be able to stall the upward manager connection.  Where stock
cmsd<->cmsd would black-hole or head-of-line-block, brix fails closed and keeps
serving.

Both framing legs are the same state machine (recv.c / server_recv.c:
8-byte header {u32 sid, u8 code, u8 mod, u16 dlen}, dlen payload, MAX_FRAME
4096, 64 frames/wakeup fairness yield), so the adversarial cases are exercised
against both the accept (server) leg and the dial-out (node/manager) leg.

Every assertion targets behaviour verified in the source:
  * oversized dlen (dlen+8 > 4096)  -> WARN + close   (server_recv.c / recv.c)
  * unknown / in-frame-garbage opcode -> dropped, connection KEPT
  * malformed Pup rrdata            -> parse returns -1 -> op dropped
  * kYR_state with ".." / no local export -> no kYR_have (kernel-confined)
  * kYR_ping                        -> kYR_pong, needs no login (pure liveness)
  * relay miss with relay on        -> entry parked, leg returns immediately
  * relay table full (>64)          -> add() returns 0, silent (fail closed)
Liveness oracle: server leg answers a header-only kYR_ping with kYR_pong with
no login required (cms_srv_frame_ping), so "is the server still serving?" is a
fresh-socket PING/PONG; the node leg proves liveness by answering the manager's
PING and by re-LOGIN on a forced reconnect.
"""

import os
import socket
import threading
import time

import pytest

from ephemeral_port import free_port  # noqa: F401  (re-exported for builders)
from server_registry import NginxInstanceSpec
from server_launcher import LifecycleHarness
from ephemeral_port import free_port

# Reuse the fully-built wire helpers/constants/peer from the conformance suite
# rather than re-deriving the byte layouts (single source of wire truth).
from test_cms_wire_pup_conformance import (
    H,
    CMS_RR_LOGIN,
    CMS_RR_PING,
    CMS_RR_PONG,
    CMS_RR_HAVE,
    CMS_RR_STATE,
    CMS_RR_LOAD,
    CMS_RR_MKDIR,
    CMS_RR_DISC,
    CMS_RR_STATFS,
    CMS_RR_STATUS,
    CMS_RR_USAGE,
    CMS_RR_AVAIL,
    CMS_RR_STATS,
    CMS_RR_UPDATE,
    CMS_RR_GONE,
    CMS_RR_SPACE,
    CMS_RSP_DATA,
    CMS_RSP_ERROR,
    CMS_STATS_SIZE,
    CMS_STATS_BUFSZ,
    CMS_ST_SUSPEND,
    CMS_ST_RESUME,
    CMS_ST_RESET,
    CMS_MOD_RAW,
    CMS_HAVE_ONLINE,
    CMS_MODE_SERVER,
    CMS_MAX_DLEN,
    NODE_DATA_PORT,
    CmsManagerPeer,
    _build_frame,
    _recv_code,
    _recv_exact,
    _node_login_dialog,
    _minimal_login_payload,
    _login_payload_with_mode,
    _fwd_a_payload,
    _statfs_wfree,
    _start_peered_node,
)

# rrCodes the conformance module does not re-export (verified against
# src/net/cms/cms_internal.h): the forwarded-namespace + redirect + auth
# opcodes exercised only by the hostile/MITM cases below.
CMS_RR_CHMOD   = 1
CMS_RR_MKPATH  = 4
CMS_RR_MV      = 5
CMS_RR_PREPADD = 6
CMS_RR_PREPDEL = 7
CMS_RR_RM      = 8
CMS_RR_RMDIR   = 9
CMS_RR_SELECT  = 10
CMS_RR_TRUNC   = 23
CMS_RR_TRY     = 24
CMS_RR_XAUTH   = 27
CMS_RR_CNS     = 40
CMS_ST_STAGE   = 0x01
CMS_ST_NOSTAGE = 0x02
CMS_PT_SHORT   = 0x80          # TLV tag: 0x80 + BE uint16
CMS_PT_INT     = 0xA0          # TLV tag: 0xA0 + BE uint32
BRIX_SRV_MAX_PATHS = 1024      # src/net/manager/registry.h — ctx->paths buffer


def _load_payload(free_mb, cpu=b"\x00" * 6):
    """A wire-shaped kYR_load payload: PT_SHORT count(6) + 6 CPU bytes +
    PT_INT free_mb (matches src/net/cms/send.c and cms_srv_parse_load_*)."""
    return (bytes([CMS_PT_SHORT, 0x00, 0x06]) + cpu
            + bytes([CMS_PT_INT]) + int(free_mb & 0xFFFFFFFF).to_bytes(4, "big"))

_HDIR = os.path.join(os.environ["TMPDIR"], "xrd_cms_hostile")
os.makedirs(_HDIR, exist_ok=True)

# A distinct streamid space so captured frames are unambiguous in a shared peer.
_SID = 0x40C50000


# ---------------------------------------------------------------------------
# Liveness / reconnect oracles
# ---------------------------------------------------------------------------

def _server_alive(port, timeout=6.0):
    """Fresh connection -> header-only kYR_ping -> expect kYR_pong.  Needs no
    login (cms_srv_frame_ping is pure liveness), so this proves the server is
    still accepting and servicing *new* clients after an attack on another
    connection."""
    sock = socket.create_connection((H, port), timeout=6)
    sock.settimeout(timeout)
    try:
        sock.sendall(_build_frame(_SID | 0x0F, CMS_RR_PING, 0))
        return _recv_code(sock, CMS_RR_PONG, timeout=timeout) is not None
    finally:
        sock.close()


def _node_alive(peer, timeout=8.0):
    """Manager -> kYR_ping down the upward leg -> node must answer kYR_pong."""
    base = peer.count_frames(CMS_RR_PONG)
    peer.send_to_node(_SID | 0x0E, CMS_RR_PING, 0)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if peer.count_frames(CMS_RR_PONG) > base:
            return True
        time.sleep(0.1)
    return False


def _wait_relogin(peer, baseline, timeout=25.0):
    """brix sends a fresh kYR_login on every (re)connect — a LOGIN count above
    the baseline proves it tore the socket down and reconnected."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if peer.count_frames(CMS_RR_LOGIN) > baseline:
            return True
        time.sleep(0.2)
    return False


# ---------------------------------------------------------------------------
# Fixtures — dedicated instances so adversarial traffic never contends on the
# ports the well-behaved conformance suite uses.
# ---------------------------------------------------------------------------

@pytest.fixture
def hostile_server(lifecycle):
    """A brix CMS *server* (accept leg) we hammer with a hostile site node."""
    return lifecycle.start(NginxInstanceSpec(
        name="lc-cms-hostile-server",
        template="nginx_cms_wire_server.conf",
        protocol="root",
        readiness="tcp",
        reason="CMS hostile-network conformance: server-leg frame parser.",
    ))


@pytest.fixture
def hostile_node(lifecycle):
    """A brix data node dialing OUT to a mock manager peer that plays the role
    of a hostile remote CMSD."""
    data_dir = os.path.join(_HDIR, "node_data")
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(data_dir, "have_me.bin"), "wb") as f:
        f.write(b"resident-bytes" * 16)
    peer = _start_peered_node(
        lifecycle, "lc-cms-hostile-node", "nginx_cms_wire_node.conf", {},
        "CMS hostile-network conformance: node vs a hostile manager.", data_dir)
    try:
        yield peer
    finally:
        peer.close()


@pytest.fixture
def hostile_super(lifecycle):
    """A supervisor tier (upward manager leg + downward accept leg + relay on):
    the MITM shape.  The peer is the (hostile) parent manager; children dial the
    supervisor's own listen port."""
    peer = _start_peered_node(
        lifecycle, "lc-cms-hostile-super", "nginx_cms_wire_super.conf",
        {"STATE_RELAY": "on"},
        "CMS hostile-network conformance: MITM cross-leg isolation.",
        os.path.join(_HDIR, "super_data"))
    try:
        yield peer
    finally:
        peer.close()


# ===========================================================================
# Server (accept) leg — a hostile site data node must never take the server
# down for well-behaved peers.
# ===========================================================================

class TestServerLegHostileFraming:

    def test_garbage_flood_does_not_disturb_other_clients(self, hostile_server):
        """A connection spewing all-0xFF bytes (header decodes to dlen 0xFFFF,
        far over MAX_FRAME) is dropped; a *separate* fresh client is served."""
        junk = socket.create_connection((H, hostile_server.port), timeout=6)
        try:
            junk.sendall(b"\xff" * 8192)
            time.sleep(0.3)
            assert _server_alive(hostile_server.port), \
                "a garbage-flooding peer took the server down for others"
        finally:
            junk.close()

    def test_oversized_frame_closes_only_the_offender(self, hostile_server):
        """A well-formed header claiming an oversized payload (dlen 5000, so
        5008 > 4096) closes the offending connection but not the server."""
        bad = socket.create_connection((H, hostile_server.port), timeout=6)
        bad.settimeout(6)
        try:
            bad.sendall(_build_frame(0, CMS_RR_LOGIN, 0, b"\x00" * 5000))
            # The offender's own connection must be closed (recv -> EOF).
            assert _recv_exact(bad, 1) is None, \
                "server did not close the oversized-frame connection"
            assert _server_alive(hostile_server.port), \
                "oversized frame from one peer disturbed the server"
        finally:
            bad.close()

    def test_max_boundary_frame_accepted(self, hostile_server):
        """The dlen boundary: dlen 4088 (total 4096 == MAX_FRAME) is ACCEPTED
        (the reject test is dlen+8 > 4096).  An unknown opcode at exactly the
        boundary is read in full and dropped, and the connection stays open."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            frame = _build_frame(0, 0x7E, 0, b"\x00" * CMS_MAX_DLEN)
            assert len(frame) == 4096
            sock.sendall(frame)
            # Same connection must still answer liveness -> boundary accepted.
            sock.sendall(_build_frame(_SID | 1, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "server closed on a legal max-size (4088) frame"
        finally:
            sock.close()

    def test_unknown_opcode_keeps_connection(self, hostile_server):
        """An unknown opcode is dropped, not fatal — cmsd tolerates frames it
        does not act on.  The same connection stays serviceable."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(0, 0x7F, 0))
            sock.sendall(_build_frame(_SID | 2, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "an unknown opcode killed the connection"
        finally:
            sock.close()

    def test_half_header_then_eof_isolated(self, hostile_server):
        """A peer that sends a partial header then hangs up (EOF mid-frame) is
        cleaned up without wedging the accumulator for anyone else."""
        stub = socket.create_connection((H, hostile_server.port), timeout=6)
        stub.sendall(b"\x00\x00\x00")   # 3 of 8 header bytes, then close
        stub.close()
        time.sleep(0.2)
        assert _server_alive(hostile_server.port), \
            "a truncated-header hangup disturbed the server"

    def test_pre_login_ops_ignored_but_alive(self, hostile_server):
        """Security-neg: LOAD/AVAIL/STATFS/STATUS/USAGE before LOGIN are all
        gated (no reply, no registration side-effect), yet the connection is
        kept — proven by a header-only PING still drawing a PONG."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            for code in (CMS_RR_LOAD, CMS_RR_AVAIL, CMS_RR_STATFS,
                         CMS_RR_STATUS, CMS_RR_USAGE):
                sock.sendall(_build_frame(0, code, 0, b"\x00\x00"))
            # None of the above may have produced a reply frame ...
            assert _recv_code(sock, CMS_RR_PONG, timeout=1.0) is None
            # ... but PING (pure liveness, no login) still answers.
            sock.sendall(_build_frame(_SID | 3, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "pre-login gated ops closed the connection"
        finally:
            sock.close()

    def test_zero_dlen_state_dropped(self, hostile_server):
        """A logged-in node sending kYR_state with an empty payload hits the
        `payload_len == 0` guard and is dropped; the connection survives and
        still answers STATFS."""
        sock = _node_login_dialog(hostile_server.port,
                                  _minimal_login_payload(NODE_DATA_PORT))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(0, CMS_RR_STATE, CMS_MOD_RAW))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 4) == 5000, \
                "empty kYR_state disturbed a logged-in connection"
        finally:
            sock.close()

    def test_second_login_on_same_connection(self, hostile_server):
        """Esoteric state machine: a duplicate LOGIN on an already-registered
        connection must re-register without crashing or dropping the peer.  The
        connection stays alive and keeps answering STATFS (the aggregate free
        space reflects the live registration(s), never a hang or a zero)."""
        sock = _node_login_dialog(hostile_server.port,
                                  _minimal_login_payload(NODE_DATA_PORT))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(0, CMS_RR_LOGIN, 0,
                                      _minimal_login_payload(NODE_DATA_PORT + 1)))
            time.sleep(0.3)
            assert _statfs_wfree(sock, _SID | 5) >= 5000, \
                "a second LOGIN wedged the connection"
        finally:
            sock.close()

    def test_ping_flood_survives_fairness_yield(self, hostile_server):
        """A logged-in node firing 200 kYR_pings in one burst crosses the
        64-frames/wakeup fairness yield several times; every frame is serviced
        (a healthy share of pongs come back) and the connection remains fully
        serviceable — STATFS still answers its unmutated 5000."""
        sock = _node_login_dialog(hostile_server.port,
                                  _minimal_login_payload(NODE_DATA_PORT))
        sock.settimeout(8)
        try:
            time.sleep(0.3)
            burst = b"".join(_build_frame(_SID | (i & 0xFF), CMS_RR_PING, 0)
                             for i in range(200))
            sock.sendall(burst)
            pongs = 0
            deadline = time.time() + 8.0
            while time.time() < deadline and pongs < 200:
                if _recv_code(sock, CMS_RR_PONG, timeout=0.5) is None:
                    break
                pongs += 1
            assert pongs >= 50, \
                f"ping flood dropped frames past the fairness yield: {pongs}"
            assert _statfs_wfree(sock, _SID | 6) == 5000, \
                "a 200-frame ping flood stalled or disturbed the connection"
        finally:
            sock.close()

    def test_connection_churn_then_serve(self, hostile_server):
        """Rapid connect/immediately-close churn (no leak, no cap wedge): after
        40 half-open churns the server still serves a fresh client."""
        for _ in range(40):
            try:
                c = socket.create_connection((H, hostile_server.port),
                                             timeout=4)
                c.close()
            except OSError:
                pass
        assert _server_alive(hostile_server.port), \
            "connection churn left the server unable to serve"


# ===========================================================================
# Node (dial-out) leg — a hostile REMOTE manager must not be able to hang the
# node; framing violations force a clean reconnect, in-frame garbage is
# tolerated.
# ===========================================================================

class TestNodeLegHostileManager:

    def test_oversized_frame_forces_clean_reconnect(self, hostile_node):
        """A manager frame with dlen 5000 (5008 > 4096) makes the node tear the
        socket down and reconnect (a fresh LOGIN), rather than mis-framing."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(0, CMS_RR_PING, 0, b"\x00" * 5000)
        assert _wait_relogin(hostile_node, base), \
            "node did not reconnect after an oversized manager frame"

    def test_manager_disc_forces_reconnect(self, hostile_node):
        """kYR_disc from the manager tears the node connection down and it
        reconnects with backoff (never sits on a dead socket)."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(0, CMS_RR_DISC, 0)
        assert _wait_relogin(hostile_node, base), \
            "node did not reconnect after a manager DISC"

    def test_in_frame_garbage_opcode_tolerated(self, hostile_node):
        """A well-sized frame with an unknown opcode is dropped WITHOUT a
        reconnect — the node tolerates junk it does not act on and stays up."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for code in (0x7E, 0x7F, 0x5A):
            hostile_node.send_to_node(_SID, code, 0, b"garbage-payload")
        time.sleep(0.5)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "an in-frame unknown opcode wrongly forced a reconnect"
        assert _node_alive(hostile_node), \
            "node stopped answering after in-frame garbage"

    def test_manager_ping_gets_pong(self, hostile_node):
        """Symmetric liveness: the manager can probe the node with kYR_ping and
        gets a kYR_pong (the node never black-holes a liveness check)."""
        assert _node_alive(hostile_node), "node did not answer a manager PING"

    def test_malformed_forwarded_op_dropped(self, hostile_node):
        """A forwarded kYR_mkdir whose Pup string claims more bytes than remain
        (rrdata parse -> -1) is dropped: no crash, no reconnect, node alive."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        # Pup string length 100 but only 2 bytes follow -> overrun -> -1.
        hostile_node.send_to_node(_SID, CMS_RR_MKDIR, 0,
                                  b"\x00\x64" + b"ab")
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "a malformed forwarded op forced a reconnect"
        assert _node_alive(hostile_node), \
            "node stopped answering after a malformed forwarded op"

    def test_state_traversal_yields_no_have(self, hostile_node):
        """Security-neg: a malicious manager asking kYR_state for a ".."
        escape path must draw NO kYR_have (kernel-confined existence probe) and
        must not disturb the connection."""
        base_have = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"/../../../../etc/passwd\x00")
        time.sleep(0.6)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base_have, \
            "node leaked kYR_have for a traversal path"
        assert _node_alive(hostile_node), \
            "a traversal state probe disturbed the node"

    def test_ping_flood_stays_connected(self, hostile_node):
        """200 back-to-back kYR_pings cross the node's 64/wakeup fairness yield;
        the node answers a healthy share of pongs and never reconnects."""
        base_login = hostile_node.count_frames(CMS_RR_LOGIN)
        base_pong = hostile_node.count_frames(CMS_RR_PONG)
        for i in range(200):
            hostile_node.send_to_node(_SID | (i & 0xFF), CMS_RR_PING, 0)
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if hostile_node.count_frames(CMS_RR_PONG) - base_pong >= 50:
                break
            time.sleep(0.1)
        assert hostile_node.count_frames(CMS_RR_PONG) - base_pong >= 50, \
            "node did not keep answering under a ping flood"
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base_login, \
            "a ping flood forced a reconnect"


# ===========================================================================
# MITM cross-leg isolation — the headline property.  Abuse on one leg must not
# stall the other; the relay fails closed rather than hanging either side.
# ===========================================================================

class TestMitmCrossLegIsolation:

    CHILD_DPORT = NODE_DATA_PORT + 20

    def _login_child(self, peer, paths=b"r /data"):
        sock = _node_login_dialog(
            peer.node_port,
            _login_payload_with_mode(self.CHILD_DPORT, CMS_MODE_SERVER,
                                     paths=paths))
        time.sleep(0.4)
        return sock

    def test_outstanding_relay_does_not_block_upward_ping(self, hostile_super):
        """A relayed probe that a (slow/hostile) child never answers leaves the
        relay entry parked — it must NOT head-of-line-block the upward leg: a
        following manager kYR_ping is answered promptly."""
        child = self._login_child(hostile_super)
        try:
            hostile_super.send_to_node(_SID | 0xA1, CMS_RR_STATE, CMS_MOD_RAW,
                                       b"/elsewhere/never-answered.bin\x00")
            # The probe reached the child (relay happened) ...
            assert _recv_code(child, CMS_RR_STATE, timeout=8) is not None, \
                "supervisor did not relay the miss to its child"
            # ... and with the entry still parked, the upward leg is responsive.
            assert _node_alive(hostile_super), \
                "an outstanding relay blocked the upward manager leg"
        finally:
            child.close()

    def test_hostile_child_cannot_wedge_upward_leg(self, hostile_super):
        """A site child that floods the downward accept leg with an oversized
        frame is dropped there; the upward manager leg stays fully responsive
        (no cross-leg contamination)."""
        child = self._login_child(hostile_super)
        try:
            child.sendall(_build_frame(0, CMS_RR_STATE, CMS_MOD_RAW,
                                       b"\x00" * 5000))
            time.sleep(0.3)
            assert _node_alive(hostile_super), \
                "a hostile child wedged the upward manager leg"
        finally:
            child.close()

    def test_relay_table_saturation_fails_closed(self, hostile_super):
        """70 distinct registry-miss probes (> RELAY_CAP 64) with no child to
        answer: the relay table saturates, add() returns 0 for the overflow and
        the leg stays silent — no crash, no hang.  The upward leg is still
        healthy afterward and no reconnect was triggered."""
        base_login = hostile_super.count_frames(CMS_RR_LOGIN)
        for i in range(70):
            path = "/miss/p{:03d}.bin\x00".format(i).encode()
            hostile_super.send_to_node(_SID | 0x300 | i, CMS_RR_STATE,
                                       CMS_MOD_RAW, path)
        time.sleep(0.5)
        assert hostile_super.count_frames(CMS_RR_LOGIN) == base_login, \
            "relay-table saturation crashed/reconnected the upward leg"
        assert _node_alive(hostile_super), \
            "relay-table saturation left the upward leg unresponsive"

    def test_child_registration_survives_relay_pressure(self, hostile_super):
        """The downward accept leg keeps admitting new site nodes even while
        the upward leg carries parked relay entries — the two planes are
        independent."""
        # Park a relay entry from the manager side.
        hostile_super.send_to_node(_SID | 0xB1, CMS_RR_STATE, CMS_MOD_RAW,
                                   b"/elsewhere/pending.bin\x00")
        # A fresh child can still log in and be served on the downward leg.
        child = self._login_child(hostile_super, paths=b"r /data")
        try:
            assert _statfs_wfree(child, _SID | 0xB2) == 5000, \
                "downward child service stalled under upward relay pressure"
        finally:
            child.close()

    @pytest.mark.slow
    def test_stale_relay_answer_after_ttl_refused(self, hostile_super):
        """A child that answers a relayed probe AFTER the 5s relay TTL has
        expired is refused — the stale entry is gone, so no upward kYR_have is
        forged, and the supervisor stays healthy."""
        child = self._login_child(hostile_super)
        try:
            path = b"/elsewhere/slow.bin"
            hostile_super.send_to_node(_SID | 0xC1, CMS_RR_STATE, CMS_MOD_RAW,
                                       path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8)
            assert fr is not None, "probe was not relayed to the child"
            down_sid = fr[0]
            base_have = hostile_super.count_frames(CMS_RR_HAVE)
            time.sleep(6.0)   # exceed BRIX_CMS_STATE_RELAY_TTL_MS (5000)
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       path + b"\x00"))
            time.sleep(1.0)
            assert hostile_super.count_frames(CMS_RR_HAVE) == base_have, \
                "a post-TTL child answer forged an upward kYR_have"
            assert _node_alive(hostile_super), \
                "the supervisor was unhealthy after a stale relay answer"
        finally:
            child.close()


def _login_server(port, dport=NODE_DATA_PORT, paths=b"r /"):
    """Open a logged-in node connection into a brix CMS *server* leg (so the
    per-op handlers actually execute rather than hitting the pre-login gate)."""
    sock = _node_login_dialog(
        port, _login_payload_with_mode(dport, CMS_MODE_SERVER, paths=paths))
    sock.settimeout(6)
    time.sleep(0.3)
    return sock


# ===========================================================================
# Server (accept) leg — esoteric ops a hostile site node can throw at the
# manager: xauth / stats / gone / status / usage / error / foreign-have.  None
# may crash, wedge, or take the server down for other peers.
# ===========================================================================

class TestServerLegEsotericOps:

    def test_xauth_out_of_sequence_closes_offender(self, hostile_server):
        """kYR_xauth when no sss challenge is outstanding is an auth violation:
        the offending connection is closed (do_Space parity), and the server
        keeps serving everyone else."""
        bad = socket.create_connection((H, hostile_server.port), timeout=6)
        bad.settimeout(6)
        try:
            bad.sendall(_build_frame(0, CMS_RR_XAUTH, 0, b"\x00" * 8))
            assert _recv_exact(bad, 1) is None, \
                "out-of-sequence xauth did not close the connection"
            assert _server_alive(hostile_server.port), \
                "an xauth violation disturbed the server for others"
        finally:
            bad.close()

    def test_stats_pre_login_ignored(self, hostile_server):
        """kYR_stats before login is gated (no stats doc leaks pre-auth), and
        the connection survives to answer a header-only ping."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(0, CMS_RR_STATS, 0))
            assert _recv_code(sock, CMS_RSP_DATA, timeout=1.0) is None, \
                "server leaked a stats doc pre-login"
            sock.sendall(_build_frame(_SID | 0x20, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
        finally:
            sock.close()

    def test_stats_full_form_returns_role_doc(self, hostile_server):
        """A logged-in kYR_stats (no kYR_size) returns [4B statsz][Cluster.Stats
        XML]: statsz is the stock advertisement and the doc carries a role."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x21, CMS_RR_STATS, 0))
            fr = _recv_code(sock, CMS_RSP_DATA, timeout=6)
            assert fr is not None, "no stats reply to a full-form kYR_stats"
            payload = fr[3]
            statsz = int.from_bytes(payload[:4], "big")
            assert statsz == CMS_STATS_BUFSZ, \
                f"statsz prefix must be {CMS_STATS_BUFSZ}, got {statsz}"
            assert b"<role>" in payload[4:], \
                "stats doc missing the role element"
        finally:
            sock.close()

    def test_stats_size_form_flood(self, hostile_server):
        """A burst of kYR_size stats queries each returns the 4-byte statsz and
        never wedges the connection."""
        sock = _login_server(hostile_server.port)
        try:
            for i in range(40):
                sock.sendall(_build_frame(_SID | i, CMS_RR_STATS,
                                          CMS_STATS_SIZE))
            got = 0
            for _ in range(40):
                fr = _recv_code(sock, CMS_RSP_DATA, timeout=4)
                if fr is None:
                    break
                assert int.from_bytes(fr[3][:4], "big") == CMS_STATS_BUFSZ
                got += 1
            assert got >= 20, f"stats size-form flood dropped replies: {got}"
        finally:
            sock.close()

    def test_gone_for_unheld_path_is_noop(self, hostile_server):
        """kYR_gone for a path the node never registered is a harmless no-op —
        the registration (and its space) is untouched."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_GONE, 0, b"/never/held/here"))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x22) == 5000, \
                "kYR_gone for an unheld path disturbed the registration"
        finally:
            sock.close()

    def test_gone_long_path_bounded(self, hostile_server):
        """kYR_gone with a long (but in-frame) path is bounded-copied without
        overflow; the connection stays serviceable."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_GONE, 0, b"/" + b"a" * 3000))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x23) == 5000, \
                "an oversized kYR_gone path disturbed the connection"
        finally:
            sock.close()

    def test_status_suspend_reset_resume_survives(self, hostile_server):
        """A node driving its own kYR_status through suspend→reset→resume must
        never crash or drop the manager connection (registry mutations are
        node-scoped); liveness is intact throughout."""
        sock = _login_server(hostile_server.port)
        try:
            for mod in (CMS_ST_SUSPEND, CMS_ST_RESET, CMS_ST_RESUME):
                sock.sendall(_build_frame(0, CMS_RR_STATUS, mod))
                time.sleep(0.1)
            sock.sendall(_build_frame(_SID | 0x24, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a suspend/reset/resume sequence killed the connection"
        finally:
            sock.close()

    def test_status_garbage_modifier_is_noop(self, hostile_server):
        """An unknown kYR_status modifier is a no-op (stock parity), not a
        crash; the connection keeps working."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_STATUS, 0x40))
            time.sleep(0.1)
            assert _statfs_wfree(sock, _SID | 0x25) == 5000
        finally:
            sock.close()

    def test_usage_query_answered_with_load(self, hostile_server):
        """kYR_usage from a logged-in node is answered with a kYR_load vector
        echoing the streamid (do_Usage parity)."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x26, CMS_RR_USAGE, 0))
            fr = _recv_code(sock, CMS_RR_LOAD, timeout=6)
            assert fr is not None, "kYR_usage drew no kYR_load reply"
            assert fr[0] == (_SID | 0x26), "usage reply must echo the streamid"
        finally:
            sock.close()

    def test_error_frame_oversized_text_bounded(self, hostile_server):
        """A kYR_error (fan-out reply fold) with a huge peer-controlled text is
        bounded before it can reach any client reply; no overflow, conn alive."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x27, CMS_RSP_ERROR, 0,
                                      b"\x00\x00\x00\x16" + b"Z" * 2000))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x28) == 5000, \
                "an oversized kYR_error text disturbed the connection"
        finally:
            sock.close()

    def test_error_frame_short_payload_safe(self, hostile_server):
        """A kYR_error shorter than the 4-byte ecode is handled safely (ecode
        defaults to 0, empty text), never a short read."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x29, CMS_RSP_ERROR, 0, b"\x01\x02"))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x2A) == 5000
        finally:
            sock.close()

    def test_foreign_have_dropped(self, hostile_server):
        """Security-neg: a node exporting only /data that asserts kYR_have for a
        path OUTSIDE its exports (no relay entry in play) is dropped by the
        paths-cover gate without disturbing the connection."""
        sock = _login_server(hostile_server.port, paths=b"r /data")
        try:
            sock.sendall(_build_frame(_SID | 0x2B, CMS_RR_HAVE,
                                      CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                      b"/etc/passwd\x00"))
            time.sleep(0.2)
            sock.sendall(_build_frame(_SID | 0x2C, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a foreign kYR_have disturbed the connection"
        finally:
            sock.close()

    def test_unsolicited_pong_ignored(self, hostile_server):
        """An unsolicited kYR_pong (we never pinged the node) is logged and
        ignored, not mistaken for a request; connection stays alive."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_PONG, 0))
            time.sleep(0.1)
            assert _statfs_wfree(sock, _SID | 0x2D) == 5000
        finally:
            sock.close()


# ===========================================================================
# Node (dial-out) leg — esoteric ops a hostile REMOTE manager can throw at the
# node, including the MITM-critical redirect-injection vector.
# ===========================================================================

class TestNodeLegEsotericManager:

    def test_unsolicited_select_injection_ignored(self, hostile_node):
        """MITM redirect-injection: a manager naming a redirect host:port for a
        streamid with NO pending locate wakes nothing — the node cannot be
        steered to an attacker-chosen server for a request it never made."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(_SID | 0x30, CMS_RR_SELECT, 0,
                                  b"evil.attacker.example\x00"
                                  + (1094).to_bytes(2, "big"))
        time.sleep(0.3)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "an injected redirect disturbed the node connection"
        assert _node_alive(hostile_node)

    def test_unsolicited_try_injection_ignored(self, hostile_node):
        """Same defense for kYR_try (ordered redirect list)."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(_SID | 0x31, CMS_RR_TRY, 0,
                                  b"evil.attacker.example\x00"
                                  + (2094).to_bytes(2, "big"))
        time.sleep(0.3)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base
        assert _node_alive(hostile_node)

    def test_truncated_redirect_ignored(self, hostile_node):
        """A redirect payload too short to carry host+NUL+port (< 3 bytes) is
        silently ignored — no over-read."""
        hostile_node.send_to_node(_SID | 0x32, CMS_RR_SELECT, 0, b"ab")
        assert _node_alive(hostile_node)

    def test_redirect_port_overrun_ignored(self, hostile_node):
        """A redirect whose port bytes would fall past the received payload
        (host+NUL present, port missing) is rejected, not read out of bounds."""
        hostile_node.send_to_node(_SID | 0x33, CMS_RR_SELECT, 0, b"host\x00")
        assert _node_alive(hostile_node)

    def test_manager_suspend_resume_survives(self, hostile_node):
        """A manager toggling the node's login gate via kYR_status suspend then
        resume must not disturb liveness — the node keeps answering pings."""
        hostile_node.send_to_node(_SID | 0x34, CMS_RR_STATUS, CMS_ST_SUSPEND)
        assert _node_alive(hostile_node), "node died on a manager suspend"
        hostile_node.send_to_node(_SID | 0x35, CMS_RR_STATUS, CMS_ST_RESUME)
        assert _node_alive(hostile_node), "node died on a manager resume"

    def test_manager_status_garbage_modifier_noop(self, hostile_node):
        """An unknown kYR_status modifier from the manager is a no-op; node
        stays alive and connected."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(_SID | 0x36, CMS_RR_STATUS, 0x40)
        time.sleep(0.2)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base
        assert _node_alive(hostile_node)

    def test_manager_space_query_answered(self, hostile_node):
        """kYR_space is answered with a kYR_avail reply echoing the streamid."""
        hostile_node.send_to_node(_SID | 0x37, CMS_RR_SPACE, 0)
        fr = hostile_node.collect_reply(CMS_RR_AVAIL, timeout=6)
        assert fr is not None, "kYR_space drew no kYR_avail reply"
        assert fr[0] == (_SID | 0x37)

    def test_manager_stats_query_answered(self, hostile_node):
        """kYR_stats is answered with a kYR_data stats document."""
        hostile_node.send_to_node(_SID | 0x38, CMS_RR_STATS, 0)
        assert hostile_node.collect_reply(CMS_RSP_DATA, timeout=6) is not None, \
            "kYR_stats drew no kYR_data reply"

    def test_manager_update_answered_with_status(self, hostile_node):
        """kYR_update makes the node resend its state as a kYR_status frame.
        collect_reply baselines at call time, so a login-time status already
        counted does not satisfy this — only the update-driven one does."""
        hostile_node.send_to_node(_SID | 0x39, CMS_RR_UPDATE, 0)
        assert hostile_node.collect_reply(CMS_RR_STATUS, timeout=6) is not None, \
            "kYR_update drew no kYR_status reply"

    def test_malformed_forwarded_ops_dropped(self, hostile_node):
        """Every forwarded namespace opcode fed a truncated Pup payload (a
        string claiming more bytes than remain) is dropped: no crash, no
        reconnect, node still answering."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for op in (CMS_RR_CHMOD, CMS_RR_MKDIR, CMS_RR_MKPATH, CMS_RR_MV,
                   CMS_RR_RM, CMS_RR_RMDIR, CMS_RR_TRUNC):
            hostile_node.send_to_node(_SID | op, op, 0, b"\x00\x64ab")
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "a malformed forwarded op forced a reconnect"
        assert _node_alive(hostile_node)

    def test_forwarded_dir_op_traversal_refused(self, hostile_node):
        """The dir-shaped forwarded ops (mkdir/mkpath/chmod share fwdArgA) with
        a '..' escape path are refused by the kernel-confined open and answered
        kYR_error — nothing is created outside the export root."""
        for op in (CMS_RR_MKDIR, CMS_RR_MKPATH, CMS_RR_CHMOD):
            hostile_node.send_to_node(
                _SID | 0x40 | op, op, 0,
                _fwd_a_payload(b"mgr", b"493", b"/../pwn_%d" % op))
            fr = hostile_node.collect_reply(CMS_RSP_ERROR, timeout=6)
            assert fr is not None, \
                f"forwarded op {op} traversal was not refused with kYR_error"
        assert _node_alive(hostile_node)

    def test_malformed_prepare_ops_dropped(self, hostile_node):
        """kYR_prepadd/kYR_prepdel with malformed rrdata are answered kYR_error
        (EINVAL) and never crash or reconnect the node."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for op in (CMS_RR_PREPADD, CMS_RR_PREPDEL):
            hostile_node.send_to_node(_SID | op, op, 0, b"\x00\x64ab")
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base
        assert _node_alive(hostile_node)


# ===========================================================================
# Wire-level framing hardening (both legs) — fragmentation, resync, streamid
# and modifier fuzzing, and slowloris LOGIN.
# ===========================================================================

class TestWireLevelHardening:

    def test_dribbled_frame_reassembled(self, hostile_server):
        """A kYR_ping delivered one byte at a time (each in its own segment) is
        reassembled across recv() calls and answered — the accumulator never
        mis-frames a fragmented header."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            frame = _build_frame(_SID | 0x50, CMS_RR_PING, 0)
            for b in frame:
                sock.sendall(bytes([b]))
                time.sleep(0.02)
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a dribbled ping frame was not reassembled"
        finally:
            sock.close()

    def test_zero_dlen_unknown_flood(self, hostile_server):
        """200 header-only unknown-opcode frames are each dropped; the
        connection stays serviceable afterward."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(b"".join(_build_frame(i, 0x7F, 0) for i in range(200)))
            sock.sendall(_build_frame(_SID | 0x51, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a zero-dlen unknown flood wedged the connection"
        finally:
            sock.close()

    def test_interleaved_valid_and_garbage_resyncs(self, hostile_server):
        """valid ping → garbage frame → valid ping: the parser drops the junk
        and stays frame-aligned, answering both pings."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(_SID | 0x52, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
            sock.sendall(_build_frame(0, 0x7E, 0, b"junk-in-the-middle"))
            sock.sendall(_build_frame(_SID | 0x53, CMS_RR_PING, 0))
            # A second (header-only, streamid-0 per stock CmsPongRequest) pong
            # only arrives if the parser dropped the junk frame cleanly and
            # stayed byte-aligned on the following ping.
            fr = _recv_code(sock, CMS_RR_PONG, timeout=6)
            assert fr is not None and fr[3] == b"", \
                "parser lost frame alignment after an interleaved junk frame"
        finally:
            sock.close()

    def test_extreme_streamid_accepted(self, hostile_server):
        """A ping with streamid 0xFFFFFFFF is parsed without a signedness /
        truncation bug and answered with a header-only pong.  (Stock cmsd's
        do_Ping replies with a static streamid-0 CmsPongRequest, so the reply
        does NOT echo the ping streamid — the property under test is that the
        extreme unsigned streamid is accepted, not mis-framed.)"""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(0xFFFFFFFF, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=6)
            assert fr is not None and fr[0] == 0 and fr[3] == b"", \
                "extreme streamid ping was mis-framed or unanswered"
        finally:
            sock.close()

    def test_modifier_byte_fuzz_no_crash(self, hostile_server):
        """Sweeping every modifier value through the two ops that read the
        header modifier (kYR_status, kYR_stats) must never crash the server —
        a fresh client is still served afterward."""
        sock = _login_server(hostile_server.port)
        try:
            for mod in range(256):
                sock.sendall(_build_frame(0, CMS_RR_STATUS, mod))
                sock.sendall(_build_frame(_SID | 0x54, CMS_RR_STATS,
                                          mod | CMS_STATS_SIZE))
            time.sleep(0.3)
        finally:
            sock.close()
        assert _server_alive(hostile_server.port), \
            "a modifier-byte sweep took the server down"

    def test_slowloris_login_does_not_block_others(self, hostile_server):
        """A connection that dribbles a partial LOGIN and then stalls (classic
        slowloris) holds only its own slot behind the absolute login deadline —
        a well-behaved client is served immediately, not head-of-line blocked."""
        slow = socket.create_connection((H, hostile_server.port), timeout=6)
        try:
            # 4 bytes of an 8-byte header, then silence.
            slow.sendall(b"\x00\x00\x00\x00")
            assert _server_alive(hostile_server.port), \
                "a slowloris login stalled service for other clients"
        finally:
            slow.close()

    @pytest.mark.slow
    def test_slowloris_login_eventually_closed(self, hostile_server):
        """The stalled partial-login connection is reaped by the absolute
        LOGIN handshake deadline (default 10s) rather than lingering forever."""
        slow = socket.create_connection((H, hostile_server.port), timeout=20)
        slow.settimeout(20)
        try:
            slow.sendall(b"\x00\x00\x00\x00")   # partial header, never completes
            time.sleep(11.0)                    # exceed the 10s login deadline
            assert _recv_exact(slow, 1) is None, \
                "the login deadline did not reap a stalled slowloris connection"
        finally:
            slow.close()


# ===========================================================================
# Deep esoterica + teardown paths — the auth/namespace/statfs handlers a
# fuzzer reaches last, half-open teardown, and the headline MITM property under
# genuinely CONCURRENT abuse of both legs at once.
# ===========================================================================

class TestDeepEsotericAndTeardown:

    def test_malformed_login_closes_offender_only(self, hostile_server):
        """A LOGIN whose CmsLoginData fails to parse is an auth violation:
        cms_srv_fail_close tears down the offender (mirroring XrdCmsLogin::Admit
        rejecting a bad login) while a fresh client is still admitted."""
        bad = socket.create_connection((H, hostile_server.port), timeout=6)
        bad.settimeout(6)
        try:
            bad.sendall(_build_frame(0, CMS_RR_LOGIN, 0, b"\xff\xff\xffnope"))
            assert _recv_exact(bad, 1) is None, \
                "a malformed LOGIN did not close the offending connection"
            assert _server_alive(hostile_server.port), \
                "a malformed LOGIN disturbed service for other clients"
        finally:
            bad.close()

    def test_statfs_malformed_rrdata_ignored(self, hostile_server):
        """A kYR_statfs with unparseable Pup rrdata draws no kYR_data (the
        handler rejects rather than guesses) and the connection recovers to
        answer a well-formed statfs."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x60, CMS_RR_STATFS, 0,
                                      b"\x00\x40ab"))   # claims 64B, gives 2
            assert _recv_code(sock, CMS_RSP_DATA, timeout=1.0) is None, \
                "server answered a malformed statfs"
            assert _statfs_wfree(sock, _SID | 0x61) == 5000, \
                "connection did not recover after a malformed statfs"
        finally:
            sock.close()

    def test_statfs_without_path_ignored(self, hostile_server):
        """A kYR_statfs carrying only an ident field (no path) is ignored
        (d.path == NULL), never a NULL-deref; a following valid statfs works."""
        sock = _login_server(hostile_server.port)
        try:
            ident = (len(b"tester") + 1).to_bytes(2, "big") + b"tester\x00"
            sock.sendall(_build_frame(_SID | 0x62, CMS_RR_STATFS, 0, ident))
            assert _recv_code(sock, CMS_RSP_DATA, timeout=1.0) is None, \
                "server answered a path-less statfs"
            assert _statfs_wfree(sock, _SID | 0x63) == 5000
        finally:
            sock.close()

    def test_have_traversal_path_dropped(self, hostile_server):
        """Security-neg: a kYR_have whose path contains '..' is dropped by the
        same reject-not-guess shaping the state ingest uses — it can never poke
        the loc cache or wake a locate; the connection stays alive."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x64, CMS_RR_HAVE,
                                      CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                      b"/data/../../etc/passwd\x00"))
            time.sleep(0.2)
            sock.sendall(_build_frame(_SID | 0x65, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a '..' kYR_have disturbed the connection"
        finally:
            sock.close()

    def test_have_relative_path_dropped(self, hostile_server):
        """A kYR_have with a non-absolute path (payload[0] != '/') is rejected
        without disturbing the connection."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x66, CMS_RR_HAVE,
                                      CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                      b"data/relative\x00"))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x67) == 5000
        finally:
            sock.close()

    def test_cns_pre_login_ignored(self, hostile_server):
        """A kYR_cns namespace event before login (and with collect mode off)
        is ignored — no inventory mutation, no crash — and the connection still
        answers a header-only ping."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(0, CMS_RR_CNS, 0, b"\x01" + b"\x00" * 24))
            time.sleep(0.1)
            sock.sendall(_build_frame(_SID | 0x68, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a pre-login CNS event disturbed the connection"
        finally:
            sock.close()

    def test_reset_mid_frame_teardown_survives(self, hostile_server):
        """A peer that announces a large dlen, sends a fraction of the body,
        then abruptly resets is a half-open teardown: the accumulator hits EOF
        with a partial frame and must clean up without wedging — a fresh client
        is served immediately."""
        rude = socket.create_connection((H, hostile_server.port), timeout=6)
        try:
            # Header claims a 4000-byte body; deliver 16 then hard-close.
            hdr = (_SID | 0x69).to_bytes(4, "big") + bytes([0x7F, 0]) \
                + (4000).to_bytes(2, "big")
            rude.sendall(hdr + b"partial-body-xxx")
            rude.close()
            assert _server_alive(hostile_server.port), \
                "a half-open partial-frame reset wedged the server"
        finally:
            try:
                rude.close()
            except OSError:
                pass

    def test_concurrent_both_leg_flood_stays_isolated(self, hostile_super):
        """THE headline MITM property under real concurrency: while a hostile
        site child saturates the supervisor's downward accept leg with garbage
        frames, the upward manager leg keeps answering pings the whole time, and
        once the flood stops the accept leg still admits a well-behaved child.
        Neither leg can be starved or wedged by sustained abuse of the other."""
        stop = threading.Event()
        errors = []

        def flood():
            try:
                fs = socket.create_connection(
                    (H, hostile_super.node_port), timeout=6)
                # Unknown opcodes pre-login are dropped-but-kept: an endless,
                # legal-to-parse torrent that never yields the socket idle.
                burst = b"".join(
                    _build_frame(i, 0x7F, 0, b"X" * 64) for i in range(64))
                while not stop.is_set():
                    fs.sendall(burst)
            except OSError:
                pass            # a mid-flood close is fine; we only measure the
                                # OTHER leg's health
            finally:
                try:
                    fs.close()
                except (OSError, UnboundLocalError):
                    pass

        t = threading.Thread(target=flood, daemon=True)
        t.start()
        try:
            for i in range(5):
                if not _node_alive(hostile_super, timeout=6):
                    errors.append(i)
        finally:
            stop.set()
            t.join(timeout=3)
        assert not errors, \
            f"upward manager leg stalled under a downward flood on rounds {errors}"

        # And the accept leg itself is still healthy for a well-behaved child.
        child = _node_login_dialog(
            hostile_super.node_port,
            _login_payload_with_mode(NODE_DATA_PORT + 40, CMS_MODE_SERVER,
                                     paths=b"r /data"))
        try:
            child.settimeout(6)
            time.sleep(0.3)
            child.sendall(_build_frame(_SID | 0x6A, CMS_RR_PING, 0))
            assert _recv_code(child, CMS_RR_PONG, timeout=6) is not None, \
                "the accept leg would not serve a fresh child after the flood"
        finally:
            child.close()


# ===========================================================================
# Role confusion — a hostile peer replaying the OTHER leg's opcodes.  This is
# the classic stock cmsd↔cmsd trouble spot: a manager that speaks node-role
# frames (or vice versa) must be tolerated (dropped, connection KEPT), never
# mis-dispatched into the wrong state machine and never able to wedge the link.
# ===========================================================================

class TestRoleConfusionFrames:

    # Opcodes that only ever travel manager→node (the node/dial-out leg's
    # vocabulary); a node must NOT be able to drive these UP into the manager.
    NODE_ROLE_OPS = (
        CMS_RR_SELECT, CMS_RR_TRY, CMS_RR_STATE, CMS_RR_CHMOD, CMS_RR_MKDIR,
        CMS_RR_MKPATH, CMS_RR_MV, CMS_RR_RM, CMS_RR_RMDIR, CMS_RR_TRUNC,
        CMS_RR_PREPADD, CMS_RR_PREPDEL,
    )

    # Opcodes that only ever travel node→manager (the server/accept leg's
    # vocabulary); a manager must NOT be able to drive these DOWN into a node.
    SERVER_ROLE_OPS = (
        CMS_RR_XAUTH, CMS_RR_GONE, CMS_RR_HAVE, CMS_RR_USAGE, CMS_RR_STATFS,
        CMS_RR_LOAD, CMS_RR_AVAIL, CMS_RR_CNS,
    )

    def test_server_leg_ignores_node_role_ops(self, hostile_server):
        """A logged-in node that emits node-role opcodes (redirect/state/
        forwarded-namespace ops it should only ever RECEIVE) has each one
        dropped by the manager's route table without a mis-dispatch; the
        connection stays fully serviceable."""
        sock = _login_server(hostile_server.port)
        try:
            for op in self.NODE_ROLE_OPS:
                sock.sendall(_build_frame(_SID | op, op, 0, b"\x00\x08junk"))
            time.sleep(0.3)
            # No reply should have been produced for any of them, and the
            # connection must still answer a well-formed statfs.
            assert _statfs_wfree(sock, _SID | 0x70) == 5000, \
                "a node-role opcode confused the manager state machine"
            sock.sendall(_build_frame(_SID | 0x71, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
        finally:
            sock.close()

    def test_node_leg_ignores_server_role_ops(self, hostile_node):
        """A hostile manager that emits server-role opcodes (statfs/gone/have/
        usage/load/avail/cns/xauth a node should only ever SEND) has each one
        dropped: no reconnect (stable LOGIN count) and the node stays alive."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for op in self.SERVER_ROLE_OPS:
            hostile_node.send_to_node(_SID | op, op, 0, b"\x00\x08junk")
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "a server-role opcode forced the node to reconnect"
        assert _node_alive(hostile_node), \
            "a server-role opcode wedged the node"

    def test_server_disc_echoes_then_closes(self, hostile_server):
        """kYR_disc from a node is echoed back (do_Disc parity) and the manager
        then closes that link cleanly — while still serving everyone else."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x72, CMS_RR_DISC, 0))
            assert _recv_code(sock, CMS_RR_DISC, timeout=6) is not None, \
                "manager did not echo kYR_disc"
            assert _recv_exact(sock, 1) is None, \
                "manager did not close the link after a disc handshake"
        finally:
            sock.close()
        assert _server_alive(hostile_server.port), \
            "a disc handshake disturbed service for other clients"

    def test_status_stage_nostage_survives(self, hostile_server):
        """A node advertising its staging capability via kYR_status(stage) then
        retracting it (nostage) — the disk-only↔staging transition a real node
        makes — never crashes or drops the connection."""
        sock = _login_server(hostile_server.port)
        try:
            for mod in (CMS_ST_STAGE, CMS_ST_NOSTAGE,
                        CMS_ST_RESUME | CMS_ST_NOSTAGE):
                sock.sendall(_build_frame(0, CMS_RR_STATUS, mod))
                time.sleep(0.1)
            assert _statfs_wfree(sock, _SID | 0x73) == 5000, \
                "a stage/nostage transition disturbed the registration"
        finally:
            sock.close()

    def test_multi_host_try_injection_ignored(self, hostile_node):
        """MITM: a kYR_try carrying an ORDERED LIST of attacker redirect targets
        for a stream with no pending locate steers nothing — the node cannot be
        walked through an attacker's redirect chain for a request it never
        issued."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        payload = (b"evil-a.attacker.example\x00" + (1094).to_bytes(2, "big")
                   + b"evil-b.attacker.example\x00" + (2094).to_bytes(2, "big"))
        hostile_node.send_to_node(_SID | 0x74, CMS_RR_TRY, 0, payload)
        time.sleep(0.3)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base
        assert _node_alive(hostile_node)


# ===========================================================================
# Numeric payload parsers, LOGIN edge cases, zero-payload safety, and the
# 64-frame fairness-boundary reassembly — the byte-level surfaces a fuzzer
# reaches only with well-formed framing but hostile field contents.
# ===========================================================================

class TestPayloadParserAndLogin:

    # Server ops that carry a payload but must never close/reauth the link when
    # fed an empty one (DISC closes, XAUTH out-of-seq closes, LOGIN re-registers
    # — all excluded so the flood measures pure parser robustness).
    ZERO_PAYLOAD_SERVER_OPS = (
        CMS_RR_LOAD, CMS_RR_AVAIL, CMS_RR_SPACE, CMS_RR_UPDATE, CMS_RR_STATFS,
        CMS_RR_USAGE, CMS_RR_STATS, CMS_RR_STATUS, CMS_RR_GONE, CMS_RR_HAVE,
        CMS_RSP_ERROR, CMS_RR_CNS,
    )

    # Node ops that carry a payload (DISC/PING excluded — DISC forces a
    # reconnect, PING is state-neutral liveness).
    ZERO_PAYLOAD_NODE_OPS = (
        CMS_RR_SELECT, CMS_RR_TRY, CMS_RR_STATE, CMS_RR_CHMOD, CMS_RR_MKDIR,
        CMS_RR_MKPATH, CMS_RR_MV, CMS_RR_RM, CMS_RR_RMDIR, CMS_RR_TRUNC,
        CMS_RR_PREPADD, CMS_RR_PREPDEL,
    )

    def test_load_extreme_free_mb_no_overflow(self, hostile_server):
        """A kYR_load advertising the maximal 0xFFFFFFFF free-MB is decoded by
        the bounded TLV reader without overflow, the statfs encoder handles the
        extreme aggregate, and the connection stays alive."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_LOAD, 0,
                                      _load_payload(0xFFFFFFFF, b"\xff" * 6)))
            time.sleep(0.2)
            # The statfs encoder must still produce a well-formed 6-field reply
            # (no crash / no short buffer) for the extreme advertised value.
            _statfs_wfree(sock, _SID | 0x80)
            sock.sendall(_build_frame(_SID | 0x81, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "an extreme kYR_load free-MB wedged the connection"
        finally:
            sock.close()

    def test_load_truncated_decodes_safe(self, hostile_server):
        """A kYR_load shorter than its declared TLV fields decodes missing
        fields as zero (documented parser posture) without an over-read; the
        connection recovers."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_LOAD, 0,
                                      bytes([CMS_PT_SHORT, 0x00])))  # truncated
            time.sleep(0.2)
            sock.sendall(_build_frame(_SID | 0x82, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
        finally:
            sock.close()

    def test_avail_malformed_then_valid_recovers(self, hostile_server):
        """A malformed kYR_avail (1 byte) decodes free/util as zero; a
        following well-formed avail restores a real figure — proving the parser
        neither crashes nor latches a bad value."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_AVAIL, 0, b"\xa0"))  # tag only
            time.sleep(0.15)
            good = (bytes([CMS_PT_INT]) + (7000).to_bytes(4, "big")
                    + bytes([CMS_PT_INT]) + (10).to_bytes(4, "big"))
            sock.sendall(_build_frame(0, CMS_RR_AVAIL, 0, good))
            time.sleep(0.15)
            assert _statfs_wfree(sock, _SID | 0x83) == 7000, \
                "avail parser did not recover a valid figure after a bad frame"
        finally:
            sock.close()

    def test_login_empty_paths_valid_registration(self, hostile_server):
        """A LOGIN advertising no export paths is a valid, non-crashing login:
        the node registers, statfs still answers a well-formed 6-field reply
        (aggregate free space is table-wide, not path-filtered — so wFree is
        unchanged; only the path-match count would be zero), and the connection
        is healthy."""
        sock = _node_login_dialog(
            hostile_server.port, _minimal_login_payload(NODE_DATA_PORT, b""))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            _statfs_wfree(sock, _SID | 0x84)   # asserts a well-formed reply
            sock.sendall(_build_frame(_SID | 0x85, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "an empty-Paths login was not a healthy registration"
        finally:
            sock.close()

    def test_login_oversized_paths_bounded(self, hostile_server):
        """A LOGIN whose Paths list (~2.5 KB) exceeds the 1 KB ctx->paths buffer
        — but still fits within one CMS frame — is copied under the dst_end
        guard: truncated, never overflowed; the node still logs in and the
        connection answers.  (A Paths list large enough to exceed the 4 KB frame
        is a different defense — the oversized-frame close — covered elsewhere.)"""
        paths = b"\n".join(b"r /export/deep/tree/%03d" % i for i in range(100))
        assert len(paths) > BRIX_SRV_MAX_PATHS, "test must exceed the paths buf"
        sock = _node_login_dialog(
            hostile_server.port, _minimal_login_payload(NODE_DATA_PORT, paths))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(_SID | 0x86, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "an oversized Paths login overflowed or wedged the connection"
            _statfs_wfree(sock, _SID | 0x87)   # live registration
        finally:
            sock.close()

    def test_login_invalid_mode_word_classified(self, hostile_server):
        """A LOGIN with an all-bits Mode word is classified by the Admit role
        bits without crashing (falls to supervisor/manager/server per the bit
        test) and the connection is serviceable."""
        sock = _node_login_dialog(
            hostile_server.port,
            _login_payload_with_mode(NODE_DATA_PORT, 0xFFFFFFFF,
                                     paths=b"r /data"))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(_SID | 0x88, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
        finally:
            sock.close()

    def test_login_traversal_in_paths_no_crash(self, hostile_server):
        """A LOGIN whose Paths advertise a '..' export is copied verbatim
        (bounded) without crashing; the actual confinement is enforced later at
        the have/statfs/forward gates, so a subsequent foreign kYR_have is still
        dropped — a hostile export declaration grants no escape."""
        sock = _node_login_dialog(
            hostile_server.port,
            _minimal_login_payload(NODE_DATA_PORT, b"r /../../etc"))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(_SID | 0x89, CMS_RR_HAVE,
                                      CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                      b"/etc/passwd\x00"))
            time.sleep(0.15)
            sock.sendall(_build_frame(_SID | 0x8A, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a traversal export declaration crashed or wedged the link"
        finally:
            sock.close()

    def test_zero_payload_all_server_ops_safe(self, hostile_server):
        """Every payload-bearing server op fed an empty (dlen=0) body is handled
        without a short read or crash; the connection still answers a ping."""
        sock = _login_server(hostile_server.port)
        try:
            for op in self.ZERO_PAYLOAD_SERVER_OPS:
                sock.sendall(_build_frame(_SID | op, op, 0))
            time.sleep(0.3)
            sock.sendall(_build_frame(_SID | 0x8B, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a zero-payload server op wedged the connection"
        finally:
            sock.close()

    def test_zero_payload_all_node_ops_safe(self, hostile_node):
        """Every payload-bearing node op fed an empty body is dropped/error'd
        without a short read: no op forces a reconnect, node still alive.  A
        single *incidental* reconnect (an idle dial-out re-dial, or the WSL2
        backward-clock-step nudging a keepalive) is tolerated -- what must not
        happen is a per-op reconnect storm (12 ops -> ~12 fresh LOGINs), which
        would prove an empty body wedged the manager leg."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for op in self.ZERO_PAYLOAD_NODE_OPS:
            try:
                hostile_node.send_to_node(_SID | op, op, 0)
            except (AssertionError, OSError, AttributeError):
                pass   # incidental mid-reconnect window
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) - base <= 1, \
            "zero-payload node ops forced a reconnect storm"
        assert _node_alive(hostile_node), \
            "the node upward leg died after a zero-payload op barrage"

    def test_64_frame_boundary_reassembles_partial(self, hostile_server):
        """Exactly 64 ping frames (one full fairness batch) followed by a 65th
        split across the wakeup boundary: all 65 pongs come back, proving no
        frame is dropped at the batch edge and the trailing partial reassembles
        on the next wakeup."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            batch = b"".join(
                _build_frame(_SID | i, CMS_RR_PING, 0) for i in range(64))
            partial = _build_frame(_SID | 0x40, CMS_RR_PING, 0)
            sock.sendall(batch + partial[:4])   # 64 whole + half a header
            time.sleep(0.3)                     # force at least one wakeup
            sock.sendall(partial[4:])           # complete the 65th
            got = 0
            for _ in range(65):
                if _recv_code(sock, CMS_RR_PONG, timeout=6) is None:
                    break
                got += 1
            assert got == 65, \
                f"expected 65 pongs across the fairness boundary, got {got}"
        finally:
            sock.close()


# ===========================================================================
# Node-leg kYR_state probe + multi-tier relay depth — the MITM *downward*
# direction.  A hostile manager probes "do you hold <path>?"; the confined
# existence check must never leak a kYR_have outside the export root, and the
# relay that parks a parent probe while re-asking children must be single-use,
# path-bound, and streamid-bound so a hostile child cannot forge an upward
# kYR_have for a path the manager never probed.  All behaviour verified against
# src/net/cms/recv_frame.c::cms_frame_state, cms_state_extract_path, and
# src/net/cms/state_relay.c (take/add) + server_recv_frame_handlers.c have
# ingest.
# ===========================================================================

def _wait_have_increment(peer, base, timeout=8.0):
    """Poll until the peer has captured MORE kYR_have frames than `base`."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if peer.count_frames(CMS_RR_HAVE) > base:
            return True
        time.sleep(0.1)
    return False


class TestNodeStateProbeAndRelayDepth:

    CHILD_DPORT = NODE_DATA_PORT + 40

    def _login_child(self, peer, paths=b"r /data"):
        sock = _node_login_dialog(
            peer.node_port,
            _login_payload_with_mode(self.CHILD_DPORT, CMS_MODE_SERVER,
                                     paths=paths))
        time.sleep(0.4)
        return sock

    # -- data-node confined existence probe ---------------------------------

    def test_state_resident_file_is_locatable(self, hostile_node):
        """Baseline (positive control): a kYR_state for the genuinely resident
        export file draws a kYR_have — proving the confined probe ANSWERS, so
        the silences asserted below are confinement, not a dead probe."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD0, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"/have_me.bin\x00")
        assert _wait_have_increment(hostile_node, base), \
            "node did not answer kYR_have for a genuinely resident path"

    def test_state_foreign_absolute_no_have(self, hostile_node):
        """Security-neg: a probe for a real host file OUTSIDE the export root
        (/etc/passwd) draws NO kYR_have — brix_stat_beneath resolves under the
        export rootfd with RESOLVE_BENEATH, so the escape is kernel-rejected."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD1, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"/etc/passwd\x00")
        time.sleep(0.6)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base, \
            "node leaked kYR_have for a path outside its export root"
        assert _node_alive(hostile_node), \
            "a foreign-path state probe disturbed the node"

    def test_state_oversized_path_bounded(self, hostile_node):
        """A ~1100-byte path (> the 1024-byte pathz buffer, still under the
        4088 frame limit) is rejected by cms_state_extract_path (pl >=
        pathz_size) with no over-read: no kYR_have, no crash, node alive."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        huge = b"/" + b"a" * 1100 + b"\x00"
        assert len(huge) < CMS_MAX_DLEN, "probe must fit inside one frame"
        hostile_node.send_to_node(_SID | 0xD2, CMS_RR_STATE, CMS_MOD_RAW, huge)
        time.sleep(0.5)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base, \
            "node answered an over-length (unbounded) state path"
        assert _node_alive(hostile_node), \
            "an over-length state probe disturbed the node"

    def test_state_relative_path_no_have(self, hostile_node):
        """A non-absolute path (no leading '/') is rejected up front
        (payload[0] != '/') — no kYR_have, connection intact."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD3, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"have_me.bin\x00")
        time.sleep(0.5)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base, \
            "node answered a relative (non-absolute) state path"
        assert _node_alive(hostile_node), \
            "a relative-path state probe disturbed the node"

    def test_state_embedded_nul_truncates_safely(self, hostile_node):
        """A path with an embedded NUL followed by a foreign path
        (/have_me.bin\\0/etc/passwd\\0): the bounded scan stops at the FIRST
        NUL, so the probe resolves to the resident path only (kYR_have for the
        resident) and the trailing foreign bytes are never read as a path."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD4, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"/have_me.bin\x00/etc/passwd\x00")
        assert _wait_have_increment(hostile_node, base), \
            "embedded-NUL probe did not truncate to the resident prefix"
        assert _node_alive(hostile_node), \
            "an embedded-NUL state probe disturbed the node"

    def test_state_empty_payload_no_have(self, hostile_node):
        """A lone NUL (zero-length path, pl == 0) is rejected — no kYR_have,
        node stays connected (distinct from the server-leg zero-dlen case)."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD5, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"\x00")
        time.sleep(0.5)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base, \
            "node answered an empty state path"
        assert _node_alive(hostile_node), \
            "an empty state probe disturbed the node"

    # -- relay depth: forged answers must not forge an upward kYR_have -------

    def test_relay_forged_path_answer_kept_for_honest(self, hostile_super):
        """take() consumes a parked relay entry ONLY on an exact path match: a
        child answering the right down_sid with the WRONG path is refused
        (paths-cover then drops it) AND the entry survives, so the child's later
        HONEST answer for the probed path still lands the upward kYR_have.
        Proves the forged-path branch keeps the entry (no self-inflicted DoS on
        the honest reply)."""
        child = self._login_child(hostile_super)
        try:
            hostile_super.send_to_node(_SID | 0xE1, CMS_RR_STATE, CMS_MOD_RAW,
                                       b"/relay/target.bin\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8)
            assert fr is not None, "supervisor did not relay the probe down"
            down_sid = fr[0]
            probed = fr[3].split(b"\x00", 1)[0]
            base_have = hostile_super.count_frames(CMS_RR_HAVE)

            # Forged path on the real down_sid: refused, entry NOT consumed.
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       b"/relay/FORGED.bin\x00"))
            time.sleep(0.6)
            assert hostile_super.count_frames(CMS_RR_HAVE) == base_have, \
                "a forged-path child answer forged an upward kYR_have"

            # Honest answer for the probed path still lands (entry survived).
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       probed + b"\x00"))
            assert _wait_have_increment(hostile_super, base_have), \
                "forged answer consumed the entry — honest reply was lost"
            assert _node_alive(hostile_super), \
                "the supervisor was unhealthy after a forged relay answer"
        finally:
            child.close()

    def test_relay_single_use_second_answer_ignored(self, hostile_super):
        """A parked relay entry is single-use: the FIRST honest child answer is
        echoed up and clears in_use; a SECOND identical answer for the same
        down_sid+path finds no live entry and is dropped by paths-cover — no
        duplicate upward kYR_have, no crash."""
        child = self._login_child(hostile_super)
        try:
            hostile_super.send_to_node(_SID | 0xE2, CMS_RR_STATE, CMS_MOD_RAW,
                                       b"/relay/once.bin\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8)
            assert fr is not None, "supervisor did not relay the probe down"
            down_sid = fr[0]
            probed = fr[3].split(b"\x00", 1)[0]
            base_have = hostile_super.count_frames(CMS_RR_HAVE)

            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       probed + b"\x00"))
            assert _wait_have_increment(hostile_super, base_have), \
                "first honest relay answer was not echoed upward"
            after_first = hostile_super.count_frames(CMS_RR_HAVE)

            # Replay: the entry is already consumed.
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       probed + b"\x00"))
            time.sleep(0.6)
            assert hostile_super.count_frames(CMS_RR_HAVE) == after_first, \
                "a replayed child answer forged a duplicate upward kYR_have"
            assert _node_alive(hostile_super), \
                "the supervisor was unhealthy after a replayed relay answer"
        finally:
            child.close()

    def test_relay_forged_down_sid_steers_nothing(self, hostile_super):
        """A hostile child that emits an UNSOLICITED kYR_have carrying a
        down_sid the supervisor never issued matches no relay entry; the path
        (outside the child's exports) then fails paths-cover and is dropped — no
        upward kYR_have is forged and the supervisor stays healthy."""
        child = self._login_child(hostile_super)
        try:
            base_have = hostile_super.count_frames(CMS_RR_HAVE)
            child.sendall(_build_frame(0x7EADBEEF, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       b"/relay/ghost.bin\x00"))
            time.sleep(0.6)
            assert hostile_super.count_frames(CMS_RR_HAVE) == base_have, \
                "an unsolicited forged-streamid have forged an upward kYR_have"
            assert _node_alive(hostile_super), \
                "a forged-streamid child answer disturbed the supervisor"
        finally:
            child.close()


# ===========================================================================
# Accept-leg resilience limits — the deadlines + admission caps (Phase-50 WS3/
# WS4, A3) that stop a hostile site node from holding a slot forever or
# exhausting the accept leg, plus the non-blocking write path that keeps a
# slow/zero-reading or half-closed peer from wedging the single worker.  These
# are the "hostile network hang" classes stock cmsd↔cmsd is weak on.  Verified
# against src/net/cms/server_handler.c (per-IP + global caps),
# src/net/cms/server_recv.c (idle watchdog), and frame_io.c::brix_cms_send_all
# (AGAIN → drop, never block).
# ===========================================================================

@pytest.fixture
def hardened_server(lifecycle):
    """Accept leg with tight idle/admission knobs (3s idle reap, 8 conns/IP)."""
    return lifecycle.start(NginxInstanceSpec(
        name="lc-cms-hostile-hardened",
        template="nginx_cms_wire_server_hardened.conf",
        protocol="root",
        readiness="tcp",
        reason="CMS hostile-network conformance: accept-leg resilience limits.",
    ))


class TestServerLegResilienceLimits:

    def test_idle_logged_in_peer_reaped(self, hardened_server):
        """A node that completes LOGIN then goes completely silent is closed by
        the post-login idle watchdog (3s here) — a hostile peer cannot register
        and then hold a slot forever.  The server keeps serving fresh clients."""
        victim = _login_server(hardened_server.port)
        victim.settimeout(0.5)
        try:
            closed = False
            deadline = time.time() + 9.0
            while time.time() < deadline:
                try:
                    if victim.recv(64) == b"":
                        closed = True
                        break
                    # server sent us something (e.g. a ping) — keep waiting
                except socket.timeout:
                    continue
                except OSError:
                    closed = True
                    break
            assert closed, \
                "a silent logged-in peer was not reaped by the idle watchdog"
        finally:
            victim.close()
        assert _server_alive(hardened_server.port), \
            "the server was unhealthy after reaping an idle peer"

    def test_per_ip_connection_cap_bounds_concurrency(self, hardened_server):
        """20 simultaneous connections from one source IP against a per-IP cap
        of 8: at most 8 are admitted+serviced and the overflow is refused
        (finalized FORBIDDEN at accept, before any frame handler) — one hostile
        IP cannot exhaust the accept leg.  After releasing, service resumes."""
        socks = []
        try:
            for _ in range(20):
                try:
                    s = socket.create_connection((H, hardened_server.port),
                                                 timeout=4)
                    s.settimeout(2.0)
                    socks.append(s)
                except OSError:
                    pass
            time.sleep(0.6)   # let the worker accept all + apply the cap
            admitted = 0
            for s in socks:
                try:
                    s.sendall(_build_frame(_SID | 0x0F, CMS_RR_PING, 0))
                    if _recv_code(s, CMS_RR_PONG, timeout=2) is not None:
                        admitted += 1
                except OSError:
                    pass
            assert 1 <= admitted <= 8, \
                f"per-IP cap not enforced: {admitted} conns serviced (cap 8)"
            assert len(socks) - admitted >= 1, \
                "no connection was refused despite exceeding the per-IP cap"
        finally:
            for s in socks:
                s.close()
        time.sleep(0.4)   # let the finalized sessions decrement the IP count
        assert _server_alive(hardened_server.port), \
            "the server did not resume service after cap enforcement"

    def test_slow_reader_does_not_block_others(self, hostile_server):
        """The canonical hostile-network wedge: a peer floods kYR_ping but NEVER
        reads the kYR_pong replies, so its receive buffer (shrunk here) and the
        server's send buffer fill.  brix_cms_send_all returns AGAIN and drops
        the frame rather than blocking, so the single worker keeps serving a
        separate well-behaved peer (where a blocking-write cmsd would stall)."""
        slow = socket.create_connection((H, hostile_server.port), timeout=6)
        slow.settimeout(8)
        try:
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
            flood = b"".join(_build_frame(_SID | (i & 0xFF), CMS_RR_PING, 0)
                             for i in range(20000))
            try:
                slow.sendall(flood)
            except OSError:
                pass   # our own send may fail once the server stops draining us
            assert _server_alive(hostile_server.port), \
                "a slow/zero-reading peer blocked the worker for other clients"
        finally:
            slow.close()

    def test_half_closed_write_side_cleaned_up(self, hostile_server):
        """A peer that half-closes (shutdown SHUT_WR — sends FIN but keeps its
        read half open, a real asymmetric-network teardown) is seen as EOF on
        the read half and torn down cleanly; other clients keep being served."""
        peer = socket.create_connection((H, hostile_server.port), timeout=6)
        peer.settimeout(6)
        try:
            peer.sendall(_build_frame(_SID | 1, CMS_RR_PING, 0))
            assert _recv_code(peer, CMS_RR_PONG, timeout=6) is not None, \
                "server did not answer before the half-close"
            peer.shutdown(socket.SHUT_WR)
            time.sleep(0.3)
            assert _server_alive(hostile_server.port), \
                "a half-closed (SHUT_WR) peer disturbed the server"
        finally:
            peer.close()


# ===========================================================================
# Large-scale opcode / frame-size / state-path sweeps.
#
# The suites above pin *named* esoteric behaviours one at a time.  The classes
# below carpet-bomb both legs with the FULL opcode space (every rrCode a stock
# cmsd defines plus a band of raw unknowns), the full accepted/rejected frame-
# size boundary, and a broad adversarial state-path corpus — each paired with a
# garbage payload — and after EVERY single hostile frame re-prove liveness:
#   * server leg  -> a *fresh* client still gets a kYR_pong (the offender may be
#     closed; the accept leg must keep serving everyone else);
#   * node leg    -> the upward manager leg still answers kYR_ping, riding out
#     any DISC-forced reconnect.
# One long-lived instance per leg endures the whole barrage, so a slow resource
# or state leak across hundreds of hostile frames would surface as a late red.
# This is the "ROCK SOLID — neither end may hang the other" property at scale.
# ===========================================================================

# Every rrCode a stock cmsd emits (src/net/cms/cms_internal.h), minus LOGIN (0,
# its own dialog) and PING (17, the liveness op), plus a band of raw unknowns
# that MUST be read-and-dropped without disturbing the framer.
_SWEEP_OPS = [
    ("chmod", CMS_RR_CHMOD), ("mkdir", CMS_RR_MKDIR), ("mkpath", CMS_RR_MKPATH),
    ("mv", CMS_RR_MV), ("prepadd", CMS_RR_PREPADD), ("prepdel", CMS_RR_PREPDEL),
    ("rm", CMS_RR_RM), ("rmdir", CMS_RR_RMDIR), ("select", CMS_RR_SELECT),
    ("stats", CMS_RR_STATS), ("avail", CMS_RR_AVAIL), ("disc", CMS_RR_DISC),
    ("gone", CMS_RR_GONE), ("have", CMS_RR_HAVE), ("load", CMS_RR_LOAD),
    ("pong", CMS_RR_PONG), ("space", CMS_RR_SPACE), ("state", CMS_RR_STATE),
    ("statfs", CMS_RR_STATFS), ("status", CMS_RR_STATUS), ("trunc", CMS_RR_TRUNC),
    ("try", CMS_RR_TRY), ("update", CMS_RR_UPDATE), ("usage", CMS_RR_USAGE),
    ("xauth", CMS_RR_XAUTH), ("cns", CMS_RR_CNS),
    # raw unknowns spanning the low gaps and the high (>0x7F) band
    ("raw02", 0x02), ("raw1c", 0x1C), ("raw1d", 0x1D), ("raw1e", 0x1E),
    ("raw1f", 0x1F), ("raw29", 0x29), ("raw7e", 0x7E), ("raw7f", 0x7F),
    ("rawfe", 0xFE), ("rawff", 0xFF),
]
_SWEEP_IDS = [n for n, _ in _SWEEP_OPS]
_SWEEP_CODES = [c for _, c in _SWEEP_OPS]

# Structured-looking garbage: a short run that under-fills every op's expected
# payload (exercises the truncated/short-decode path of each handler).
_SWEEP_GARBAGE = bytes(range(32))


def _node_survives(peer, timeout=20.0):
    """Upward-leg liveness that tolerates a reconnect: keep pinging until a
    fresh kYR_pong lands, retrying through the brief window where a DISC-forced
    reconnect has torn the old socket down and not yet re-established (in which
    window ``send_to_node`` asserts no live conn)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        base = peer.count_frames(CMS_RR_PONG)
        try:
            peer.send_to_node(_SID | 0x7E, CMS_RR_PING, 0)
        except (AssertionError, OSError, AttributeError):
            time.sleep(0.3)   # reconnect window — retry
            continue
        inner = time.time() + 2.5
        while time.time() < inner:
            if peer.count_frames(CMS_RR_PONG) > base:
                return True
            time.sleep(0.1)
    return False


# --- module-scoped sweep instances -----------------------------------------
# One boot per leg for the whole sweep (dedicated ledger ports so they never
# contend with the per-test fixtures above), each on its own LifecycleHarness
# so teardown is self-contained.

@pytest.fixture(scope="module")
def sweep_server():
    """A single long-lived accept-leg instance that must survive the full
    server-side opcode + frame-size barrage."""
    h = LifecycleHarness()
    try:
        ep = h.start(NginxInstanceSpec(
            name="lc-cms-hostile-sweep-srv",
            template="nginx_cms_wire_server.conf",
            protocol="root",
            readiness="tcp",
            reason="CMS hostile-network conformance: server-leg opcode/size sweep.",
        ))
        yield ep
    finally:
        h.close()


@pytest.fixture(scope="module")
def sweep_node():
    """A single long-lived data node (dialing a mock manager peer) that must
    survive the full node-side opcode + state-path barrage."""
    h = LifecycleHarness()
    data_dir = os.path.join(_HDIR, "sweep_node_data")
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(data_dir, "have_me.bin"), "wb") as f:
        f.write(b"resident-bytes" * 16)
    peer = None
    try:
        peer = _start_peered_node(
            h, "lc-cms-hostile-sweep-node", "nginx_cms_wire_node.conf", {},
            "CMS hostile-network conformance: node-leg opcode/state sweep.",
            data_dir)
        yield peer
    finally:
        if peer is not None:
            peer.close()
        h.close()


class TestServerLegOpcodeMatrix:
    """Every opcode, with a garbage payload, on the accept leg — once BEFORE
    login (pre-auth gate) and once AFTER a valid login (per-op handler live).
    The offending frame may cost the offender its connection; a fresh client
    must always still be served."""

    @pytest.mark.parametrize("code", _SWEEP_CODES, ids=_SWEEP_IDS)
    def test_pre_login_opcode_garbage_keeps_server_alive(self, sweep_server, code):
        junk = socket.create_connection((H, sweep_server.port), timeout=6)
        junk.settimeout(4)
        try:
            junk.sendall(_build_frame(_SID | code, code, 0, _SWEEP_GARBAGE))
            time.sleep(0.05)
            assert _server_alive(sweep_server.port), \
                f"pre-login opcode 0x{code:02x} took the accept leg down"
        finally:
            junk.close()

    @pytest.mark.parametrize("code", _SWEEP_CODES, ids=_SWEEP_IDS)
    def test_post_login_opcode_garbage_keeps_server_alive(self, sweep_server, code):
        victim = _login_server(sweep_server.port)
        try:
            try:
                victim.sendall(_build_frame(_SID | code, code, 0, _SWEEP_GARBAGE))
            except OSError:
                pass   # offender may already be closed by an earlier violation
            time.sleep(0.05)
            assert _server_alive(sweep_server.port), \
                f"post-login opcode 0x{code:02x} took the accept leg down"
        finally:
            victim.close()


class TestFrameSizeBoundarySweep:
    """The exact dlen boundary on the accept leg.  dlen+8 <= 4096 (MAX_FRAME)
    is read-and-dropped in full (unknown opcode) with the connection intact;
    dlen+8 > 4096 closes only the offender.  Either way a fresh client is
    served."""

    # dlen values whose total frame (dlen+8) is <= 4096 -> ACCEPTED.
    ACCEPTED = [0, 1, 2, 7, 8, 9, 16, 64, 255, 256, 1000, 2048,
                4080, 4086, 4087, 4088]
    # dlen values whose total frame (dlen+8) is > 4096 -> offender CLOSED.
    REJECTED = [4089, 4090, 5000, 8000, 16000, 32000, 65535]

    @pytest.mark.parametrize("dlen", ACCEPTED, ids=[str(d) for d in ACCEPTED])
    def test_accepted_dlen_read_in_full(self, sweep_server, dlen):
        sock = socket.create_connection((H, sweep_server.port), timeout=6)
        sock.settimeout(6)
        try:
            frame = _build_frame(_SID | 0x11, 0x7E, 0, b"\x00" * dlen)
            assert len(frame) == dlen + 8 <= 4096
            sock.sendall(frame)
            # Same connection must still answer -> the frame was consumed whole
            # and framer alignment is preserved.
            sock.sendall(_build_frame(_SID | 0x12, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                f"accepted dlen {dlen} broke framer alignment"
        finally:
            sock.close()

    @pytest.mark.parametrize("dlen", REJECTED, ids=[str(d) for d in REJECTED])
    def test_rejected_dlen_closes_only_offender(self, sweep_server, dlen):
        bad = socket.create_connection((H, sweep_server.port), timeout=6)
        bad.settimeout(6)
        try:
            # Craft an 8-byte header advertising an over-cap dlen and send ONLY
            # the header — the server rejects on the length word, before the
            # (never-sent) body, so it must close without waiting for bytes.
            hdr = ((_SID | 0x13).to_bytes(4, "big") + bytes([0x7E, 0])
                   + dlen.to_bytes(2, "big"))
            bad.sendall(hdr)
            assert _recv_exact(bad, 1) is None, \
                f"over-cap dlen {dlen} did not close the offender"
            assert _server_alive(sweep_server.port), \
                f"over-cap dlen {dlen} disturbed the accept leg"
        finally:
            bad.close()


class TestNodeLegOpcodeMatrix:
    """Every opcode, with a garbage payload, thrown by a hostile manager DOWN
    the upward leg into the node.  The node must never hang: the manager leg
    keeps answering kYR_ping, tolerating a DISC-forced reconnect."""

    @pytest.mark.parametrize("code", _SWEEP_CODES, ids=_SWEEP_IDS)
    def test_manager_opcode_garbage_keeps_node_alive(self, sweep_node, code):
        try:
            sweep_node.send_to_node(_SID | code, code, 0, _SWEEP_GARBAGE)
        except (AssertionError, OSError):
            pass   # a prior DISC may have the socket mid-reconnect
        assert _node_survives(sweep_node), \
            f"manager opcode 0x{code:02x} wedged the node's upward leg"


class TestNodeStatePathCorpus:
    """A broad corpus of adversarial kYR_state paths, every one of which MUST
    draw NO kYR_have from a data node whose only resident file is
    /have_me.bin: parent-traversal, non-absolute, absolute-outside-export,
    control-byte, oversized, and near-miss paths.  brix_stat_beneath resolves
    under the export rootfd with RESOLVE_BENEATH and cms_state_extract_path
    rejects ``..``/relative/oversized before any syscall."""

    CORPUS = [
        # parent traversal (cms_state_extract_path rejects any "..")
        ("dotdot_etc", b"/../etc/passwd"),
        ("dotdot_deep", b"/a/../../etc/passwd"),
        ("dotdot_bare", b"/.."),
        ("dotdot_trail", b"/../"),
        ("dotdot_mid", b"/foo/../bar"),
        ("dotdot_multi", b"/x/../../../../root"),
        # absolute, but outside the export root (stat_beneath miss)
        ("etc_passwd", b"/etc/passwd"),
        ("etc_shadow", b"/etc/shadow"),
        ("proc_maps", b"/proc/self/maps"),
        ("dev_zero", b"/dev/zero"),
        ("root_ssh", b"/root/.ssh/id_rsa"),
        ("bin_sh", b"/bin/sh"),
        ("var_log", b"/var/log/syslog"),
        ("sys_kernel", b"/sys/kernel/notes"),
        ("home_bashrc", b"/home/someone/.bashrc"),
        ("double_slash_foreign", b"//etc/passwd"),
        # near-miss / nonexistent under the root
        ("nonexistent", b"/nonexistent/deep/path.bin"),
        ("near_miss", b"/have_me.binX"),
        ("case_flip", b"/HAVE_ME.BIN"),
        ("trailing_slash", b"/have_me.bin/"),
        # control / high bytes (miss)
        ("ctrl_bytes", b"/\x01\x02\x03"),
        ("newline", b"/foo\nbar"),
        ("tab", b"/foo\tbar"),
        ("high_bytes", b"/\xff\xfe\xfd"),
        # oversized (extract_path pl >= buffer -> reject)
        ("oversized", b"/" + b"z" * 1500),
        # non-absolute (payload[0] != '/')
        ("relative_file", b"have_me.bin"),
        ("relative_dir", b"foo/bar"),
        ("bare_token", b"x"),
    ]

    @pytest.mark.parametrize("path", [p for _, p in CORPUS],
                             ids=[n for n, _ in CORPUS])
    def test_adversarial_state_path_draws_no_have(self, sweep_node, path):
        base = sweep_node.count_frames(CMS_RR_HAVE)
        sweep_node.send_to_node(_SID | 0x5A, CMS_RR_STATE, CMS_MOD_RAW,
                                path + b"\x00")
        time.sleep(0.6)   # give any (wrongly) generated kYR_have time to land
        assert _node_alive(sweep_node), \
            "the node's upward leg died after an adversarial state probe"
        assert sweep_node.count_frames(CMS_RR_HAVE) == base, \
            "an adversarial state path forged a kYR_have (confinement escape)"


# ===========================================================================
# Second-wave deep-fuzz sweeps — the header modifier/streamid space, the frame
# re-assembly + pipelining paths, the LOGIN and load/avail TLV parsers, and the
# node-leg forwarded-op / redirect-injection / state-path corpora, all widened
# to hundreds of adversarial cases.  Same invariant as above: after every
# hostile frame the *other* side must still be served (server leg) or the
# upward leg must still answer (node leg).  Reuses the two module-scoped sweep
# instances so the whole second wave runs against one process per leg.
# ===========================================================================

# --- header modifier / streamid corpora ------------------------------------

# kYR_status reads the modifier as a suspend/resume/reset/stage/nostage bitset;
# sweeping the whole low-6-bit space covers every bit combination the handler
# branches on.  An unknown bit is a stock no-op, never a close (verified:
# TestServerLegEsotericOps.test_status_garbage_modifier_is_noop).
_STATUS_MODS = list(range(64))

# kYR_stats reads the modifier for the CMS_STATS_SIZE form; a full byte sweep
# (paired with the size bit) must never crash the encoder.
_STATS_MODS = list(range(32))

# Streamids that stress signedness / truncation / high-bit handling.  The
# server's do_Ping replies with a static streamid-0 pong, so the property is
# "accepted + not mis-framed", asserted by a pong coming back at all.
_STREAMIDS = [
    0x00000000, 0x00000001, 0x00000002, 0x000000FF, 0x00000100, 0x00000101,
    0x00007FFF, 0x00008000, 0x0000FFFF, 0x00010000, 0x00FF00FF, 0x0100_0000,
    0x7FFFFFFF, 0x80000000, 0x80000001, 0xC0000000, 0xDEADBEEF, 0xF0F0F0F0,
    0xFFFF0000, 0x0000FFFE, 0xFFFFFFFE, 0xFFFFFFFF, 0xABAD1DEA, 0x40C50000,
]


class TestServerModifierByteSweep:
    """Every low-band kYR_status modifier and kYR_stats modifier, one at a time
    on a single logged-in link, each re-proving the *same* connection stays
    frame-aligned and answers a ping — the header modifier byte can never
    desync the parser or crash the handler."""

    @pytest.fixture(scope="class")
    def status_link(self, sweep_server):
        sock = _login_server(sweep_server.port)
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("mod", _STATUS_MODS, ids=[str(m) for m in _STATUS_MODS])
    def test_status_modifier_keeps_link_aligned(self, status_link, mod):
        status_link.sendall(_build_frame(0, CMS_RR_STATUS, mod))
        status_link.sendall(_build_frame(_SID | 0x90, CMS_RR_PING, 0))
        assert _recv_code(status_link, CMS_RR_PONG, timeout=6) is not None, \
            f"kYR_status modifier {mod} desynced the link"

    @pytest.mark.parametrize("mod", _STATS_MODS, ids=[str(m) for m in _STATS_MODS])
    def test_stats_modifier_no_crash(self, sweep_server, mod):
        sock = _login_server(sweep_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x91, CMS_RR_STATS,
                                      mod | CMS_STATS_SIZE))
            time.sleep(0.05)
        finally:
            sock.close()
        assert _server_alive(sweep_server.port), \
            f"kYR_stats modifier {mod} crashed the accept leg"


class TestServerStreamidSweep:
    """A ping at each adversarial streamid is parsed without a signedness or
    truncation bug and answered — the 32-bit streamid word is treated as the
    unsigned wire value throughout."""

    @pytest.mark.parametrize("sid", _STREAMIDS,
                             ids=["0x%08x" % s for s in _STREAMIDS])
    def test_extreme_streamid_ping_answered(self, sweep_server, sid):
        sock = socket.create_connection((H, sweep_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(sid, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=6)
            assert fr is not None, f"streamid 0x{sid:08x} ping was not answered"
        finally:
            sock.close()


# --- fragmentation / pipelining --------------------------------------------

# A composite buffer: an unknown-opcode junk frame (dropped) immediately
# followed by a real ping (answered).  Splitting it at every interesting offset
# proves the accumulator reassembles a header/body straddling a recv() edge and
# never mis-frames the trailing ping.
_FRAG_BASE = (_build_frame(_SID | 0x7C, 0x7E, 0, bytes(16))
              + _build_frame(_SID | 0x7D, CMS_RR_PING, 0))
_FRAG_OFFSETS = [1, 2, 3, 4, 7, 8, 9, 12, 16, 20, 23, 24, 25, 28, 30, 31]

# Pipeline depths spanning the 64-frame fairness batch boundary and well beyond.
_PIPELINE_NS = [1, 2, 3, 4, 8, 16, 31, 32, 33, 48, 63, 64, 65, 96, 128, 192,
                256, 384, 512]


class TestServerFragmentationSweep:
    """The junk+ping composite split at every interesting byte offset — each a
    fresh connection — must always drop the junk and answer the ping,
    reassembling across the segment boundary."""

    @pytest.mark.parametrize("off", _FRAG_OFFSETS, ids=[str(o) for o in _FRAG_OFFSETS])
    def test_split_frame_reassembled(self, sweep_server, off):
        sock = socket.create_connection((H, sweep_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_FRAG_BASE[:off])
            time.sleep(0.05)
            sock.sendall(_FRAG_BASE[off:])
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                f"a frame split at offset {off} was not reassembled"
        finally:
            sock.close()


class TestServerPipeliningSweep:
    """N back-to-back ping frames in a single write must draw exactly N pongs —
    no frame dropped at the 64-per-wakeup fairness boundary, all excess
    reassembled across subsequent wakeups."""

    @pytest.mark.parametrize("n", _PIPELINE_NS, ids=[str(n) for n in _PIPELINE_NS])
    def test_pipelined_pings_all_answered(self, sweep_server, n):
        sock = socket.create_connection((H, sweep_server.port), timeout=8)
        sock.settimeout(8)
        try:
            sock.sendall(b"".join(
                _build_frame(_SID | (i & 0xFFFF), CMS_RR_PING, 0)
                for i in range(n)))
            got = 0
            for _ in range(n):
                if _recv_code(sock, CMS_RR_PONG, timeout=8) is None:
                    break
                got += 1
            assert got == n, f"pipelined {n} pings drew only {got} pongs"
        finally:
            sock.close()


# --- LOGIN + load/avail TLV parser fuzz ------------------------------------

_GOOD_LOGIN = _minimal_login_payload(NODE_DATA_PORT, b"r /data")
_LOGIN_FUZZ = [
    ("empty", b""),
    ("one_byte", b"\x00"),
    ("short2", b"\x80\x00"),
    ("short3", b"\xa0\x00\x00"),
    ("tag_short_only", bytes([CMS_PT_SHORT])),
    ("tag_int_only", bytes([CMS_PT_INT])),
    ("badtag0_8", b"\x00" * 8),
    ("badtagff_8", b"\xff" * 8),
    ("ff16", b"\xff" * 16),
    ("ff64", b"\xff" * 64),
    ("ff300", b"\xff" * 300),
    ("zero16", b"\x00" * 16),
    ("zero64", b"\x00" * 64),
    ("zero300", b"\x00" * 300),
    ("rand31", bytes(range(31))),
    ("rand200", bytes((i * 7) & 0xFF for i in range(200))),
] + [("trunc_%d" % n, _GOOD_LOGIN[:n])
     for n in (2, 4, 6, 9, 13, 17, 21, 27, 33, 41, 55, len(_GOOD_LOGIN) - 1)] + [
    ("good_tail_junk", _GOOD_LOGIN + b"\xff" * 24),
    ("good_tail_zeros", _GOOD_LOGIN + b"\x00" * 512),
]

_TLV_FUZZ = [
    ("empty", b""),
    ("short_tag", bytes([CMS_PT_SHORT])),
    ("int_tag", bytes([CMS_PT_INT])),
    ("short_partial", bytes([CMS_PT_SHORT, 0x00])),
    ("int_partial1", bytes([CMS_PT_INT, 0x00])),
    ("int_partial3", bytes([CMS_PT_INT, 0x00, 0x00, 0x00])),
    ("bad_tag_00", b"\x00\x00\x00"),
    ("bad_tag_ff", b"\xff\xff\xff\xff"),
    ("bad_tag_7f", b"\x7f\x11\x22"),
    ("short_max", bytes([CMS_PT_SHORT, 0xFF, 0xFF])),
    ("int_max", bytes([CMS_PT_INT]) + b"\xff\xff\xff\xff"),
    ("count_then_trunc", bytes([CMS_PT_SHORT, 0x00, 0x06]) + b"\x00" * 6
     + bytes([CMS_PT_SHORT, 0xFF, 0xFF])),
    ("only_cpu", bytes([CMS_PT_SHORT, 0x00, 0x06]) + b"\x11" * 6),
    ("cpu_trunc", bytes([CMS_PT_SHORT, 0x00, 0x06]) + b"\x11" * 3),
    ("double_int", bytes([CMS_PT_INT]) + b"\x00\x00\x27\x10"
     + bytes([CMS_PT_INT]) + b"\x00\x00\x00\x0a"),
    ("nested_tags", bytes([CMS_PT_SHORT, CMS_PT_INT, CMS_PT_SHORT])),
    ("ff32", b"\xff" * 32),
    ("zeros32", b"\x00" * 32),
    ("rand40", bytes((i * 13) & 0xFF for i in range(40))),
    ("alt_tags", bytes(CMS_PT_SHORT if i % 2 else CMS_PT_INT
                       for i in range(20))),
    ("short_then_int_trunc", bytes([CMS_PT_SHORT, 0x00, 0x03, CMS_PT_INT, 0x00])),
    ("giant_short_run", bytes([CMS_PT_SHORT]) * 100),
    ("giant_int_run", bytes([CMS_PT_INT]) * 100),
    ("one_byte", b"\x2a"),
]


class TestServerLoginFuzzSweep:
    """A broad corpus of malformed CmsLoginData payloads on the accept leg.
    Each may cost the offender its own connection, but the accept leg must keep
    serving a fresh, well-behaved client — a hostile login can never wedge the
    single worker."""

    @pytest.mark.parametrize("payload", [p for _, p in _LOGIN_FUZZ],
                             ids=[n for n, _ in _LOGIN_FUZZ])
    def test_malformed_login_keeps_server_alive(self, sweep_server, payload):
        try:
            bad = _node_login_dialog(sweep_server.port, payload)
        except OSError:
            # even the connect/handshake failing is fine — what matters is the
            # server still serves others.
            assert _server_alive(sweep_server.port)
            return
        try:
            time.sleep(0.05)
            assert _server_alive(sweep_server.port), \
                "a malformed login took the accept leg down for other clients"
        finally:
            bad.close()


class TestServerLoadAvailTlvFuzzSweep:
    """The load/avail TLV reader fed a broad corpus of malformed payloads on a
    single logged-in link: the bounded reader decodes missing/garbage fields as
    zero (documented posture) and never over-reads — the same link answers a
    ping after each."""

    @pytest.fixture(scope="class")
    def tlv_link(self, sweep_server):
        sock = _login_server(sweep_server.port)
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("payload", [p for _, p in _TLV_FUZZ],
                             ids=[n for n, _ in _TLV_FUZZ])
    def test_load_tlv_fuzz_recovers(self, tlv_link, payload):
        tlv_link.sendall(_build_frame(0, CMS_RR_LOAD, 0, payload))
        tlv_link.sendall(_build_frame(_SID | 0x92, CMS_RR_PING, 0))
        assert _recv_code(tlv_link, CMS_RR_PONG, timeout=6) is not None, \
            "a malformed kYR_load TLV payload wedged the link"


# --- node-leg forwarded-op / redirect / state fuzz -------------------------

_FWD_OPS = [
    ("chmod", CMS_RR_CHMOD), ("mkdir", CMS_RR_MKDIR), ("mkpath", CMS_RR_MKPATH),
    ("mv", CMS_RR_MV), ("rm", CMS_RR_RM), ("rmdir", CMS_RR_RMDIR),
    ("trunc", CMS_RR_TRUNC), ("prepadd", CMS_RR_PREPADD),
    ("prepdel", CMS_RR_PREPDEL),
]
_FWD_VARIANTS = [
    ("empty", b""),
    ("trunc_pup", b"\x00\x64ab"),
    ("garbage", bytes(range(32))),
    ("traversal", _fwd_a_payload(b"mgr", b"493", b"/../pwn")),
    ("embedded_nul", _fwd_a_payload(b"mgr", b"493", b"/a\x00b/c")),
]
_FWD_MATRIX = [("%s_%s" % (on, vn), oc, pv)
               for on, oc in _FWD_OPS for vn, pv in _FWD_VARIANTS]

_REDIR_FUZZ = [
    ("empty", b""),
    ("ab", b"ab"),
    ("host_nul_only", b"host\x00"),
    ("valid", b"good.example\x00" + (1094).to_bytes(2, "big")),
    ("port0", b"h\x00" + (0).to_bytes(2, "big")),
    ("portmax", b"h\x00" + (0xFFFF).to_bytes(2, "big")),
    ("no_nul", b"hostwithoutnul"),
    ("nul_first", b"\x00" + (1094).to_bytes(2, "big")),
    ("embedded_nul", b"ho\x00st\x00" + (1094).to_bytes(2, "big")),
    ("long_host", b"h" * 300 + b"\x00" + (1094).to_bytes(2, "big")),
    ("many_hosts", b"".join(b"h%d.ex\x00" % i + (1000 + i).to_bytes(2, "big")
                            for i in range(50))),
    ("nonascii", b"\xff\xfe host\x00" + (1094).to_bytes(2, "big")),
    ("only_port", (1094).to_bytes(2, "big")),
    ("trailing_junk", b"h\x00" + (1094).to_bytes(2, "big") + b"\xff" * 20),
    ("newline_host", b"ho\nst\x00" + (1094).to_bytes(2, "big")),
    ("spaces", b"   \x00" + (1094).to_bytes(2, "big")),
]
_REDIR_MATRIX = [("select_%s" % n, CMS_RR_SELECT, p) for n, p in _REDIR_FUZZ] \
    + [("try_%s" % n, CMS_RR_TRY, p) for n, p in _REDIR_FUZZ]

# A second, disjoint corpus of adversarial kYR_state paths (none overlap the
# first corpus, none resolve to the resident /have_me.bin) — every one must
# draw NO kYR_have from the confined data node.
_STATE_CORPUS_2 = [
    ("proc_environ", b"/proc/self/environ"),
    ("proc_root", b"/proc/1/root/etc/passwd"),
    ("proc_cmdline", b"/proc/self/cmdline"),
    ("proc_mounts", b"/proc/mounts"),
    ("dev_null", b"/dev/null"),
    ("dev_mem", b"/dev/mem"),
    ("dev_kmsg", b"/dev/kmsg"),
    ("dev_random", b"/dev/random"),
    ("sys_net", b"/sys/class/net/eth0/address"),
    ("sys_firmware", b"/sys/firmware/efi"),
    ("run_secret", b"/run/secrets/token"),
    ("docker_sock", b"/var/run/docker.sock"),
    ("boot_kernel", b"/boot/vmlinuz"),
    ("libc", b"/lib/x86_64-linux-gnu/libc.so.6"),
    ("opt_secret", b"/opt/secret/key"),
    ("srv_other", b"/srv/other/data"),
    ("mnt_foreign", b"/mnt/foreign/vol"),
    ("media_usb", b"/media/usb/stick"),
    ("trailing_space", b"/have_me.bin "),
    ("leading_space", b"/ have_me.bin"),
    ("prefix_only", b"/have_me"),
    ("suffix_only", b"/e_me.bin"),
    ("dotdot_to_resident", b"/xyz/../have_me.bin"),
    ("utf8_accent", "/café/passwd".encode("utf-8")),
    ("utf8_cjk", "/日本/secret".encode("utf-8")),
    ("many_components", b"/" + b"deep/" * 50 + b"x"),
    ("long_component", b"/" + b"a" * 500),
    ("mixed_slashes", b"/a///b////c"),
]


class TestNodeForwardedOpFuzzSweep:
    """Every forwarded namespace opcode × a corpus of malformed/adversarial
    payloads thrown DOWN the upward leg.  None may crash, wedge, or force the
    node to hang up (reconnect): after each the upward leg still answers and the
    login count is unchanged."""

    @pytest.mark.parametrize("code,payload", [(c, p) for _, c, p in _FWD_MATRIX],
                             ids=[n for n, _, _ in _FWD_MATRIX])
    def test_forwarded_op_fuzz_no_hangup(self, sweep_node, code, payload):
        base = sweep_node.count_frames(CMS_RR_LOGIN)
        try:
            sweep_node.send_to_node(_SID | code, code, 0, payload)
        except (AssertionError, OSError):
            pass   # mid-reconnect window from a prior case — liveness check follows
        time.sleep(0.1)
        assert sweep_node.count_frames(CMS_RR_LOGIN) == base, \
            f"forwarded op 0x{code:02x} forced the node to hang up + reconnect"
        assert _node_alive(sweep_node), \
            f"forwarded op 0x{code:02x} wedged the node's upward leg"


class TestNodeRedirectInjectionSweep:
    """MITM redirect-injection at scale: unsolicited kYR_select / kYR_try with a
    broad corpus of host-list payloads for a streamid with no pending locate.
    None may steer the node (it never issued the locate) nor make it hang up —
    the upward leg stays connected and answering."""

    @pytest.mark.parametrize("code,payload", [(c, p) for _, c, p in _REDIR_MATRIX],
                             ids=[n for n, _, _ in _REDIR_MATRIX])
    def test_redirect_injection_steers_nothing(self, sweep_node, code, payload):
        base = sweep_node.count_frames(CMS_RR_LOGIN)
        try:
            sweep_node.send_to_node(_SID | 0x99, code, 0, payload)
        except (AssertionError, OSError):
            pass
        time.sleep(0.1)
        assert sweep_node.count_frames(CMS_RR_LOGIN) == base, \
            f"an injected redirect (op 0x{code:02x}) made the node hang up"
        assert _node_alive(sweep_node), \
            f"an injected redirect (op 0x{code:02x}) wedged the upward leg"


class TestNodeStatePathCorpusExtended:
    """A second, disjoint corpus of adversarial kYR_state paths — /proc, /dev,
    /sys, secrets, UTF-8, oversized-but-in-buffer, and near-miss — each drawing
    NO kYR_have from a data node holding only /have_me.bin."""

    @pytest.mark.parametrize("path", [p for _, p in _STATE_CORPUS_2],
                             ids=[n for n, _ in _STATE_CORPUS_2])
    def test_extended_state_path_draws_no_have(self, sweep_node, path):
        base = sweep_node.count_frames(CMS_RR_HAVE)
        sweep_node.send_to_node(_SID | 0x5B, CMS_RR_STATE, CMS_MOD_RAW,
                                path + b"\x00")
        time.sleep(0.4)
        assert _node_alive(sweep_node), \
            "the node's upward leg died after an extended state probe"
        assert sweep_node.count_frames(CMS_RR_HAVE) == base, \
            "an extended adversarial state path forged a kYR_have"


# ===========================================================================
# WAVE-3 exhaustive fuzz (+469 -> >=1000 total): carpet-bomb both legs across
# the modifier, streamid, login-value, ingest, forwarded-op, resync and
# concurrency axes.  Every case re-proves the MITM's core promise -- a hostile
# frame on either leg can never wedge, desync, or hang up the proxy for the
# honest peer on the *other* side.  Server-leg classes come first (sweep_server
# is order-independent); the node-leg classes are appended LAST so the shared
# sweep_node is never mid-DISC-reconnect from an earlier barrage when they run.
# ===========================================================================

# 24 modifier bytes: every low nibble, the 0x40 flag band, the 0x80 "raw form"
# bit and the high 0xE0..0xFF range.
_OP_MODS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0A, 0x0F, 0x10, 0x1F, 0x20, 0x3F,
            0x40, 0x7F, 0x80, 0xBF, 0xC0, 0xE0, 0xFE, 0xFF]

# The six accept-leg opcodes that take a body but emit NO reply frame, so an
# empty-payload probe leaves the shared link clean for the trailing ping.
_SILENT_SRV_OPS = [
    ("state", CMS_RR_STATE), ("have", CMS_RR_HAVE), ("load", CMS_RR_LOAD),
    ("avail", CMS_RR_AVAIL), ("gone", CMS_RR_GONE), ("status", CMS_RR_STATUS),
]
_OP_MOD_CASES = [(name, code, mod)
                 for name, code in _SILENT_SRV_OPS for mod in _OP_MODS]


class TestServerOpModifierMatrix:
    """Each body-carrying accept-leg opcode, empty-bodied, swept across 24
    modifier bytes on ONE logged-in link.  A weird modifier can neither desync
    the framer nor close the connection: the same link keeps answering a
    ping (empty kYR_state is already known to survive same-conn, and the
    modifier byte never gates a close)."""

    @pytest.fixture(scope="class")
    def op_link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("name,code,mod", _OP_MOD_CASES,
                             ids=["%s_m%02x" % (n, m) for n, _c, m in _OP_MOD_CASES])
    def test_op_modifier_keeps_link_aligned(self, op_link, name, code, mod):
        op_link.sendall(_build_frame(_SID | 0xA0, code, mod))
        op_link.sendall(_build_frame(_SID | 0xA1, CMS_RR_PING, 0))
        assert _recv_code(op_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_%s modifier 0x%02x desynced the accept leg" % (name, mod)


# 24 distinct 32-bit login mode words spanning single role bits, flag
# combinations and the sign boundary -- every classification must still yield a
# serviceable registration (the Admit path classifies by bits, never rejects).
_MODE_WORDS = [
    0x00000000, 0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x0000000A,
    0x00000010, 0x00000020, 0x00000040, 0x0000001F, 0x000000FF, 0x00000100,
    0x00008000, 0x00010000, 0x08000000, 0x40000000, 0x80000000, 0xC000000A,
    0x0000FFFF, 0xFFFF0000, 0xFFFFFFFF, 0xDEADBEEF, 0x02020202, 0x0A0A0A0A,
]


class TestServerLoginModeWordSweep:
    """A structurally valid login carrying each esoteric role/mode word must
    register a HEALTHY link -- the classifier can never leave a peer half-open
    or refuse to service a subsequent ping."""

    @pytest.mark.parametrize("mode", _MODE_WORDS,
                             ids=["0x%08x" % m for m in _MODE_WORDS])
    def test_mode_word_registers_healthy(self, sweep_server, mode):
        sock = _node_login_dialog(
            sweep_server.port,
            _login_payload_with_mode(NODE_DATA_PORT, mode, paths=b"r /data"))
        sock.settimeout(6)
        try:
            time.sleep(0.2)
            sock.sendall(_build_frame(_SID | 0xB0, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "login mode word 0x%08x did not yield a serviceable link" % mode
        finally:
            sock.close()


# Edge advertised-data-port values (u16). Whether or not a given port is
# accepted, an edge value can never wedge the accept leg for other peers.
_LOGIN_PORTS = [1, 2, 80, 443, 1024, 1094, 1095, 8443, 20000, 32767, 32768,
                49152, 60000, 65534, 65535, 1200]


class TestServerLoginPortSweep:
    """A login advertising each edge data port must leave the accept leg
    serving a fresh client -- a bogus port can never take the worker down."""

    @pytest.mark.parametrize("dport", _LOGIN_PORTS, ids=[str(p) for p in _LOGIN_PORTS])
    def test_login_data_port_does_not_wedge(self, sweep_server, dport):
        try:
            _node_login_dialog(
                sweep_server.port,
                _minimal_login_payload(dport, b"r /data")).close()
        except OSError:
            pass
        assert _server_alive(sweep_server.port), \
            "a login advertising data port %d wedged the accept leg" % dport


# Structurally valid logins carrying edge / hostile path declarations. None may
# wedge the accept leg (offender may be refused; a fresh client is still served).
_LOGIN_PATH_CORPUS = [
    ("empty", b""),
    ("root", b"r /"),
    ("data", b"r /data"),
    ("write", b"w /data"),
    ("rw_split", b"r /data w /data"),
    ("two_lines", b"r /a\nr /b"),
    ("traversal", b"r /../etc"),
    ("deep", b"r /a/b/c/d/e"),
    ("many", b"\n".join(b"r /p%d" % i for i in range(20))),
    ("hundred", b"\n".join(b"r /export/deep/%03d" % i for i in range(100))),
    ("dot", b"r /."),
    ("dotdot_only", b"r /.."),
    ("trailing_slash", b"r /data/"),
    ("double_slash", b"r //data"),
    ("embedded_space", b"r / data"),
    ("nonascii", b"r /d\xc3\xa9ta"),
    ("embedded_nul", b"r /da\x00ta"),
    ("no_flag", b"/data"),
    ("bad_flag", b"x /data"),
    ("flag_only", b"r"),
    ("flag_space", b"r "),
    ("rw_flags", b"rw /data"),
    ("tab_sep", b"r\t/data"),
    ("long_single", b"r /" + b"a" * 400),
]


class TestServerLoginPathListCorpus:
    """Every edge / hostile export declaration in a login: bounded copy, no
    escape, no wedge.  A fresh client is always served afterwards."""

    @pytest.mark.parametrize("paths", [p for _, p in _LOGIN_PATH_CORPUS],
                             ids=[n for n, _ in _LOGIN_PATH_CORPUS])
    def test_edge_path_declaration_does_not_wedge(self, sweep_server, paths):
        try:
            _node_login_dialog(
                sweep_server.port,
                _minimal_login_payload(NODE_DATA_PORT, paths)).close()
        except OSError:
            pass
        assert _server_alive(sweep_server.port), \
            "an edge path declaration wedged the accept leg"


# kYR_have ingest fuzz: a logged-in child advertising foreign / covered /
# traversal paths under every online/pending/raw modifier.  The paths-cover gate
# (and relay-take, which finds no entry) drops the foreign advertisements; the
# connection stays frame-aligned throughout.
_HAVE_PATHS = [
    ("foreign_passwd", b"/etc/passwd"),
    ("empty", b""),
    ("covered_root", b"/data"),
    ("covered_child", b"/data/have_me.bin"),
    ("traversal", b"/../etc/shadow"),
    ("proc", b"/proc/self/maps"),
]
_HAVE_MODS = [CMS_MOD_RAW | CMS_HAVE_ONLINE, CMS_MOD_RAW, CMS_HAVE_ONLINE, 0, 0xFF]
_HAVE_CASES = [(pn, pv, m) for pn, pv in _HAVE_PATHS for m in _HAVE_MODS]


class TestServerHaveIngestFuzz:
    """Adversarial kYR_have advertisements (foreign / covered / traversal paths
    x online/pending/raw modifiers) on one logged-in link never desync the
    framer nor drop the connection."""

    @pytest.fixture(scope="class")
    def have_link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("pv,mod", [(pv, m) for _pn, pv, m in _HAVE_CASES],
                             ids=["%s_m%02x" % (pn, m) for pn, _pv, m in _HAVE_CASES])
    def test_have_ingest_keeps_link_aligned(self, have_link, pv, mod):
        body = (pv + b"\x00") if pv else b""
        have_link.sendall(_build_frame(_SID | 0xC0, CMS_RR_HAVE, mod, body))
        have_link.sendall(_build_frame(_SID | 0xC1, CMS_RR_PING, 0))
        assert _recv_code(have_link, CMS_RR_PONG, timeout=6) is not None, \
            "a kYR_have advertisement (mod 0x%02x) desynced the accept leg" % mod


# kYR_gone for an adversarial path set: an unheld gone is a no-op, the framer
# stays aligned, and no path string can crash the handler.
_GONE_PATHS = [
    ("foreign", b"/etc/passwd"), ("covered", b"/data"),
    ("covered_child", b"/data/have_me.bin"), ("empty", b""), ("root", b"/"),
    ("dotdot", b"/.."), ("deep_dotdot", b"/../../root"),
    ("proc", b"/proc/1/environ"), ("dev", b"/dev/null"), ("sys", b"/sys/kernel"),
    ("mid_dotdot", b"/data/../etc"), ("dot_seg", b"/data/./x"),
    ("double_lead", b"//data"), ("double_mid", b"/data//x"),
    ("deep_chain", b"/a/b/c/d/e/f/g"), ("long", b"/" + b"z" * 300),
    ("trailing_space", b"/data "), ("leading_space", b"  /data"),
    ("embedded_nul", b"/da\x00ta"), ("tab", b"/tab\tpath"),
    ("nonascii", b"/uni\xc3\xa9"), ("backslash", b"/mixed\\slash"),
    ("trailing_slash", b"/data/"), ("bare_name", b"CVE"),
]


class TestServerGonePathCorpus:
    """kYR_gone for every adversarial path -- an unheld gone is a bounded no-op
    that leaves the connection aligned and answering a ping."""

    @pytest.fixture(scope="class")
    def gone_link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("path", [p for _, p in _GONE_PATHS],
                             ids=[n for n, _ in _GONE_PATHS])
    def test_gone_path_keeps_link_aligned(self, gone_link, path):
        body = (path + b"\x00") if path else b""
        gone_link.sendall(_build_frame(_SID | 0xF0, CMS_RR_GONE, 0, body))
        gone_link.sendall(_build_frame(_SID | 0xF1, CMS_RR_PING, 0))
        assert _recv_code(gone_link, CMS_RR_PONG, timeout=6) is not None, \
            "a kYR_gone for an adversarial path desynced the accept leg"


# kYR_error frames the manager may receive from a child: every ecode x text
# length is logged/dropped without a bound-read past the payload.
_ERR_CASES = [(ec, tl) for ec in (0, 1, 22, 0xDEADBEEF)
              for tl in (0, 1, 16, 100, 1000, 3000)]


class TestServerErrorFrameCorpus:
    """A received kYR_error (RSP_ERROR) with each ecode / text length is
    consumed exactly, never over-read; the connection stays aligned."""

    @pytest.fixture(scope="class")
    def err_link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("ecode,tlen", _ERR_CASES,
                             ids=["e%08x_t%d" % (ec, tl) for ec, tl in _ERR_CASES])
    def test_error_frame_keeps_link_aligned(self, err_link, ecode, tlen):
        payload = ecode.to_bytes(4, "big") + b"E" * tlen
        err_link.sendall(_build_frame(_SID | 0xE8, CMS_RSP_ERROR, 0, payload))
        err_link.sendall(_build_frame(_SID | 0xE9, CMS_RR_PING, 0))
        assert _recv_code(err_link, CMS_RR_PONG, timeout=6) is not None, \
            "a received kYR_error (ecode 0x%08x, %d text bytes) desynced the " \
            "accept leg" % (ecode, tlen)


# Interleave-resync: a valid ping, then ONE arbitrary opcode frame carrying a
# 16-byte body, then a second ping.  The framer must stay aligned across the
# interposed frame and answer the trailing ping.  DISC/XAUTH are excluded (they
# legitimately close the offender pre-login, which is a *different*, already
# covered, behaviour).
_RESYNC_OPS = [(n, c) for n, c in _SWEEP_OPS if n not in ("disc", "xauth")]


class TestServerInterleaveResyncMatrix:
    """A fresh connection: ping (answered) / one arbitrary opcode+body / ping.
    The second pong proves the accumulator resynced past the interposed frame
    -- no opcode can slide the framer out of alignment."""

    @pytest.mark.parametrize("name,code", _RESYNC_OPS,
                             ids=[n for n, _ in _RESYNC_OPS])
    def test_junk_between_pings_resyncs(self, sweep_server, name, code):
        sock = socket.create_connection((H, sweep_server.port), timeout=8)
        sock.settimeout(8)
        try:
            sock.sendall(_build_frame(_SID | 0xD0, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "the first ping was not answered"
            sock.sendall(_build_frame(_SID | 0xD1, code, 0, bytes(16)))
            sock.sendall(_build_frame(_SID | 0xD2, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "the framer failed to resync after an interleaved 0x%02x frame" % code
        finally:
            sock.close()


# Concurrent hostile storm: N simultaneous peers each running one attack, then a
# fresh honest client must still be admitted and answered.  This is the headline
# stock-cmsd failure this MITM removes -- one hostile peer (or a swarm) must
# never head-of-line-block the single worker.
def _atk_garbage(s):
    s.sendall(b"\xff" * 8192)


def _atk_oversized(s):
    s.sendall(_build_frame(0, CMS_RR_LOGIN, 0, b"\x00" * 5000))


def _atk_zeroflood(s):
    s.sendall(b"".join(_build_frame(i, 0x7F, 0) for i in range(300)))


def _atk_pingflood(s):
    s.sendall(b"".join(_build_frame(_SID | (i & 0xFFFF), CMS_RR_PING, 0)
                       for i in range(2000)))


def _atk_halfopen(s):
    s.sendall(_build_frame(_SID | 1, CMS_RR_PING, 0))
    s.shutdown(socket.SHUT_WR)


def _atk_partial(s):
    s.sendall(b"\x00\x00\x00\x00")   # 4-byte dangling header, then idle


_STORM_ATTACKS = [("garbage", _atk_garbage), ("oversized", _atk_oversized),
                  ("zeroflood", _atk_zeroflood), ("pingflood", _atk_pingflood),
                  ("halfopen", _atk_halfopen), ("partial", _atk_partial)]
_STORM_CONC = [2, 4, 8]
_STORM_CASES = [(an, af, c) for an, af in _STORM_ATTACKS for c in _STORM_CONC]


class TestServerConcurrentStormMatrix:
    """N concurrent hostile peers (per attack) can never wedge the accept leg --
    a fresh client is admitted and answered while the storm is still open."""

    @pytest.mark.parametrize("name,attack,conc", _STORM_CASES,
                             ids=["%s_x%d" % (an, c) for an, _af, c in _STORM_CASES])
    def test_concurrent_hostile_storm_survived(self, sweep_server, name, attack, conc):
        socks = []
        try:
            for _ in range(conc):
                s = socket.create_connection((H, sweep_server.port), timeout=6)
                s.settimeout(4)
                try:
                    attack(s)
                except OSError:
                    pass   # e.g. oversized closes the offender mid-write
                socks.append(s)
            time.sleep(0.1)
            assert _server_alive(sweep_server.port), \
                "%d concurrent '%s' peers wedged the accept leg" % (conc, name)
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass


# ===========================================================================
# NODE-LEG wave-3 classes -- appended LAST so the shared sweep_node is settled
# (never mid-DISC-reconnect from an earlier node barrage) when they start.
# ===========================================================================

# 12 modifier bytes down into the node's manager leg.
_NODE_MODS = [0, 1, 2, 3, 4, 8, 0x10, 0x40, 0x7F, 0x80, 0xC0, 0xFF]
_NODE_MOD_OPS = [
    ("state", CMS_RR_STATE), ("have", CMS_RR_HAVE), ("load", CMS_RR_LOAD),
    ("avail", CMS_RR_AVAIL), ("status", CMS_RR_STATUS), ("space", CMS_RR_SPACE),
]
_NODE_MOD_CASES = [(n, c, m) for n, c in _NODE_MOD_OPS for m in _NODE_MODS]


class TestNodeOpModifierMatrix:
    """Each manager-leg opcode, empty-bodied, swept across 12 modifier bytes
    DOWN into the node.  A weird modifier can never permanently hang up the
    node's upward leg (it survives, reconnecting if it must)."""

    @pytest.mark.parametrize("name,code,mod", _NODE_MOD_CASES,
                             ids=["%s_m%02x" % (n, m) for n, _c, m in _NODE_MOD_CASES])
    def test_node_op_modifier_survives(self, sweep_node, name, code, mod):
        try:
            sweep_node.send_to_node(_SID | 0xE0, code, mod)
        except (AssertionError, OSError, AttributeError):
            pass   # mid-reconnect window
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_%s modifier 0x%02x" % (name, mod)


class TestNodeStreamidSweep:
    """A ping DOWN into the node at each adversarial streamid: the node parses
    the unsigned 32-bit word and keeps its upward leg alive."""

    @pytest.mark.parametrize("sid", _STREAMIDS, ids=["0x%08x" % s for s in _STREAMIDS])
    def test_node_extreme_streamid_survives(self, sweep_node, sid):
        try:
            sweep_node.send_to_node(sid, CMS_RR_PING, 0)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after a ping at streamid 0x%08x" % sid


# Downward flood: 120 back-to-back frames of one opcode (garbage-bodied) rained
# down on the node, then the upward manager ping must still be answered.  DISC is
# excluded (a DISC flood is a deliberate reconnect storm, covered elsewhere).
_FLOOD_OPS = [(n, c) for n, c in _SWEEP_OPS if n != "disc"]


class TestNodeDownwardFloodMatrix:
    """A 120-frame downward flood of each opcode can never wedge the node's
    upward leg -- the manager ping is answered after the barrage (through a
    reconnect if one was forced)."""

    @pytest.mark.parametrize("name,code", _FLOOD_OPS, ids=[n for n, _ in _FLOOD_OPS])
    def test_downward_flood_keeps_upward_leg(self, sweep_node, name, code):
        for i in range(120):
            try:
                sweep_node.send_to_node(_SID | (i & 0xFFFF), code, 0, _SWEEP_GARBAGE)
            except (AssertionError, OSError, AttributeError):
                break   # mid-reconnect; the survive check re-establishes below
        assert _node_survives(sweep_node), \
            "a 120-frame downward '%s' flood wedged the node's upward leg" % name


# ===========================================================================
# WAVE-4 full-byte exhaustive sweeps (+1280 -> >=2000 total): drive the modifier
# and opcode bytes across their ENTIRE 0..255 range on both legs.  No single byte
# value -- however esoteric or undefined -- may desync the framer, crash a
# handler, or hang up the proxy for the peer on the other side.  The four
# server-leg classes come first (giving the shared node time to settle after the
# wave-3 downward floods); the single node-leg class is appended LAST.
# ===========================================================================

_FULL_BYTE = list(range(256))
_BYTE_IDS = ["0x%02x" % b for b in _FULL_BYTE]


class TestServerStatusFullModifierSweep:
    """kYR_status across the ENTIRE modifier byte range on one logged-in link.
    The suspend/resume/reset/stage/nostage state machine -- and every undefined
    bit combination -- can never desync the framer nor stop the link answering a
    ping (a status update emits no reply, so the link stays balanced)."""

    @pytest.fixture(scope="class")
    def link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_status_modifier_keeps_link_aligned(self, link, mod):
        link.sendall(_build_frame(_SID | 0x100, CMS_RR_STATUS, mod))
        link.sendall(_build_frame(_SID | 0x101, CMS_RR_PING, 0))
        assert _recv_code(link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_status modifier 0x%02x desynced the accept leg" % mod


class TestServerStateFullModifierSweep:
    """kYR_state (empty body) across the ENTIRE modifier byte range on one
    logged-in link.  The 0x80 raw-form bit and every other value select a parse
    form, but an empty body always fails path extraction and is dropped -- no
    modifier can close the connection or misframe the trailing ping."""

    @pytest.fixture(scope="class")
    def link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_state_modifier_keeps_link_aligned(self, link, mod):
        link.sendall(_build_frame(_SID | 0x110, CMS_RR_STATE, mod))
        link.sendall(_build_frame(_SID | 0x111, CMS_RR_PING, 0))
        assert _recv_code(link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_state modifier 0x%02x desynced the accept leg" % mod


class TestServerHaveFullModifierSweep:
    """kYR_have for a foreign path across the ENTIRE modifier byte range on one
    logged-in link.  Every online/pending/raw bit combination advertises a path
    outside the peer's exports, so the paths-cover gate drops it (relay-take
    finds no entry) without desyncing the link."""

    @pytest.fixture(scope="class")
    def link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_have_modifier_keeps_link_aligned(self, link, mod):
        link.sendall(_build_frame(_SID | 0x120, CMS_RR_HAVE, mod, b"/etc/passwd\x00"))
        link.sendall(_build_frame(_SID | 0x121, CMS_RR_PING, 0))
        assert _recv_code(link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_have modifier 0x%02x desynced the accept leg" % mod


class TestServerFullOpcodeByteSweep:
    """Every possible rrCode byte 0..255, garbage-bodied, on a fresh pre-login
    accept-leg connection.  The offender may be closed (malformed login, disc,
    out-of-sequence xauth, …) but a fresh client is ALWAYS served afterwards --
    no opcode byte can take the single worker down."""

    @pytest.mark.parametrize("code", _FULL_BYTE, ids=_BYTE_IDS)
    def test_opcode_byte_keeps_server_alive(self, sweep_server, code):
        junk = socket.create_connection((H, sweep_server.port), timeout=6)
        junk.settimeout(4)
        try:
            try:
                junk.sendall(_build_frame(_SID | code, code, 0, _SWEEP_GARBAGE))
            except OSError:
                pass   # offender may be torn down mid-write
            time.sleep(0.02)
            assert _server_alive(sweep_server.port), \
                "opcode byte 0x%02x took the accept leg down" % code
        finally:
            junk.close()


# --- node-leg full-byte sweep (appended LAST) ------------------------------

class TestNodeStateFullModifierSweep:
    """kYR_state (empty body) DOWN into the node across the ENTIRE modifier byte
    range.  No modifier value can permanently hang up the node's upward leg -- a
    manager ping is answered after every one (through a reconnect if forced)."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_state_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x200, CMS_RR_STATE, mod)
        except (AssertionError, OSError, AttributeError):
            pass   # mid-reconnect window
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_state modifier 0x%02x" % mod


# ===========================================================================
# WAVE-5 exhaustive full-byte + fine-grained sweeps (+2944 -> >=5000 total):
# carry the 0..255 modifier sweep across every remaining SILENT accept-leg op,
# add fine payload-length / frame-size / streamid / pipelining sweeps, and drive
# the full-byte modifier + opcode sweep across the node leg.  No byte value,
# body length, or pipeline depth may desync the framer or hang up either leg.
# Server-leg classes come first; node-leg classes are appended LAST.
# ===========================================================================


@pytest.fixture(scope="class")
def shared_srv_link(sweep_server):
    """A class-scoped logged-in accept-leg link (exports ``r /data``) reused
    across every case of a full-byte / fine-grained sweep.  The swept ops all
    emit NO reply frame, so a same-connection ping stays balanced throughout."""
    sock = _login_server(sweep_server.port, paths=b"r /data")
    try:
        yield sock
    finally:
        sock.close()


class TestServerLoadFullModifierSweep:
    """kYR_load (empty body) across the ENTIRE modifier byte range on one
    logged-in link -- a child load report is consumed as a bounded metric update
    for every modifier; the link keeps answering a ping."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_load_modifier_keeps_link_aligned(self, shared_srv_link, mod):
        shared_srv_link.sendall(_build_frame(_SID | 0x130, CMS_RR_LOAD, mod))
        shared_srv_link.sendall(_build_frame(_SID | 0x131, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_load modifier 0x%02x desynced the accept leg" % mod


class TestServerAvailFullModifierSweep:
    """kYR_avail (empty body) across the ENTIRE modifier byte range on one
    logged-in link -- a bounded free-space update for every modifier value."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_avail_modifier_keeps_link_aligned(self, shared_srv_link, mod):
        shared_srv_link.sendall(_build_frame(_SID | 0x134, CMS_RR_AVAIL, mod))
        shared_srv_link.sendall(_build_frame(_SID | 0x135, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_avail modifier 0x%02x desynced the accept leg" % mod


class TestServerGoneFullModifierSweep:
    """kYR_gone (empty body) across the ENTIRE modifier byte range on one
    logged-in link -- an unheld gone is a no-op for every modifier value."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_gone_modifier_keeps_link_aligned(self, shared_srv_link, mod):
        shared_srv_link.sendall(_build_frame(_SID | 0x138, CMS_RR_GONE, mod))
        shared_srv_link.sendall(_build_frame(_SID | 0x139, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_gone modifier 0x%02x desynced the accept leg" % mod


class TestServerStatePayloadLengthSweep:
    """kYR_state carrying a foreign path truncated to every body length 0..255 --
    the path-length decode boundary is exercised finely.  A foreign path is
    always dropped (no relay entry, not covered) so the link stays a bounded
    no-op and answers a ping after each length."""

    @pytest.mark.parametrize("blen", _FULL_BYTE, ids=_BYTE_IDS)
    def test_state_body_length_keeps_link_aligned(self, shared_srv_link, blen):
        body = (b"/" + b"a" * 255)[:blen]
        shared_srv_link.sendall(_build_frame(_SID | 0x140, CMS_RR_STATE, CMS_MOD_RAW, body))
        shared_srv_link.sendall(_build_frame(_SID | 0x141, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_state body length %d desynced the accept leg" % blen


class TestServerFrameSizeFineSweep:
    """An unknown-opcode frame at every body length 0..255 is read in full and
    dropped with the connection intact -- the length accumulator handles every
    small dlen; the same link answers a ping after each."""

    @pytest.mark.parametrize("blen", _FULL_BYTE, ids=_BYTE_IDS)
    def test_unknown_frame_length_keeps_link_aligned(self, shared_srv_link, blen):
        shared_srv_link.sendall(_build_frame(_SID | 0x150, 0x7E, 0, bytes(blen)))
        shared_srv_link.sendall(_build_frame(_SID | 0x151, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "an unknown frame of body length %d desynced the accept leg" % blen


# 256 densely-spread 32-bit streamids (0x00000000, 0x01010101, ... 0xFFFFFFFF).
_DENSE_SIDS = [(b * 0x01010101) & 0xFFFFFFFF for b in range(256)]


class TestServerStreamidDenseSweep:
    """A ping at each of 256 densely-spread streamids is parsed as the unsigned
    wire value and answered -- no streamid word can misframe or drop the ping."""

    @pytest.mark.parametrize("sid", _DENSE_SIDS, ids=["0x%08x" % s for s in _DENSE_SIDS])
    def test_dense_streamid_ping_answered(self, sweep_server, sid):
        sock = socket.create_connection((H, sweep_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(sid, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a ping at streamid 0x%08x was not answered" % sid
        finally:
            sock.close()


# Every pipeline depth 1..128, spanning the 64-per-wakeup fairness batch edge.
_PIPE_FINE = list(range(1, 129))


class TestServerPipeliningFineSweep:
    """Every pipeline depth 1..128 in a single write draws EXACTLY that many
    pongs -- no frame is dropped at the 64-per-wakeup fairness boundary, and
    every excess frame reassembles across subsequent wakeups."""

    @pytest.mark.parametrize("n", _PIPE_FINE, ids=[str(n) for n in _PIPE_FINE])
    def test_pipelined_depth_all_answered(self, sweep_server, n):
        sock = socket.create_connection((H, sweep_server.port), timeout=10)
        sock.settimeout(10)
        try:
            sock.sendall(b"".join(
                _build_frame(_SID | (i & 0xFFFF), CMS_RR_PING, 0) for i in range(n)))
            got = 0
            for _ in range(n):
                if _recv_code(sock, CMS_RR_PONG, timeout=8) is None:
                    break
                got += 1
            assert got == n, "pipelined %d pings drew only %d pongs" % (n, got)
        finally:
            sock.close()


# --- node-leg full-byte sweeps (appended LAST) -----------------------------

class TestNodeStatusFullModifierSweep:
    """kYR_status DOWN into the node across the ENTIRE modifier byte range -- the
    node's manager-leg status handler never permanently hangs up the upward leg."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_status_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x210, CMS_RR_STATUS, mod)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_status modifier 0x%02x" % mod


class TestNodeHaveFullModifierSweep:
    """kYR_have (empty body) DOWN into the node across the ENTIRE modifier byte
    range -- dropped for every online/pending/raw combination, upward leg alive."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_have_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x220, CMS_RR_HAVE, mod)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_have modifier 0x%02x" % mod


class TestNodeLoadFullModifierSweep:
    """kYR_load (empty body) DOWN into the node across the ENTIRE modifier byte
    range -- a bounded metric update for every modifier, upward leg alive."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_load_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x230, CMS_RR_LOAD, mod)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_load modifier 0x%02x" % mod


class TestNodeAvailFullModifierSweep:
    """kYR_avail (empty body) DOWN into the node across the ENTIRE modifier byte
    range -- a bounded free-space update for every modifier, upward leg alive."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_avail_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x240, CMS_RR_AVAIL, mod)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_avail modifier 0x%02x" % mod


class TestNodeOpcodeByteFullSweep:
    """Every rrCode byte 0..255, garbage-bodied, DOWN into the node.  No opcode
    value can permanently hang up the node's upward leg -- a manager ping is
    answered after each (through a forced reconnect if any)."""

    @pytest.mark.parametrize("code", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_opcode_byte_survives(self, sweep_node, code):
        try:
            sweep_node.send_to_node(_SID | (code & 0xFF), code, 0, _SWEEP_GARBAGE)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after opcode byte 0x%02x" % code
