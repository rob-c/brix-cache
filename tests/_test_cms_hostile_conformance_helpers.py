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

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-hostile")]

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
        template="nginx_cms_hostile_server.conf",
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


def _wait_have_increment(peer, base, timeout=8.0):
    """Poll until the peer has captured MORE kYR_have frames than `base`."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if peer.count_frames(CMS_RR_HAVE) > base:
            return True
        time.sleep(0.1)
    return False



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
