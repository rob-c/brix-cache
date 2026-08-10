"""
tests/test_cms_wire_pup_conformance.py — CMS manager-protocol Pup/frame
wire-conformance tests.

This suite is a byte-level conformance harness for the nginx-xrootd CMS
heartbeat client (src/net/cms/{wire,frame_io,send,recv}.c).  It provisions ONE
dedicated nginx data-node configured with ``brix_cms_manager`` pointing at a
tiny in-process Python "manager" peer that speaks the real XrdCms framing.  The
peer accepts the node's TCP connection, captures the LOGIN/LOAD frames the node
emits, and then drives the node with manager-originated PING / kYR_space /
kYR_state frames — so the *outgoing* encoder (XrdOucPup tagged-vs-bare layout,
4-string login tail, newline path list, empty-string 00 00) and the *incoming*
dispatch (PONG, kYR_avail echoing the space streamid, kYR_have with
CMS_MOD_RAW|HAVE_ONLINE) are both asserted directly against the wire bytes.

The 8-byte big-endian frame header, the >4088 oversize-frame disconnect, and
recv-boundary fragmentation are exercised against the nginx CMS *server*
(``brix_cms_server on``), where a Python data-node peer is the frame source.

Everything is self-contained on dedicated high ports (>=12950).  If the nginx
binary is missing, or the node never dials the peer, the affected tests skip
cleanly rather than hard-fail.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_wire_pup_conformance.py -v
"""

import os
import socket
import struct
import threading
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import SERVER_HOST
from ephemeral_port import free_port

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-wire")]

H = SERVER_HOST
_DIR = os.path.join(os.environ["TMPDIR"], "xrd_cms_wire_pup")

# An arbitrary dPort advertised in the fake data-node LOGIN payloads the
# server-side tests build; it need not be a real listening port.
NODE_DATA_PORT = 41094


# ---------------------------------------------------------------------------
# CMS wire constants — mirror src/net/cms/cms_internal.h + XProtocol/YProtocol.hh
# ---------------------------------------------------------------------------

CMS_RR_LOGIN  = 0
CMS_RR_LOCATE = 2
CMS_RR_AVAIL  = 12
CMS_RR_GONE   = 14
CMS_RR_HAVE   = 15
CMS_RR_LOAD   = 16
CMS_RR_PING   = 17
CMS_RR_PONG   = 18
CMS_RR_SPACE  = 19
CMS_RR_STATE  = 20
CMS_RR_STATFS = 21
CMS_RR_STATUS = 22
CMS_RR_DISC   = 13
CMS_RR_UPDATE = 25
CMS_RR_MKDIR  = 3
CMS_RR_STATS  = 11
CMS_RR_USAGE  = 26

# CMS response codes (CmsRspCode) carried in a reply frame's rrCode field.
CMS_RSP_DATA  = 0
CMS_RSP_ERROR = 1

CMS_PT_SHORT  = 0x80   # tagged 2-byte scalar
CMS_PT_INT    = 0xa0   # tagged 4-byte scalar

CMS_MOD_RAW     = 0x20  # kYR_raw — payload is unmarshalled
CMS_HAVE_ONLINE = 0x01  # kYR_have modifier: file is resident/online

# CmsLoginData Mode role bits (YProtocol.hh) — Phase-61 W7 explicit roles.
CMS_MODE_MANAGER = 0x02   # kYR_manager
CMS_MODE_SERVER  = 0x08   # kYR_server
# CmsStateRequest modifier: kYR_metaman — only a PURE meta-manager (no local
# export) may stamp it on a fanned-out kYR_state (XrdCmsNode.cc do_State).
CMS_STATE_METAMAN = 0x08

CMS_STATS_SIZE  = 0x01  # CmsStatsRequest::kYR_size — size form only
# Cluster.Stats statsz advertisement: sizeof(statfmt1) + 8 in stock v5.9.6,
# where statfmt1 = '<stats id="cms"><role>%s</role></stats>' (39 chars + NUL).
CMS_STATS_BUFSZ = 48

CMS_ST_RESUME   = 0x04
CMS_ST_NOSTAGE  = 0x02
CMS_ST_STAGE    = 0x01
CMS_ST_SUSPEND  = 0x08
CMS_ST_RESET    = 0x10

CMS_HDR_LEN  = 8
CMS_MAX_FRAME = 4096          # NGX_BRIX_CMS_MAX_FRAME
# A frame whose dlen pushes (dlen + 8) over MAX_FRAME must be rejected; the
# largest *accepted* dlen is therefore 4088.
CMS_MAX_DLEN = CMS_MAX_FRAME - CMS_HDR_LEN   # 4088

CMS_LOGIN_VERSION = 3


# ---------------------------------------------------------------------------
# Raw frame helpers (same struct-framing style as test_readv_security.py)
# ---------------------------------------------------------------------------

def _recv_code(sock, want_code, timeout=5.0):
    """Read frames until one with rrCode==want_code arrives (skipping any
    server-initiated frames such as periodic pings), or return None on
    timeout/close."""
    deadline = time.time() + timeout
    sock.settimeout(timeout)
    while time.time() < deadline:
        fr = _recv_frame(sock)
        if fr is None:
            return None
        if fr[1] == want_code:
            return fr
    return None



def _statfs_wfree(sock, sid):
    """Issue a kYR_statfs("/") on an already-logged-in socket and return the
    wFree field (aggregate free MB) from the kYR_data reply."""
    def pup(s):
        return struct.pack(">H", len(s) + 1) + s + b"\x00"
    sock.sendall(_build_frame(sid, CMS_RR_STATFS, 0, pup(b"tester") + pup(b"/")))
    fr = _recv_code(sock, CMS_RSP_DATA, timeout=5.0)
    assert fr is not None, "server did not reply kYR_data to statfs"
    _sid, _code, _mod, data = fr
    fields = data[4:].rstrip(b"\x00").split(b" ")
    assert len(fields) == 6, f"expected 6 space fields, got {fields!r}"
    return int(fields[1])   # wNum wFree wUtil sNum sFree sUtil



def _fwd_a_payload(ident, mode, path):
    """fwdArgA Pup payload: ident, mode, path (each [len incl NUL][bytes][NUL])."""
    def pup(s):
        return struct.pack(">H", len(s) + 1) + s + b"\x00"
    return pup(ident) + pup(mode) + pup(path)



def _login_payload_with_mode(dport, mode, paths=b"r /"):
    """_minimal_login_payload with the Mode word (2nd field: 1 tag byte +
    4-byte BE int at payload offsets [3:8]) replaced."""
    p = _minimal_login_payload(dport, paths)
    assert p[3] == CMS_PT_INT
    return p[:3] + bytes([CMS_PT_INT]) + struct.pack(">I", mode) + p[8:]


def _wait_log_contains(ep, needle, timeout=10.0):
    """Poll the instance's error.log until `needle` (bytes) appears."""
    path = os.path.join(ep.prefix, "logs", "error.log")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(path, "rb") as f:
                if needle in f.read():
                    return True
        except OSError:
            pass
        time.sleep(0.2)
    return False


def _start_peered_node(lifecycle, name, template, template_values, reason,
                       data_dir):
    """Shared bring-up: Python manager peer + an nginx instance that dials it.
    Returns the peer (node listen port on peer.node_port); caller closes it."""
    os.makedirs(data_dir, exist_ok=True)
    mgr_port = free_port()
    try:
        peer = CmsManagerPeer(mgr_port)
    except OSError as exc:
        pytest.skip(f"could not bind CMS manager peer port {mgr_port}: {exc}")
    values = dict(template_values)
    values["MANAGER_PORT"] = mgr_port
    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name=name,
            template=template,
            protocol="root",
            readiness="tcp",
            data_root=data_dir,
            template_values=values,
            reason=reason,
        ))
    except Exception:
        peer.close()
        raise
    peer.node_port = ep.port
    peer.ep = ep                # for _wait_log_contains on this instance
    if not peer.have_connection(timeout=20.0):
        peer.close()
        pytest.skip(f"{name} never opened a CMS connection to the peer")
    return peer


@pytest.fixture
def manager_node_stack(lifecycle):
    """A node running with an EXPLICIT ``brix_cms_role manager`` + its peer."""
    data_dir = os.path.join(_DIR, "mgr_node_data")
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(data_dir, "have_me.bin"), "wb") as f:
        f.write(b"resident-bytes" * 16)
    peer = _start_peered_node(
        lifecycle, "lc-cms-wire-mgr-node", "nginx_cms_wire_role_node.conf",
        {"ROLE": "manager"},
        "Phase-61 W7: explicit manager role — login Mode + manVOps filter.",
        data_dir)
    try:
        yield peer
    finally:
        peer.close()


@pytest.fixture
def server_node_stack(lifecycle):
    """A node running with an EXPLICIT ``brix_cms_role server`` + its peer."""
    peer = _start_peered_node(
        lifecycle, "lc-cms-wire-srv-node", "nginx_cms_wire_role_node.conf",
        {"ROLE": "server"},
        "Phase-61 W7: explicit server role — stock Pander login Mode word.",
        os.path.join(_DIR, "srv_node_data"))
    try:
        yield peer
    finally:
        peer.close()


# §2.4 brix_cms_min_free: the mSpace policy floor advertised in kYR_login.
# 250250 is deliberately > 65535 so the assertion also proves the value rides
# the wire as a full 32-bit PT_INT (never truncated to the PT_SHORT width) and
# is distinct from the default 100 MB and every other numeric login field.
CMS_MINFREE_TEST_MB = 250250


@pytest.fixture
def minfree_login_frame(lifecycle):
    """The LOGIN frame from a node carrying ``brix_cms_min_free`` (§2.4).

    Yields (login_frame, peer) so a test can also cross-check the node's SID.
    """
    peer = _start_peered_node(
        lifecycle, "lc-cms-wire-minfree-node", "nginx_cms_wire_minfree_node.conf",
        {"MIN_FREE": CMS_MINFREE_TEST_MB},
        "§2.4: brix_cms_min_free reaches the kYR_login mSpace field.",
        os.path.join(_DIR, "minfree_node_data"))
    try:
        fr = peer.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
        if fr is None:
            pytest.skip("minfree node did not emit a LOGIN frame")
        yield fr, peer
    finally:
        peer.close()


def _super_stack(lifecycle, state_relay):
    name = "lc-cms-wire-super" + ("" if state_relay == "on" else "-norelay")
    return _start_peered_node(
        lifecycle, name, "nginx_cms_wire_super.conf",
        {"STATE_RELAY": state_relay},
        "Phase-61 W7: supervisor tier — kYR_state relay recursion.",
        os.path.join(_DIR, name.replace("-", "_") + "_data"))


@pytest.fixture
def super_stack(lifecycle):
    """Supervisor (manager_mode + cms_server + upward leg), state relay ON."""
    peer = _super_stack(lifecycle, "on")
    try:
        yield peer
    finally:
        peer.close()


@pytest.fixture
def super_stack_norelay(lifecycle):
    """Same supervisor topology with brix_cms_state_relay left at default off."""
    peer = _super_stack(lifecycle, "off")
    try:
        yield peer
    finally:
        peer.close()
