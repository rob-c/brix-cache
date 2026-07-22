"""
tests/test_cms_fanout_rm.py — Phase-89 W8: manager rm/rmdir fan-out to all
holder nodes (brix_cms_fanout).

A manager with brix_cms_fanout on forwards a client kXR_rm on a path with two
or more registered holders to EVERY holder over the CMS plane (kYR_rm frames),
parks the client for the reply window, and answers kXR_ok when no node errored
or kXR_error carrying the first node error.  Python data-node peers register
over the real CMS wire (as in test_cms_affinity_multi.py) and frame-parse the
manager's traffic so the forwarded deletes are observable.

Covered (phase-61 App B.5 W8 row, v1 scope):
  success       — kXR_rm of a 2-holder path answers kXR_ok and BOTH nodes
                  received a forwarded kYR_rm frame naming the path;
  error         — one holder answers the forward with kYR_error: the client
                  gets kXR_error carrying that node's error text (partial
                  failure surfaces, never a silent half-delete);
  security-neg  — fan-out never over- or under-reaches: a single-holder path
                  falls back to the shipped single-node redirect (kXR_redirect,
                  no forwards), and a node whose exports do not cover the path
                  never receives the forwarded delete.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_fanout_rm.py -v
"""

import socket
import struct
import threading
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import SERVER_HOST
from test_cms_wire_pup_conformance import (
    _build_frame,
    _minimal_login_payload,
)
from test_cms_locate_have import (
    _xrd_session,
    _recv_response,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-fanout")]

H = SERVER_HOST

CMS_RR_LOGIN = 0
CMS_RSP_ERROR = 1
CMS_RR_RM = 8
CMS_RR_RMDIR = 9

KXR_OK = 0
KXR_ERROR = 4003
KXR_REDIRECT = 4004

PORT_NODE_A = 43321
PORT_NODE_B = 43322
PORT_SCOPED = 43323


class _FanNode:
    """A registered data node that frame-parses manager traffic: every
    forwarded kYR_rm/kYR_rmdir is recorded, and (optionally) answered with a
    kYR_error echoing the fan-out streamid — the node executor's only
    non-silent reply."""

    def __init__(self, cms_port, dport, paths=b"r /", error_reply=None):
        self.dport = dport
        self.error_reply = error_reply      # None, or (ecode, text) for RM
        self.forwards = []                  # [(code, streamid, payload)]
        self._closing = False
        self.sock = socket.create_connection((H, cms_port), timeout=8)
        self.sock.settimeout(0.25)
        self.sock.sendall(_build_frame(0, CMS_RR_LOGIN, 0,
                                       _minimal_login_payload(dport, paths)))
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n and not self._closing:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("peer closed")
            buf += chunk
        return buf

    def _reader(self):
        try:
            while not self._closing:
                hdr = self._recv_exact(8)
                if self._closing or len(hdr) < 8:
                    return
                streamid, code, _mod, dlen = struct.unpack(">IBBH", hdr)
                payload = self._recv_exact(dlen) if dlen else b""
                if code in (CMS_RR_RM, CMS_RR_RMDIR):
                    self.forwards.append((code, streamid, payload))
                    if self.error_reply is not None:
                        ecode, text = self.error_reply
                        self.sock.sendall(_build_frame(
                            streamid, CMS_RSP_ERROR, 0,
                            struct.pack(">I", ecode) + text + b"\x00"))
        except (OSError, ConnectionError):
            return

    def close(self):
        self._closing = True
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


class _Manager:
    def __init__(self, root_port, cms_port):
        self.root_port = root_port      # XRootD clients (kXR_rm)
        self.cms_port = cms_port        # data-node CMS logins


@pytest.fixture
def manager(lifecycle):
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-cms-fanout",
        template="nginx_cms_fanout.conf",
        protocol="root",
        readiness="tcp",
        reason="Phase-89 W8: rm/rmdir fan-out to all holder nodes.",
    ))
    return _Manager(ep.port, ep.extra_ports["CMS_PORT"])


def _rm(sock, path):
    """kXR_rm: 16 reserved bytes, then the path as the body."""
    payload = path.encode()
    sock.sendall(struct.pack(">BBH16sI", 0, 1, 3014,
                             b"\x00" * 16, len(payload)) + payload)
    return _recv_response(sock)


def test_rm_fans_out_to_all_holders(manager):
    """success: a 2-holder delete reaches BOTH nodes and answers kXR_ok."""
    node_a = _FanNode(manager.cms_port, PORT_NODE_A)
    node_b = _FanNode(manager.cms_port, PORT_NODE_B)
    try:
        time.sleep(0.4)    # both registrations processed

        sock = _xrd_session(manager.root_port)
        try:
            status, body = _rm(sock, "/fan/x.bin")
        finally:
            sock.close()

        assert status == KXR_OK, \
            f"silent-success window must yield kXR_ok, got {status} {body!r}"
        for node in (node_a, node_b):
            assert len(node.forwards) == 1, \
                f"node dport={node.dport} expected 1 forwarded rm, " \
                f"got {node.forwards}"
            code, _sid, payload = node.forwards[0]
            assert code == CMS_RR_RM
            assert b"/fan/x.bin" in payload, \
                f"forwarded frame must carry the path: {payload!r}"
    finally:
        node_a.close()
        node_b.close()


def test_partial_failure_surfaces_node_error(manager):
    """error: one holder rejects the forwarded delete — the client must see
    kXR_error carrying that node's text, never a silent half-delete."""
    node_a = _FanNode(manager.cms_port, PORT_NODE_A)
    node_b = _FanNode(manager.cms_port, PORT_NODE_B,
                      error_reply=(3011, b"replica pinned"))
    try:
        time.sleep(0.4)

        sock = _xrd_session(manager.root_port)
        try:
            status, body = _rm(sock, "/fan/pinned.bin")
        finally:
            sock.close()

        assert status == KXR_ERROR, \
            f"a node error inside the window must fail the rm, got {status}"
        assert b"replica pinned" in body, \
            f"client error must carry the folded node error text: {body!r}"
        assert len(node_a.forwards) == 1    # still forwarded everywhere
        assert len(node_b.forwards) == 1
    finally:
        node_a.close()
        node_b.close()


def test_fanout_never_over_or_under_reaches(manager):
    """security-neg: a single-holder path falls back to the shipped redirect
    (no forwards sent), and a node not exporting the path never receives the
    forwarded delete of a covered 2-holder path."""
    node_a = _FanNode(manager.cms_port, PORT_NODE_A)
    try:
        time.sleep(0.4)

        # Single holder: fan-out must NOT engage — redirect to the one node.
        sock = _xrd_session(manager.root_port)
        try:
            status, body = _rm(sock, "/fan/solo.bin")
        finally:
            sock.close()
        assert status == KXR_REDIRECT, \
            f"single-holder rm must keep the redirect path, got {status}"
        assert struct.unpack(">I", body[:4])[0] == PORT_NODE_A
        assert node_a.forwards == [], \
            "no forwarded delete may be sent when fan-out does not engage"

        # Two holders + one scoped node: the delete fans out to the holders
        # only; the /data-scoped node must never see it.
        node_b = _FanNode(manager.cms_port, PORT_NODE_B)
        scoped = _FanNode(manager.cms_port, PORT_SCOPED, paths=b"r /data")
        try:
            time.sleep(0.4)
            sock = _xrd_session(manager.root_port)
            try:
                status, _body = _rm(sock, "/fan/covered.bin")
            finally:
                sock.close()
            assert status == KXR_OK
            assert len(node_a.forwards) == 1
            assert len(node_b.forwards) == 1
            assert scoped.forwards == [], \
                "a node must never receive a delete outside its exports"
        finally:
            node_b.close()
            scoped.close()
    finally:
        node_a.close()
