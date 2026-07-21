"""
tests/test_cms_affinity_multi.py — Phase-89 W5: selection breadth
(brix_cms_affinity path-sticky selection + brix_cms_locate_multi full-set
locate replies).

One nginx manager process carries two root listeners over one shared server
registry: the affinity listener answers kXR_locate with a single sticky
kXR_redirect (the path hash — not the load metric — picks among the FRESH
candidates), and the multi listener answers with the full live server set as a
kXR_ok "S<r|w>host:port" list (lateral redirect).  Python data-node peers
register over the real CMS wire, exactly as in test_cms_locate_have.py.

Covered (phase-61 App B.5 W5 row, adapted to this topology):
  success       — repeated locates of one path always land on ONE node
                  (affinity sticky, stable across client sessions), and the
                  multi listener lists BOTH registered nodes for a covered path;
  error         — draining the sticky node (CMS connection drop → blacklist)
                  moves selection to the surviving node and removes the drained
                  node from the multi list: a drained host is never sticky;
  security-neg  — a node registering only "r /data" never appears in the multi
                  list for a path outside its exports, and every emitted entry
                  is a clean printable "Sr<host>:<port>" token (the registry's
                  host-allowlist choke point holds on the new emit surface).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_affinity_multi.py -v
"""

import re
import socket
import struct
import threading
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import SERVER_HOST, free_port
from test_cms_wire_pup_conformance import (
    _build_frame,
    _minimal_login_payload,
)
from test_cms_locate_have import (
    _xrd_session,
    _locate,
)

pytestmark = pytest.mark.uses_lifecycle_harness

H = SERVER_HOST

CMS_RR_LOGIN = 0

KXR_OK = 0
KXR_ERROR = 4003
KXR_REDIRECT = 4004
KXR_WAIT = 4005

PORT_NODE_A = 43311
PORT_NODE_B = 43312
PORT_SCOPED = 43313


class _RegNode:
    """A minimal registered data node: logs in over the CMS wire, then a
    background reader drains (and ignores) manager traffic so pings never
    back up.  close() drops the connection — the manager blacklists the
    entry (drain)."""

    def __init__(self, cms_port, dport, paths=b"r /"):
        self.dport = dport
        self._closing = False
        self.sock = socket.create_connection((H, cms_port), timeout=8)
        self.sock.settimeout(0.25)
        self.sock.sendall(_build_frame(0, CMS_RR_LOGIN, 0,
                                       _minimal_login_payload(dport, paths)))
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self):
        try:
            while not self._closing:
                try:
                    if not self.sock.recv(4096):
                        return
                except socket.timeout:
                    continue
        except OSError:
            return

    def close(self):
        self._closing = True
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


class _Manager:
    def __init__(self, sticky_port, multi_port, cms_port):
        self.sticky_port = sticky_port    # affinity listener (redirects)
        self.multi_port = multi_port      # locate_multi listener (kXR_ok list)
        self.cms_port = cms_port          # data-node CMS logins


@pytest.fixture
def manager(lifecycle):
    multi_port = free_port()
    cms_port = free_port()
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-cms-affinity",
        template="nginx_cms_affinity.conf",
        protocol="root",
        readiness="tcp",
        template_values={"MULTI_PORT": multi_port, "CMS_PORT": cms_port},
        reason="Phase-89 W5: affinity-sticky selection + multi-source locate.",
    ))
    return _Manager(ep.port, multi_port, cms_port)


def _redirect_port(sock, path):
    status, body = _locate(sock, path)
    assert status == KXR_REDIRECT, f"expected redirect for {path}, got {status}"
    return struct.unpack(">I", body[:4])[0]


def _multi_ports(manager, path):
    """Locate on the multi listener; return (status, set-of-ports, raw body)."""
    sock = _xrd_session(manager.multi_port)
    try:
        status, body = _locate(sock, path)
    finally:
        sock.close()
    if status != KXR_OK:
        return status, set(), body
    text = body.rstrip(b"\x00").decode()
    ports = {int(tok.rsplit(":", 1)[1]) for tok in text.split(" ") if tok}
    return status, ports, body


def test_affinity_sticky_and_multi_lists_all(manager):
    """success: one path always selects one node (across requests AND client
    sessions), and the multi listener lists both live nodes."""
    node_a = _RegNode(manager.cms_port, PORT_NODE_A)
    node_b = _RegNode(manager.cms_port, PORT_NODE_B)
    try:
        time.sleep(0.4)    # both registrations processed

        sock = _xrd_session(manager.sticky_port)
        try:
            first = _redirect_port(sock, "/aff/sticky.bin")
            assert first in (PORT_NODE_A, PORT_NODE_B)
            for _ in range(5):
                assert _redirect_port(sock, "/aff/sticky.bin") == first, \
                    "affinity selection must be sticky per path"
        finally:
            sock.close()

        # Stickiness is a pure function of the path — a NEW session (and any
        # other worker/manager) computes the same member.
        sock = _xrd_session(manager.sticky_port)
        try:
            assert _redirect_port(sock, "/aff/sticky.bin") == first
        finally:
            sock.close()

        status, ports, _body = _multi_ports(manager, "/aff/sticky.bin")
        assert status == KXR_OK, f"multi locate expected kXR_ok, got {status}"
        assert ports == {PORT_NODE_A, PORT_NODE_B}, \
            f"multi list must carry both live nodes, got {ports}"
    finally:
        node_a.close()
        node_b.close()


def test_drained_node_never_sticky(manager):
    """error: dropping the sticky node's CMS connection blacklists it — the
    next locate moves to the survivor and the multi list shrinks to it."""
    nodes = {PORT_NODE_A: _RegNode(manager.cms_port, PORT_NODE_A),
             PORT_NODE_B: _RegNode(manager.cms_port, PORT_NODE_B)}
    try:
        time.sleep(0.4)

        sock = _xrd_session(manager.sticky_port)
        try:
            sticky = _redirect_port(sock, "/aff/drain.bin")
            survivor = PORT_NODE_B if sticky == PORT_NODE_A else PORT_NODE_A

            nodes[sticky].close()    # → brix_srv_blacklist on the manager
            time.sleep(0.6)

            assert _redirect_port(sock, "/aff/drain.bin") == survivor, \
                "a drained host must never stay sticky"
        finally:
            sock.close()

        status, ports, _body = _multi_ports(manager, "/aff/drain.bin")
        assert status == KXR_OK
        assert ports == {survivor}, \
            f"multi list must exclude the drained node, got {ports}"
    finally:
        for n in nodes.values():
            n.close()


def test_scoped_node_absent_outside_exports(manager):
    """security-neg: a node exporting only /data never leaks into the multi
    list for a path outside its exports, and every emitted entry is a clean
    printable Sr<host>:<port> token (host-allowlist choke holds on emit)."""
    node_root = _RegNode(manager.cms_port, PORT_NODE_A)
    node_scoped = _RegNode(manager.cms_port, PORT_SCOPED, paths=b"r /data")
    try:
        time.sleep(0.4)

        status, ports, body = _multi_ports(manager, "/secret/f.bin")
        assert status == KXR_OK
        assert PORT_SCOPED not in ports, \
            "node must not be listed for a path outside its exported prefixes"
        assert ports == {PORT_NODE_A}

        # Emit-surface hygiene: printable, strictly "Sr<host>:<port>" tokens.
        text = body.rstrip(b"\x00").decode("ascii")
        for tok in text.split(" "):
            assert re.fullmatch(r"Sr[0-9A-Za-z.\-\[\]:]+:\d+", tok), \
                f"malformed locate entry: {tok!r}"

        # Inside its exports the scoped node IS eligible.
        status, ports, _body = _multi_ports(manager, "/data/f.bin")
        assert status == KXR_OK
        assert ports == {PORT_NODE_A, PORT_SCOPED}
    finally:
        node_root.close()
        node_scoped.close()
