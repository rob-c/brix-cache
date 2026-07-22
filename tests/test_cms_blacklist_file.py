"""
tests/test_cms_blacklist_file.py — Phase-89 W6′: file-driven server blacklist.

A dedicated nginx CMS manager is started with ``brix_cms_blacklist_file``
pointing at a test-owned file and a 1s ping interval (the poll cadence).  A
Python data-node peer logs in over the real CMS wire so the manager registers
it, and the dashboard cluster snapshot's ``draining`` flag is the observable
for "this server is blacklisted".

Covered (phase-89 App D matrix, PR-4 row):
  success       — a file-listed host (via IPv4 CIDR) is drained from the moment
                  it registers (the post-registration force poll);
  success       — an mtime edit (adding the host) is picked up within one poll;
  error         — a malformed line is skipped with a warning while the good
                  lines still apply, and the manager stays alive;
  security-neg  — an admin-API ``undrain`` succeeds but the file re-asserts the
                  blacklist within one poll: the file wins.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_blacklist_file.py -v
"""

import json
import os
import socket
import time
import urllib.request

import pytest

from server_registry import NginxInstanceSpec
from settings import SERVER_HOST
from test_cms_wire_pup_conformance import (
    CMS_RR_LOGIN,
    _build_frame,
    _minimal_login_payload,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-blfile")]

H = SERVER_HOST
# What the registry stores as the node's host is the CMS connection's remote
# IP TEXT (ctx->host), not a name — the blacklist file must use the literal.
NODE_IP = "127.0.0.1"  # net-literal-allow: CMS node remote-IP literal the blacklist file must match (see comment)
SECRET = "blfile-admin-secret"

# Distinct advertised data ports so each test's registry entry is its own.
PORT_CIDR     = 42101
PORT_MTIME    = 42102
PORT_MALFORM  = 42103
PORT_UNDRAIN  = 42104


class _BlfileManager:
    """One nginx CMS manager + its blacklist file + its dashboard endpoints."""

    def __init__(self, cms_port, http_port, blfile):
        self.cms_port = cms_port
        self.http_port = http_port
        self.blfile = blfile

    # -- blacklist file -----------------------------------------------------

    def write_blacklist(self, text):
        """Rewrite the blacklist file and force a strictly newer mtime, so the
        manager's mtime-change re-read is deterministic even on coarse
        filesystem timestamp granularity."""
        st = os.stat(self.blfile) if os.path.exists(self.blfile) else None
        with open(self.blfile, "w") as f:
            f.write(text)
        if st is not None:
            os.utime(self.blfile, (st.st_atime, st.st_mtime + 2))

    # -- CMS node side ------------------------------------------------------

    def login_node(self, dport):
        """Dial the CMS port and register as a data node advertising dport.
        Returns the connected socket (caller keeps it open: the live
        connection is what drives the manager's ping-tick poll)."""
        sock = socket.create_connection((H, self.cms_port), timeout=8)
        sock.settimeout(8)
        sock.sendall(_build_frame(0, CMS_RR_LOGIN, 0,
                                  _minimal_login_payload(dport)))
        return sock

    # -- dashboard / admin side ---------------------------------------------

    def cluster_servers(self):
        url = f"http://{H}:{self.http_port}/brix/api/v1/cluster"
        with urllib.request.urlopen(url, timeout=8) as resp:
            doc = json.loads(resp.read().decode())
        return doc.get("servers", [])

    def find_server(self, _port):
        """The single registered server of this dedicated instance (each test
        registers exactly one node).  The anonymous snapshot redacts host and
        port, so entries cannot be matched by identity — sole-entry it is."""
        servers = self.cluster_servers()
        assert len(servers) <= 1, f"expected at most one server: {servers}"
        return servers[0] if servers else None

    def wait_draining(self, port, want, timeout=8.0):
        """Poll the snapshot until the (sole) entry has draining == want.
        Returns the entry (never None on success); asserts on timeout."""
        deadline = time.time() + timeout
        entry = None
        while time.time() < deadline:
            entry = self.find_server(port)
            if entry is not None and entry.get("draining") is want:
                return entry
            time.sleep(0.25)
        raise AssertionError(
            f"server on port {port} never reached draining={want}: {entry}")

    def admin(self, method, path, body=None):
        url = f"http://{H}:{self.http_port}/brix/api/v1/admin{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Authorization": f"Bearer {SECRET}",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()


@pytest.fixture
def manager(lifecycle, tmp_path):
    """A CMS manager whose blacklist file starts EMPTY (each test writes its
    own entries), plus the dashboard/admin plane on a second port."""
    blfile = tmp_path / "cms.blacklist"
    blfile.write_text("")
    secret = tmp_path / "admin.secret"
    secret.write_text(SECRET + "\n")

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-cms-blfile",
        template="nginx_cms_blfile_server.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BLACKLIST_FILE": str(blfile),
                         "SECRET_FILE": str(secret)},
        reason="Phase-89 W6' file-driven blacklist: poll + re-assert semantics.",
    ))
    return _BlfileManager(ep.port, ep.extra_ports["HTTP_PORT"], str(blfile))


def test_file_listed_cidr_drained_at_registration(manager):
    """success: a host covered by an IPv4 CIDR line is drained immediately —
    the post-registration force poll wins the race with selection."""
    manager.write_blacklist("# operator blacklist\n127.0.0.0/8\n")
    sock = manager.login_node(PORT_CIDR)
    try:
        manager.wait_draining(PORT_CIDR, True)
    finally:
        sock.close()


def test_mtime_edit_picked_up(manager):
    """success: the node registers un-drained (empty file), then an edit adding
    its host is enforced within one ping-tick poll."""
    sock = manager.login_node(PORT_MTIME)
    try:
        entry = manager.wait_draining(PORT_MTIME, False)
        assert entry is not None
        manager.write_blacklist(f"{NODE_IP}:{PORT_MTIME}\n")
        manager.wait_draining(PORT_MTIME, True)
    finally:
        sock.close()


def test_malformed_line_skipped_good_line_applies(manager):
    """error: junk lines (bad CIDR prefix, bad port, garbage) are skipped —
    the good line still drains the node and the manager keeps serving."""
    manager.write_blacklist(
        "10.0.0.0/64\n"          # CIDR prefix out of range
        "127.0.0.1:99999\n"      # port out of range  # net-literal-allow: malformed blacklist line under test (port out of range)
        "not a host line at all with spaces\n"
        f"{NODE_IP}:{PORT_MALFORM}\n"  # the one good line
    )
    sock = manager.login_node(PORT_MALFORM)
    try:
        manager.wait_draining(PORT_MALFORM, True)
        # Still alive and parseable after eating the junk file.
        assert manager.find_server(PORT_MALFORM) is not None
    finally:
        sock.close()


def test_file_wins_over_admin_undrain(manager):
    """security-neg: an authorized admin undrain succeeds, but the next poll
    re-asserts the file — the operator file is authoritative."""
    manager.write_blacklist(f"{NODE_IP}:{PORT_UNDRAIN}\n")
    sock = manager.login_node(PORT_UNDRAIN)
    try:
        manager.wait_draining(PORT_UNDRAIN, True)

        status, body = manager.admin(
            "POST", f"/cluster/servers/{NODE_IP}/{PORT_UNDRAIN}/undrain")
        assert status == 200, body
        assert json.loads(body.decode())["result"] == "undrained"

        # Within ~1 ping tick the file must re-assert the blacklist.
        manager.wait_draining(PORT_UNDRAIN, True)
    finally:
        sock.close()
