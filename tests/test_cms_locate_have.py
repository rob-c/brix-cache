"""
tests/test_cms_locate_have.py — Phase-89 W3: dynamic location via kYR_state
fan-out + kYR_have + the SHM loc cache.

One nginx CMS manager runs with ``brix_cms_locate_window`` enabled.  Python
data-node peers log in over the real CMS wire (so the manager registers them
and adds them to the worker's fan-out set) and script their kYR_have replies;
a raw XRootD client issues kXR_locate against the same manager and observes
redirect / wait / error.

Covered (phase-89 App D matrix, PR-5 row):
  success       — a locate miss probes both nodes; the one answering kYR_have
                  wins the redirect, and a second locate for the same path is
                  served from the loc cache (the node sees exactly one probe);
  error         — no node answers: the collection window expires and the
                  parked client gets kXR_wait (the shared WAITING_CMS timeout),
                  with the connection still usable afterwards;
  security-neg  — a node asserting have for a path OUTSIDE its login-Paths
                  prefixes is dropped (logged, not cached): a locate for that
                  path never redirects to the hostile node.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_locate_have.py -v
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

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-locate-have")]

H = SERVER_HOST

CMS_RR_LOGIN = 0
CMS_RR_HAVE = 15
CMS_RR_STATE = 20
CMS_MOD_RAW = 0x20
CMS_HAVE_ONLINE = 0x01

KXR_ERROR = 4003
KXR_REDIRECT = 4004
KXR_WAIT = 4005

WINDOW_MS = 1200

PORT_ANSWERER = 43301
PORT_SILENT = 43302
PORT_HOSTILE = 43303


# ---------------------------------------------------------------------------
# CMS data-node peer
# ---------------------------------------------------------------------------

class _CmsNode:
    """A scripted data node: logs in over the CMS wire, then a background
    reader answers (or ignores) the manager's kYR_state probes.  Received
    state paths are collected for probe-count assertions."""

    def __init__(self, cms_port, dport, paths=b"r /", answer_have=True):
        self.dport = dport
        self.answer_have = answer_have
        self.state_paths = []          # every kYR_state path received
        self._lock = threading.Lock()
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
                if self._closing:
                    return
                sid, code, _mod, dlen = struct.unpack(">IBBH", hdr)
                payload = self._recv_exact(dlen) if dlen else b""
                if code != CMS_RR_STATE:
                    continue    # pings etc. — ignore
                path = payload.split(b"\x00", 1)[0].decode()
                with self._lock:
                    self.state_paths.append(path)
                if self.answer_have:
                    self.sock.sendall(_build_frame(
                        sid, CMS_RR_HAVE, CMS_MOD_RAW | CMS_HAVE_ONLINE,
                        path.encode() + b"\x00"))
        except (ConnectionError, OSError):
            return

    def send_have(self, streamid, path):
        """Volunteer an (unsolicited) kYR_have."""
        self.sock.sendall(_build_frame(
            streamid, CMS_RR_HAVE, CMS_MOD_RAW | CMS_HAVE_ONLINE,
            path.encode() + b"\x00"))

    def probes(self):
        with self._lock:
            return list(self.state_paths)

    def close(self):
        self._closing = True
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Raw XRootD client (handshake + protocol + login + locate)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server closed")
        buf += chunk
    return buf


def _recv_response(sock):
    hdr = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack(">HHI", hdr)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _xrd_session(port):
    sock = socket.create_connection((H, port), timeout=8)
    sock.settimeout(8)
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
    _recv_exact(sock, 16)          # handshake response
    _recv_response(sock)           # protocol response
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, 3007, 0,
                             b"anon\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    _recv_response(sock)           # login response
    return sock


def _locate(sock, path):
    payload = path.encode() + b"\x00"
    sock.sendall(struct.pack(">BBHH14sI", 0, 1, 3027, 0,
                             b"\x00" * 14, len(payload)) + payload)
    return _recv_response(sock)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

class _Manager:
    def __init__(self, root_port, cms_port):
        self.root_port = root_port      # XRootD clients (kXR_locate)
        self.cms_port = cms_port        # data-node CMS logins


@pytest.fixture
def manager(lifecycle):
    """One CMS manager with the dynamic-location window enabled.  The CMS
    listener needs its own port: brix_cms_server replaces the stream handler
    for its whole server block."""
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-cms-locate-have",
        template="nginx_cms_locate_have.conf",
        protocol="root",
        readiness="tcp",
        template_values={"WINDOW_MS": WINDOW_MS},
        reason="Phase-89 W3: kYR_state fan-out + kYR_have + loc cache.",
    ))
    return _Manager(ep.port, ep.extra_ports["CMS_PORT"])


def test_have_wins_redirect_then_loc_cache(manager):
    """success: of two probed nodes only the answerer's kYR_have redirects the
    client, and the second locate is a loc-cache hit (no second probe)."""
    answerer = _CmsNode(manager.cms_port, PORT_ANSWERER, answer_have=True)
    silent = _CmsNode(manager.cms_port, PORT_SILENT, answer_have=False)
    try:
        time.sleep(0.3)    # both registrations processed
        sock = _xrd_session(manager.root_port)
        try:
            status, body = _locate(sock, "/w3/file.bin")
            assert status == KXR_REDIRECT, f"expected redirect, got {status}"
            port = struct.unpack(">I", body[:4])[0]
            assert port == PORT_ANSWERER, f"redirected to wrong node: {port}"

            # Both nodes were probed for the miss.
            assert "/w3/file.bin" in answerer.probes()
            assert "/w3/file.bin" in silent.probes()

            # Second locate: loc-cache hit — same redirect, no new probes.
            probes_before = len(answerer.probes())
            status, body = _locate(sock, "/w3/file.bin")
            assert status == KXR_REDIRECT
            assert struct.unpack(">I", body[:4])[0] == PORT_ANSWERER
            time.sleep(0.3)
            assert len(answerer.probes()) == probes_before, \
                "loc-cache hit must not re-probe the nodes"
        finally:
            sock.close()
    finally:
        answerer.close()
        silent.close()


def test_window_expiry_sends_wait(manager):
    """error: no node answers — the parked client gets kXR_wait when the
    collection window expires, and the connection stays usable."""
    silent = _CmsNode(manager.cms_port, PORT_SILENT, answer_have=False)
    try:
        time.sleep(0.3)
        sock = _xrd_session(manager.root_port)
        try:
            t0 = time.time()
            status, _body = _locate(sock, "/w3/nowhere.bin")
            elapsed = time.time() - t0
            assert status == KXR_WAIT, f"expected kXR_wait, got {status}"
            assert elapsed >= WINDOW_MS / 1000.0 - 0.2, \
                f"wait arrived before the window expired ({elapsed:.2f}s)"

            # Connection still serves requests after the timeout wake.
            status, _body = _locate(sock, "/w3/nowhere.bin")
            assert status in (KXR_WAIT, KXR_REDIRECT, KXR_ERROR)
        finally:
            sock.close()
    finally:
        silent.close()


def test_hostile_have_outside_exports_not_cached(manager):
    """security-neg: a node exporting only /data asserts have for /secret/x —
    the manager must drop it (never cache, never redirect to that node)."""
    hostile = _CmsNode(manager.cms_port, PORT_HOSTILE, paths=b"r /data",
                       answer_have=False)
    try:
        time.sleep(0.3)
        hostile.send_have(0x80000099, "/secret/x")
        time.sleep(0.3)

        sock = _xrd_session(manager.root_port)
        try:
            status, body = _locate(sock, "/secret/x")
            if status == KXR_REDIRECT:
                port = struct.unpack(">I", body[:4])[0]
                assert port != PORT_HOSTILE, \
                    "hostile have outside exported paths was cached"
            # No covering node ⇒ expected terminal result is an error/wait,
            # never a redirect to the hostile node.
            assert status in (KXR_ERROR, KXR_WAIT), \
                f"unexpected locate result {status}"
        finally:
            sock.close()
    finally:
        hostile.close()
