"""
Preamble for tests/test_phase115_cms_locate_coalesce.py — §2.15 request
coalescing.  Split out under the 600-logical-line file cap; the test module
reexports this namespace so pytest resolves the fixtures.

THE NODE THIS FILE ADDS
-----------------------
Coalescing is only observable while a kYR_state wave is IN FLIGHT, and the two
scripted nodes already in the corpus both settle it immediately: parity's
FakeNode never answers, and test_cms_locate_have's _CmsNode answers the instant
it is probed.  Either way the leader is resolved before a second client can
arrive, and there is nothing to coalesce onto.

_HeldNode holds the wave open: it records every probe as (streamid, path) and
answers only when the test says so.  That turns "did the follower probe?" into
a plain frame count taken while both clients are demonstrably parked.
"""

import socket
import struct
import threading
import time

import pytest

from _test_cms_parity_wave_helpers import (
    CMS_RR_LOGIN,
    CMS_RR_PING,
    CMS_RR_PONG,
    CMS_RR_STATE,
    _cms_frame,
    _locate,
    _login_payload,
    _mgr,
    _recv_exact,
    _redir_port,
)
from settings import SERVER_HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(120),
              pytest.mark.xdist_group("lc-p115-cms-coalesce")]

H = SERVER_HOST
MGR = "lc-p115-cms-coalesce-mgr"

CMS_RR_HAVE = 15
CMS_MOD_RAW = 0x20
CMS_HAVE_ONLINE = 0x01

kXR_ok, kXR_redirect, kXR_wait = 0, 4004, 4005
kXR_refresh = 0x0080

# Long enough that a second client provably arrives inside it, short enough
# that an unanswered wave still expires well inside the module timeout.
WINDOW_MS = 3000


class _HeldNode:
    """A data node that records kYR_state probes and answers on demand."""

    def __init__(self, cms_port, dport, paths=b"r /"):
        self.dport = dport
        self.probes = []           # [(streamid, path)]
        self.ready = threading.Event()
        self._lock = threading.Lock()
        self._closing = False
        self.sock = socket.create_connection((H, cms_port), timeout=8)
        self.sock.settimeout(0.25)
        self.sock.sendall(_cms_frame(0, CMS_RR_LOGIN, 0,
                                     _login_payload(dport, paths=paths)))
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self):
        try:
            while not self._closing:
                try:
                    hdr = _recv_exact(self.sock, 8)
                except socket.timeout:
                    continue
                sid, code, _mod, dlen = struct.unpack(">IBBH", hdr)
                payload = _recv_exact(self.sock, dlen) if dlen else b""
                self.ready.set()
                if code == CMS_RR_PING:
                    self.sock.sendall(_cms_frame(sid, CMS_RR_PONG))
                elif code == CMS_RR_STATE:
                    path = payload.split(b"\x00", 1)[0].decode()
                    with self._lock:
                        self.probes.append((sid, path))
        except (ConnectionError, OSError):
            return

    def probes_for(self, path):
        with self._lock:
            return [sid for sid, p in self.probes if p == path]

    def wait_probe(self, path, timeout=8.0):
        """Block until at least one probe for `path` has arrived."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.probes_for(path):
                return True
            time.sleep(0.05)
        return False

    def answer(self, path, streamid=None):
        """Send kYR_have for `path`, echoing the recorded probe streamid.

        `streamid` overrides it — that is how an UNSOLICITED have (one that
        answers no probe of ours) is forged in the security-negative.
        """
        if streamid is None:
            sids = self.probes_for(path)
            assert sids, f"no probe recorded for {path}"
            streamid = sids[0]
        self.sock.sendall(_cms_frame(streamid, CMS_RR_HAVE,
                                     CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                     path.encode() + b"\x00"))

    def wait_ready(self, timeout=8.0):
        return self.ready.wait(timeout)

    def close(self):
        self._closing = True
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


class _Client(threading.Thread):
    """One kXR_locate issued off-thread so several can be in flight at once."""

    def __init__(self, root_port, path, options=0, delay=0.0):
        super().__init__(daemon=True)
        self.root_port = root_port
        self.path = path
        self.options = options
        self.delay = delay
        self.status = None
        self.body = None
        self.error = None

    def run(self):
        if self.delay:
            time.sleep(self.delay)
        try:
            self.status, self.body = _locate(self.root_port, self.path,
                                             self.options)
        except Exception as exc:            # surfaced by the assertions
            self.error = exc

    def port(self):
        assert self.error is None, f"client raised: {self.error!r}"
        assert self.status == kXR_redirect, \
            f"expected a redirect for {self.path}, got status {self.status}"
        return _redir_port(self.body)


def _coalescing_mgr(lifecycle, on, reason):
    """The dynamic-locate manager, with §2.15 coalescing on or off."""
    extra = (f"brix_cms_locate_window {WINDOW_MS}ms; "
             f"brix_cms_state_fanout 8; "
             f"brix_cms_coalesce {'on' if on else 'off'};")
    return _mgr(lifecycle, MGR, extra, reason)


def _run_pair(root_port, path, second_options=0, gap=0.4):
    """Start two locates for one path, the second `gap` seconds later."""
    first = _Client(root_port, path)
    second = _Client(root_port, path, options=second_options, delay=gap)
    first.start()
    second.start()
    return first, second
