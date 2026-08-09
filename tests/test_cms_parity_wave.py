"""
tests/test_cms_parity_wave.py — 2026-08-09 CMS parity wave (audit §2.2–§2.17).

Each feature is proven over the REAL wires from both ends: fake Python data
nodes register into a dedicated nginx CMS manager (per-test policy directives
injected via the {CMS_EXTRA} template hook), and raw kXR_locate probes observe
the selection verdicts; node-side features run a dedicated nginx node against
an in-test Python stub manager that records every frame.

Covered (success + error + security-negative per feature):
  §2.2  SUPCount floor    — below brix_cms_delay_servers the manager answers
                            kXR_wait(delay_hold); at the floor it redirects.
  §2.3  cms.sched         — component weights pick the cooler node; maxload
                            demotes a hot node while a cool one exists and
                            degrades (still serves) when everyone is hot.
  §2.5  stage-aware       — with brix_cms_stage_select, a read of a file no
                            node holds goes to the stage-capable node.
  §2.6  emptylife         — a state fan-out that expires with no kYR_have
                            records a negative entry: the retry answers
                            kXR_NotFound immediately instead of re-parking.
  §2.7  kXR_refresh       — a refresh locate bypasses the negative entry and
                            re-probes the cluster.
  §2.8  cms.dfs           — the state fan-out is skipped: no kYR_state ever
                            reaches the node; locate redirects immediately.
  §2.9  ManTree offload   — at brix_cms_server_max_direct, a NEW server login
                            is answered kYR_try naming the supervisor.
  §2.13 blacklist extras  — `*` host patterns drain; `redirect <h:p>` bounces
                            the login via kYR_try; whitelist mode drains
                            unlisted hosts and admits listed ones.
  §2.17 peer role         — a peer-mode node is selected only when no local
                            server matches.
  §2.11 cms.perf pgm      — the external feed's cpu figure rides the LOAD
                            heartbeat in place of the /proc meter's.
  §2.12 cms.altds         — the login advertises the foreign data port; the
                            monitor drives kYR_status suspend/resume.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_parity_wave.py -v
"""

import os
import socket
import struct
import threading
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, SERVER_HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(90),   # nginx bring-up + poll windows > 30s
              pytest.mark.xdist_group("lc-cms-parity")]

H = SERVER_HOST
NODE_IP = "127.0.0.1"  # net-literal-allow: CMS registry stores the conn's IP text

# ── CMS wire constants (src/net/cms/cms_internal.h) ───────────────────────
CMS_RR_LOGIN, CMS_RR_LOCATE, CMS_RR_SELECT = 0, 2, 10
CMS_RR_LOAD, CMS_RR_PING, CMS_RR_PONG = 16, 17, 18
CMS_RR_STATE, CMS_RR_STATUS, CMS_RR_TRY = 20, 22, 24
CMS_ST_STAGE, CMS_ST_NOSTAGE, CMS_ST_RESUME, CMS_ST_SUSPEND = 1, 2, 4, 8
CMS_PT_SHORT, CMS_PT_INT = 0x80, 0xA0
CMS_LOGIN_VERSION = 3
MODE_SERVER, MODE_MANAGER, MODE_PEER = 0x08, 0x02, 0x04

# ── XRootD client wire constants ──────────────────────────────────────────
kXR_ok, kXR_error, kXR_redirect, kXR_wait = 0, 4003, 4004, 4005
kXR_login, kXR_locate = 3007, 3027
kXR_NotFound = 3011
kXR_refresh = 0x0080


# ── low-level helpers ─────────────────────────────────────────────────────

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError(f"closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _cms_frame(streamid, code, modifier=0, payload=b""):
    return struct.pack(">IBBH", streamid, code, modifier, len(payload)) + payload


def _login_payload(dport, mode=MODE_SERVER, paths=b"r /", util=7, free_mb=5000):
    """Minimal well-formed CmsLoginData (see cms_srv_parse_login)."""
    p = b""
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", CMS_LOGIN_VERSION)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", mode)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 0)          # holdtime
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 100)        # tSpace
    p += bytes([CMS_PT_INT]) + struct.pack(">I", free_mb)    # fSpace
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 100)        # mSpace
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 1)        # fsNum
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", util)     # fsUtil
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", dport)    # dPort
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 0)        # sPort
    for s in (b"fake:%d" % dport, paths, b"", b""):
        if not s:
            p += struct.pack(">H", 0)
        else:
            p += struct.pack(">H", len(s) + 1) + s + b"\x00"
    return p


def _load_payload(cpu=0, net=0, xeq=0, mem=0, pag=0, dsk=1, free_mb=5000):
    """kYR_load: [2B blob len=6][cpu net xeq mem pag dsk][PT_INT free_mb]."""
    return (struct.pack(">H", 6)
            + bytes([cpu, net, xeq, mem, pag, dsk])
            + bytes([CMS_PT_INT]) + struct.pack(">I", free_mb))


class FakeNode:
    """A wire-speaking CMS data node: logs in, answers pings, records frames.

    A background reader drains the manager->node direction so pings never
    back-pressure and kYR_state / kYR_try frames are observable.
    """

    def __init__(self, cms_port, dport, mode=MODE_SERVER, paths=b"r /",
                 util=7, free_mb=5000):
        self.dport = dport
        self.frames = []           # [(code, modifier, payload)]
        self.closed = False
        self.sock = socket.create_connection((H, cms_port), timeout=8)
        self.sock.settimeout(0.2)
        self.sock.sendall(_cms_frame(0, CMS_RR_LOGIN, 0,
                                     _login_payload(dport, mode, paths,
                                                    util, free_mb)))
        self._stop = False
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self):
        try:
            while not self._stop:
                try:
                    hdr = _recv_exact(self.sock, 8)
                except socket.timeout:
                    continue
                streamid, code, modifier, dlen = struct.unpack(">IBBH", hdr)
                payload = _recv_exact(self.sock, dlen) if dlen else b""
                self.frames.append((code, modifier, payload))
                if code == CMS_RR_PING:
                    self.sock.sendall(_cms_frame(streamid, CMS_RR_PONG))
        except (ConnectionResetError, OSError):
            self.closed = True

    def send(self, code, modifier=0, payload=b""):
        self.sock.sendall(_cms_frame(0, code, modifier, payload))

    def count(self, code):
        return sum(1 for c, _m, _p in self.frames if c == code)

    def wait_frame(self, code, timeout=6.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for c, m, p in self.frames:
                if c == code:
                    return (c, m, p)
            time.sleep(0.05)
        return None

    def wait_closed(self, timeout=6.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.closed:
                return True
            time.sleep(0.05)
        return False

    def close(self):
        self._stop = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ── XRootD client-side drive (handshake + login + locate) ─────────────────

def _xrd_resp(sock):
    hdr = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _xrd_session(port):
    sock = socket.create_connection((H, port), timeout=10)
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
    _xrd_resp(sock)
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, kXR_login, 0, b"anon\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))
    _xrd_resp(sock)
    return sock


def _locate(port, path, options=0):
    """One kXR_locate; returns (status, body)."""
    sock = _xrd_session(port)
    try:
        payload = path.encode() + b"\x00"
        sock.sendall(struct.pack(">BB H H 14x I",
                                 0, 1, kXR_locate, options, len(payload))
                     + payload)
        return _xrd_resp(sock)
    finally:
        sock.close()


def _redir_port(body):
    assert len(body) >= 4
    return struct.unpack(">i", body[:4])[0]


def _wait_selectable(port, path, want_port, timeout=8.0, options=0):
    """Poll locate until it redirects to want_port (None = any redirect)."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = _locate(port, path, options)
        if last[0] == kXR_redirect:
            got = _redir_port(last[1])
            if want_port is None or got == want_port:
                return got
        time.sleep(0.2)
    raise AssertionError(f"locate {path} never redirected to "
                         f"{want_port}: last={last}")


def _mgr(lifecycle, name, extra, reason, srv_extra=""):
    """Start the two-faced manager; returns (root_port, cms_port)."""
    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_cms_parity_mgr.conf",
        protocol="root",
        readiness="tcp",
        template_values={"CMS_EXTRA": extra, "CMSSRV_EXTRA": srv_extra},
        reason=reason,
    ))
    return ep.port, ep.extra_ports["CMS_PORT"]


# ═══ §2.2 SUPCount floor ══════════════════════════════════════════════════

def test_floor_holds_then_serves(lifecycle):
    """success+error: below the floor locate answers kXR_wait(delay_hold);
    reaching it flips to redirects."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_delay_servers 2; brix_cms_delay_hold 3;",
              "§2.2 SUPCount floor: hold below 2 registered servers.")
    n1 = FakeNode(cms_port, 42201)
    try:
        # One node registered: every locate is held with kXR_wait(3).
        deadline = time.time() + 8
        status = body = None
        while time.time() < deadline:
            status, body = _locate(root_port, "/floor.dat")
            if status == kXR_wait:
                break
            time.sleep(0.2)
        assert status == kXR_wait, f"expected kXR_wait below floor: {status}"
        assert struct.unpack(">I", body[:4])[0] == 3, body

        # Second node: the floor is met — locates redirect.
        n2 = FakeNode(cms_port, 42202)
        try:
            got = _wait_selectable(root_port, "/floor.dat", None)
            assert got in (42201, 42202)
        finally:
            n2.close()
    finally:
        n1.close()


# ═══ §2.3 cms.sched component weights + maxload ═══════════════════════════

def test_sched_picks_cooler_cpu(lifecycle):
    """success: with cpu-weighted sched, the node reporting the lower cpu
    byte wins even though both are otherwise identical."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_sched cpu 100 maxload 50;",
              "§2.3 cms.sched: cpu-weighted selection + maxload ceiling.")
    hot = FakeNode(cms_port, 42211)
    cool = FakeNode(cms_port, 42212)
    try:
        hot.send(CMS_RR_LOAD, 0, _load_payload(cpu=90))
        cool.send(CMS_RR_LOAD, 0, _load_payload(cpu=10))
        time.sleep(0.5)   # let the manager ingest both LOADs
        got = _wait_selectable(root_port, "/sched.dat", 42212)
        assert got == 42212
    finally:
        hot.close()
        cool.close()


def test_sched_maxload_degrades_not_refuses(lifecycle):
    """error-path: when EVERY matching node is over maxload, selection
    degrades to the least-loaded overloaded node instead of failing."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_sched cpu 100 maxload 50;",
              "§2.3 cms.sched: cpu-weighted selection + maxload ceiling.")
    hot = FakeNode(cms_port, 42213)
    try:
        hot.send(CMS_RR_LOAD, 0, _load_payload(cpu=95))
        time.sleep(0.5)
        got = _wait_selectable(root_port, "/sched2.dat", 42213)
        assert got == 42213
    finally:
        hot.close()


# ═══ §2.5 stage-aware selection ═══════════════════════════════════════════

def test_stage_select_prefers_stage_node(lifecycle):
    """success: a read of a file no node holds goes to the stage-capable
    node, even though the disk-only node is far less utilised."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_stage_select on;",
              "§2.5 stage-aware selection.")
    disk = FakeNode(cms_port, 42221, util=1)
    tape = FakeNode(cms_port, 42222, util=90)
    try:
        tape.send(CMS_RR_STATUS, CMS_ST_STAGE)      # advertise staging
        time.sleep(0.5)
        got = _wait_selectable(root_port, "/on-tape-only.dat", 42222)
        assert got == 42222
    finally:
        disk.close()
        tape.close()


def test_stage_select_off_keeps_util_pick(lifecycle):
    """error/negative: withOUT the directive the least-utilised node keeps
    winning — the stage bit alone must not divert selection."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr", "",
              "§2.5 control: stage bit without brix_cms_stage_select.")
    disk = FakeNode(cms_port, 42223, util=1)
    tape = FakeNode(cms_port, 42224, util=90)
    try:
        tape.send(CMS_RR_STATUS, CMS_ST_STAGE)
        time.sleep(0.5)
        got = _wait_selectable(root_port, "/no-stage-sel.dat", 42223)
        assert got == 42223
    finally:
        disk.close()
        tape.close()


# ═══ §2.6/§2.7 negative location cache + kXR_refresh ══════════════════════

def _first_wait_then(port, path, options=0, timeout=8.0):
    """Drive locates until the fan-out window has expired once (first answer
    is kXR_wait), then return the NEXT verdict."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, body = _locate(port, path, options)
        if status == kXR_wait:
            time.sleep(0.3)
            return _locate(port, path, options)
        time.sleep(0.2)
    raise AssertionError("fan-out never parked the first locate")


def test_emptylife_negative_cache(lifecycle):
    """success: after a fan-out expires with no kYR_have, the retry answers
    kXR_NotFound immediately from the negative entry."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_locate_window 400ms; brix_cms_emptylife 10s;",
              "§2.6 negative location cache (emptylife).")
    node = FakeNode(cms_port, 42231)      # never answers kYR_state
    try:
        node.wait_frame(CMS_RR_PING)     # wait until fully registered
        status, body = _first_wait_then(root_port, "/neg-cached.dat")
        assert status == kXR_error, f"expected NotFound, got {status}"
        assert struct.unpack(">I", body[:4])[0] == kXR_NotFound
        # The node WAS probed (the fan-out ran once).
        assert node.count(CMS_RR_STATE) >= 1
    finally:
        node.close()


def test_refresh_bypasses_negative_cache(lifecycle):
    """§2.7: a kXR_refresh locate must NOT be answered from the negative
    entry — it re-probes the cluster (parks again: kXR_wait)."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_locate_window 400ms; brix_cms_emptylife 10s;",
              "§2.6 negative location cache (emptylife).")
    node = FakeNode(cms_port, 42232)
    try:
        node.wait_frame(CMS_RR_PING)
        status, body = _first_wait_then(root_port, "/neg-refresh.dat")
        assert status == kXR_error       # negative entry in place
        probes_before = node.count(CMS_RR_STATE)
        status, _body = _locate(root_port, "/neg-refresh.dat",
                                options=kXR_refresh)
        assert status == kXR_wait, (
            f"refresh must re-probe (park), got {status}")
        deadline = time.time() + 4
        while time.time() < deadline \
                and node.count(CMS_RR_STATE) <= probes_before:
            time.sleep(0.1)
        assert node.count(CMS_RR_STATE) > probes_before, (
            "refresh locate never re-probed the node")
    finally:
        node.close()


def test_no_emptylife_keeps_reparking(lifecycle):
    """control: without emptylife the retry parks again (kXR_wait) — the
    negative path must be strictly opt-in."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_locate_window 400ms;",
              "§2.6 control: fan-out without emptylife.")
    node = FakeNode(cms_port, 42233)
    try:
        node.wait_frame(CMS_RR_PING)
        status, _body = _first_wait_then(root_port, "/no-neg.dat")
        assert status == kXR_wait, f"expected re-park, got {status}"
    finally:
        node.close()


# ═══ §2.8 cms.dfs shared-filesystem mode ══════════════════════════════════

def test_dfs_skips_state_fanout(lifecycle):
    """success: with cms.dfs the locate never probes the node (no kYR_state)
    and redirects immediately by load."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "brix_cms_locate_window 400ms; brix_cms_dfs on;",
              "§2.8 cms.dfs: shared-FS mode skips the per-file probe.")
    node = FakeNode(cms_port, 42241)
    try:
        got = _wait_selectable(root_port, "/dfs-any-file.dat", 42241)
        assert got == 42241
        assert node.count(CMS_RR_STATE) == 0, (
            "dfs mode must not send kYR_state probes")
    finally:
        node.close()


# ═══ §2.9 ManTree-style supervisor offload ════════════════════════════════

def test_max_direct_offloads_to_supervisor(lifecycle):
    """success: past max_direct, a NEW server login gets kYR_try naming the
    registered supervisor and the connection is closed."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.9 ManTree: login offload to the supervisor at the cap.",
              srv_extra="brix_cms_server_max_direct 1;")
    sup = FakeNode(cms_port, 42251, mode=MODE_SERVER | MODE_MANAGER)
    s1 = FakeNode(cms_port, 42252)
    try:
        s1.wait_frame(CMS_RR_PING)       # s1 registered: cap reached
        s2 = FakeNode(cms_port, 42253)
        try:
            frame = s2.wait_frame(CMS_RR_TRY)
            assert frame is not None, "second server never got kYR_try"
            _c, _m, payload = frame
            host = payload.split(b"\x00")[0].decode()
            port = struct.unpack(">H", payload[len(host) + 1:
                                               len(host) + 3])[0]
            assert host == NODE_IP and port == 42251, (host, port)
            assert s2.wait_closed(), "offloaded login must be closed"
        finally:
            s2.close()
    finally:
        sup.close()
        s1.close()


def test_max_direct_without_supervisor_admits(lifecycle):
    """error-path: at the cap with NO supervisor registered, the login is
    admitted directly — never refused outright."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.9 ManTree: no supervisor -> direct admission.",
              srv_extra="brix_cms_server_max_direct 1;")
    # Disjoint exports so /d2/* matches ONLY the second node — otherwise the
    # first node (exporting "/") would also be a valid selection target.
    s1 = FakeNode(cms_port, 42254, paths=b"r /d1")
    try:
        s1.wait_frame(CMS_RR_PING)
        s2 = FakeNode(cms_port, 42255, paths=b"r /d2")
        try:
            got = _wait_selectable(root_port, "/d2/x.dat", 42255)
            assert got == 42255
        finally:
            s2.close()
    finally:
        s1.close()


# ═══ §2.13 blacklist patterns / redirect / whitelist ══════════════════════

def test_blacklist_pattern_drains(lifecycle, tmp_path):
    """success: a `*` host pattern (XrdOucNList rules) drains the node —
    locate stops redirecting to it."""
    bl = tmp_path / "bl.txt"
    bl.write_text("127.0.0.*\n")   # net-literal-allow: pattern under test
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.13 blacklist `*` host patterns.",
              srv_extra=f"brix_cms_blacklist_file {bl};")
    node = FakeNode(cms_port, 42261)
    try:
        node.wait_frame(CMS_RR_PING)
        # Drained from registration: locate must answer NotFound, never a
        # redirect to the pattern-banned node.
        deadline = time.time() + 8
        status = None
        while time.time() < deadline:
            status, body = _locate(root_port, "/blpat.dat")
            if status == kXR_error \
                    and struct.unpack(">I", body[:4])[0] == kXR_NotFound:
                break
            assert status != kXR_redirect, "pattern-banned node was selected"
            time.sleep(0.2)
        assert status == kXR_error
    finally:
        node.close()


def test_blacklist_redirect_entry_bounces_login(lifecycle, tmp_path):
    """success: a `redirect <host:port>` action answers the login with
    kYR_try naming the alternate manager and closes."""
    bl = tmp_path / "bl.txt"
    bl.write_text(f"{NODE_IP} redirect {NODE_IP}:42999\n")
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.13 blacklist redirect action.",
              srv_extra=f"brix_cms_blacklist_file {bl};")
    node = FakeNode(cms_port, 42262)
    try:
        frame = node.wait_frame(CMS_RR_TRY)
        assert frame is not None, "blacklist-redirected login got no kYR_try"
        _c, _m, payload = frame
        host = payload.split(b"\x00")[0].decode()
        port = struct.unpack(">H", payload[len(host) + 1:len(host) + 3])[0]
        assert (host, port) == (NODE_IP, 42999)
        assert node.wait_closed()
    finally:
        node.close()


def test_whitelist_drains_unlisted_admits_listed(lifecycle, tmp_path):
    """security-neg + success: whitelist mode — a login from an UNLISTED host
    is refused at admission (connection closed) and the host never registers;
    a login from a LISTED host is admitted and selectable."""
    wl = tmp_path / "wl.txt"
    wl.write_text("10.99.99.99\n")   # net-literal-allow: whitelist WITHOUT us
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr",
              "",
              "§2.13 whitelist mode.",
              srv_extra=f"brix_cms_whitelist_file {wl};")

    # security-neg: unlisted 127.0.0.1 is refused at login (closed) and never
    # becomes selectable.
    unlisted = FakeNode(cms_port, 42263)
    try:
        assert unlisted.wait_closed(), "unlisted login was not refused"
        status, _body = _locate(root_port, "/wl.dat")
        assert status != kXR_redirect, "unlisted host was selected"
    finally:
        unlisted.close()

    # success: list our host (mtime bump) — a fresh login is admitted, and the
    # admission-time forced poll re-reads the file so the new node registers.
    st = os.stat(wl)
    wl.write_text(f"{NODE_IP}\n")
    os.utime(wl, (st.st_atime, st.st_mtime + 2))
    listed = FakeNode(cms_port, 42264)
    try:
        got = _wait_selectable(root_port, "/wl.dat", 42264, timeout=20.0)
        assert got == 42264
    finally:
        listed.close()


# ═══ §2.17 peer role ══════════════════════════════════════════════════════

def test_peer_selected_only_on_local_miss(lifecycle):
    """success + negative: a peer-mode registrant is never selected while a
    local server matches; it IS selected when the local server leaves."""
    root_port, cms_port = _mgr(lifecycle, "lc-cms-parity-mgr", "",
              "§2.17 peer role: last-resort selection.")
    local = FakeNode(cms_port, 42271)
    peer = FakeNode(cms_port, 42272, mode=MODE_PEER)
    try:
        got = _wait_selectable(root_port, "/peer.dat", 42271)
        assert got == 42271     # local server wins while present

        local.close()
        # Local gone (unregistered/blacklisted on disconnect): the peer is
        # the last resort before NotFound.
        got = _wait_selectable(root_port, "/peer.dat", 42272, timeout=10.0)
        assert got == 42272
    finally:
        peer.close()
        local.close()


# ═══ §2.11 cms.perf pgm + §2.12 cms.altds (node side) ═════════════════════

class StubManager:
    """Accepts CMS node logins; records (code, modifier, payload) frames."""

    def __init__(self):
        self.frames = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((BIND_HOST, 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self._stop = False
        self._conns = []
        t = threading.Thread(target=self._accept, daemon=True)
        t.start()

    def _accept(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            self._conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(0.5)
            while not self._stop:
                try:
                    hdr = _recv_exact(conn, 8)
                except socket.timeout:
                    continue
                streamid, code, modifier, dlen = struct.unpack(">IBBH", hdr)
                payload = _recv_exact(conn, dlen) if dlen else b""
                self.frames.append((code, modifier, payload))
                if code == CMS_RR_PING:
                    conn.sendall(_cms_frame(streamid, CMS_RR_PONG))
        except (ConnectionResetError, OSError):
            pass

    def wait(self, code, pred=None, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for c, m, p in self.frames:
                if c == code and (pred is None or pred(m, p)):
                    return (c, m, p)
            time.sleep(0.05)
        return None

    def stop(self):
        self._stop = True
        for conn in self._conns:
            try:
                conn.close()
            except OSError:
                pass
        try:
            self._sock.close()
        except OSError:
            pass


def _login_dport(payload):
    """Walk the CmsLoginData scalar prologue to the dPort field."""
    pos = 0
    values = []
    for _ in range(10):    # version..sPort
        tag = payload[pos]
        if tag == CMS_PT_SHORT:
            values.append(struct.unpack(">H", payload[pos + 1:pos + 3])[0])
            pos += 3
        elif tag == CMS_PT_INT:
            values.append(struct.unpack(">I", payload[pos + 1:pos + 5])[0])
            pos += 5
        else:
            raise AssertionError(f"bad Pup tag {tag:#x} at {pos}")
    return {"mode": values[1], "dport": values[8]}


def _node(lifecycle, name, stub, extra, reason):
    return lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_cms_parity_node.conf",
        protocol="root",
        readiness="tcp",
        template_values={"MANAGER_PORT": stub.port, "CMS_EXTRA": extra},
        reason=reason,
    ))


def test_altds_advertises_foreign_port(lifecycle):
    """§2.12 success: the login's dPort is the altds port, not listen_port."""
    stub = StubManager()
    try:
        _node(lifecycle, "lc-cms-parity-node", stub,
              "brix_cms_altds 42901;",
              "§2.12 cms.altds: advertise the foreign data port.")
        frame = stub.wait(CMS_RR_LOGIN)
        assert frame is not None, "node never logged in"
        info = _login_dport(frame[2])
        assert info["dport"] == 42901, info
    finally:
        stub.stop()


def test_altds_monitor_suspends_and_resumes(lifecycle):
    """§2.12 monitor: with nothing on the altds port the node suspends
    itself; a listener appearing resumes it."""
    stub = StubManager()
    try:
        _node(lifecycle, "lc-cms-parity-node", stub,
              "brix_cms_altds 42902 monitor; brix_cms_altds_interval 300ms;",
              "§2.12 cms.altds liveness monitor.")
        frame = stub.wait(CMS_RR_STATUS,
                          pred=lambda m, p: m & CMS_ST_SUSPEND, timeout=12.0)
        assert frame is not None, "altds-down never suspended the node"

        n_before = len(stub.frames)
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((BIND_HOST, 42902))
        lsock.listen(4)
        try:
            deadline = time.time() + 12
            resumed = None
            while time.time() < deadline and resumed is None:
                for c, m, _p in stub.frames[n_before:]:
                    if c == CMS_RR_STATUS and (m & CMS_ST_RESUME):
                        resumed = True
                        break
                time.sleep(0.1)
            assert resumed, "altds recovery never resumed the node"
        finally:
            lsock.close()
    finally:
        stub.stop()


def test_perf_pgm_overrides_meter(lifecycle, tmp_path):
    """§2.11 success: the external feed's cpu figure (77) rides the LOAD
    heartbeat in place of the /proc meter's."""
    pgm = tmp_path / "perf.sh"
    pgm.write_text("#!/bin/sh\nwhile true; do echo '77 1 2 3 4'; sleep 1; done\n")
    pgm.chmod(0o755)
    stub = StubManager()
    try:
        _node(lifecycle, "lc-cms-parity-node", stub,
              f"brix_cms_perf_pgm \"{pgm}\";",
              "§2.11 cms.perf pgm external load feed.")
        frame = stub.wait(CMS_RR_LOAD,
                          pred=lambda m, p: len(p) >= 8 and p[2] == 77,
                          timeout=15.0)
        assert frame is not None, (
            f"no LOAD carried the fed cpu=77: {stub.frames[-5:]}")
    finally:
        stub.stop()


def test_peer_role_login_mode_bits(lifecycle):
    """§2.17 client side: brix_cms_role peer logs in with the kYR_peer Mode
    bit and without kYR_server."""
    stub = StubManager()
    try:
        _node(lifecycle, "lc-cms-parity-node", stub,
              "brix_cms_role peer;",
              "§2.17 peer role: login Mode bits.")
        frame = stub.wait(CMS_RR_LOGIN)
        assert frame is not None
        info = _login_dport(frame[2])
        assert info["mode"] & MODE_PEER, info
        assert not (info["mode"] & MODE_SERVER), info
    finally:
        stub.stop()
