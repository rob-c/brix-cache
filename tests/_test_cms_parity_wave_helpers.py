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


# ── negative-cache probe (§2.6/§2.7) ──────────────────────────────────────

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


# ── node-side stub manager + node harness (§2.11 perf feed, §2.12 altds) ──

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
