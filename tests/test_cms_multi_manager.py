"""
test_cms_multi_manager.py — CMS multi-manager redundancy (stock parity: a node
logs into ALL configured managers, locates rotate over the live links).

Self-contained: each test provisions its OWN registry-lifecycle nginx node
pointed at in-test wire-speaking stub managers (login-accept, kYR_locate →
kYR_select, PING → PONG, frames recorded), so redundancy, rotation, failover
and the CNS fan-out are all asserted from BOTH ends of the wire — no cmsd
fleet dependency.

Covered:
  * concurrent login — both stub managers receive kYR_login from one node;
  * ClientMan-style rotation — successive registry-miss locates are answered
    by different managers (the redirect port reveals which one);
  * failover — with one manager dead, locates keep resolving via the survivor;
  * CNS fan-out — a namespace mutation on an emit node reaches EVERY manager;
  * security-neg — an unsolicited kYR_select with an unknown streamid is
    ignored (no crash, node keeps serving);
  * config-negatives — duplicate manager and a 16th manager are rejected at
    parse time; three managers (single or repeated directive) are accepted.
"""

import os
import re
import socket
import struct
import threading
import time

import pytest

from config_parse import nginx_t
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-multi")]

# ── CMS wire constants (see cms_parent_stubs.py / src/net/cms/cns.h) ──────
CMS_RR_LOGIN, CMS_RR_LOCATE, CMS_RR_SELECT = 0, 2, 10
CMS_RR_PING, CMS_RR_PONG = 17, 18
CMS_RR_CNS = 40

# ── XRootD client wire constants (see test_manager_mode.py) ───────────────
kXR_ok, kXR_redirect = 0, 4004
kXR_login, kXR_locate = 3007, 3027


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError(f"closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


# ── stub manager ──────────────────────────────────────────────────────────

class StubManager:
    """A wire-speaking CMS manager stand-in.

    Accepts node connections, records every received frame as
    ``(opcode, streamid)``, answers kYR_locate with kYR_select pointing at
    ``redir_port`` and kYR_ping with kYR_pong.  ``rogue_select=True`` fires an
    unsolicited kYR_select with a bogus streamid right after the login lands
    (the security-negative probe).
    """

    def __init__(self, redir_port, rogue_select=False):
        self.port = _free_port()
        self.redir_port = redir_port
        self.rogue_select = rogue_select
        self.frames = []          # [(opcode, streamid)] in arrival order
        self.logins = 0
        self._sock = None
        self._conns = []
        self._threads = []
        self._stop = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((BIND_HOST, self.port))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._threads.append(t)

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            self._conns.append(conn)
            t = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            t.start()
            self._threads.append(t)

    def _serve(self, conn):
        try:
            conn.settimeout(0.5)
            while not self._stop:
                try:
                    hdr = _recv_exact(conn, 8)
                except socket.timeout:
                    continue
                streamid, opcode, _mod, dlen = struct.unpack(">IBBH", hdr)
                if dlen:
                    _recv_exact(conn, dlen)
                self.frames.append((opcode, streamid))
                if opcode == CMS_RR_LOGIN:
                    self.logins += 1
                    if self.rogue_select:
                        self._send(conn, 0xDEADBEEF, CMS_RR_SELECT,
                                   self._select_payload())
                elif opcode == CMS_RR_LOCATE:
                    self._send(conn, streamid, CMS_RR_SELECT,
                               self._select_payload())
                elif opcode == CMS_RR_PING:
                    self._send(conn, streamid, CMS_RR_PONG)
        except (ConnectionResetError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _select_payload(self):
        return HOST.encode() + b"\x00" + struct.pack(">H", self.redir_port)

    @staticmethod
    def _send(conn, streamid, opcode, payload=b""):
        conn.sendall(struct.pack(">IBBH", streamid, opcode, 0, len(payload))
                     + payload)

    def count(self, opcode):
        return sum(1 for op, _ in self.frames if op == opcode)

    def wait_login(self, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.logins >= 1:
                return True
            time.sleep(0.02)
        return False

    def stop(self):
        """Hard-stop: close accepted links too, so the node sees FIN at once
        (a lingering serve thread must not answer post-mortem locates)."""
        self._stop = True
        for conn in self._conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


# ── XRootD client-side drive (bootstrap + locate) ─────────────────────────

def _xrd_resp(sock):
    hdr = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _xrd_session(port):
    sock = socket.create_connection((HOST, port), timeout=10)
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


def _locate(port, path):
    """One kXR_locate; returns (status, redirect_port_or_None)."""
    sock = _xrd_session(port)
    try:
        payload = path.encode() + b"\x00"
        sock.sendall(struct.pack(">BB H H 14x I",
                                 0, 1, kXR_locate, 0, len(payload)) + payload)
        status, body = _xrd_resp(sock)
        if status == kXR_redirect and len(body) >= 4:
            return status, struct.unpack(">i", body[:4])[0]
        return status, None
    finally:
        sock.close()


# ── fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def stub_pair():
    """Two stub managers with distinguishable redirect targets."""
    a, b = StubManager(redir_port=29101), StubManager(redir_port=29102)
    a.start()
    b.start()
    yield a, b
    a.stop()
    b.stop()


@pytest.fixture
def multi_node(lifecycle, stub_pair):
    """A manager-mode node logged into both stub managers."""
    a, b = stub_pair
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-cms-multi-node",
        template="nginx_cms_multi_manager.conf",
        protocol="root",
        readiness="tcp",
        template_values={"MANAGER_PORT_A": a.port, "MANAGER_PORT_B": b.port},
        reason="CMS multi-manager parent-lookup node (two stub managers).",
    ))
    assert a.wait_login(), "manager A never saw kYR_login"
    assert b.wait_login(), "manager B never saw kYR_login"
    return ep, a, b


def _read_log(ep):
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


# ── tests: concurrent login ───────────────────────────────────────────────

def test_node_logs_into_all_managers(multi_node):
    """One node, two managers: BOTH receive kYR_login (stock all-manager join)."""
    ep, a, b = multi_node
    assert a.logins >= 1 and b.logins >= 1
    log = _read_log(ep)
    # Two per-link registrations, and the config notice counted both entries.
    assert len(re.findall(r"CMS registered with \S+ after \d+ ms", log)) >= 2, log
    assert "(2 total)" in log, "config notice missing the manager count\n" + log


# ── tests: rotation + failover ────────────────────────────────────────────

def test_locate_rotates_over_managers(multi_node):
    """Registry-miss locates spread over BOTH managers (ClientMan rotation)."""
    ep, a, b = multi_node
    seen = set()
    for i in range(4):
        status, redir = _locate(ep.port, f"/rot-{i}.dat")
        assert status == kXR_redirect, f"locate {i}: status {status}"
        seen.add(redir)
    assert seen == {a.redir_port, b.redir_port}, (
        f"expected answers from both managers, got redirect ports {seen}")
    assert a.count(CMS_RR_LOCATE) >= 1 and b.count(CMS_RR_LOCATE) >= 1


def test_locate_fails_over_to_surviving_manager(multi_node):
    """Kill manager A: locates keep resolving via B — redundancy's whole point."""
    ep, a, b = multi_node
    a.stop()

    got = []
    deadline = time.time() + 15
    i = 0
    while time.time() < deadline and len(got) < 2:
        i += 1
        try:
            status, redir = _locate(ep.port, f"/fo-{i}.dat")
        except (ConnectionResetError, OSError):
            continue
        if status == kXR_redirect and redir == b.redir_port:
            got.append(redir)
        else:
            got = []          # want two CONSECUTIVE survivor-only answers
    assert len(got) == 2, "locates never settled on the survivor\n" + _read_log(ep)
    assert got == [b.redir_port, b.redir_port], (
        f"post-failover redirects {got}, expected only manager B "
        f"({b.redir_port})")


# ── tests: security-negative ──────────────────────────────────────────────

def test_unsolicited_select_is_ignored(lifecycle):
    """A rogue manager fires kYR_select with an unknown streamid right after
    login: the node must drop it on the pending-table miss and keep serving."""
    a = StubManager(redir_port=29101, rogue_select=True)
    b = StubManager(redir_port=29102)
    a.start()
    b.start()
    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-cms-multi-node",
            template="nginx_cms_multi_manager.conf",
            protocol="root",
            readiness="tcp",
            template_values={"MANAGER_PORT_A": a.port,
                             "MANAGER_PORT_B": b.port},
            reason="CMS multi-manager node vs rogue unsolicited kYR_select.",
        ))
        assert a.wait_login() and b.wait_login()
        time.sleep(0.3)       # let the rogue frame land and be processed
        status, redir = _locate(ep.port, "/after-rogue.dat")
        assert status == kXR_redirect, f"node stopped serving: status {status}"
        assert redir in (a.redir_port, b.redir_port)
        log = _read_log(ep)
        assert "exited on signal" not in log, "worker crashed\n" + log
    finally:
        a.stop()
        b.stop()


# ── tests: CNS fan-out ────────────────────────────────────────────────────

def test_cns_event_fans_out_to_all_managers(lifecycle, stub_pair, tmp_path):
    """A write+close on an emit node reaches EVERY manager link (split-brain
    prevention: each redundant manager keeps its own inventory)."""
    a, b = stub_pair
    data_root = str(tmp_path / "emit-data")
    os.makedirs(data_root, exist_ok=True)
    os.chmod(data_root, 0o777)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-cms-multi-emit",
        template="nginx_cms_multi_emit.conf",
        protocol="root",
        readiness="tcp",
        data_root=data_root,
        template_values={"MANAGER_PORT_A": a.port, "MANAGER_PORT_B": b.port},
        reason="CNS-emit data node fanning events to two stub managers.",
    ))
    assert a.wait_login() and b.wait_login()

    # write+close via the raw client (same frames as test_cns.py) → CNS event.
    s = _xrd_session(ep.port)
    p = b"/fanout.dat"
    opts = 0x0008 | 0x4000 | 0x0100   # kXR_new | write | mkpath
    s.sendall(struct.pack(">2sHHHH6s4sI", b"\x00\x03", 3010, 0o644, opts, 0,
                          b"\x00" * 6, b"\x00" * 4, len(p)) + p)
    st, body = _xrd_resp(s)
    assert st == kXR_ok, ("open-write", st, body)
    fh = body[0:4]
    s.sendall(struct.pack(">2sH4sqiI", b"\x00\x07", 3019, fh, 0, 0, 4) + b"data")
    assert _xrd_resp(s)[0] == kXR_ok
    s.sendall(struct.pack(">2sH4s12sI", b"\x00\x0e", 3003, fh, b"\x00" * 12, 0))
    _xrd_resp(s)
    s.close()

    deadline = time.time() + 8
    while time.time() < deadline:
        if a.count(CMS_RR_CNS) >= 1 and b.count(CMS_RR_CNS) >= 1:
            break
        time.sleep(0.05)
    assert a.count(CMS_RR_CNS) >= 1, "manager A never got the CNS event"
    assert b.count(CMS_RR_CNS) >= 1, "manager B never got the CNS event"


# ── tests: config negatives (parse-only, no boot) ─────────────────────────

def _parse(tmp_path, directives):
    (tmp_path / "logs").mkdir(exist_ok=True)
    return nginx_t("nginx_cms_multi_parse.conf", tmp_path,
                   MANAGER_DIRECTIVES=directives)


def test_config_three_managers_accepted(tmp_path):
    r = _parse(tmp_path, f"        brix_cms_manager {BIND_HOST}:12801 "
                         f"{BIND_HOST}:12802 {BIND_HOST}:12803;")
    assert r.returncode == 0, r.stderr


def test_config_repeated_directive_accumulates(tmp_path):
    r = _parse(tmp_path, f"        brix_cms_manager {BIND_HOST}:12801;\n"
                         f"        brix_cms_manager {BIND_HOST}:12802;")
    assert r.returncode == 0, r.stderr


def test_config_duplicate_manager_rejected(tmp_path):
    r = _parse(tmp_path, f"        brix_cms_manager {BIND_HOST}:12801 "
                         f"{BIND_HOST}:12801;")
    assert r.returncode != 0
    assert "duplicate manager" in r.stderr, r.stderr


def test_config_sixteenth_manager_rejected(tmp_path):
    ports = " ".join(f"{BIND_HOST}:{12801 + i}" for i in range(16))
    r = _parse(tmp_path, f"        brix_cms_manager {ports};")
    assert r.returncode != 0
    assert "more than 15 managers" in r.stderr, r.stderr
