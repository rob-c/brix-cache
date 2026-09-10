"""
tests/test_phase115_cms_select_proxy.py — Phase-115 W2.1: ``brix_cms_response``.

A CMS manager that answers "which data server has this path" by pinning the
client's session to the selected node and relaying its requests (``proxy``)
instead of sending a kXR_redirect (``redirect``, the stock answer).  Registered
nodes are scripted CMS peers (``test_cms_locate_have._CmsNode``) whose data
port is a real read-only nginx data server, a port with nothing behind it, or
``_FakeDataServer`` — just enough xrootd to bootstrap a proxy session, count
its connections, and die on cue.  The gateway's own export is an EMPTY
directory, so every byte read through it can only have come from the node.

Covered (3-per-change rule: success + error + security-negative, plus the
design choices the implementation made):
  success       proxy mode: open/read/close through the gateway, kXR_ok never
                kXR_redirect, bytes that exist only on the data server
  compat        redirect mode: the same registration yields kXR_redirect to
                the data server's port (stock behaviour untouched)
  design        kXR_locate through a proxying gateway names the gateway
                itself — both the registry chokepoint and the kYR_have wake
  design        an idle session re-pins to a newly selected node; a session
                with a file open keeps its node (one upstream per session)
  error         the selected node has nothing listening: kXR_error, session
                still usable, the next selection works
  error         the data server dies mid-transfer: a clean error or EOF
                inside the socket timeout, never a hang
  security-neg  brix_auth unix gateway: an open before kXR_auth never reaches
                the data node (zero connections); after auth it does
  security-neg  a node claiming write access for a read-only data server: the
                proxied write-open is refused BY THE DATA SERVER, nothing
                created on either export
  config-neg    brix_cms_response bogus is rejected at parse; proxy accepted

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_phase115_cms_select_proxy.py -v
"""

import os
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

import config_parse
from ephemeral_port import free_port
from server_registry import NginxInstanceSpec
from settings import SERVER_HOST
from test_cms_locate_have import _CmsNode
from test_pgwrite_checksum import _handshake_login, _read_response
from test_unix_auth_wire import _auth, _read

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-cms-select")]

H = SERVER_HOST

kXR_ok = 0
kXR_error = 4003
kXR_redirect = 4004
kXR_close = 3003
kXR_protocol = 3006
kXR_login = 3007
kXR_open = 3010
kXR_read = 3013
kXR_locate = 3027

kXR_new = 0x0008
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_mkpath = 0x0100
WRITE_CREATE = kXR_new | kXR_open_updt | kXR_mkpath

WINDOW_MS = 1200
SEED = b"phase-115 bytes that live only on the data server\n"
WAKE_SEED = b"woken by kYR_have\n"
UNLISTED = b"on the node's disk, in no node's registry entry\n"
GATEWAY_TEMPLATE = "nginx_p115_cms_gateway.conf"
DS_TEMPLATE = "nginx_p115_cms_dataserver.conf"


# ---------------------------------------------------------------------------
# Raw client requests (login helpers come from the shared modules)
# ---------------------------------------------------------------------------

def _open(sock, path: bytes, options: int, mode: int = 0):
    sock.sendall(struct.pack("!2sHHH2s6s4sI", b"\x00\x04", kXR_open, mode,
                             options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                             len(path)) + path)
    return _read_response(sock)


def _close(sock, fh: bytes):
    sock.sendall(struct.pack("!2sH4sq4sI", b"\x00\x06", kXR_close, fh, 0,
                             b"\x00" * 4, 0))
    return _read_response(sock)


def _locate(sock, path: bytes):
    payload = path + b"\x00"
    sock.sendall(struct.pack("!2sHH14sI", b"\x00\x07", kXR_locate, 0,
                             b"\x00" * 14, len(payload)) + payload)
    return _read_response(sock)


def _response_or_eof(sock):
    """Like _read_response, but an upstream-induced close is a result, not an
    assertion.  A socket timeout still propagates — that is the hang."""
    buf = b""
    while len(buf) < 8:
        chunk = sock.recv(8 - len(buf))
        if not chunk:
            return "eof", b""
        buf += chunk
    _sid, status, dlen = struct.unpack("!2sHI", buf)
    body = b""
    while len(body) < dlen:
        chunk = sock.recv(dlen - len(body))
        if not chunk:
            return "eof", body
        body += chunk
    return status, body


def _redirect_port(body: bytes) -> int:
    return struct.unpack(">I", body[:4])[0]


def _settle(*nodes):
    """Block until every node is in the manager's registry.  The manager
    speaks to a node only after brix_srv_register (its ping timer is armed
    in cms_srv_complete_login), so the first inbound frame is the proof; a
    fixed sleep raced two logins on one manager and lost under load."""
    for node in nodes:
        assert node.wait_ready(8.0), "CMS node never entered the registry"


def _closed_port() -> int:
    """A loopback port nothing listens on.

    A lease from the mock range is already exclusive to this session, so it
    needs no bind/close dance to prove it is free — and unlike a kernel-assigned
    port it cannot collide with a managed service.
    """
    return free_port(H)


# ---------------------------------------------------------------------------
# A scripted data server: bootstrap + open/read/close, connection counting
# ---------------------------------------------------------------------------

class _FakeDataServer:
    """Enough xrootd for a brix proxy session: hello, kXR_protocol, kXR_login
    (no sec token), kXR_open (fh 7), kXR_read, kXR_close.  ``mode``:
    ``serve`` answers reads with PAYLOAD; ``die_on_read`` closes the socket
    on the first kXR_read — a data server dying mid-transfer."""

    PAYLOAD = b"fake-node-bytes!"

    def __init__(self, mode="serve"):
        self.mode = mode
        self.accepted = 0
        self._lock = threading.Lock()
        self._closing = False
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port = free_port(H)
        self._srv.bind((H, self.port))
        self._srv.listen(8)
        self._srv.settimeout(0.2)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def connections(self) -> int:
        with self._lock:
            return self.accepted

    def _accept_loop(self):
        while not self._closing:
            try:
                conn, _peer = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self.accepted += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed")
            buf += chunk
        return buf

    def _reply_for(self, reqid, conn):
        if reqid == kXR_protocol:
            return struct.pack(">II", 0x00000310, 0)      # pval, no gotoTLS
        if reqid == kXR_login:
            return b"\x00" * 16                            # sessid, no sec token
        if reqid == kXR_open:
            return struct.pack(">I", 7) + b"\x00" * 8      # fh, cpsize, cptype
        if reqid == kXR_read:
            if self.mode == "die_on_read":
                conn.close()
                return None
            return self.PAYLOAD
        return b""

    def _serve(self, conn):
        conn.settimeout(5)
        try:
            self._exact(conn, 20)                          # client hello
            conn.sendall(struct.pack(">HHI", 0, 0, 8) + struct.pack(">II", 0x00000310, 1))
            while not self._closing:
                hdr = self._exact(conn, 24)
                sid = hdr[:2]
                reqid = struct.unpack(">H", hdr[2:4])[0]
                dlen = struct.unpack(">I", hdr[20:24])[0]
                if dlen:
                    self._exact(conn, dlen)
                body = self._reply_for(reqid, conn)
                if body is None:
                    return
                conn.sendall(sid + struct.pack(">HI", kXR_ok, len(body)) + body)
        except (OSError, ConnectionError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self._closing = True
        try:
            self._srv.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _gateway(lifecycle, name, response, auth="none"):
    return lifecycle.start(NginxInstanceSpec(
        name=name,
        template=GATEWAY_TEMPLATE,
        protocol="root",
        readiness="tcp",
        template_values={"RESPONSE": response, "AUTH": auth, "WINDOW_MS": WINDOW_MS},
        reason="Phase-115 W2.1: brix_cms_response select-then-proxy gateway.",
    ))


@pytest.fixture
def gateway(lifecycle):
    return _gateway(lifecycle, "lc-p115-gw-proxy", "proxy")


@pytest.fixture
def redirect_gateway(lifecycle):
    return _gateway(lifecycle, "lc-p115-gw-redirect", "redirect")


@pytest.fixture
def unix_gateway(lifecycle):
    return _gateway(lifecycle, "lc-p115-gw-unix", "proxy", auth="unix")


@pytest.fixture
def data_server(lifecycle):
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-p115-ds",
        template=DS_TEMPLATE,
        protocol="root",
        readiness="tcp",
        reason="Phase-115 W2.1: read-only data server behind the gateway.",
    ))
    root = Path(ep.data_root)
    (root / "live").mkdir(parents=True, exist_ok=True)
    (root / "live" / "hello.bin").write_bytes(SEED)
    (root / "wake").mkdir(parents=True, exist_ok=True)
    (root / "wake" / "x.bin").write_bytes(WAKE_SEED)
    return ep


def _cms_port(gw) -> int:
    return gw.extra_ports["CMS_PORT"]


# ---------------------------------------------------------------------------
# success / compat
# ---------------------------------------------------------------------------

def test_proxy_mode_serves_data_server_bytes_without_redirect(gateway, data_server):
    """success: the client never sees kXR_redirect; the bytes come from the
    data server's export, which the gateway's own (empty) export lacks."""
    node = _CmsNode(_cms_port(gateway), data_server.port, paths=b"r /live")
    try:
        _settle(node)
        sock = _handshake_login(H, gateway.port)
        try:
            status, body = _open(sock, b"/live/hello.bin", kXR_open_read)
            assert status == kXR_ok, f"expected kXR_ok, got {status} {body!r}"
            fh = body[:4]
            status, data = _read(sock, fh, len(SEED))
            assert status == kXR_ok and data == SEED, (status, data)
            status, _ = _close(sock, fh)
            assert status == kXR_ok
        finally:
            sock.close()
        assert not (Path(gateway.data_root) / "live" / "hello.bin").exists(), \
            "the gateway's own export must stay empty — bytes must be proxied"
    finally:
        node.close()


def test_redirect_mode_still_redirects_to_the_selected_node(redirect_gateway, data_server):
    """compat: brix_cms_response redirect (the default) keeps the stock
    kXR_redirect answer, port first, host after."""
    node = _CmsNode(_cms_port(redirect_gateway), data_server.port, paths=b"r /live")
    try:
        _settle(node)
        sock = _handshake_login(H, redirect_gateway.port)
        try:
            status, body = _open(sock, b"/live/hello.bin", kXR_open_read)
            assert status == kXR_redirect, f"expected kXR_redirect, got {status}"
            assert _redirect_port(body) == data_server.port
            assert b"127.0.0.1" in body[4:]  # net-literal-allow: the redirect payload under test carries the host
        finally:
            sock.close()
    finally:
        node.close()


# ---------------------------------------------------------------------------
# design choices
# ---------------------------------------------------------------------------

def test_locate_through_a_proxying_gateway_names_the_gateway(gateway, data_server):
    """design: a proxying gateway is, to its clients, a data server — locate
    answers with the gateway's own location on both the registry-hit path and
    the kYR_have wake path; the open that follows is proxied."""
    node = _CmsNode(_cms_port(gateway), data_server.port, paths=b"r /",
                    answer_have=True)
    try:
        _settle(node)
        sock = _handshake_login(H, gateway.port)
        try:
            # loc-cache miss → kYR_state probe → kYR_have → wake → self
            status, body = _locate(sock, b"/wake/x.bin")
            assert status == kXR_ok, f"locate: {status} {body!r}"
            loc = body.rstrip(b"\x00").decode()
            assert loc.startswith("Sr") and loc.endswith(f":{gateway.port}"), loc
            assert node.probes(), "the wake path was not exercised (no probe seen)"

            # ...and the open that follows rides the pinned proxy session.
            status, body = _open(sock, b"/wake/x.bin", kXR_open_read)
            assert status == kXR_ok, f"open after locate: {status} {body!r}"
            status, data = _read(sock, body[:4], len(WAKE_SEED))
            assert status == kXR_ok and data == WAKE_SEED, (status, data)
        finally:
            sock.close()
    finally:
        node.close()


def test_idle_session_repins_to_the_newly_selected_node(gateway, data_server):
    """design: one upstream per session, so a selection naming another node
    re-pins the session — when it is idle with no file open."""
    fake = _FakeDataServer("serve")
    live = _CmsNode(_cms_port(gateway), data_server.port, paths=b"r /live")
    other = _CmsNode(_cms_port(gateway), fake.port, paths=b"r /fake")
    try:
        _settle(live, other)
        sock = _handshake_login(H, gateway.port)
        try:
            status, body = _open(sock, b"/live/hello.bin", kXR_open_read)
            assert status == kXR_ok, (status, body)
            assert _close(sock, body[:4])[0] == kXR_ok
            assert fake.connections() == 0

            status, body = _open(sock, b"/fake/x", kXR_open_read)
            assert status == kXR_ok, f"re-pinned open: {status} {body!r}"
            assert fake.connections() == 1, "idle session did not move to the new node"
            status, data = _read(sock, body[:4], len(_FakeDataServer.PAYLOAD))
            assert status == kXR_ok and data == _FakeDataServer.PAYLOAD, (status, data)
            assert _close(sock, body[:4])[0] == kXR_ok

            # and back again: the pin follows the selection, not the first node
            status, body = _open(sock, b"/live/hello.bin", kXR_open_read)
            assert status == kXR_ok, (status, body)
            status, data = _read(sock, body[:4], len(SEED))
            assert status == kXR_ok and data == SEED, (status, data)
        finally:
            sock.close()
    finally:
        live.close()
        other.close()
        fake.close()


def test_session_with_an_open_file_keeps_its_node(gateway, data_server):
    """design: with a file open the session cannot leave its node — the
    request rides the pinned upstream (which lacks the path) and the other
    node sees no connection; once the file is closed the re-pin happens."""
    fake = _FakeDataServer("serve")
    live = _CmsNode(_cms_port(gateway), data_server.port, paths=b"r /live")
    other = _CmsNode(_cms_port(gateway), fake.port, paths=b"r /fake")
    try:
        _settle(live, other)
        sock = _handshake_login(H, gateway.port)
        try:
            status, body = _open(sock, b"/live/hello.bin", kXR_open_read)
            assert status == kXR_ok, (status, body)
            held = body[:4]

            status, body = _open(sock, b"/fake/x", kXR_open_read)
            assert status == kXR_error, f"open on the pinned node: {status} {body!r}"
            time.sleep(0.2)
            assert fake.connections() == 0, "a busy session must not change node"

            assert _close(sock, held)[0] == kXR_ok
            status, body = _open(sock, b"/fake/x", kXR_open_read)
            assert status == kXR_ok, f"open after close: {status} {body!r}"
            assert fake.connections() == 1
        finally:
            sock.close()
    finally:
        live.close()
        other.close()
        fake.close()


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_dead_selected_node_is_an_error_not_a_hang(gateway, data_server):
    """error: the registry names a node with nothing listening — the client
    gets kXR_error (twice, promptly) and the session then serves a live node."""
    dead = _CmsNode(_cms_port(gateway), _closed_port(), paths=b"r /dead")
    live = _CmsNode(_cms_port(gateway), data_server.port, paths=b"r /live")
    try:
        _settle(dead, live)
        sock = _handshake_login(H, gateway.port)
        try:
            for _ in range(2):
                status, body = _open(sock, b"/dead/x", kXR_open_read)
                assert status == kXR_error, f"dead node: {status} {body!r}"
                assert b"proxy" in body, body

            status, body = _open(sock, b"/live/hello.bin", kXR_open_read)
            assert status == kXR_ok, f"session unusable after error: {status} {body!r}"
            status, data = _read(sock, body[:4], len(SEED))
            assert status == kXR_ok and data == SEED
        finally:
            sock.close()
    finally:
        dead.close()
        live.close()


def test_data_server_dying_mid_transfer_is_a_clean_error(gateway):
    """error: the node closes its socket on the first kXR_read — the client
    sees kXR_error or EOF within the socket timeout, never a hang."""
    fake = _FakeDataServer("die_on_read")
    node = _CmsNode(_cms_port(gateway), fake.port, paths=b"r /fake")
    try:
        _settle(node)
        sock = _handshake_login(H, gateway.port)
        try:
            status, body = _open(sock, b"/fake/x", kXR_open_read)
            assert status == kXR_ok, (status, body)
            sock.sendall(struct.pack("!2sH4sqiI", b"\x00\x05", kXR_read,
                                     body[:4], 0, 64, 0))
            t0 = time.monotonic()
            status, body = _response_or_eof(sock)
            assert status in (kXR_error, "eof"), (status, body)
            assert time.monotonic() - t0 < 5.0
        finally:
            sock.close()
    finally:
        node.close()
        fake.close()


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

def test_unauthenticated_open_never_reaches_the_data_node(unix_gateway):
    """security-neg: on a brix_auth unix gateway the proxy leg opens only for
    an authenticated session — before kXR_auth the node sees no connection."""
    fake = _FakeDataServer("serve")
    node = _CmsNode(_cms_port(unix_gateway), fake.port, paths=b"r /fake")
    try:
        _settle(node)
        sock = _handshake_login(H, unix_gateway.port)
        try:
            status, body = _open(sock, b"/fake/x", kXR_open_read)
            assert status == kXR_error, f"unauthenticated open: {status} {body!r}"
            time.sleep(0.2)
            assert fake.connections() == 0, "proxy leg opened before authentication"

            status, errcode, _ = _auth(sock, b"unix\x00brixuser")
            assert status == kXR_ok, f"unix auth refused: {status} {errcode}"
            status, body = _open(sock, b"/fake/x", kXR_open_read)
            assert status == kXR_ok, f"authenticated open: {status} {body!r}"
            assert fake.connections() == 1
        finally:
            sock.close()
    finally:
        node.close()
        fake.close()


def test_unregistered_path_is_not_served_through_a_stale_pin(gateway, data_server):
    """security-neg: the REGISTRY, not the session's existing pin, decides what
    a session may reach.  A session pinned to the data server by a legitimate
    selection on /live must not then be able to read a file that lives on that
    same server's export under a prefix no node advertises: the manager has no
    selection for it, so the gateway refuses instead of forwarding the request
    verbatim to whichever node the session happens to be riding.

    This is the security half of the W2.1 dispatch-gate fix.  Before it, the pin
    was permanent — every opcode after the first selection short-circuited onto
    the pinned upstream without consulting the manager — so this open was served
    with the file's bytes."""
    root = Path(data_server.data_root)
    (root / "unlisted").mkdir(parents=True, exist_ok=True)
    (root / "unlisted" / "secret.bin").write_bytes(UNLISTED)

    live = _CmsNode(_cms_port(gateway), data_server.port, paths=b"r /live")
    try:
        _settle(live)
        sock = _handshake_login(H, gateway.port)
        try:
            # pin the session to the data server through a legitimate selection
            status, body = _open(sock, b"/live/hello.bin", kXR_open_read)
            assert status == kXR_ok, (status, body)
            assert _close(sock, body[:4])[0] == kXR_ok

            # same upstream, and the file is really there — but unadvertised
            status, body = _open(sock, b"/unlisted/secret.bin", kXR_open_read)
            assert status == kXR_error, \
                f"stale pin served an unadvertised path: {status} {body!r}"
            assert UNLISTED not in body

            # ...and the refusal does not poison the session: an advertised
            # path still selects, re-pins and serves.
            status, body = _open(sock, b"/live/hello.bin", kXR_open_read)
            assert status == kXR_ok, f"session unusable after refusal: {status} {body!r}"
            status, data = _read(sock, body[:4], len(SEED))
            assert status == kXR_ok and data == SEED, (status, data)
        finally:
            sock.close()
    finally:
        live.close()


def test_write_open_is_refused_by_the_read_only_data_server(gateway, data_server):
    """security-neg: a node registers `w /ro` for a data server that has no
    brix_allow_write — the gateway selects it, the DATA SERVER refuses the
    proxied create, and nothing appears on either export."""
    liar = _CmsNode(_cms_port(gateway), data_server.port, paths=b"w /ro")
    try:
        _settle(liar)
        sock = _handshake_login(H, gateway.port)
        try:
            status, body = _open(sock, b"/ro/new.bin", WRITE_CREATE, 0o644)
            assert status == kXR_error, f"write-open: {status} {body!r}"
            assert b"no data server" not in body, \
                "refused by the gateway's selection, not by the data server"
        finally:
            sock.close()
        assert not (Path(data_server.data_root) / "ro" / "new.bin").exists()
        assert not (Path(gateway.data_root) / "ro" / "new.bin").exists()
    finally:
        liar.close()


# ---------------------------------------------------------------------------
# config-negative
# ---------------------------------------------------------------------------

def test_bogus_response_mode_is_rejected_at_parse(tmp_path):
    """config-neg: the directive is an enum — `bogus` fails nginx -t with the
    enum's message; `proxy` parses (the directive is registered)."""
    # Free ports, not 1/2: `nginx -t` binds every listen socket, so the
    # ACCEPTING half below would fail with `bind() ... (13: Permission denied)`
    # as an ordinary uid — after reporting the syntax ok, which is what makes it
    # read like a missing directive rather than a privileged port.
    values = dict(PORT=free_port(), CMS_PORT=free_port(), AUTH="none",
                  WINDOW_MS=WINDOW_MS,
                  DATA_ROOT=str(tmp_path), LOG_DIR=str(tmp_path))
    bad = config_parse.nginx_t(GATEWAY_TEMPLATE, tmp_path / "bad", RESPONSE="bogus", **values)
    assert bad.returncode != 0
    # Stock ngx_conf_set_enum_slot wording: it names the rejected VALUE and the
    # file:line, never the directive.  Asserting the directive name here was
    # asserting a message nginx does not emit — the registration is proved by
    # the accepting half below, which is the only half that can prove it.
    assert "invalid value" in bad.stderr and "bogus" in bad.stderr, bad.stderr
    good = config_parse.nginx_t(GATEWAY_TEMPLATE, tmp_path / "good", RESPONSE="proxy", **values)
    assert good.returncode == 0, good.stderr
