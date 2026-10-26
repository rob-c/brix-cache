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

import struct
import time
from pathlib import Path

import pytest

import config_parse
from _test_phase115_cms_select_proxy_helpers import (
    WRITE_CREATE,
    _FakeDataServer,
    _bind_secondary,
    _close,
    _closed_port,
    _locate,
    _login_with_session,
    _namespace_mutation,
    _open,
    _redirect_port,
    _response_or_eof,
    _settle,
    kXR_NotAuthorized,
    kXR_error,
    kXR_mv,
    kXR_ok,
    kXR_open_read,
    kXR_redirect,
    kXR_rm,
)
from ephemeral_port import free_port
from server_registry import NginxInstanceSpec
from settings import SERVER_HOST
from test_cms_locate_have import _CmsNode
from test_pgwrite_checksum import _handshake_login
from test_unix_auth_wire import _auth, _read

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-cms-select")]

H = SERVER_HOST

WINDOW_MS = 1200
SEED = b"phase-115 bytes that live only on the data server\n"
WAKE_SEED = b"woken by kYR_have\n"
UNLISTED = b"on the node's disk, in no node's registry entry\n"
GATEWAY_TEMPLATE = "nginx_p115_cms_gateway.conf"
DS_TEMPLATE = "nginx_p115_cms_dataserver.conf"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _gateway(lifecycle, name, response, auth="none", authz=""):
    return lifecycle.start(NginxInstanceSpec(
        name=name,
        template=GATEWAY_TEMPLATE,
        protocol="root",
        readiness="tcp",
        template_values={"RESPONSE": response, "AUTH": auth,
                         "WINDOW_MS": WINDOW_MS, "AUTHZ": authz},
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
def policy_gateway(lifecycle, tmp_path):
    authdb = tmp_path / "manager.authdb"
    authdb.write_text("u * /live a\n")
    authz = ("brix_authdb_engine xrdacc; "
             f"brix_authdb {authdb};")
    return _gateway(lifecycle, "lc-p115-gw-policy", "proxy", authz=authz)


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


@pytest.mark.parametrize(("opcode", "source", "destination"), [
    (kXR_rm, b"/blocked/item", b""),
    (kXR_mv, b"/live/source", b"/blocked/destination"),
])
def test_busy_proxy_pin_cannot_bypass_manager_path_policy(
        policy_gateway, opcode, source, destination):
    """security-neg: a held handle makes the CMS proxy pin non-movable, but
    single-path denial and independent MV-destination denial still occur at
    the manager before the request can ride the pinned service credential.

    The scripted upstream answers every unknown opcode with kXR_ok, so an OK
    response here is direct proof that the dispatcher shortcut bypassed policy.
    """
    fake = _FakeDataServer("serve")
    node = _CmsNode(_cms_port(policy_gateway), fake.port, paths=b"r /live")
    try:
        _settle(node)
        sock = _handshake_login(H, policy_gateway.port)
        try:
            status, body = _open(sock, b"/live/held", kXR_open_read)
            assert status == kXR_ok, (status, body)
            held = body[:4]

            status, body = _namespace_mutation(sock, opcode, source,
                                               destination)
            assert status == kXR_error, (status, body)
            assert len(body) >= 4
            assert struct.unpack(">I", body[:4])[0] == kXR_NotAuthorized

            assert _close(sock, held)[0] == kXR_ok
        finally:
            sock.close()
    finally:
        node.close()
        fake.close()


def test_bound_secondary_cannot_issue_manager_mutation(gateway):
    """security-neg: even after the primary pins a live proxy handle, a bound
    data secondary inherits identity only—not namespace-mutation authority."""
    fake = _FakeDataServer("serve")
    node = _CmsNode(_cms_port(gateway), fake.port, paths=b"r /live")
    primary = secondary = None
    try:
        _settle(node)
        primary, sessid = _login_with_session(gateway.port)
        status, body = _open(primary, b"/live/held", kXR_open_read)
        assert status == kXR_ok, (status, body)
        held = body[:4]

        secondary = _bind_secondary(gateway.port, sessid)
        status, body = _namespace_mutation(secondary, kXR_rm,
                                           b"/live/forbidden")
        assert status == kXR_error, (status, body)
        assert len(body) >= 4
        assert struct.unpack(">I", body[:4])[0] == kXR_NotAuthorized
        assert _close(primary, held)[0] == kXR_ok
    finally:
        if secondary is not None:
            secondary.close()
        if primary is not None:
            primary.close()
        node.close()
        fake.close()


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
    values = dict(PORT=free_port(), CMS_PORT=free_port(), AUTH="none", AUTHZ="",
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
