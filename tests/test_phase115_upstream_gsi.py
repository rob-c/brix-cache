"""Phase-115 W2.4 — the transparent upstream (`brix_upstream`) authenticates
outbound with GSI (`brix_upstream_x509_proxy` / `brix_upstream_x509_key`) and
reads the server's `&P=` advert from a kXR_ok login reply.

Two discoveries this suite pins (docs/refactor/phase-115-…md §W2.4):

* **Login-advert blindness.** A real brix or stock XRootD server that requires
  authentication answers kXR_login with kXR_ok + 16-byte session id + its
  "&P=gsi,...&P=ztn,..." advert — never kXR_authmore (that was a stub
  convention).  The pre-W2.4 connector treated every kXR_ok as "logged in" and
  the relayed request was refused as unauthenticated.  `bootstrap.c` now scans
  the advert and starts gsi/ztn from it.
* **Body cap.** The kXR_auth reply carrying a kXGS_cert (server X.509 chain +
  DH parameters) is far larger than the BRIX_MAX_PATH+256 cap every other
  upstream reply is held to; `events.c` widens it to XRD_UP_AUTH_BODY_MAX only
  while `bs_phase == XRD_UP_BS_AUTH`.

Two labs: a REAL GSI upstream (nginx_gsi_handshake_root.conf, the handshake
suite's PKI) behind fronts that differ only in the credential/trust lines they
carry, and an in-process MOCK upstream whose scripted replies exercise the
advert parser, the abort paths and the cap without a PKI in the loop.
"""
import os
import socket
import struct
import threading
from pathlib import Path

import pytest

import config_parse
# The _b shard is a CONTINUATION, not a module: split_continuation.reexport
# exec's its body into the parent's globals, so its `pki` fixture resolves
# names (`_have`) that only the parent defines.  Imported standalone it raises
# NameError, so every name here comes from the parent module.
from _test_gsi_handshake_helpers import (  # noqa: F401
    _gsi_log, _gsi_nginx, _make_ca, pki,
)
from ephemeral_port import free_port
from settings import HOST
from test_pgwrite_checksum import _handshake_login
from test_phase115_cms_select_proxy import _locate

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-upstream-gsi")]

kXR_ok, kXR_error, kXR_redirect, kXR_authmore = 0, 4003, 4004, 4002
kXR_auth = 3000

FRONT_TEMPLATE = "nginx_p115_upstream_gsi.conf"
UPSTREAM_TEMPLATE = "nginx_gsi_handshake_root.conf"
SESSID = b"\x01" * 16
REDIRECT_BODY = struct.pack(">I", 1094) + b"storage.example.org"

# BRIX_MAX_PATH + 256 = 4352: the pre-W2.4 cap every kXR_auth reply was held to.
OLD_CAP = 4096 + 256
AUTH_CAP = 64 * 1024                     # XRD_UP_AUTH_BODY_MAX


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _cred_lines(*lines):
    return "\n".join(f"        {line}" for line in lines)


def _front(name, up_port, data_root, *cred_lines):
    harness, ep = _gsi_nginx(name, FRONT_TEMPLATE, str(data_root),
                             UP_PORT=str(up_port), CRED_LINES=_cred_lines(*cred_lines))
    return harness, {"port": ep.port, "log": Path(_gsi_log(ep))}


def _relay_locate(port, path=b"/hello.txt"):
    """Handshake + login to the front, kXR_locate a path the front does not hold
    (so it relays), return (status, body).  A 10 s socket timeout is the hang
    detector: an abort must reach the client as a frame, never as silence."""
    sock = _handshake_login(HOST, port)
    try:
        return _locate(sock, path)
    finally:
        sock.close()


def _err_text(body):
    return body[4:].rstrip(b"\x00").decode(errors="replace")


def _log_text(path):
    return path.read_text(errors="replace") if path.exists() else ""


def _tail(path, n=12):
    return "\n".join(_log_text(path).splitlines()[-n:])


# ---------------------------------------------------------------------------
# lab 1 — a real GSI upstream behind credential-variant fronts
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gsi_upstream(pki):
    harness, ep = _gsi_nginx("lc-p115-up-gsi", UPSTREAM_TEMPLATE, pki["data"],
                             CERT=pki["hostcert"], KEY=pki["hostkey"], CA=pki["ca"],
                             CIPHERS_DIRECTIVE="", SIGNED_DH_DIRECTIVE="")
    try:
        yield {"port": ep.port, "log": Path(_gsi_log(ep))}
    finally:
        harness.close()


def _front_fixture(name, *cred_lines_from_pki):
    @pytest.fixture(scope="module")
    def fixture(pki, gsi_upstream, tmp_path_factory):
        lines = [line.format(**pki) for line in cred_lines_from_pki]
        harness, front = _front(name, gsi_upstream["port"],
                                tmp_path_factory.mktemp(name), *lines)
        try:
            yield front
        finally:
            harness.close()
    return fixture


front_proxy = _front_fixture(
    "lc-p115-up-front-proxy",
    "brix_upstream_x509_proxy {valid_proxy};", "brix_trusted_ca {ca};")
front_eec = _front_fixture(
    "lc-p115-up-front-eec",
    "brix_upstream_x509_proxy {usercert};", "brix_upstream_x509_key {userkey};",
    "brix_trusted_ca {ca};")
front_nocred = _front_fixture(
    "lc-p115-up-front-nocred", "brix_trusted_ca {ca};")
front_untrusted = _front_fixture(
    "lc-p115-up-front-untrusted",
    "brix_upstream_x509_proxy {untrusted_proxy};", "brix_trusted_ca {ca};")
front_noca = _front_fixture(
    "lc-p115-up-front-noca", "brix_upstream_x509_proxy {valid_proxy};")


@pytest.fixture(scope="module")
def front_rogueca(pki, gsi_upstream, tmp_path_factory):
    """A front whose ONLY trust anchor is a CA the upstream's host cert does not
    chain to — the MITM checkpoint must refuse to agree a session secret."""
    rogue = tmp_path_factory.mktemp("rogue-ca")
    _key, rogue_pem = _make_ca(str(rogue), "/O=Rogue/CN=Rogue Trust Anchor")
    harness, front = _front("lc-p115-up-front-rogueca", gsi_upstream["port"],
                            tmp_path_factory.mktemp("front-rogueca"),
                            f"brix_upstream_x509_proxy {pki['valid_proxy']};",
                            f"brix_trusted_ca {rogue_pem};")
    try:
        yield front
    finally:
        harness.close()


def _assert_relayed_ok(front, gsi_upstream, status, body):
    assert status == kXR_ok, (
        f"expected kXR_ok via the GSI-authenticated relay, got {status} "
        f"{_err_text(body) if status == kXR_error else body!r}\n"
        f"front: {_tail(front['log'])}\nupstream: {_tail(gsi_upstream['log'])}")
    assert "upstream abort" not in _log_text(front["log"])


def test_proxy_credential_authenticates_the_relay(front_proxy, gsi_upstream):
    """success: a GSI-only upstream serves the relayed kXR_locate once the front
    presents brix_upstream_x509_proxy — the two-round exchange completes and the
    kXR_ok login advert (not a kXR_authmore) is what started it."""
    status, body = _relay_locate(front_proxy["port"])
    _assert_relayed_ok(front_proxy, gsi_upstream, status, body)


def test_eec_with_separate_key_authenticates(front_eec, gsi_upstream):
    """success: a plain cert + separate key (brix_upstream_x509_key) works
    without hand-concatenating them into a proxy file."""
    status, body = _relay_locate(front_eec["port"])
    _assert_relayed_ok(front_eec, gsi_upstream, status, body)


def test_without_trusted_ca_the_leaf_is_unverified_but_warned(front_noca, gsi_upstream):
    """design choice: no brix_trusted_ca = the operator opted out of server
    verification (as on the cache origin).  The relay still works, and the
    opt-out is loud — one WARN per handshake names the missing directive."""
    status, body = _relay_locate(front_noca["port"])
    _assert_relayed_ok(front_noca, gsi_upstream, status, body)
    assert "no brix_trusted_ca configured" in _log_text(front_noca["log"])


def test_no_credential_fails_closed_naming_both_directives(front_nocred):
    """error: the upstream advertises gsi, the front has neither credential —
    the client gets a kXR_error that names the two directives that would fix it,
    instead of the upstream's opaque refusal of an unauthenticated request."""
    status, body = _relay_locate(front_nocred["port"])
    assert status == kXR_error, (status, body)
    text = _err_text(body)
    assert "brix_upstream_token_file" in text and "brix_upstream_x509_proxy" in text, text


def test_rogue_trust_anchor_refuses_the_server_certificate(front_rogueca):
    """security-negative: with a trust store the upstream's leaf does not chain
    to, the front refuses before agreeing a session secret; the reason is logged
    and the client gets a frame, not a hang."""
    status, body = _relay_locate(front_rogueca["port"])
    assert status == kXR_error, (status, body)
    assert "gsi credential exchange failed" in _err_text(body)
    assert "server certificate verification failed" in _log_text(front_rogueca["log"])


def test_untrusted_proxy_is_refused_by_the_upstream_not_hung(front_untrusted):
    """security-negative: a proxy the upstream does not trust is rejected in
    round 2; the front turns the refusal into a client-visible kXR_error."""
    status, body = _relay_locate(front_untrusted["port"])
    assert status == kXR_error, (status, body)
    assert "upstream" in _err_text(body)
    assert "brix_upstream_x509_proxy" not in _err_text(body)   # a credential WAS offered


# ---------------------------------------------------------------------------
# lab 2 — a scripted mock upstream (advert parser, abort paths, body cap)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _hdr(sid, status, dlen):
    return struct.pack(">2sHI", sid, status, dlen)


class MockUpstream(threading.Thread):
    """root:// upstream whose login/auth behaviour is picked per connection by
    `scenario`; records every kXR_auth (credtype, payload) it receives."""

    def __init__(self):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((HOST, free_port(HOST)))
        self.srv.listen(8)
        self.srv.settimeout(0.5)
        self.port = self.srv.getsockname()[1]
        self.scenario = "ztn_advert"
        self.auths = []
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()
        self.srv.close()

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(20)
        try:
            self._serve_conn(conn)
        except OSError:
            pass
        finally:
            conn.close()

    @staticmethod
    def _read_req(conn):
        hdr = _recv_exact(conn, 24)
        if hdr is None:
            return None, None
        dlen = struct.unpack(">I", hdr[20:24])[0]
        return hdr, (_recv_exact(conn, dlen) if dlen else b"")

    def _read_auth(self, conn):
        hdr, payload = self._read_req(conn)
        if hdr is None:
            return None
        assert struct.unpack(">H", hdr[2:4])[0] == kXR_auth, hdr
        self.auths.append((hdr[16:20], payload))
        return hdr[:2]

    def _serve_conn(self, conn):
        if _recv_exact(conn, 20) is None:
            return
        conn.sendall(_hdr(b"\x00\x00", kXR_ok, 8) + struct.pack(">II", 0x520, 1))
        hdr, _ = self._read_req(conn)                         # kXR_protocol
        if hdr is None:
            return
        conn.sendall(_hdr(hdr[:2], kXR_ok, 8) + struct.pack(">II", 0x520, 1))
        hdr, _ = self._read_req(conn)                         # kXR_login
        if hdr is None:
            return
        sid = hdr[:2]
        if getattr(self, f"_login_{self.scenario}")(conn, sid) is None:
            return
        hdr, _ = self._read_req(conn)                         # kXR_locate
        if hdr is not None:
            conn.sendall(_hdr(hdr[:2], kXR_redirect, len(REDIRECT_BODY)) + REDIRECT_BODY)

    # -- login scenarios: return None to end the connection without a locate --

    def _login_ztn_advert(self, conn, sid):
        advert = b"&P=ztn,test"
        conn.sendall(_hdr(sid, kXR_ok, 16 + len(advert)) + SESSID + advert)
        sid = self._read_auth(conn)
        if sid is not None:
            conn.sendall(_hdr(sid, kXR_ok, 0))
        return sid

    def _login_unix_only(self, conn, sid):
        advert = b"&P=unix"
        conn.sendall(_hdr(sid, kXR_ok, 16 + len(advert)) + SESSID + advert)
        return sid

    def _login_bare_authmore(self, conn, sid):
        conn.sendall(_hdr(sid, kXR_authmore, 0))
        sid = self._read_auth(conn)
        if sid is not None:
            conn.sendall(_hdr(sid, kXR_ok, 16) + SESSID)
        return sid

    def _gsi_login(self, conn, sid, advert):
        conn.sendall(_hdr(sid, kXR_ok, 16 + len(advert)) + SESSID + advert)
        return self._read_auth(conn)

    def _login_gsi_no_ca_hint(self, conn, sid):
        sid = self._gsi_login(conn, sid, b"&P=gsi,v:10600,c:ssl")
        if sid is not None:
            body = struct.pack(">I", 3010) + b"mock: certreq refused\x00"
            conn.sendall(_hdr(sid, kXR_error, len(body)) + body)
        return None

    def _login_gsi_junk_cert(self, conn, sid):
        sid = self._gsi_login(conn, sid, b"&P=gsi,v:10600,c:ssl,ca:deadbeef")
        if sid is not None:
            conn.sendall(_hdr(sid, kXR_authmore, 5 * OLD_CAP) + b"\x00" * (5 * OLD_CAP))
        return None

    def _login_gsi_huge_cert(self, conn, sid):
        sid = self._gsi_login(conn, sid, b"&P=gsi,v:10600,c:ssl,ca:deadbeef")
        if sid is not None:
            conn.sendall(_hdr(sid, kXR_authmore, AUTH_CAP + 1) + b"\x00" * (AUTH_CAP + 1))
        return None


@pytest.fixture(scope="module")
def mock():
    m = MockUpstream()
    m.start()
    try:
        yield m
    finally:
        m.stop()


@pytest.fixture(scope="module")
def front_mock(pki, mock, tmp_path_factory):
    token = tmp_path_factory.mktemp("token") / "upstream.jwt"
    token.write_text("eyJhbGciOiJSUzI1NiJ9.p115.sig\n")
    harness, front = _front("lc-p115-up-front-mock", mock.port,
                            tmp_path_factory.mktemp("front-mock"),
                            f"brix_upstream_x509_proxy {pki['valid_proxy']};",
                            f"brix_upstream_token_file {token};",
                            f"brix_trusted_ca {pki['ca']};")
    try:
        yield front
    finally:
        harness.close()


@pytest.fixture
def scripted(mock):
    def _set(scenario):
        mock.scenario = scenario
        del mock.auths[:]
        return mock
    return _set


def test_kxr_ok_login_advert_starts_the_ztn_exchange(front_mock, scripted):
    """bug pinned (login-advert blindness): the advert arrives in a kXR_ok body
    after the session id; the front must send kXR_auth "ztn" before relaying."""
    m = scripted("ztn_advert")
    status, body = _relay_locate(front_mock["port"])
    assert status == kXR_redirect, (status, body, _tail(front_mock["log"]))
    assert body == REDIRECT_BODY
    assert [c for c, _ in m.auths] == [b"ztn\x00"]
    assert m.auths[0][1].startswith(b"ztn\x00eyJ")


def test_advert_without_a_supported_protocol_relays_unauthenticated(front_mock, scripted):
    """design choice: an advert of only unix/host/… is left to the upstream to
    judge — the front relays without inventing a credential (pre-W2.4 behaviour
    for every advert; kept for the ones it cannot satisfy)."""
    m = scripted("unix_only")
    status, body = _relay_locate(front_mock["port"])
    assert status == kXR_redirect, (status, body, _tail(front_mock["log"]))
    assert m.auths == []


def test_bare_authmore_still_gets_the_ztn_token(front_mock, scripted):
    """compat: a kXR_authmore with no advert body (minimal origins, the older
    stub convention) still receives the configured token, as before W2.4."""
    m = scripted("bare_authmore")
    status, body = _relay_locate(front_mock["port"])
    assert status == kXR_redirect, (status, body, _tail(front_mock["log"]))
    assert [c for c, _ in m.auths] == [b"ztn\x00"]


def test_gsi_is_preferred_and_a_missing_ca_hint_does_not_crash(front_mock, scripted):
    """bug pinned: brix_gsi_build_certreq took strlen() of a NULL issuer hash
    when the advert carried no `ca:` — a worker crash on a hostile/minimal
    advert.  Now the certreq is built with an empty hash; the mock's refusal
    surfaces as the round-1 error, and gsi is chosen over the also-configured
    token because the advert offers gsi."""
    m = scripted("gsi_no_ca_hint")
    status, body = _relay_locate(front_mock["port"])
    assert status == kXR_error, (status, body, _tail(front_mock["log"]))
    assert "gsi certreq rejected by server" in _err_text(body)
    assert [c for c, _ in m.auths] == [b"gsi\x00"]
    assert m.auths[0][1][:8] == b"gsi\x00" + struct.pack(">I", 1000)   # kXGC_certreq


def test_kxgs_cert_larger_than_the_old_cap_is_read_then_judged(front_mock, scripted):
    """cap widened: a 21 KiB kXR_auth reply (5x the old BRIX_MAX_PATH+256 cap)
    is accepted and judged on its content — here refused for carrying no
    kXRS_x509 — instead of aborting as "too large"."""
    scripted("gsi_junk_cert")
    status, body = _relay_locate(front_mock["port"])
    assert status == kXR_error, (status, body, _tail(front_mock["log"]))
    assert "gsi credential exchange failed" in _err_text(body)
    log = _log_text(front_mock["log"])
    assert "server presented no certificate to verify" in log
    assert "response body too large" not in log


def test_kxgs_cert_above_the_auth_cap_is_refused(front_mock, scripted):
    """security-negative: the widened cap is still a cap — a kXR_auth reply one
    byte over XRD_UP_AUTH_BODY_MAX aborts before the body is allocated."""
    scripted("gsi_huge_cert")
    status, body = _relay_locate(front_mock["port"])
    assert status == kXR_error, (status, body, _tail(front_mock["log"]))
    assert "upstream response body too large" in _err_text(body)


def test_front_stays_healthy_after_an_aborted_gsi_exchange(front_mock, scripted):
    """recovery: the aborted exchanges above left the front serving — the next
    relay (a clean ztn advert) still completes."""
    scripted("ztn_advert")
    status, body = _relay_locate(front_mock["port"])
    assert status == kXR_redirect, (status, body, _tail(front_mock["log"]))


# ---------------------------------------------------------------------------
# config surface
# ---------------------------------------------------------------------------

def _parse(tmp_path, tag, cred_lines):
    """Render the front and run `nginx -t` over it.

    The ports are free ephemeral ones rather than the 1/2 a parse-only test
    invites, because `nginx -t` BINDS every listen socket: as an ordinary uid
    with net.ipv4.ip_unprivileged_port_start=1024 a privileged port makes the
    ACCEPTING case fail with `bind() ... (13: Permission denied)` after the
    syntax has already been reported ok.  The refusing cases hide it — their
    parse error fires before any bind — so the defect shows up as exactly one
    red row and reads like a directive that was never registered.
    """
    return config_parse.nginx_t(FRONT_TEMPLATE, tmp_path / tag,
                                PORT=free_port(HOST), UP_PORT=free_port(HOST),
                                DATA_ROOT=str(tmp_path), LOG_DIR=str(tmp_path),
                                CRED_LINES=_cred_lines(*cred_lines))


def test_upstream_x509_directives_parse(tmp_path):
    """config: both new directives are registered and take one argument."""
    good = _parse(tmp_path, "good", ["brix_upstream_x509_proxy /run/proxy.pem;",
                                     "brix_upstream_x509_key /run/key.pem;"])
    assert good.returncode == 0, good.stderr


def test_upstream_x509_directive_arity_is_enforced(tmp_path):
    """config-negative: a second argument is a parse error, not a silent drop."""
    bad = _parse(tmp_path, "bad", ["brix_upstream_x509_proxy /a.pem /b.pem;"])
    assert bad.returncode != 0
    assert "invalid number of arguments" in bad.stderr, bad.stderr
    assert "brix_upstream_x509_proxy" in bad.stderr


def test_upstream_x509_directive_is_srv_scoped(tmp_path):
    """config-negative: the credential is per-server; at stream{} level it is
    refused (`is not allowed here`), so one server's proxy never leaks into
    a sibling server block by accident."""
    template = Path(config_parse.__file__).parent / "configs" / FRONT_TEMPLATE
    body = template.read_text().replace(
        "stream {\n", "stream {\n    brix_upstream_x509_proxy /run/proxy.pem;\n", 1)
    stray = tmp_path / "configs" / "p115_stray.conf"
    stray.parent.mkdir()
    stray.write_text(body)
    bad = config_parse.nginx_t(stray, tmp_path / "stray",
                               PORT=free_port(HOST), UP_PORT=free_port(HOST),
                               DATA_ROOT=str(tmp_path), LOG_DIR=str(tmp_path), CRED_LINES="")
    assert bad.returncode != 0
    assert "is not allowed here" in bad.stderr, bad.stderr
