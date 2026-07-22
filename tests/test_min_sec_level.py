"""D-1 protocol-downgrade protection — brix_min_sec_level session-posture floor.

brix_min_sec_level is a distinct axis from brix_security_level (which governs
kXR_sigver request *signing*): it enforces the negotiated *session's* transport /
identity posture so a client cannot walk the connection below the operator's
floor.  brix_tls only ADVERTISES an in-protocol TLS upgrade — a client is free to
finish login/auth in cleartext — so the floor is what actually refuses a walked-
down session, post-handshake, on the first data/metadata opcode.

Proves the SHIPPED behaviour at the wire level, to the plan's acceptance
("below-floor client dropped post-handshake; at/above proceeds"):

  security  — a cleartext session against a ``compat`` listener is refused every
              data op with kXR_error/kXR_TLSRequired (walked-down → dropped);
  success   — the SAME handshake over a TLS-terminated listener satisfies
              ``compat`` and stat/open proceed normally (at/above → proceeds);
  security  — ``intense`` additionally refuses an anonymous (auth=none) identity
              even over TLS, with kXR_error/kXR_NotAuthorized (the second branch);
  error/neg — a malformed ``brix_min_sec_level`` is refused by ``nginx -t``.

Reuses the raw XRootD wire client from test_phase25_ratelimit (login / stat /
open / status parsing) so the test drives the real protocol.  The TLS case
performs the genuine XRootD in-protocol TLS upgrade (kXR_protocol advertises
kXR_ableTLS → the ``brix_tls``-enabled server replies kXR_gotoTLS and switches
to a server-side TLS handshake, which we complete client-side before finishing
login), so brix sees ``c->ssl`` set exactly as a stock ``roots://`` client leaves
it — no nginx-terminated ``listen ssl`` shortcut.
"""

import socket
import ssl
import struct

import pytest

from config_parse import nginx_t
from server_registry import NginxInstanceSpec
from settings import (
    NGINX_BIN, HOST, BIND_HOST, SERVER_CERT, SERVER_KEY,
)
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from test_phase25_ratelimit import _xrd_stat, _xrd_open, KXR_OK

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-minsec")]

# Response status field (kXR_error) and the two policy error codes it carries.
KXR_ERROR = 4003
kXR_NotAuthorized = 3010
kXR_TLSRequired = 3028


@pytest.fixture(autouse=True)
def _require_binary():
    import os
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _drain_reply(s):
    """Read one XRootD response header + its (possibly empty) body off s."""
    hdr = s.recv(8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        s.recv(dlen)


def _send_initial(s):
    """The 20-byte initial handshake and its 16-byte server reply."""
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    s.recv(16)


def _send_protocol(s):
    """kXR_protocol advertising kXR_ableTLS (body[4]=0x02); read the reply."""
    s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
    _drain_reply(s)


def _send_login(s):
    """Anonymous kXR_login and its reply."""
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                          b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    _drain_reply(s)


def _login_plain(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HOST, port))
    _send_initial(s)
    _send_protocol(s)
    _send_login(s)
    return s


def _login_tls(port):
    """Genuine in-protocol upgrade: initial + kXR_protocol happen in cleartext,
    then the brix_tls server switches to a server-side TLS handshake — we
    complete it client-side and finish kXR_login inside the tunnel."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(5)
    raw.connect((HOST, port))
    _send_initial(raw)
    _send_protocol(raw)          # reply consumed; server now expects a ClientHello
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname=HOST)
    _send_login(s)
    return s


def _errcode(body):
    """kXR_error bodies are [errnum:4B BE][errmsg]; pull the code."""
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


_TLS_LINES = (f"        brix_tls on;\n"
              f"        brix_certificate     {SERVER_CERT};\n"
              f"        brix_certificate_key {SERVER_KEY};\n")


def _values(*, tls, auth, min_sec, **extra):
    v = {
        "BIND_HOST": BIND_HOST,
        "TLS_LINES": _TLS_LINES if tls else "",
        "AUTH": auth,
        "MIN_SEC": min_sec,
    }
    v.update(extra)
    return v


def _start(lifecycle, data, name, *, tls, auth, min_sec):
    ep = lifecycle.start(NginxInstanceSpec(
        name=name, template="nginx_min_sec.conf", data_root=str(data),
        template_values=_values(tls=tls, auth=auth, min_sec=min_sec),
        reason="D-1 brix_min_sec_level floor coverage"))
    return ep.port


# --------------------------------------------------------------------------- #
# security-negative: a cleartext session is below the compat floor → dropped.
# --------------------------------------------------------------------------- #
def test_cleartext_below_compat_floor_dropped(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "real.dat").write_text("present\n")
    port = _start(lifecycle, data, "lc-minsec-cleartext",
                  tls=False, auth="none", min_sec="compat")

    s = _login_plain(port)
    st_stat, body_stat = _xrd_stat(s, "/real.dat")
    st_open, body_open = _xrd_open(s, "/real.dat")
    s.close()

    # A real, readable file is refused purely because the session is cleartext.
    assert st_stat == KXR_ERROR, ("below-floor stat must be an error", st_stat)
    assert _errcode(body_stat) == kXR_TLSRequired, _errcode(body_stat)
    assert st_open == KXR_ERROR, ("below-floor open must be an error", st_open)
    assert _errcode(body_open) == kXR_TLSRequired, _errcode(body_open)


# --------------------------------------------------------------------------- #
# success: the same handshake over TLS satisfies the compat floor → proceeds.
# --------------------------------------------------------------------------- #
def test_tls_session_satisfies_compat_floor(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "real.dat").write_text("present\n")
    port = _start(lifecycle, data, "lc-minsec-tls",
                  tls=True, auth="none", min_sec="compat")

    s = _login_tls(port)
    st_stat, _ = _xrd_stat(s, "/real.dat")
    st_open, _ = _xrd_open(s, "/real.dat")
    s.close()

    assert st_stat == KXR_OK, ("TLS session stat must proceed", st_stat)
    assert st_open == KXR_OK, ("TLS session open must proceed", st_open)


# --------------------------------------------------------------------------- #
# security-negative: intense also refuses an anonymous identity, even over TLS.
# --------------------------------------------------------------------------- #
def test_intense_refuses_anonymous_over_tls(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "real.dat").write_text("present\n")
    port = _start(lifecycle, data, "lc-minsec-intense",
                  tls=True, auth="none", min_sec="intense")

    s = _login_tls(port)
    st_stat, body_stat = _xrd_stat(s, "/real.dat")
    s.close()

    # TLS clears the transport half of the floor, but auth=none has no identity
    # to present, so intense refuses it with kXR_NotAuthorized.
    assert st_stat == KXR_ERROR, ("anonymous under intense must error", st_stat)
    assert _errcode(body_stat) == kXR_NotAuthorized, _errcode(body_stat)


# --------------------------------------------------------------------------- #
# error: a malformed directive value is refused at config parse.
# --------------------------------------------------------------------------- #
def test_bogus_config_refused(tmp_path):
    # nginx -t rejects before any bind; a non-binding placeholder port suffices.
    port = PARSE_PLACEHOLDER_PORT
    data = tmp_path / "data"; data.mkdir()
    values = _values(tls=False, auth="none", min_sec="banana",
                     PORT=port, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), TMP_DIR=str(tmp_path))
    result = nginx_t("nginx_min_sec.conf", tmp_path, **values)
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0, out
    # ngx_conf_set_enum_slot rejects the unknown word by value, on the line the
    # brix_min_sec_level directive sits (conf line 12 of the rendered template).
    assert 'invalid value "banana"' in out, out
