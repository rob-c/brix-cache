"""Per-capability TLS gating — `brix_tls_require` + `brix_ztn_cleartext`.

Stock XRootD gates TLS per capability (`xrootd.tls login/session/data/tpc`
with `-cap` exceptions) and advertises the enforced policy as kXR_tls* bits in
the kXR_protocol reply.  brix_tls_require is the generic VFS port of that
policy (src/fs/vfs/vfs_secgate.c): one mask enforced on the stream plane
pre-dispatch, the native-TPC choke point, and the WebDAV/S3 handlers.

Proves the SHIPPED stream-plane behaviour at the wire level:

  security  — `session` refuses every cleartext post-login op with
              kXR_error/kXR_TLSRequired while kXR_login itself still proceeds
              (finer grain than the brix_min_sec_level floor);
  security  — `data` leaves cleartext stat/open untouched but refuses read;
  security  — `login` refuses the cleartext kXR_login itself;
  success   — `all -login -tpc` honours the subtraction grammar (login
              proceeds, session ops still refused);
  success   — the full `all` mask over a genuine in-protocol TLS upgrade
              gates nothing;
  success   — the mask is advertised as kXR_tlsSess/tlsData/tlsTPC bits in
              the kXR_protocol flags word, and `none` leaves the flags word
              byte-identical to the pre-feature advertisement;
  security  — a token-auth (ztn) server REFUSES cleartext token login with
              kXR_TLSRequired unless `brix_ztn_cleartext on` opts in (stock
              parity: ztn is TLS-only by default);
  success   — the opt-in restores the historical cleartext ztn flow
              end-to-end (login → kXR_auth ztn → stat), and TLS ztn is
              unaffected without any opt-in;
  error/neg — unknown capability, `none` mixed with a capability, and a
              duplicate directive are all refused by ``nginx -t``.

Reuses the raw wire client from test_min_sec_level / test_phase25_ratelimit
so the tests drive the real protocol.
"""

import os
import socket
import ssl
import struct
import sys

import pytest

from config_parse import nginx_t
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from test_min_sec_level import (
    _TLS_LINES, _send_initial, _send_protocol, _errcode,
    KXR_ERROR, kXR_TLSRequired,
)
from test_phase25_ratelimit import _xrd_recv_status, _xrd_stat, _xrd_open, \
    _xrd_read, KXR_OK

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tokenconf import _send_auth_ztn, kXR_ok  # noqa: E402
from utils.make_token import TokenIssuer  # noqa: E402

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tlsreq")]

# kXR_protocol flags-word bits (XProtocol.hh).
kXR_haveTLS  = 0x80000000
kXR_gotoTLS  = 0x40000000
kXR_tlsData  = 0x01000000
kXR_tlsLogin = 0x04000000
kXR_tlsSess  = 0x08000000
kXR_tlsTPC   = 0x10000000


@pytest.fixture(autouse=True)
def _require_binary():
    import os
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _xrd_login(s):
    """Anonymous kXR_login; return (status, body) instead of draining."""
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                          b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    return _xrd_recv_status(s)


def _connect(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HOST, port))
    _send_initial(s)
    return s


def _upgrade_tls(raw):
    """Complete the in-protocol TLS upgrade armed by the ableTLS kXR_protocol."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=HOST)


def _protocol_flags(s):
    """kXR_protocol with kXR_ableTLS; return the reply's host-order flags word."""
    s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006,
                          0x00000520, 0x02, 0x03, 0))
    status, body = _xrd_recv_status(s)
    assert status == KXR_OK, (status, body)
    return struct.unpack(">I", body[4:8])[0]


_TOKEN_LINES = ('        brix_token_jwks     {jwks};\n'
                '        brix_token_issuer   "https://test.example.com";\n'
                '        brix_token_audience "nginx-xrootd";\n'
                '        brix_token_clock_skew 30;\n')


def _values(*, tls, auth, tls_require, auth_lines="", **extra):
    v = {
        "BIND_HOST": BIND_HOST,
        "TLS_LINES": _TLS_LINES if tls else "",
        "AUTH": auth,
        "AUTH_LINES": auth_lines,
        "TLS_REQUIRE": tls_require,
    }
    v.update(extra)
    return v


def _start(lifecycle, data, name, *, tls, auth, tls_require, auth_lines=""):
    ep = lifecycle.start(NginxInstanceSpec(
        name=name, template="nginx_tls_require.conf", data_root=str(data),
        template_values=_values(tls=tls, auth=auth, tls_require=tls_require,
                                auth_lines=auth_lines),
        reason="brix_tls_require per-capability TLS gating coverage"))
    return ep.port


def _data_dir(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "real.dat").write_text("present\n")
    return data


def _issuer(tmp_path):
    tok = tmp_path / "tok"
    tok.mkdir()
    issuer = TokenIssuer(str(tok))
    issuer.init_keys()
    return issuer


# --------------------------------------------------------------------------- #
# security-negative: `session` locks cleartext post-login ops, not login.
# --------------------------------------------------------------------------- #
def test_session_mask_refuses_cleartext_ops(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-session",
                  tls=False, auth="none", tls_require="session")

    s = _connect(port)
    _send_protocol(s)
    st_login, _ = _xrd_login(s)
    st_stat, body_stat = _xrd_stat(s, "/real.dat")
    st_open, body_open = _xrd_open(s, "/real.dat")
    s.close()

    # login carries only the LOGIN capability, so a session-only mask lets it
    # through — the per-capability grain brix_min_sec_level cannot express.
    assert st_login == KXR_OK, ("session mask must not gate login", st_login)
    assert st_stat == KXR_ERROR and _errcode(body_stat) == kXR_TLSRequired, \
        (st_stat, body_stat)
    assert st_open == KXR_ERROR and _errcode(body_open) == kXR_TLSRequired, \
        (st_open, body_open)


# --------------------------------------------------------------------------- #
# security-negative: `data` leaves cleartext metadata open but refuses read.
# --------------------------------------------------------------------------- #
def test_data_mask_gates_only_data_ops(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-data",
                  tls=False, auth="none", tls_require="data")

    s = _connect(port)
    _send_protocol(s)
    st_login, _ = _xrd_login(s)
    st_stat, _ = _xrd_stat(s, "/real.dat")
    st_open, body_open = _xrd_open(s, "/real.dat")
    st_read, body_read = _xrd_read(s, body_open[:4], 0, 8)
    s.close()

    assert st_login == KXR_OK and st_stat == KXR_OK and st_open == KXR_OK, \
        ("data mask must not gate login/stat/open", st_login, st_stat, st_open)
    assert st_read == KXR_ERROR and _errcode(body_read) == kXR_TLSRequired, \
        (st_read, body_read)


# --------------------------------------------------------------------------- #
# security-negative: `login` refuses the cleartext kXR_login itself.
# --------------------------------------------------------------------------- #
def test_login_mask_refuses_cleartext_login(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-login",
                  tls=False, auth="none", tls_require="login")

    s = _connect(port)
    _send_protocol(s)
    st_login, body_login = _xrd_login(s)
    s.close()

    assert st_login == KXR_ERROR, ("login mask must refuse login", st_login)
    assert _errcode(body_login) == kXR_TLSRequired, _errcode(body_login)


# --------------------------------------------------------------------------- #
# success: `-cap` subtraction — `all -login -tpc` frees login, keeps session.
# --------------------------------------------------------------------------- #
def test_cap_exception_subtraction(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-except",
                  tls=False, auth="none", tls_require="all -login -tpc")

    s = _connect(port)
    _send_protocol(s)
    st_login, _ = _xrd_login(s)
    st_stat, body_stat = _xrd_stat(s, "/real.dat")
    s.close()

    assert st_login == KXR_OK, ("-login exception must free login", st_login)
    assert st_stat == KXR_ERROR and _errcode(body_stat) == kXR_TLSRequired, \
        (st_stat, body_stat)


# --------------------------------------------------------------------------- #
# success: the full mask over a genuine in-protocol TLS upgrade gates nothing.
# --------------------------------------------------------------------------- #
def test_all_mask_tls_session_proceeds(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-tls",
                  tls=True, auth="none", tls_require="all")

    raw = _connect(port)
    _send_protocol(raw)          # arms the upgrade; server expects ClientHello
    s = _upgrade_tls(raw)
    st_login, _ = _xrd_login(s)
    st_stat, _ = _xrd_stat(s, "/real.dat")
    st_open, body_open = _xrd_open(s, "/real.dat")
    st_read, body_read = _xrd_read(s, body_open[:4], 0, 8)
    s.close()

    assert (st_login, st_stat, st_open, st_read) == (KXR_OK,) * 4, \
        (st_login, st_stat, st_open, st_read)
    assert body_read == b"present\n", body_read


# --------------------------------------------------------------------------- #
# success: the mask is advertised as kXR_tls* bits; `none` stays byte-identical.
# --------------------------------------------------------------------------- #
def test_mask_advertised_in_protocol_flags(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-adv",
                  tls=True, auth="none", tls_require="session data tpc")

    s = _connect(port)
    flags = _protocol_flags(s)
    s.close()

    base = kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin
    want = kXR_tlsSess | kXR_tlsData | kXR_tlsTPC
    assert flags & base == base, hex(flags)
    assert flags & want == want, hex(flags)


def test_none_mask_advertises_no_extra_bits(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-adv-none",
                  tls=True, auth="none", tls_require="none")

    s = _connect(port)
    flags = _protocol_flags(s)
    s.close()

    # Regression guard: mask 0 must leave the pre-feature advertisement — the
    # TLS base triple only — with no per-capability requirement bits.
    base = kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin
    assert flags & base == base, hex(flags)
    assert flags & (kXR_tlsSess | kXR_tlsData | kXR_tlsTPC) == 0, hex(flags)


# --------------------------------------------------------------------------- #
# security-negative: cleartext ztn is refused by default (stock parity).
# --------------------------------------------------------------------------- #
def test_ztn_cleartext_refused_without_optin(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    issuer = _issuer(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-ztn-refuse",
                  tls=False, auth="token", tls_require="none",
                  auth_lines=_TOKEN_LINES.format(jwks=issuer.jwks_path))

    s = _connect(port)
    _send_protocol(s)
    st_login, body_login = _xrd_login(s)
    s.close()

    # Stock XrdSecztn refuses to even offer ztn off-TLS; with token as the only
    # protocol the cleartext login has nothing left to advertise → refused.
    assert st_login == KXR_ERROR, ("cleartext ztn login must error", st_login)
    assert _errcode(body_login) == kXR_TLSRequired, _errcode(body_login)


# --------------------------------------------------------------------------- #
# success: `brix_ztn_cleartext on` restores the lab cleartext flow end-to-end.
# --------------------------------------------------------------------------- #
def test_ztn_cleartext_optin_accepts(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    issuer = _issuer(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-ztn-optin",
                  tls=False, auth="token", tls_require="none",
                  auth_lines=_TOKEN_LINES.format(jwks=issuer.jwks_path)
                  + "        brix_ztn_cleartext on;\n")

    s = _connect(port)
    _send_protocol(s)
    st_login, body_login = _xrd_login(s)
    assert st_login == KXR_OK, (st_login, body_login)
    assert b"ztn" in body_login, body_login

    st_auth, body_auth = _send_auth_ztn(s, issuer.generate())
    st_stat, _ = _xrd_stat(s, "/real.dat")
    s.close()

    assert st_auth == kXR_ok, (st_auth, body_auth)
    assert st_stat == KXR_OK, st_stat


# --------------------------------------------------------------------------- #
# success: ztn over TLS needs no opt-in — the default only bites cleartext.
# --------------------------------------------------------------------------- #
def test_ztn_over_tls_unaffected(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    issuer = _issuer(tmp_path)
    port = _start(lifecycle, data, "lc-tlsreq-ztn-tls",
                  tls=True, auth="token", tls_require="none",
                  auth_lines=_TOKEN_LINES.format(jwks=issuer.jwks_path))

    raw = _connect(port)
    _send_protocol(raw)
    s = _upgrade_tls(raw)
    st_login, body_login = _xrd_login(s)
    assert st_login == KXR_OK, (st_login, body_login)
    assert b"ztn" in body_login, body_login

    st_auth, _ = _send_auth_ztn(s, issuer.generate())
    st_stat, _ = _xrd_stat(s, "/real.dat")
    s.close()

    assert st_auth == kXR_ok, st_auth
    assert st_stat == KXR_OK, st_stat


# --------------------------------------------------------------------------- #
# error: malformed directive values are refused at config parse.
# --------------------------------------------------------------------------- #
def _parse(tmp_path, tls_require):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    values = _values(tls=False, auth="none", tls_require=tls_require,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), TMP_DIR=str(tmp_path))
    result = nginx_t("nginx_tls_require.conf", tmp_path, **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def test_unknown_capability_refused(tmp_path):
    rc, out = _parse(tmp_path, "banana")
    assert rc != 0 and "invalid brix_tls_require capability" in out, out


def test_none_mixed_with_capability_refused(tmp_path):
    rc, out = _parse(tmp_path, "none session")
    assert rc != 0 and "invalid brix_tls_require capability" in out, out


def test_duplicate_directive_refused(tmp_path):
    # The template holds one brix_tls_require line; smuggle a second directive
    # in through the substitution to exercise the duplicate check.
    rc, out = _parse(tmp_path, "session;\n        brix_tls_require data")
    assert rc != 0 and "is duplicate" in out, out
