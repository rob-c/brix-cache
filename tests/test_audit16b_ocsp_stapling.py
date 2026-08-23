"""brix_ocsp_stapling at VALUE granularity — audit §Method, 16th tranche.

The tranche re-runs the audit's Method (steps 1-2) per (directive, VALUE) over
the 128 directives whose setter is ``ngx_conf_set_flag_slot``: a flag's NAME is
answered by one of its two tokens, and 106 of the 256 pairs are written nowhere
in the corpus in any form.  ``brix_ocsp_stapling`` is one of the seven
directives with BOTH arms unwritten, and the only one of those seven that
touches a TLS handshake.  test_audit16a_ocsp_flags.py takes the other two OCSP
flags, whose observable is a GSI login verdict; this file takes the one whose
observable is what the server puts on the wire.

WHAT THE VALUE SELECTS — AND WHAT IT DOES NOT
---------------------------------------------
``on`` installs a status callback on the server's SSL_CTX
(tls_config.c:118-122)::

    if (xcf->ocsp.stapling) {
        SSL_CTX_set_tlsext_status_cb(xcf->tls_ctx->ctx, brix_ocsp_stapling_cb);
        SSL_CTX_set_tlsext_status_arg(xcf->tls_ctx->ctx, xcf);
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix: OCSP stapling enabled for TLS context");
    }

and the callback attaches ``xcf->ocsp.staple_data`` to the ServerHello — if
anything ever put a staple there.  Nothing does.

DEFECT CANDIDATE #66 — brix_ocsp_staple_fetch() has no caller
-------------------------------------------------------------
``brix_ocsp_staple_fetch()`` (ocsp.c:329) is the only writer of
``ocsp.staple_data``, and no translation unit in ``src/`` calls it.  The
comments say otherwise in three places — srv_conf_fields_cache.h:300
("staple_data/len populated at init_process"), server_conf_merge_proxy_net.c:151
("populated at init_process, not here"), and src/auth/crypto/README.md, which
says stapling "is driven at reload".  There is no init_process hook and no
reload hook; the fetch is dead code reached from nothing.

So ``staple_data`` is NULL for the lifetime of the process,
``brix_ocsp_stapling_cb`` can only take its NULL branch and return
``SSL_TLSEXT_ERR_NOACK``, and a client that sets status_request gets no
CertificateStatus back — from the ``on`` plane exactly as from the ``off``
plane.  The whole observable difference between the two tokens today is one
NOTICE line in the error log, which is worse than no feature: an operator who
writes ``brix_ocsp_stapling on``, greps the log, and finds "OCSP stapling
enabled for TLS context" has been told the opposite of what is true.

WHAT THIS FILE ASSERTS
----------------------
§A  the config-time observable: the NOTICE appears under ``on`` and under
    neither ``off`` nor the absent flag (which pins the merge default).
§B  the wire: with status_request set, NO staple arrives on any plane —
    today's behaviour, pinned so that fixing #66 has to come here and invert
    it rather than land silently.
§C  attribution: the handshake completes and carries a real kXR_login on every
    plane, and the probe only sees the callback when it actually asked — so
    "no staple" is not "no TLS" and not "no request".
§D  the root cause, pinned at the source: the fetch has no caller.

The parse tier for all four OCSP flags — token set, case-insensitivity, arity
and NGX_STREAM_SRV_CONF placement — lives in test_audit16a_ocsp_flags.py §F and
is not repeated here.
"""

import os
import re
import socket
import struct
from pathlib import Path

import pytest

def _expression_1(line, pattern):
    return (
        not pattern.search(line) or line.lstrip().startswith("*")
    )

def _expression_2(path, line):
    return (
        path.name == "ocsp.c" and line.startswith(
                                "brix_ocsp_staple_fetch")
    )


def _check_test_brix_ocsp_staple_fetch_is_called_from_nowhere_1(callers):
    assert callers == [], (
        "brix_ocsp_staple_fetch() now has a caller — defect candidate #66 "
        "is being fixed; the wire assertions in §B must be revisited:\n"
        + "\n".join(callers))


try:
    from OpenSSL import SSL
except ModuleNotFoundError:
    pytest.skip("pyOpenSSL is not installed for the optional OCSP wire probe",
                allow_module_level=True)

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN, SERVER_CERT, SERVER_KEY
from test_min_sec_level import _send_initial, _send_protocol
from test_phase25_ratelimit import _xrd_recv_status, _xrd_stat, KXR_OK

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16b-staple")]

NAME = "lc-audit16b-staple"
SEED = b"staple seed\n"
SEED_PATH = "/seed.txt"

# Every socket second in this file, cleartext preamble and tunnel alike.
IO_TIMEOUT_SECS = 15

# The three listeners, by the template placeholder that carries each one.
OFF, ON, DEFAULT = "PORT", "ON_PORT", "DEF_PORT"
ALL_PLANES = (OFF, ON, DEFAULT)

_NOTICE = "OCSP stapling enabled for TLS context"

REPO = Path(__file__).resolve().parents[1]

_TLS_LINES = (f"        brix_auth none;\n"
              f"        brix_tls on;\n"
              f"        brix_certificate     {SERVER_CERT};\n"
              f"        brix_certificate_key {SERVER_KEY};\n")


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not (os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY)):
        pytest.skip("the shared server certificate is not minted in this lane")


@pytest.fixture
def staple(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / SEED_PATH.lstrip("/")).write_bytes(SEED)
    return lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16b_staple.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CERT": SERVER_CERT, "KEY": SERVER_KEY},
        reason="audit-16b brix_ocsp_stapling at value granularity"))


# --------------------------------------------------------------------------- #
# Client — the in-protocol TLS upgrade, with status_request set                #
# --------------------------------------------------------------------------- #

def _port(endpoint, plane):
    return endpoint.port if plane == OFF else endpoint.extra_ports[plane]


def _bounded(raw):
    """Hand OpenSSL a BLOCKING fd that still cannot hang the run.

    ``socket.settimeout()`` implements its timeout by putting the fd in
    NON-blocking mode and running the wait loop in Python.  The stdlib ``ssl``
    module knows that and re-selects; pyOpenSSL does not, so every read where
    the next record has not landed yet surfaces as ``WantReadError`` and
    ``do_handshake()`` fails against a server that is behaving perfectly.  The
    fd therefore goes back to blocking and the bound moves into the kernel as
    SO_RCVTIMEO/SO_SNDTIMEO, where a genuine stall still fails the test — as a
    WantReadError raised at the deadline — instead of wedging the session.
    """
    raw.setblocking(True)
    bound = struct.pack("@ll", IO_TIMEOUT_SECS, 0)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, bound)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, bound)


def _upgrade(endpoint, plane, *, ask):
    """Drive root:// to the TLS upgrade point and hand back (conn, staples).

    ``staples`` collects one entry per invocation of the client status
    callback; pyOpenSSL passes b"" when the server sent no CertificateStatus,
    and OpenSSL invokes the callback at all only when status_request went out —
    which is what makes ``ask=False`` a usable control rather than a second way
    of writing the same assertion.

    The sequence is test_tls_require.py's: the initial handshake, then a
    kXR_protocol carrying kXR_ableTLS, after which the server is waiting for a
    ClientHello on the same socket.
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(IO_TIMEOUT_SECS)
    raw.connect((HOST, _port(endpoint, plane)))
    _send_initial(raw)
    _send_protocol(raw)
    _bounded(raw)                # from here the fd belongs to OpenSSL

    staples = []
    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *_a: True)
    ctx.set_ocsp_client_callback(
        lambda _conn, data, _arg: staples.append(data) or True)
    conn = SSL.Connection(ctx, raw)
    conn.set_connect_state()
    if ask:
        conn.request_ocsp()
    conn.do_handshake()
    return conn, staples


def _login(conn):
    """Anonymous kXR_login inside the tunnel; returns the status word."""
    conn.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                             b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    return _xrd_recv_status(conn)[0]


def _probe(endpoint, plane, *, ask=True):
    conn, staples = _upgrade(endpoint, plane, ask=ask)
    try:
        return staples, _login(conn)
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# §A — the config-time observable                                              #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, knobs):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit16aparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=knobs, STREAM_EXTRA="")
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestTheConfigTimeObservable:
    """brix_configure_tls() runs during postconfig, so `nginx -t` is enough to
    see which arm installed the callback — and it is the same NOTICE an
    operator greps for in a running server's log."""

    def test_the_on_token_announces_the_callback(self, tmp_path):
        rc, out = _parse(tmp_path, _TLS_LINES +
                         "        brix_ocsp_stapling on;\n")
        assert rc == 0, out
        assert _NOTICE in out, \
            f"brix_ocsp_stapling on installed no status callback:\n{out}"

    def test_the_off_token_announces_nothing(self, tmp_path):
        rc, out = _parse(tmp_path, _TLS_LINES +
                         "        brix_ocsp_stapling off;\n")
        assert rc == 0, out
        assert _NOTICE not in out, \
            f"brix_ocsp_stapling off still installed the callback:\n{out}"

    def test_the_absent_flag_matches_off(self, tmp_path):
        """conf_structs.h:535 merges the unset field to 0.  Written down
        because `off` and "not written" are the same wire behaviour for a
        working feature but not the same for a broken one: if stapling is ever
        made to work, this is the test that says an unconfigured server does
        not start answering status_request."""
        rc, out = _parse(tmp_path, _TLS_LINES)
        assert rc == 0, out
        assert _NOTICE not in out, \
            f"the absent flag installed the callback — the default is not off:\n{out}"

    def test_the_notice_needs_tls_to_be_on(self, tmp_path):
        """brix_configure_tls() is only called for a TLS-enabled server, so
        `brix_ocsp_stapling on` without `brix_tls on` configures nothing at
        all and says nothing about it.  The security-negative of §A: an
        operator cannot conclude from a clean `nginx -t` that stapling is
        armed."""
        rc, out = _parse(tmp_path, "        brix_auth none;\n"
                                   "        brix_ocsp_stapling on;\n")
        assert rc == 0, out
        assert _NOTICE not in out, out


# --------------------------------------------------------------------------- #
# §B — the wire (DEFECT CANDIDATE #66)                                         #
# --------------------------------------------------------------------------- #

class TestNoStapleEverArrives:

    @pytest.mark.parametrize("plane", ALL_PLANES)
    def test_the_server_staples_nothing(self, staple, plane):
        """DEFECT CANDIDATE #66, from the outside.  status_request goes out,
        the handshake completes, and the CertificateStatus is empty — on the
        plane that announced "OCSP stapling enabled" exactly as on the two that
        did not.

        Pinning today's behaviour, not endorsing it: when
        brix_ocsp_staple_fetch() acquires a caller, the ON plane's assertion
        here has to be inverted and the other two left alone."""
        staples, status = _probe(staple, plane)
        assert staples == [b""], (
            f"{plane}: the server stapled something — if that is the fix for "
            f"defect candidate #66, invert this test: {staples}")
        assert status == KXR_OK, status

    def test_the_two_tokens_are_indistinguishable_on_the_wire(self, staple):
        """The pair, as one assertion.  brix_ocsp_stapling is the only flag in
        this tranche whose two arms produce identical observable behaviour, and
        that identity is the defect rather than a property worth keeping."""
        on = _probe(staple, ON)[0]
        off = _probe(staple, OFF)[0]
        assert on == off == [b""], (on, off)

    def test_a_client_that_does_not_ask_is_never_called_back(self, staple):
        """The control that keeps the class from being vacuous: the callback
        fires because status_request was sent, not because pyOpenSSL calls it
        unconditionally.  Without this, a probe that silently failed to request
        status would report an empty staple and read as the defect."""
        staples, status = _probe(staple, ON, ask=False)
        assert staples == [], staples
        assert status == KXR_OK, status


# --------------------------------------------------------------------------- #
# §C — attribution                                                             #
# --------------------------------------------------------------------------- #

class TestTheTunnelIsReal:
    """Every assertion in §B is about something the handshake did NOT carry, so
    each one needs the handshake itself to have worked."""

    @pytest.mark.parametrize("plane", ALL_PLANES)
    def test_the_upgraded_connection_serves_a_read(self, staple, plane):
        conn, _ = _upgrade(staple, plane, ask=True)
        try:
            assert _login(conn) == KXR_OK
            status, _body = _xrd_stat(conn, SEED_PATH)
        finally:
            conn.close()
        assert status == KXR_OK, (plane, status)

    @pytest.mark.parametrize("plane", ALL_PLANES)
    def test_the_peer_presented_the_configured_certificate(self, staple, plane):
        """All three listeners are one process sharing one certificate, which
        is what makes the §B comparison a comparison: the planes differ in the
        flag and in nothing else about their TLS context."""
        conn, _ = _upgrade(staple, plane, ask=True)
        try:
            subject = conn.get_peer_certificate().get_subject().CN
        finally:
            conn.close()
        assert subject, f"{plane}: the peer presented no certificate"


# --------------------------------------------------------------------------- #
# §D — the root cause, pinned at the source                                    #
# --------------------------------------------------------------------------- #

class TestTheFetchHasNoCaller:
    """§B can only ever show an absence.  This class names the reason, so that
    a future reader who finds the wire tests green does not conclude stapling
    works — and so that giving the fetch a caller trips something."""

    def test_brix_ocsp_staple_fetch_is_called_from_nowhere(self):
        """DEFECT CANDIDATE #66 at its cause.  A call is any occurrence of the
        symbol followed by `(` that is not its own definition or prototype, and
        today there are none: the only writer of ocsp.staple_data is
        unreachable, so brix_ocsp_stapling_cb has nothing to attach."""
        pattern = re.compile(r"brix_ocsp_staple_fetch\s*\(")
        callers = []
        for path in sorted(REPO.joinpath("src").rglob("*.c")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), 1):
                if _expression_1(line, pattern):
                    continue
                # The definition itself: the previous line is the return type
                # on its own, which is how this tree writes function headers.
                if _expression_2(path, line):
                    continue
                callers.append(f"{path.relative_to(REPO)}:{number}: {line.strip()}")
        _check_test_brix_ocsp_staple_fetch_is_called_from_nowhere_1(callers)

    def test_the_comments_still_claim_it_runs_at_init_process(self):
        """The other half of the defect, and the reason it survived: three
        comments describe a hook that does not exist.  Pinned so that removing
        the claim — or making it true — is a deliberate edit rather than
        something a reader has to re-derive from the call graph."""
        claims = []
        for relative in ("src/core/types/srv_conf_fields_cache.h",
                         "src/core/config/server_conf_merge_proxy_net.c"):
            text = REPO.joinpath(relative).read_text(encoding="utf-8")
            if "init_process" in text and "staple_data" in text:
                claims.append(relative)
        assert claims, (
            "the init_process claims are gone — if the hook was implemented "
            "instead of the comment deleted, the tests above are now wrong")
