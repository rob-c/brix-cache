"""A-1/T2·T5 — the proxy & redirector upstream-TLS legs authenticate the peer.

Both outbound TLS upgrade paths used to proceed the instant
``uconn->ssl->handshaked`` was true — but a completed handshake means only "a TLS
session exists," NOT "the peer is trusted."  With the CTX built at
``SSL_VERIFY_NONE`` (the OpenSSL client default), an on-path attacker presenting
any self-signed / wrong-host certificate completes the handshake and the leg
re-sends ``kXR_login`` (or proxies the client) over the attacker's channel — a
credential-stealing MITM (CWE-295).

The fix authenticates the peer in two independent places, and BOTH must hold for
a regression to be caught:

  1. Context build (``brix_tls_ctx_enable_verify`` in ``runtime_server.c``) sets
     ``SSL_VERIFY_PEER`` and pins the expected hostname
     (``X509_VERIFY_PARAM_set1_host``) on each outbound CTX whenever a CA is
     configured — so a bad chain OR a valid-cert-wrong-host fails the handshake
     itself.  It is wired for the proxy leg AND the redirector leg.
  2. Belt-and-braces: each handshake-done callback (``net/upstream/tls.c``,
     ``net/proxy/connect_upstream.c``) explicitly aborts when
     ``SSL_get_verify_result() != X509_V_OK`` — before any login/proxy work.

The verify branch is dormant in the shipped configs (no config wires
``upstream_tls`` + a CA today) and, once the CTX flags are set, the rejection is
enforced inside OpenSSL's handshake — neither is drivable as a live negative from
this suite.  So, matching the OCSP-transport / ucred-zeroization guardrails, the
properties are asserted against the source.  The security-negative pins the exact
regression that reintroduces the CVE: a callback that proceeds on ``handshaked``
alone, without the verify-result gate in front of the login/proxy work.
"""

import re
import subprocess
from pathlib import Path

import pytest

from server_launcher import RegistryCommandFailure
from server_registry import NginxInstanceSpec
from settings import BIND_HOST

_SRC = Path(__file__).resolve().parents[1] / "src"

RUNTIME_SERVER = _SRC / "core" / "config" / "runtime_server.c"
UP_TLS = _SRC / "net" / "upstream" / "tls.c"
PROXY_UP = _SRC / "net" / "proxy" / "connect_upstream.c"


class TestUpstreamTlsVerify:
    @pytest.fixture(scope="class")
    def runtime(self):
        return RUNTIME_SERVER.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def up_tls(self):
        return UP_TLS.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def proxy_up(self):
        return PROXY_UP.read_text(encoding="utf-8")

    # -- success: the CTX-build helper turns on PEER verify + host pinning --- #
    def test_ctx_helper_sets_verify_peer_and_host(self, runtime):
        helper = _fn_body(runtime, "brix_tls_ctx_enable_verify")
        assert "SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER" in helper
        assert "X509_VERIFY_PARAM_set1_host(param" in helper
        assert "X509_VERIFY_PARAM_set_hostflags(param" in helper

    # -- coverage: verification is enabled for BOTH outbound legs, not one --- #
    def test_both_legs_enable_verification(self, runtime):
        setup = _fn_body(runtime, "brix_server_setup_tls")
        # proxy CTX and redirector CTX each route their CA-guarded branch through
        # the shared enable-verify helper.
        assert "brix_tls_ctx_enable_verify(cf, xcf->proxy.tls_ctx->ctx" in setup
        assert "brix_tls_ctx_enable_verify(cf, xcf->upstream_tls_ctx->ctx" in setup

    # -- error: each done-callback fails closed on a bad verify result ------- #
    def test_callbacks_check_verify_result(self, up_tls, proxy_up):
        for src in (up_tls, proxy_up):
            assert "SSL_get_verify_result(uconn->ssl->connection) != X509_V_OK" \
                in src

    # -- security-negative: `handshaked` alone must NOT be the only gate — the
    #    verify-result abort must sit BEFORE the login/proxy work it guards ---- #
    def test_verify_gate_precedes_the_login_work(self, up_tls):
        cb = _fn_body(up_tls, "brix_upstream_tls_handshake_done") \
            if _has_fn(up_tls, "brix_upstream_tls_handshake_done") \
            else _cb_after(up_tls, "handshaked")
        verify_at = cb.index("SSL_get_verify_result")
        # The re-login is the sensitive action the MITM wants; it must come after.
        login_at = cb.index("build_login")
        assert verify_at < login_at, "verify-result gate must precede re-login"

    def test_proxy_verify_gate_precedes_the_proxy_work(self, proxy_up):
        cb = _cb_after(proxy_up, "brix_proxy_tls_handshake_done")
        verify_at = cb.index("SSL_get_verify_result")
        # The state transition to BOOTSTRAP / first flush is the sensitive step.
        proceed_at = cb.index("XRD_PX_BOOTSTRAP")
        assert verify_at < proceed_at, "verify-result gate must precede proxying"


# --------------------------------------------------------------------------- #
# Config-time gate: peer verification is MANDATORY by default (fail-closed).
#
# The source-assertion class above proves the runtime crypto (SSL_VERIFY_PEER +
# host pinning + the belt-and-braces verify-result abort) is wired.  This class
# proves the operator cannot LEAVE it unwired: a TLS leg turned on without a CA is
# refused at `nginx -t` unless verification is explicitly, loudly disabled.
# --------------------------------------------------------------------------- #
_GATE = pytest.mark.uses_lifecycle_harness

_REDIR_HOST = "brix_upstream 127.0.0.1:1095;"
_PROXY = "brix_tap_proxy on;\n        brix_tap_proxy_upstream 127.0.0.1:1095;"


@pytest.fixture(scope="module")
def ca_pem(tmp_path_factory):
    """A throwaway self-signed CA PEM — enough for ngx_ssl_trusted_certificate to
    load and flip the CTX into SSL_VERIFY_PEER.  Kept out of the shared test PKI so
    a parallel fleet is never disturbed."""
    d = tmp_path_factory.mktemp("a1_ca")
    pem = d / "ca.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(d / "ca.key"), "-out", str(pem), "-days", "1",
                    "-subj", "/CN=brix-a1-test-ca"],
                   check=True, capture_output=True)
    return str(pem)


def _nginx_t(lifecycle, data_root, directives, name):
    """Render + `nginx -t`; return (returncode, combined output).  The launcher
    raises on a failing `nginx -t`, which the no-CA cases expect."""
    spec = NginxInstanceSpec(
        name=name, template="nginx_upstream_tls_verify.conf",
        readiness="none", data_root=str(data_root),
        template_values={"BIND_HOST": BIND_HOST, "TLS_DIRECTIVES": directives},
        reason="A-1 upstream TLS verify fail-closed gate.")
    reg = lifecycle.register(spec)
    lifecycle.launcher.render_nginx(reg)
    try:
        res = lifecycle.launcher.nginx_test(reg)
    except RegistryCommandFailure as failure:
        return failure.returncode, failure.stdout_tail + failure.stderr_tail
    return res.returncode, res.stdout + res.stderr


# -- success: a leg with a pinned CA parses and enables verification --------- #
@_GATE
def test_redirector_ca_present_accepted(lifecycle, tmp_path, ca_pem):
    data = tmp_path / "d"; data.mkdir()
    d = f"{_REDIR_HOST}\n        brix_upstream_tls on;\n        brix_upstream_tls_ca {ca_pem};"
    rc, out = _nginx_t(lifecycle, data, d, "lc-a1-redir-ca")
    assert rc == 0, "redirector upstream_tls + CA must parse\n" + out


@_GATE
def test_proxy_ca_present_accepted(lifecycle, tmp_path, ca_pem):
    data = tmp_path / "d"; data.mkdir()
    d = f"{_PROXY}\n        brix_tap_proxy_upstream_tls on;\n        brix_tap_proxy_upstream_tls_ca {ca_pem};"
    rc, out = _nginx_t(lifecycle, data, d, "lc-a1-proxy-ca")
    assert rc == 0, "proxy upstream_tls + CA must parse\n" + out


# -- error: a leg on WITHOUT a CA (verify defaults on) is refused ------------ #
@_GATE
def test_redirector_no_ca_refused(lifecycle, tmp_path):
    data = tmp_path / "d"; data.mkdir()
    rc, out = _nginx_t(lifecycle, data,
                       f"{_REDIR_HOST}\n        brix_upstream_tls on;",
                       "lc-a1-redir-noca")
    assert rc != 0, "redirector upstream_tls without a CA MUST fail nginx -t\n" + out
    assert "refusing an unauthenticated" in out, "wrong rejection reason\n" + out


@_GATE
def test_proxy_no_ca_refused(lifecycle, tmp_path):
    data = tmp_path / "d"; data.mkdir()
    rc, out = _nginx_t(lifecycle, data,
                       f"{_PROXY}\n        brix_tap_proxy_upstream_tls on;",
                       "lc-a1-proxy-noca")
    assert rc != 0, "proxy upstream_tls without a CA MUST fail nginx -t\n" + out
    assert "refusing an unauthenticated" in out, "wrong rejection reason\n" + out


# -- security-negative: verification can only be absent via the loud opt-out - #
@_GATE
def test_redirector_verify_off_escape_hatch(lifecycle, tmp_path):
    data = tmp_path / "d"; data.mkdir()
    rc, out = _nginx_t(lifecycle, data,
                       f"{_REDIR_HOST}\n        brix_upstream_tls on;\n        brix_upstream_tls_verify off;",
                       "lc-a1-redir-off")
    assert rc == 0, "explicit brix_upstream_tls_verify off must parse\n" + out


@_GATE
def test_proxy_verify_off_escape_hatch(lifecycle, tmp_path):
    data = tmp_path / "d"; data.mkdir()
    rc, out = _nginx_t(lifecycle, data,
                       f"{_PROXY}\n        brix_tap_proxy_upstream_tls on;\n        brix_tap_proxy_upstream_tls_verify off;",
                       "lc-a1-proxy-off")
    assert rc == 0, "explicit brix_tap_proxy_upstream_tls_verify off must parse\n" + out


# --------------------------------------------------------------------------- #
def _has_fn(src: str, name: str) -> bool:
    return re.search(rf"\n{re.escape(name)}\(", src) is not None


def _fn_body(src: str, name: str) -> str:
    m = re.search(rf"\n{re.escape(name)}\(", src)
    assert m, f"function {name} not found"
    return _brace_block(src, src.index("{", m.end()))


def _cb_after(src: str, anchor: str) -> str:
    """Return the brace block of the function whose signature contains `anchor`
    (used when the callback is reached via its definition name)."""
    m = re.search(rf"\n{re.escape(anchor)}\(", src)
    assert m, f"anchor {anchor} not found"
    return _brace_block(src, src.index("{", m.end()))


def _brace_block(src: str, i: int) -> str:
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    raise AssertionError("unbalanced braces")
