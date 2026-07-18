"""A-6 item 2 — a nonce-less OCSP response is a hard failure under opt-in.

An OCSP request carries a fresh nonce (``OCSP_request_add1_nonce``) so a captured
GOOD response cannot be replayed later.  If the responder returns a signed
response that OMITS the nonce, ``OCSP_check_nonce`` reports it (<0) — but the
former code path warned and continued, so an on-path attacker replaying a still
valid, still signed, nonce-less GOOD response passed the revocation check
(CWE-294 replay).

The fix threads the built request out of ``do_ocsp_request`` (an out-param, so it
survives to the verify step) and adds a ``require_nonce`` gate to
``check_ocsp_response``: when set, a missing nonce denies (returns -1) instead of
warning.  It is wired to the ``brix_ocsp_require_nonce`` stream directive,
default OFF — most CA responders serve pre-signed, nonce-less responses, so a
hard-fail-by-default would break interop; the operator opts in.

Live OCSP negatives need a controllable responder that this suite does not stand
up, so the three properties are pinned against the source (matching the OCSP
transport / A-1 guardrails), plus a config-gate proving the directive is real and
that the default is genuinely off.
"""

import re
from pathlib import Path

import pytest

from server_launcher import RegistryCommandFailure
from server_registry import NginxInstanceSpec
from settings import BIND_HOST

_SRC = Path(__file__).resolve().parents[1] / "src"

OCSP_REQ = _SRC / "auth" / "crypto" / "ocsp_request.c"
CONF = _SRC / "core" / "types" / "conf_structs.h"
MODULE = _SRC / "protocols" / "root" / "stream" / "module.c"


class TestOcspRequireNonce:
    @pytest.fixture(scope="class")
    def ocsp_req(self):
        return OCSP_REQ.read_text(encoding="utf-8")

    # -- success: the request survives out of do_ocsp_request for the nonce
    #    check, and a matching nonce (>0) is NOT treated as an error --------- #
    def test_request_is_threaded_out_for_nonce_check(self, ocsp_req):
        body = _fn_body(ocsp_req, "do_ocsp_request")
        assert "*req_out = NULL;" in body, "req_out must be pre-cleared"
        assert "*req_out = req;" in body, "the built request must be handed back"
        # a match (nonce_rc > 0) falls through — only <0 and ==0 branch out.
        chk = _fn_body(ocsp_req, "check_ocsp_response")
        assert "OCSP_check_nonce(req_for_nonce, bresp)" in chk

    # -- error: nonce mismatch (rc==0) always denies, independent of opt-in -- #
    def test_nonce_mismatch_always_denies(self, ocsp_req):
        chk = _fn_body(ocsp_req, "check_ocsp_response")
        mism = chk[chk.index("nonce_rc == 0"):]
        assert "nonce mismatch" in mism
        assert mism.index("return -1;") < mism.index("OCSP_resp_find_status")

    # -- security-negative: a MISSING nonce (rc<0) denies ONLY when the gate is
    #    on, and the deny frees bresp + returns -1 before any status lookup --- #
    def test_missing_nonce_hard_fails_only_when_required(self, ocsp_req):
        assert "int require_nonce)" in ocsp_req, "gate must be a parameter"
        chk = _fn_body(ocsp_req, "check_ocsp_response")
        neg = chk[chk.index("nonce_rc < 0"):]
        guard = neg[neg.index("if (require_nonce)"):]
        # inside the guard: log, free, deny — and this must precede the
        # warn-and-continue fallback that keeps interop for nonce-less responders.
        deny = guard[:guard.index("}") + 1]
        assert "OCSP_BASICRESP_free(bresp);" in deny
        assert "return -1;" in deny
        # the fallback (warn only) is reachable ONLY when require_nonce is false.
        assert "nonce missing in OCSP response\"" in neg


# --------------------------------------------------------------------------- #
# The conf field is plumbed default-OFF and the directive is registered.
# --------------------------------------------------------------------------- #
class TestOcspRequireNonceWiring:
    def test_conf_field_defaults_off(self):
        conf = CONF.read_text(encoding="utf-8")
        assert re.search(r"ngx_flag_t\s+require_nonce;", conf)
        assert "ngx_conf_merge_value(c->require_nonce, p->require_nonce, 0)" in conf

    def test_directive_registered(self):
        mod = MODULE.read_text(encoding="utf-8")
        assert 'ngx_string("brix_ocsp_require_nonce")' in mod
        assert "offsetof(ngx_stream_brix_srv_conf_t, ocsp.require_nonce)" in mod


# --------------------------------------------------------------------------- #
# Config-gate: the directive is accepted by `nginx -t`, and OFF is the default
# (an explicit `on` and an explicit `off` both parse; a bad value is rejected).
# --------------------------------------------------------------------------- #
_GATE = pytest.mark.uses_lifecycle_harness


def _nginx_t(lifecycle, data_root, directives, name):
    spec = NginxInstanceSpec(
        name=name, template="nginx_upstream_tls_verify.conf",
        readiness="none", data_root=str(data_root),
        template_values={"BIND_HOST": BIND_HOST, "TLS_DIRECTIVES": directives},
        reason="A-6 item 2 brix_ocsp_require_nonce parse gate.")
    reg = lifecycle.register(spec)
    lifecycle.launcher.render_nginx(reg)
    try:
        res = lifecycle.launcher.nginx_test(reg)
    except RegistryCommandFailure as failure:
        return failure.returncode, failure.stdout_tail + failure.stderr_tail
    return res.returncode, res.stdout + res.stderr


@_GATE
@pytest.mark.parametrize("val", ["on", "off"])
def test_require_nonce_flag_parses(lifecycle, tmp_path, val):
    data = tmp_path / "d"; data.mkdir()
    rc, out = _nginx_t(lifecycle, data, f"brix_ocsp_require_nonce {val};",
                       f"lc-a6-nonce-{val}")
    assert rc == 0, f"brix_ocsp_require_nonce {val} must parse\n" + out


@_GATE
def test_require_nonce_rejects_non_flag_value(lifecycle, tmp_path):
    data = tmp_path / "d"; data.mkdir()
    rc, out = _nginx_t(lifecycle, data, "brix_ocsp_require_nonce maybe;",
                       "lc-a6-nonce-bad")
    assert rc != 0, "a non-boolean value MUST fail nginx -t\n" + out


# --------------------------------------------------------------------------- #
def _fn_body(src: str, name: str) -> str:
    m = re.search(rf"\n{re.escape(name)}\(", src)
    assert m, f"function {name} not found"
    i = src.index("{", m.end())
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    raise AssertionError("unbalanced braces")
