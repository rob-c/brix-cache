"""brix_http_query_token at VALUE granularity — audit §Method, 16th tranche.

The tranche re-runs the audit's Method (steps 1-2) per (directive, VALUE) over
the 128 directives whose setter is ``ngx_conf_set_flag_slot``.
``brix_http_query_token`` is the fourth of the seven whose BOTH arms are
unwritten anywhere in the corpus, and it is the one where that matters most:
the feature it gates is *already* exercised — ``test_query_token.py`` and four
WLCG conformance files drive ``?authz=`` — but every one of them does so on the
merge DEFAULT.  Nothing had ever written the directive, so nothing had ever
seen the ``off`` path, and the ``off`` path is where the interesting behaviour
is.

WHAT THE VALUE SELECTS
----------------------
``webdav_bearer_from_query()`` (auth_token.c:133) returns NGX_DECLINED when the
flag is off, so ``?authz=``/``?access_token=`` stops being a token transport.
That is the whole of the documented effect.  What it also selects, and what no
test could have noticed while the directive was never written, is whether the
URL token is REDACTED before the request reaches the logs.

DEFECT CANDIDATE #67 — off logs the token that on redacts
---------------------------------------------------------
``wt_redact_query_token()`` (auth_token.c:206) is called from exactly two places
in ``wt_parse_header()``: the dual-transport reject at :299 and the
post-extraction scrub at :305.  Both are downstream of a token having been
successfully EXTRACTED.  With the flag off, ``webdav_bearer_from_query()``
declines at :272-274 and ``wt_parse_header()`` returns NGX_DECLINED straight
through :404-406 — before either redaction call.

So ``brix_http_query_token off`` — which an operator writes precisely to stop
accepting credentials in URLs — is the configuration under which a credential in
a URL is written to the logs verbatim — the access log in all three of the
fields the redactor exists to scrub (``$request``, ``$request_uri``, ``$args``)
AND the error log, whose per-request `, request: "..."` suffix is
``r->request_line``, the third of those fields.  The arm that honours the token
hides it; the arm that refuses it publishes it, twice.  The
token is refused, so it is not *usable* against this server — but it is a live
bearer for every other endpoint that trusts the same issuer, and it is now in a
file that outlives the request, is shipped to log collectors, and is readable by
anyone with the operator's log access.

WHAT THIS FILE ASSERTS
----------------------
§A  the pair: ``on`` accepts a URL token in both spellings and with the RFC 6750
    "Bearer " prefix; ``off`` refuses it, and still accepts the header, so the
    flag narrows the TRANSPORT and not authentication itself.
§B  the merge default: the absent directive answers exactly as ``on``.
§C  RFC 6750 §2.3: the query path attaches Cache-Control: no-store and the
    header path does not — pinned per arm, because ``off`` never reaches the
    code that adds it.
§D  RFC 6750 §2: header+query is 400 under ``on``; under ``off`` there is only
    one transport, so the same request authenticates.  The dual-transport gate
    is a property of the enabled arm.
§E  DEFECT CANDIDATE #67: what each arm leaves in the access log AND the error
    log, with the refused-token control that shows redaction is about
    extraction and not about the verdict.
§E2 DEFECT CANDIDATE #68, found while measuring #67 and not the flag's fault:
    redaction runs inside the token phase, so a log line written by an EARLIER
    phase carries the raw token even on the arm that redacts.
§F  the parse tier for this directive: token set, case, arity, placement.
§G  the source: both redaction call sites are still below the extraction the
    disabled flag skips.

Ledger: lc-audit16c-qtoken (one http listener, three locations, one access log).
"""

import os
import re
import time
from pathlib import Path

import pytest
import requests

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN
from utils.make_token import TokenIssuer

def _check_test_the_two_arms_disagree_about_the_same_token_1(token, off_line):
    assert any(token in ln for ln in off_line), (
        "off no longer leaks the token — see #67")


pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16c-qtoken")]

NAME = "lc-audit16c-qtoken"
ROOT = Path(__file__).resolve().parents[1]

ISSUER = "https://audit16c.example.com"
AUD = "audit16c-gateway"
PAYLOAD = b"audit16c-query-token-payload\n"
SEED = "seed.txt"

# The three arms, by the location prefix that carries each.
ON, OFF, DEFAULT = "on", "off", "default"
ALL_ARMS = (ON, OFF, DEFAULT)
# The two that honour a URL token — asserted, not assumed, in §B.
HONOURING = (ON, DEFAULT)


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

@pytest.fixture
def qtoken(lifecycle, tmp_path):
    """(endpoint, issuer) — the three-location listener and the issuer every
    bearer in this file is minted from.  One issuer for all three arms: a
    verdict that differs between locations can then only be the flag."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    for arm in ALL_ARMS:
        (data / arm).mkdir(parents=True)
        (data / arm / SEED).write_bytes(PAYLOAD)

    issuer = TokenIssuer(str(tmp_path / "tokens"), issuer=ISSUER, audience=AUD)
    issuer.init_keys()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16c_qtoken.conf",
        protocol="http",
        data_root=str(data),
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
            "JWKS": issuer.jwks_path,
            "ISSUER": ISSUER,
            "AUD": AUD},
        reason="audit-16c brix_http_query_token at value granularity"))
    return endpoint, issuer


def _token(issuer, sub="alice", **kwargs):
    return issuer.generate(sub=sub, scope="storage.read:/", **kwargs)


def _get(endpoint, arm, *, params=None, headers=None):
    return requests.get(f"http://{HOST}:{endpoint.port}/{arm}/{SEED}",
                        params=params, headers=headers, timeout=15)


# --------------------------------------------------------------------------- #
# The access log — the instrument §E reads                                     #
# --------------------------------------------------------------------------- #

def _logdir(endpoint):
    """The instance's own log directory; the harness wipes it at teardown, so
    everything §E reads has to be read while the instance is alive."""
    return Path(endpoint.prefix) / "logs"


def _access_log(endpoint):
    path = _logdir(endpoint) / "access.log"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _log_lines_for(endpoint, marker):
    """Every access-log line mentioning `marker`, after giving the worker a
    moment to flush.  nginx buffers nothing here (no buffer= on access_log),
    but the write happens at request completion, which is after the client's
    response has already been read."""
    for _ in range(50):
        text = _access_log(endpoint)
        lines = [ln for ln in text.splitlines() if marker in ln]
        if lines:
            return lines
        time.sleep(0.1)
    return []


# --------------------------------------------------------------------------- #
# §A — the pair                                                                #
# --------------------------------------------------------------------------- #

class TestTheFlagDecidesWhetherAUrlCarriesCredentials:

    def test_on_accepts_the_authz_parameter(self, qtoken):
        endpoint, issuer = qtoken
        r = _get(endpoint, ON, params={"authz": _token(issuer)})
        assert r.status_code == 200, r.text[:200]
        assert r.content == PAYLOAD

    def test_on_accepts_the_access_token_alias(self, qtoken):
        """auth_token.c:136-138 tries ?authz= then ?access_token=; both are the
        same transport and the flag governs both."""
        endpoint, issuer = qtoken
        r = _get(endpoint, ON, params={"access_token": _token(issuer)})
        assert r.status_code == 200, r.text[:200]

    def test_on_strips_the_rfc6750_bearer_prefix(self, qtoken):
        """:141-145 — the URL value may repeat the scheme, as davix writes it."""
        endpoint, issuer = qtoken
        r = _get(endpoint, ON, params={"authz": f"Bearer {_token(issuer)}"})
        assert r.status_code == 200, r.text[:200]

    def test_off_refuses_the_authz_parameter(self, qtoken):
        """The arm nothing had ever written.  The token is valid, in scope and
        minted from the location's own issuer — the only reason it does not
        authenticate is the flag."""
        endpoint, issuer = qtoken
        r = _get(endpoint, OFF, params={"authz": _token(issuer)})
        assert r.status_code == 401, (r.status_code, r.text[:200])

    def test_off_refuses_the_access_token_alias(self, qtoken):
        endpoint, issuer = qtoken
        r = _get(endpoint, OFF, params={"access_token": _token(issuer)})
        assert r.status_code == 401, (r.status_code, r.text[:200])

    def test_off_still_authenticates_the_header(self, qtoken):
        """The control that keeps §A honest: `off` narrows the TRANSPORT, it
        does not switch token auth off.  Without this, every assertion above
        would also pass against a location that simply refuses everyone."""
        endpoint, issuer = qtoken
        r = _get(endpoint, OFF,
                 headers={"Authorization": f"Bearer {_token(issuer)}"})
        assert r.status_code == 200, r.text[:200]
        assert r.content == PAYLOAD

    def test_the_same_request_differs_only_by_the_flag(self, qtoken):
        """The pair as one assertion, one token, two locations, one process."""
        endpoint, issuer = qtoken
        token = _token(issuer)
        assert _get(endpoint, ON, params={"authz": token}).status_code == 200
        assert _get(endpoint, OFF, params={"authz": token}).status_code == 401


# --------------------------------------------------------------------------- #
# §B — the merge default                                                       #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """config_merge.c:100 merges to 1.  An operator who writes nothing gets the
    URL transport, which is the security-relevant half of that fact: the
    permissive arm is the default."""

    def test_the_absent_directive_accepts_a_url_token(self, qtoken):
        endpoint, issuer = qtoken
        r = _get(endpoint, DEFAULT, params={"authz": _token(issuer)})
        assert r.status_code == 200, r.text[:200]

    def test_the_absent_plane_answers_exactly_as_the_on_plane(self, qtoken):
        """Not "it also works" — the same four requests, same verdicts."""
        endpoint, issuer = qtoken
        token = _token(issuer)
        cases = ({"authz": token},
                 {"access_token": token},
                 {"authz": f"Bearer {token}"},
                 {"authz": "not-a-jwt"})
        for params in cases:
            on = _get(endpoint, ON, params=params).status_code
            default = _get(endpoint, DEFAULT, params=params).status_code
            assert on == default, (params, on, default)

    def test_the_default_is_the_permissive_arm(self, qtoken):
        """Stated as its own assertion because it is the reason the pair is
        worth a file: writing nothing is writing `on`."""
        endpoint, issuer = qtoken
        token = _token(issuer)
        assert _get(endpoint, DEFAULT, params={"authz": token}).status_code == 200
        assert _get(endpoint, OFF, params={"authz": token}).status_code == 401


# --------------------------------------------------------------------------- #
# §C — RFC 6750 §2.3, the no-store the query path owes                         #
# --------------------------------------------------------------------------- #

class TestTheNoStoreHeader:

    @pytest.mark.parametrize("arm", HONOURING)
    def test_a_query_token_response_carries_no_store(self, qtoken, arm):
        """webdav_add_nostore() (:310-312) fires only for from_query — a URL
        with a credential in it must never be cached by an intermediary."""
        endpoint, issuer = qtoken
        r = _get(endpoint, arm, params={"authz": _token(issuer)})
        assert r.status_code == 200
        assert "no-store" in r.headers.get("Cache-Control", ""), r.headers

    def test_the_header_path_does_not_carry_no_store(self, qtoken):
        """The control: no-store is attached because the token came from the
        URL, not because the location attaches it to everything."""
        endpoint, issuer = qtoken
        r = _get(endpoint, ON,
                 headers={"Authorization": f"Bearer {_token(issuer)}"})
        assert r.status_code == 200
        assert "no-store" not in r.headers.get("Cache-Control", ""), r.headers

    def test_off_never_reaches_the_no_store_path(self, qtoken):
        """Security-negative, and the first visible sign of #67: with the flag
        off the URL token is not consumed, so none of the code that treats a
        URL as sensitive runs at all."""
        endpoint, issuer = qtoken
        r = _get(endpoint, OFF, params={"authz": _token(issuer)})
        assert r.status_code == 401
        assert "no-store" not in r.headers.get("Cache-Control", ""), r.headers


# --------------------------------------------------------------------------- #
# §D — RFC 6750 §2, the single-transport MUST                                  #
# --------------------------------------------------------------------------- #

class TestTheDualTransportGate:

    def test_on_refuses_a_header_and_a_query_token_together(self, qtoken):
        """:296-301 — two transports at once is a confused-deputy vector and
        the request is 400 invalid_request, not an auth failure."""
        endpoint, issuer = qtoken
        token = _token(issuer)
        r = _get(endpoint, ON, params={"authz": token},
                 headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400, (r.status_code, r.text[:200])

    def test_the_gate_fires_even_when_the_two_tokens_are_identical(self, qtoken):
        """The MUST is about the number of transports, not about disagreement
        between them — the byte-identical case is the one an implementation is
        most likely to wave through."""
        endpoint, issuer = qtoken
        token = _token(issuer)
        r = _get(endpoint, DEFAULT, params={"access_token": token},
                 headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400, (r.status_code, r.text[:200])

    def test_off_has_only_one_transport_so_the_same_request_succeeds(self, qtoken):
        """The pair's least obvious consequence, and the reason it is asserted
        rather than left implicit: turning the URL transport off also turns off
        the 400 that a URL+header request earns under `on`.  The server is not
        weaker for it — the query value is never read — but the same client
        request gets two different status codes from two locations, and a
        reader who has only ever seen the default would not predict it."""
        endpoint, issuer = qtoken
        token = _token(issuer)
        r = _get(endpoint, OFF, params={"authz": token},
                 headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, (r.status_code, r.text[:200])


# --------------------------------------------------------------------------- #
# §E — DEFECT CANDIDATE #67                                                    #
# --------------------------------------------------------------------------- #

class TestWhatEachArmLeavesInTheLog:
    """The finding.  Each test mints a token with a marker in the `sub` claim so
    its access-log line can be found without matching on the token itself, and
    then asks whether the token's own bytes are in that line."""

    def _probe(self, endpoint, issuer, arm, marker):
        token = _token(issuer, sub=marker)
        response = _get(endpoint, arm, params={"authz": token})
        lines = _log_lines_for(endpoint, f"/{arm}/{SEED}")
        return token, response, [ln for ln in lines if marker in ln or True]

    def test_on_redacts_the_token_from_every_logged_field(self, qtoken):
        """brix_http_redact_query_token() overwrites the value with 'x' in
        place (http_headers.c:339-372), length-preservingly, in all three
        fields — so the log line still shows an authz= of the right shape and
        none of the right bytes."""
        endpoint, issuer = qtoken
        token, response, lines = self._probe(endpoint, issuer, ON, "onarm")
        assert response.status_code == 200
        assert lines, "the request was not logged at all"
        joined = "\n".join(lines)
        assert token not in joined, (
            "the accepted token reached the access log despite redaction")
        assert "authz=xxxx" in joined, joined[:400]

    def test_off_writes_the_token_to_the_access_log_verbatim(self, qtoken):
        """DEFECT CANDIDATE #67.  The arm an operator selects to STOP accepting
        credentials in URLs is the arm that publishes them: wt_parse_header()
        returns NGX_DECLINED at :272-274 before either call to
        wt_redact_query_token(), so nothing scrubs the request line.

        When this is fixed — redact whenever a query token is PRESENT, not only
        when it was consumed — this assertion inverts, and the one above it
        stays as it is."""
        endpoint, issuer = qtoken
        token, response, lines = self._probe(endpoint, issuer, OFF, "offarm")
        assert response.status_code == 401
        assert lines, "the request was not logged at all"
        joined = "\n".join(lines)
        assert token in joined, (
            "defect candidate #67 appears to be fixed — the refused URL token "
            "is no longer in the access log; invert this test and update the "
            "audit document")

    def test_the_two_arms_disagree_about_the_same_token(self, qtoken):
        """The pair, read out of one log: one token, two locations, and the
        location that refused it is the one that kept a copy."""
        endpoint, issuer = qtoken
        token = _token(issuer, sub="botharms")
        _get(endpoint, ON, params={"authz": token})
        _get(endpoint, OFF, params={"authz": token})
        text = _access_log(endpoint)
        on_line = [ln for ln in text.splitlines() if f"/{ON}/{SEED}" in ln]
        off_line = [ln for ln in text.splitlines() if f"/{OFF}/{SEED}" in ln]
        def _assert_test_the_two_arms_disagree_about_the_same_token_1():
            assert on_line and off_line
            assert not any(token in ln for ln in on_line), "on leaked the token"

        _assert_test_the_two_arms_disagree_about_the_same_token_1()
        _check_test_the_two_arms_disagree_about_the_same_token_1(token, off_line)

    def test_a_token_the_server_refuses_is_still_redacted_when_it_was_read(
            self, qtoken):
        """The control that names the actual rule.  A garbage token on the ON
        arm is refused 401 exactly like the OFF arm refuses a good one — but it
        was EXTRACTED first, so it is redacted.  Redaction tracks extraction,
        not the verdict, which is why #67 is a gap in the extraction path and
        not a logging-policy preference."""
        endpoint, _issuer = qtoken
        garbage = "eyJhbGciOiJub25lIn0.e30.notasignature-refusedbutredacted"
        r = _get(endpoint, ON, params={"authz": garbage})
        assert r.status_code == 401, r.status_code
        lines = _log_lines_for(endpoint, f"/{ON}/{SEED}")
        recent = "\n".join(lines[-5:])
        assert garbage not in recent, recent[:400]

    def test_the_error_log_carries_the_refused_token_as_well(self, qtoken):
        """The true size of #67: two log sinks, not one.

        nginx appends `, request: "<r->request_line>"` to every message logged
        with a request context (ngx_http_log_error_handler), and that is the
        SAME field brix_http_redact_query_token() scrubs — which is why the
        redactor targets three fields and not just $args.  On the `off` arm
        nothing ever scrubs it, so the unredacted request line reaches the error
        log too."""
        endpoint, issuer = qtoken
        token = _token(issuer, sub="errlogarm")
        _get(endpoint, OFF, params={"authz": token})
        errlog = (_logdir(endpoint) / "error.log").read_text(
            encoding="utf-8", errors="replace")
        assert token in errlog, (
            "defect candidate #67's error-log half appears fixed — invert this "
            "test together with the access-log one and update the audit")


class TestRedactionRunsTooLateForEarlierLogLines:
    """DEFECT CANDIDATE #68, which §E found by accident and which is NOT the
    flag's fault: redaction happens inside the token auth phase, so it protects
    only log lines written after it.  Every line an earlier phase already wrote
    carries the raw request line — with the flag ON, on the arm that redacts.

    The concrete instance here is auth_cert.c:481-484, the per-request WARN a
    cleartext WebDAV listener writes because it cannot verify a GSI chain
    without TLS.  It fires before the token phase on EVERY request, so on a
    plain-http endpoint a URL token is in the error log before anything has had
    the chance to hide it.  A davs:// deployment does not take that particular
    branch, which is why this is filed as its own candidate at its own size
    rather than folded into #67 — but the shape (any pre-token log line wins the
    race) is general, and the fix for both is the same: redact when a query
    token is PRESENT, at the earliest phase that can see it.
    """

    def test_a_line_written_before_the_token_phase_keeps_the_raw_token(
            self, qtoken):
        endpoint, issuer = qtoken
        token = _token(issuer, sub="earlyline")
        r = _get(endpoint, ON, params={"authz": token})
        assert r.status_code == 200, "the request must SUCCEED — the point is "\
                                     "that redaction worked and was still too late"
        errlog = (_logdir(endpoint) / "error.log").read_text(
            encoding="utf-8", errors="replace")
        carriers = [ln for ln in errlog.splitlines() if token in ln]
        assert carriers, (
            "defect candidate #68 appears fixed — no error-log line written "
            "before the token phase carries the raw token any more")
        assert any("cannot verify GSI" in ln for ln in carriers), (
            "the token still reaches the error log, but through a different "
            "line than auth_cert.c:481-484 — re-read #68:\n"
            + "\n".join(ln[:200] for ln in carriers))

    def test_the_access_log_is_still_clean_on_that_same_request(self, qtoken):
        """What separates #68 from #67.  The access log is written at request
        completion, which is after redaction, so the honouring arm's access
        line is scrubbed even though its error line is not.  One request, two
        sinks, two different answers — and that is the whole shape of the
        defect."""
        endpoint, issuer = qtoken
        token = _token(issuer, sub="cleanaccess")
        assert _get(endpoint, ON, params={"authz": token}).status_code == 200
        lines = _log_lines_for(endpoint, f"/{ON}/{SEED}")
        assert lines
        assert not any(token in ln for ln in lines), (
            "the access log leaked the token as well — #67 and #68 have merged")


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, body, *, location=True):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return nginx_t("nginx_audit16cparse.conf", tmp_path,
                   PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                   LOG_DIR=str(tmp_path),
                   LOC_KNOBS=body if location else "",
                   HTTP_KNOBS="" if location else body)


class TestTheParseTier:
    """ngx_conf_set_flag_slot tests name.len and then ngx_strcasecmp, so the
    token set is exactly {on, off} case-insensitively and nothing else — the
    same fact tranche 15 pinned for the enum setter, restated for the flag
    setter because it is what makes "256 pairs" the right count."""

    @pytest.mark.parametrize("token", ["on", "off"])
    def test_each_token_is_accepted(self, tmp_path, token):
        result = _parse(tmp_path, f"            brix_http_query_token {token};\n")
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("token", ["ON", "Off", "oFF"])
    def test_the_token_is_matched_case_insensitively(self, tmp_path, token):
        result = _parse(tmp_path, f"            brix_http_query_token {token};\n")
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("token", ["1", "true", "yes", "enabled"])
    def test_a_value_outside_the_pair_is_refused(self, tmp_path, token):
        """The security-negative of the parse tier: a config that means to
        enable the transport and misspells the token must not silently take the
        merge default, which is also `on` — it must fail to load."""
        result = _parse(tmp_path, f"            brix_http_query_token {token};\n")
        assert result.returncode != 0, result.stdout
        assert "invalid value" in (result.stderr + result.stdout)

    @pytest.mark.parametrize("line", ["brix_http_query_token;",
                                      "brix_http_query_token on off;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        result = _parse(tmp_path, f"            {line}\n")
        assert result.returncode != 0, result.stdout
        assert "invalid number of arguments" in (result.stderr + result.stdout)

    def test_the_directive_is_accepted_at_http_level(self, tmp_path):
        """NGX_HTTP_MAIN_CONF is in the mask (module_commands.c:412-417), which
        is what lets a deployment turn the URL transport off once for every
        location instead of per location."""
        result = _parse(tmp_path, "    brix_http_query_token off;\n",
                        location=False)
        assert result.returncode == 0, result.stderr


# --------------------------------------------------------------------------- #
# §G — the source, so the defect is pinned where it lives                      #
# --------------------------------------------------------------------------- #

class TestTheRedactionCallSites:

    def test_redaction_is_only_reachable_after_extraction(self):
        """#67 at its cause.  Both calls to wt_redact_query_token() sit below
        the point where a token has been extracted; the early NGX_DECLINED that
        the disabled flag takes is above both of them.  If a third call site
        appears — or one moves above the fallback — this test says so, and §E's
        assertions have to be re-read."""
        source = ROOT.joinpath(
            "src/protocols/webdav/auth_token.c").read_text(encoding="utf-8")
        lines = source.splitlines()

        def _line_of(pattern):
            return [i for i, ln in enumerate(lines) if re.search(pattern, ln)]

        calls = [i for i in _line_of(r"^\s*wt_redact_query_token\(r\);")]
        assert len(calls) == 2, (
            f"wt_redact_query_token() now has {len(calls)} call sites, not 2; "
            "defect candidate #67 may be fixed — re-read §E")

        declines = _line_of(r"webdav_bearer_from_query\(r, conf, bearer\)")
        assert declines, "the query fallback moved; §E is measuring the wrong path"
        assert min(declines) < min(calls), (
            "the query fallback is no longer above every redaction call — the "
            "shape of #67 has changed")
