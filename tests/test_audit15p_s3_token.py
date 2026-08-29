"""
test_audit15p_s3_token.py — §Method step 2 sharpened, third file
(docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

WHY THIS FILE EXISTS

Step 2 of the audit's method counts a directive covered when its name appears
anywhere in the test corpus.  That is not coverage — a directive written into a
launched template is *exercised* by every test that dials the port, and
*asserted* by none of them.  Re-running step 2 as "is there a test whose verdict
changes when this directive changes?" left thirteen survivors that the 08-15
pass scored as covered.  Four went to the WebDAV response surface
(test_audit15n_webdav_cors.py), four to the CMS timing plane
(test_audit15o_cms_windows.py), and this file takes the S3 bearer gate.

But two of the four names on that shortlist did not survive contact with the
corpus.  Re-measuring them one at a time, rather than by grep:

  brix_token_audience   COVERED IN EFFECT.  test_wlcg_token_conformance_s3
                           ::test_s3_04_wrong_audience_reject and
                           test_audit15k_s3_coresidency::test_a_wrong_audience_
                           bearer_is_refused each mint a token whose `aud`
                           differs from the configured string and read the 403.
                           Neither passes unless the directive is what the
                           verifier compares against: with the value ignored,
                           brix_token_validate() has no expected audience and
                           admits the token.  The verdict already moves with
                           the directive; there is nothing to add.
  brix_token_jwks       COVERED IN EFFECT for the same reason — those two
                           suites serve a valid token, which cannot happen
                           unless the named file was loaded and its key used.
                           What they do NOT show is that the PATH selects the
                           trust anchor, which §E below adds.

That leaves the third knob, which really is untested: brix_token_clock_skew
occurs exactly once in the tree (test_audit15_zero_directive_parse.py, which
proves the line parses and nothing else), and the two config-time refusals
brix_token_jwks owns (module_merge.c:134-152), which are asserted nowhere.

THE MEASUREMENT PROBLEM, AND THE ANSWER

The CMS timing plane had to defeat a slow host by measuring differences.  A
token skew has the opposite shape and a cleaner answer: the deadline is written
into the token, not read off the wall, so nothing here is timed at all.  The
four arms are four locations on ONE listener that differ in nothing but the
knob, and one minted token collects a different verdict from each:

    arm         brix_token_clock_skew      a token that died 30s ago
    /skew0/     0                             403 AccessDenied
    /skewdef/   (absent — merge default 60)   200
    /skewwide/  1800                          200
    /keyb/      (absent) + a SECOND JWKS      403, on the anchor not the clock

A test that set /skewdef/ to 60 explicitly would prove that 60 equals 60.  The
directive is left OUT of that arm on purpose, so the arm asserts the frozen
default at module_merge.c:132 as well as the effect.

WHAT THE BLOCK ESTABLISHES

- The skew widens `exp` by exactly the configured number of seconds and no
  more: one token 30s dead is refused at 0 and served at 60; one token 120s
  dead is refused at 60 and served at 1800.  The knob is a bound, not a switch.
- The widening is ONE-SIDED.  token_check_time_window() (validate.c:321-343)
  adds the skew to `exp` and compares `nbf` against the bare clock, so a
  not-yet-valid token is refused even on the arm carrying half an hour of
  grace.  A skew is a tolerance for a lagging clock, never a licence to accept
  a token before its issuer says it starts.
- brix_token_jwks names a trust anchor, and the name is load-bearing: both
  JWKS files here carry the same kid (`test-key-1`) over different key
  material, so each arm refusing the other's token refused it on the key, not
  on the label.
- The gate will not start misconfigured: `brix_s3_token on` without a JWKS, an
  empty JWKS and an absent JWKS are all NGX_LOG_EMERG at `nginx -t`.

DEFECT CANDIDATE #50 (hardening, missing bound) — brix_token_clock_skew is
the only one of the three token-skew directives with no upper bound.  Its two
twins refuse anything outside [0, 300] at config time:

    brix_token_clock_skew          server_conf_merge_security.c:154
    brix_webdav_token_clock_skew   webdav/config_merge.c:164

both emitting "... must be >= 0 and <= 300".  The S3 twin is a bare
ngx_conf_set_num_slot with no post handler (module.c:410-415) and no check in
s3_merge_token(), so `brix_token_clock_skew 1800;` loads and grants half an
hour of grace past every `exp` on that export — and §C proves it live: a token
that expired 25 minutes ago is served with a 200.  Nothing here is a bypass; a
skew of 1800 is what the operator typed.  The cost is that two of three planes
tell an operator the number is out of range and the third does not, so the same
mistake is caught on a WebDAV export and silently honoured on an S3 one.  The
asymmetry is the finding, and it is pinned in both directions below so that
bounding the S3 setter breaks exactly one test with a message saying so.
"""

import os
import re
from pathlib import Path

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN
from tokenforge import TokenForge
from test_phase25_ratelimit import _parse_fail, _http_values, _stream_values

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15p-s3token")]

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK), reason=f"nginx not executable: {NGINX_BIN}")

ISSUER = "https://test.example.com"
AUDIENCE = "audit15p-s3"

# The three arms that share one trust anchor and differ only in the skew, plus
# the fourth that shares the skew and differs only in the anchor.
SKEW_ARMS = ("skew0", "skewdef", "skewwide")
ARMS = SKEW_ARMS + ("keyb",)

DEFAULT_SKEW = 60      # module_merge.c:132, frozen
WIDE_SKEW = 300        # the config: the widest LEGAL grace (the unified clamp)
OVER_BOUND = 1800      # what the pre-unification S3 twin used to accept
TWIN_BOUND = 300       # the one shared clamp (shared_conf_merge.h; stream twin
                       # in server_conf_merge_security.c)

SEED = b"audit15p s3 bearer window seed\n"

DEFECT50 = (
    "DEFECT CANDIDATE #50 regressed: the unified brix_token_clock_skew must "
    "refuse anything over 300s on EVERY plane (the shared security clamp in "
    "shared_conf_merge.h and its stream twin).")


# --------------------------------------------------------------------------- #
# The block.                                                                   #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def s3token(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    for arm in ARMS:
        (data / arm / "pub").mkdir(parents=True)
        (data / arm / "pub" / "seed.txt").write_bytes(SEED)
    tmp = tmp_path / "ngxtmp"
    tmp.mkdir()

    # Two independent signing authorities, same issuer, same audience, same
    # kid.  Everything a token says about itself is identical; only the key
    # that signed it differs, which is what makes §E a claim about the JWKS
    # path rather than about any claim in the token.
    forge_a = TokenForge(str(tmp_path / "tokens_a"), issuer=ISSUER,
                         audience=AUDIENCE)
    forge_a.init_keys()
    forge_b = TokenForge(str(tmp_path / "tokens_b"), issuer=ISSUER,
                         audience=AUDIENCE)
    forge_b.init_keys()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15p-s3token",
        template="nginx_audit15p_s3token.conf",
        protocol="s3",
        data_root=str(data),
        template_values={"JWKS_A": forge_a.jwks_path,
                         "JWKS_B": forge_b.jwks_path,
                         "ISSUER": ISSUER,
                         "AUDIENCE": AUDIENCE,
                         "TMP_DIR": str(tmp)},
        reason="audit-15p: the S3 bearer gate's exp/nbf window"))
    return endpoint, forge_a, forge_b


@pytest.fixture(scope="module")
def anchor(tmp_path_factory):
    """A valid JWKS for the `nginx -t` arms, minted once for the whole file."""
    forge = TokenForge(str(tmp_path_factory.mktemp("audit15p-anchor")),
                       issuer=ISSUER, audience=AUDIENCE)
    forge.init_keys()
    return forge


def _get(endpoint, arm, token):
    """A bearer GET of the one object every arm carries."""
    return requests.get(f"http://{HOST}:{endpoint.port}/{arm}/pub/seed.txt",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=30)


def _code(resp):
    """The <Code> of an S3 XML error, or None when the body is not S3 XML."""
    m = re.search(r"<Code>([^<]+)</Code>", resp.text)
    return m.group(1) if m else None


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _s3_t(tmp_path, knobs):
    """`nginx -t` over one http location carrying `knobs`. Never boots."""
    return _parse_fail(tmp_path, "nginx_rl_http.conf", _http_values(knobs))


def _stream_t(tmp_path, knobs):
    return _parse_fail(tmp_path, "nginx_rl_stream.conf", _stream_values(knobs, ""))


def _token_knobs(jwks, extra=""):
    # issuer + audience ride along: the unified token surface (W4) validates
    # jwks ⇒ issuer + audience once for every HTTP plane, so a knob block
    # without them dies on THAT refusal instead of the one under test.
    return ("            brix_s3_token on;\n"
            f"            brix_token_jwks {jwks};\n"
            f'            brix_token_issuer "{ISSUER}";\n'
            f'            brix_token_audience "{AUDIENCE}";\n'
            f"{extra}")


# --------------------------------------------------------------------------- #
# §A  The control arm: the four locations are one export with one variable.    #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheControlArm:

    @pytest.mark.parametrize("arm", SKEW_ARMS)
    def test_a_live_token_is_served_by_every_arm(self, s3token, arm):
        """Every skew arm serves a token that is nowhere near its deadline.

        The arms differ in one directive, and this is the assertion that says
        so: with an hour of validity left, the skew cannot matter, and any
        difference between the arms here would mean a later difference is not
        attributable to the knob.
        """
        endpoint, forge_a, _ = s3token
        resp = _get(endpoint, arm, forge_a.generate())
        assert resp.status_code == 200, (arm, resp.status_code, resp.text)
        assert resp.content == SEED, arm

    def test_the_fourth_arm_serves_its_own_anchors_token(self, s3token):
        """/keyb/ is the same export over a different JWKS, and it works.

        Without this the §E refusals would be consistent with /keyb/ simply
        being broken.
        """
        endpoint, _, forge_b = s3token
        resp = _get(endpoint, "keyb", forge_b.generate())
        assert resp.status_code == 200, (resp.status_code, resp.text)
        assert resp.content == SEED


# --------------------------------------------------------------------------- #
# §B  The skew widens exp by exactly the configured number of seconds.         #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheGraceIsTheConfiguredNumber:

    def test_a_token_just_past_expiry_is_refused_where_there_is_no_grace(
            self, s3token):
        """skew 0 means exact expiry: 30 seconds dead is dead."""
        endpoint, forge_a, _ = s3token
        resp = _get(endpoint, "skew0", forge_a.temporal(-30))
        assert resp.status_code == 403, (resp.status_code, resp.text)
        assert _code(resp) == "AccessDenied", resp.text
        assert "bearer token validation failed" in resp.text, resp.text

    def test_the_same_token_is_served_where_the_default_grace_covers_it(
            self, s3token):
        """THE differential: one token string, two arms, two verdicts.

        The token is minted once and presented to both arms, so nothing about
        the token can explain the disagreement — 30 < 60 can, and the arms
        differ in nothing but that 60 (which /skewdef/ does not even write:
        it is the merge default at module_merge.c:132).
        """
        endpoint, forge_a, _ = s3token
        token = forge_a.temporal(-30)
        refused = _get(endpoint, "skew0", token)
        served = _get(endpoint, "skewdef", token)
        assert refused.status_code == 403, (refused.status_code, refused.text)
        assert served.status_code == 200, (served.status_code, served.text)
        assert served.content == SEED

    def test_the_grace_is_a_bound_and_not_an_open_door(self, s3token):
        """Twice the default is past the default, and the same arm refuses it.

        Together with the previous test this pins the knob as a *number*: the
        default arm serves 30 seconds of decay and refuses 120, so it is not
        "expired tokens are tolerated" but "expired by less than the skew".
        """
        endpoint, forge_a, _ = s3token
        token = forge_a.temporal(-(DEFAULT_SKEW * 2))
        refused = _get(endpoint, "skewdef", token)
        served = _get(endpoint, "skewwide", token)
        assert refused.status_code == 403, (refused.status_code, refused.text)
        assert _code(refused) == "AccessDenied", refused.text
        assert served.status_code == 200, (served.status_code, served.text)

    def test_the_expiry_refusal_is_attributed_to_the_clock(self, s3token):
        """The log names exp, now and the skew that failed to cover the gap.

        An operator reading a 403 needs to tell "your token is old" from "your
        token is forged"; validate.c:329-333 says which, and this pins that the
        line survives to the instance log at the configured level.
        """
        endpoint, forge_a, _ = s3token
        assert _get(endpoint, "skew0", forge_a.temporal(-30)).status_code == 403
        log = _errlog(endpoint)
        assert "token expired at" in log, log[-4000:]
        assert "skew=0" in log, log[-4000:]


# --------------------------------------------------------------------------- #
# §C  DEFECT CANDIDATE #50 — two of three planes bound the skew.               #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheUnboundedSkew:

    def test_the_root_plane_refuses_a_skew_over_five_minutes(self, tmp_path):
        rc, out = _stream_t(tmp_path,
                            f"        brix_token_clock_skew {OVER_BOUND};\n")
        assert rc != 0, out
        assert f"brix_token_clock_skew is capped at {TWIN_BOUND}s" in out, out

    def test_the_webdav_plane_refuses_the_same_number(self, tmp_path):
        rc, out = _s3_t(tmp_path,
                        f"            brix_token_clock_skew {OVER_BOUND};\n")
        assert rc != 0, out
        assert f"brix_token_clock_skew is capped at {TWIN_BOUND}s" in out, out

    def test_the_s3_plane_refuses_it_too(self, tmp_path, anchor):
        """DEFECT CANDIDATE #50 FIXED: the S3 plane shares the unified clamp —
        the same number, the same file, the same location, the same refusal."""
        rc, out = _s3_t(tmp_path, _token_knobs(
            anchor.jwks_path,
            f"            brix_token_clock_skew {OVER_BOUND};\n"))
        assert rc != 0, DEFECT50 + "\n" + out
        assert f"brix_token_clock_skew is capped at {TWIN_BOUND}s" in out, out

    def test_the_widest_legal_grace_is_still_a_bound(self, s3token):
        """A token twenty-five minutes dead is refused even at the widest arm.

        1500 seconds is five times the clamp — no configurable arm may serve
        it.  A 250-second decay sits inside /skewwide/'s 300 and outside
        /skewdef/'s 60, so the wide arm is live and still a bound.
        """
        endpoint, forge_a, _ = s3token
        long_dead = forge_a.temporal(-1500)
        assert _get(endpoint, "skewdef", long_dead).status_code == 403
        assert _get(endpoint, "skewwide", long_dead).status_code == 403, DEFECT50
        just_dead = forge_a.temporal(-250)
        assert _get(endpoint, "skewdef", just_dead).status_code == 403
        served = _get(endpoint, "skewwide", just_dead)
        assert served.status_code == 200, (served.status_code, served.text)
        assert served.content == SEED

    def test_a_negative_skew_is_refused_at_parse_time(self, tmp_path, anchor):
        """The lower half of the missing bound is enforced by ngx_atoi.

        `-1` never reaches the merge: ngx_conf_set_num_slot's ngx_atoi returns
        NGX_ERROR on a leading minus.  Worth pinning because it is the reason
        the missing check is only half a hole — a skew cannot be negative, only
        unboundedly large.
        """
        rc, out = _s3_t(tmp_path, _token_knobs(
            anchor.jwks_path,
            "            brix_token_clock_skew -1;\n"))
        assert rc != 0, out
        assert "invalid value" in out, out


# --------------------------------------------------------------------------- #
# §D  The widening is one-sided: nbf is compared against the bare clock.       #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheWindowIsOneSided:

    def test_a_not_yet_valid_token_is_refused_however_wide_the_grace(
            self, s3token):
        """SECURITY-NEGATIVE.  1800 seconds of grace admits nothing early.

        The arm carrying the widest skew in the file is handed a token whose
        nbf is five minutes in the future and an hour of validity after that.
        If the skew were applied symmetrically this would be served; it is not,
        because token_check_time_window() adds the skew to exp only and tests
        nbf against time(NULL) directly (validate.c:337).  A tolerance for a
        lagging clock must never become a licence to pre-date a credential.
        """
        endpoint, forge_a, _ = s3token
        token = forge_a.temporal(3600, nbf_delta=300)
        for arm in SKEW_ARMS:
            resp = _get(endpoint, arm, token)
            assert resp.status_code == 403, (arm, resp.status_code, resp.text)
            assert _code(resp) == "AccessDenied", (arm, resp.text)

    def test_the_refusal_names_the_nbf_and_not_the_expiry(self, s3token):
        """The two halves of the window fail with two different log lines."""
        endpoint, forge_a, _ = s3token
        assert _get(endpoint, "skewwide",
                    forge_a.temporal(3600, nbf_delta=300)).status_code == 403
        log = _errlog(endpoint)
        assert "token not yet valid (nbf=" in log, log[-4000:]
        assert "token expired at" not in log, log[-4000:]


# --------------------------------------------------------------------------- #
# §E  brix_token_jwks names a trust anchor, and the name is load-bearing.   #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheJwksSelectsTheAnchor:

    def test_an_arm_refuses_the_other_anchors_token(self, s3token):
        """SECURITY-NEGATIVE.  Same issuer, same audience, same kid, other key.

        Every claim the verifier compares against config is identical between
        the two forges, and both JWKS files announce `test-key-1`, so the key
        lookup succeeds and the signature check is what refuses.  A verifier
        that trusted the kid, or that pooled every JWKS loaded anywhere in the
        configuration, would serve this.
        """
        endpoint, _, forge_b = s3token
        for arm in SKEW_ARMS:
            resp = _get(endpoint, arm, forge_b.generate())
            assert resp.status_code == 403, (arm, resp.status_code, resp.text)
            assert _code(resp) == "AccessDenied", (arm, resp.text)

    def test_the_refusal_runs_in_the_other_direction_too(self, s3token):
        """Neither anchor is privileged: /keyb/ refuses forge A the same way.

        One-directional trust would be explicable by the second JWKS never
        loading at all; both directions can only be two anchors.
        """
        endpoint, forge_a, _ = s3token
        resp = _get(endpoint, "keyb", forge_a.generate())
        assert resp.status_code == 403, (resp.status_code, resp.text)
        assert _code(resp) == "AccessDenied", resp.text

    def test_the_anchor_is_checked_before_the_clock_is_forgiving(self, s3token):
        """SECURITY-NEGATIVE.  A wide skew never softens the signature check.

        The widest arm is handed a live, well-formed, correctly-audienced token
        from the wrong anchor.  Nothing about it is expired, so a gate that
        ordered its checks badly could reach the skew and stop there.
        """
        endpoint, _, forge_b = s3token
        resp = _get(endpoint, "skewwide", forge_b.generate())
        assert resp.status_code == 403, (resp.status_code, resp.text)


# --------------------------------------------------------------------------- #
# §F  The gate will not start misconfigured (config tier, tmp_path only).      #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheGateRefusesToStartMisconfigured:

    def test_the_token_gate_will_not_start_without_a_jwks(self, tmp_path):
        """module_merge.c:134 — enabling the gate with no anchor is fatal.

        The alternative would be an export advertising token auth that trusts
        nothing and therefore refuses everyone, which reads as an outage rather
        than as the configuration error it is.
        """
        rc, out = _s3_t(tmp_path, "            brix_s3_token on;\n")
        assert rc != 0, out
        assert ("brix_s3_token: brix_token_jwks is required when "
                "brix_s3_token is on") in out, out

    def test_a_jwks_with_no_usable_keys_is_refused(self, tmp_path):
        """module_merge.c:147 — a well-formed but empty key set is not usable."""
        jwks = tmp_path / "empty.json"
        jwks.write_text('{"keys": []}\n', encoding="utf-8")
        rc, out = _s3_t(tmp_path, _token_knobs(jwks))
        assert rc != 0, out
        assert f'brix_token_jwks: no usable keys in "{jwks}"' in out, out

    def test_a_jwks_path_that_does_not_exist_is_refused(self, tmp_path):
        """The typo is caught even earlier: the unified surface stats the path
        at parse time and names the file, before any key parsing runs."""
        missing = tmp_path / "not-there.json"
        rc, out = _s3_t(tmp_path, _token_knobs(missing))
        assert rc != 0, out
        assert f'brix_token_jwks path "{missing}" is not accessible' in out, out

    def test_the_jwks_is_only_required_once_the_gate_is_on(self, tmp_path,
                                                           anchor):
        """SUCCESS PATH.  The refusals above are the gate, not the directive.

        A JWKS named on an export whose token gate is off must not be a parse
        error — the check is `token_enable && !token_jwks.len`, and this is the
        assertion that keeps it from drifting into an unconditional one.
        """
        rc, out = _s3_t(tmp_path,
                        f"            brix_token_jwks {anchor.jwks_path};\n"
                        f'            brix_token_issuer "{ISSUER}";\n'
                        f'            brix_token_audience "{AUDIENCE}";\n')
        assert rc == 0, out


# --------------------------------------------------------------------------- #
# §G  Source pins — the asymmetry #50 rests on, read off the C.                #
# --------------------------------------------------------------------------- #

ROOT = Path(__file__).resolve().parents[1]


def _source(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_the_skew_clamp_is_shared_not_copied():
    """DEFECT CANDIDATE #50, pinned at the source after the unification.

    The [0, 300] clamp lives ONCE for the HTTP planes (shared_conf_merge.h,
    behind the shared preamble every protocol merges through) plus its stream
    twin, and the S3 module no longer registers a skew slot of its own — so a
    plane cannot drift back to an unbounded copy.
    """
    assert "is capped at 300s" in _source(
        "src/core/config/shared_conf_merge.h")
    assert "is capped at 300s" in _source(
        "src/core/config/server_conf_merge_security.c")
    assert 'ngx_string("brix_s3_token_clock_skew")' not in _source(
        "src/protocols/s3/module.c")
    assert "brix_token_clock_skew moved to http_common.c" in _source(
        "src/protocols/s3/module.c")
