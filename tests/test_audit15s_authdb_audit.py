"""
test_audit15s_authdb_audit.py — §Method at VALUE granularity, first file
(docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

WHY THIS FILE EXISTS

Steps 1 and 2 of the audit's method count directive NAMES.  Tranche 14 sharpened
step 2 from "does the name appear?" to "does a test's verdict change when the
value changes?", which closed the last thirteen names.  Both questions share a
blind spot that no tranche has ever measured: for an ENUM-valued directive they
are answered by ONE of its tokens.  Write `brix_acc_audit all` once and the
directive is scored covered forever, however many other values the table holds.

Re-running step 1 per (directive, value) pair over the 36 `ngx_conf_enum_t`
tables in src/ gives 93 pairs, of which 45 are written nowhere in the coverage
corpus (tests/, k8s-tests/, deploy/, contrib/, docker/, examples/).  Excluding
the pairs that are written through a template placeholder rather than as a
literal — brix_webdav_signing_policy's on/off/require and brix_webdav_crl_mode's
off/try/require are all driven by wlcg_fleet.WlcgInstance, brix_cache_verify's
three by test_cache_verify_require, brix_seccomp audit by test_seccomp_enforce —
leaves a real backlog of about two dozen.

`brix_acc_audit` is its archetype and the first one taken.  The name occurs
in eleven templates plus the k8s remote suite; every one of them writes `all`.
Its other three values have never been written anywhere, and one of them —
`none` — is also the merge default, so the code path that runs when an operator
leaves the directive out has never been exercised either.

WHAT THE VALUE SELECTS

brix_acc_audit() (auth/authz/acc/audit.c:44-68) reads the merged value as a
two-bit mask, 1 = log denials and 2 = log grants, and returns before formatting
anything when the decision's bit is clear.  The four tokens are therefore the
four subsets of a two-element set, and each is observable as the PRESENCE or
ABSENCE of a NOTICE line:

    xrootd authz: <id>@<host> grant|deny <op> "<path>"

Eight WebDAV locations on one listener differ in nothing but that token (and, in
the nested pair, in whether they write it at all).  Each is driven with the same
two requests — one path the authdb grants, one it does not — and the whole truth
table is read out of the single error log the single worker writes:

    location        token       grant line   deny line
    /none/          none            -            -
    /deny/          deny            -           YES
    /grant/         grant          YES           -
    /all/           all            YES          YES
    /default/       (absent)        -            -
    /outer/         all            YES          YES
    /outer/loud/    (absent)       YES          YES     <- inherits the parent
    /outer/quiet/   none            -            -      <- overrides the parent

WHAT THE TABLE ESTABLISHES

- The token selects the SUBSET of decisions that reach the log, and nothing
  else.  All eight locations answer 200 on the granted path and 403 on the
  refused one; a location logging nothing enforces exactly as hard as the one
  logging both.  `grant` in particular is a silent-deny configuration: the
  refusal happens, the operator never sees it.
- The merge default is `none`, not `all`.  /default/ writes no directive and is
  otherwise identical to /all/, and it is silent — so an export that turns the
  xrdacc engine on without naming an audit level gets no authorization trail.
  Nothing in the corpus establishes this today because every template writes the
  directive.
- On the HTTP plane the directive is NGX_HTTP_LOC_CONF only (module_commands.c
  :91-93): it is refused in `server {}` and in `http {}`, so the merge from
  `prev` at config.c:181-182 runs between NESTED locations and nowhere else.
  /outer/loud/ (writes nothing, inherits `all`) and /outer/quiet/ (writes
  `none`, overrides `all`) are the two halves of that one inheritance path.
- The op field is real, not a constant: the same location logs `read` for a GET
  and a HEAD, `create` for a PUT, `delete` for a DELETE and `readdir` for a
  PROPFIND, because webdav_method_aop() (access.c:32-58) maps the method before
  the engine ever sees it.
- The untrusted fields are sanitised.  The path comes off the wire, so a quote
  is escaped and every byte below 0x20 or at/above 0x7f becomes `?` — one audit
  line per decision no matter what the client asks for.

A FACT PINNED RATHER THAN A DEFECT — OPTIONS IS EXEMPT

webdav_method_aop() maps NGX_HTTP_OPTIONS to BRIX_AOP_ANY, but the caller never
reaches it: access_options_preflight() (access.c:221-232) short-circuits OPTIONS
with NGX_OK before webdav_acc_check() runs, and its comment says so ("OPTIONS is
a capability query, never rejected here").  So an OPTIONS on a path the authdb
grants nothing on answers 200 and writes no audit line even under `all`.  That
is deliberate and it is the CORS preflight contract, but it is worth an
assertion in both directions: the exemption is pinned here so that wiring the
acc tier into OPTIONS — or removing the now-unreachable BRIX_AOP_ANY arm — is a
visible change rather than a silent one.

No defect candidates.  The directive does exactly what its four values say, on
every plane and at every tier probed here.
"""

import os
import re
from pathlib import Path

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
from _test_phase25_ratelimit_helpers import _http_values, _parse_fail

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15s-auditmodes")]

# The five top-level faces, then the nested pair.  Each entry is
# (location, logs-grants, logs-denials).
FACES = (
    ("none",        False, False),
    ("deny",        False, True),
    ("grant",       True,  False),
    ("all",         True,  True),
    ("default",     False, False),
    ("outer",       True,  True),
    ("outer/loud",  True,  True),
    ("outer/quiet", False, False),
)
PLANES = tuple(face for face, _g, _d in FACES)

GRANTED = "granted/obj.bin"     # the authdb gives `rl` on the parent directory
REFUSED = "refused/obj.bin"     # no rule matches: fail-closed
PAYLOAD = b"audit15s-authdb-audit-payload\n"

# `rl` is read+lookup and nothing else, so every write verb is denied on BOTH
# paths — which is what lets the op field be probed without changing any state.
AUTHDB_PRIVS = "rl"

_LINE = re.compile(
    r'xrootd authz: (?P<id>[^@]*)@(?P<host>\S+) '
    r'(?P<verdict>grant|deny) (?P<op>\S+) "(?P<path>[^"]*)"')


# ── the block ───────────────────────────────────────────────────────────── #

@pytest.fixture()
def auditmodes(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    export = tmp_path / "export"
    for plane in PLANES:
        for leaf in ("granted", "refused"):
            (export / plane / leaf).mkdir(parents=True)
            (export / plane / leaf / "obj.bin").write_bytes(PAYLOAD)

    # ONE `u *` record: acc_record_named() refuses a second one for the same id
    # ("duplicate rule for id"), so the eight granted prefixes are eight
    # (path, privs) pairs on a single line — the XrdAcc authfile form.
    authdb = tmp_path / "authdb"
    authdb.write_text("u * " + " ".join(
        f"/{plane}/granted {AUTHDB_PRIVS}" for plane in PLANES) + "\n")

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15s-auditmodes",
        template="nginx_audit15s_auditmodes.conf",
        protocol="webdav",
        data_root=str(export),
        template_values={"BIND_HOST": BIND_HOST,
                         "EXPORT_ROOT": str(export),
                         "AUTHDB": str(authdb)},
        reason="audit-15s: the authorization audit sink's level"))
    return ep


def _req(ep, method, plane, leaf, **kwargs):
    kwargs.setdefault("timeout", 30)
    return requests.request(
        method, f"http://{HOST}:{ep.port}/{plane}/{leaf}", **kwargs)


def _get(ep, plane, leaf):
    return _req(ep, "GET", plane, leaf)


def _errlog(ep):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except OSError:
        return "(error log unavailable)"


def _audit(ep):
    """Every audit line the instance has written so far, parsed."""
    return [m.groupdict() for m in _LINE.finditer(_errlog(ep))]


def _for(lines, path):
    """The audit lines that judged one exact path."""
    return [ln for ln in lines if ln["path"] == path]


def _drive(ep, plane):
    """The one pair of requests every face is judged on."""
    return _get(ep, plane, GRANTED), _get(ep, plane, REFUSED)


def _verdicts(ep, plane):
    """The (grant?, deny?) pair this face actually logged for that request pair."""
    _drive(ep, plane)
    lines = _audit(ep)
    grants = _for(lines, f"/{plane}/{GRANTED}")
    denials = _for(lines, f"/{plane}/{REFUSED}")
    return grants, denials


# --------------------------------------------------------------------------- #
# §A — the truth table: the token selects which decisions are logged.          #
# --------------------------------------------------------------------------- #

class TestTheTokenSelectsTheSubset:
    """Eight faces differing only in the token, one request pair each."""

    @pytest.mark.parametrize("plane,logs_grant,logs_deny", FACES,
                             ids=[f.replace("/", "-") for f, _g, _d in FACES])
    def test_the_token_selects_which_decisions_reach_the_log(
            self, auditmodes, plane, logs_grant, logs_deny):
        """The whole eight-row table, one row per case: `none` logs neither,
        `deny` only the refusal, `grant` only the success, `all` both — and the
        absent directive behaves as `none` because that is the merge default."""
        grants, denials = _verdicts(auditmodes, plane)

        assert bool(grants) == logs_grant, (
            f"/{plane}/ (grant bit {'set' if logs_grant else 'clear'}) logged "
            f"{len(grants)} grant lines:\n{_errlog(auditmodes)[-3000:]}")
        assert bool(denials) == logs_deny, (
            f"/{plane}/ (deny bit {'set' if logs_deny else 'clear'}) logged "
            f"{len(denials)} deny lines:\n{_errlog(auditmodes)[-3000:]}")

        for line in grants:
            assert line["verdict"] == "grant"
        for line in denials:
            assert line["verdict"] == "deny"

    @pytest.mark.parametrize("plane", PLANES,
                             ids=[p.replace("/", "-") for p in PLANES])
    def test_the_token_never_changes_the_status_code(self, auditmodes, plane):
        """Auditing observes; it does not decide.  Every face answers 200 on
        the granted path and 403 on the one no rule matches, whichever subset of
        those two decisions it happens to write down."""
        granted, refused = _drive(auditmodes, plane)
        assert granted.status_code == 200, (
            f"/{plane}/{GRANTED}: {granted.status_code}\n"
            f"{_errlog(auditmodes)[-2000:]}")
        assert granted.content == PAYLOAD
        assert refused.status_code == 403, (
            f"/{plane}/{REFUSED}: {refused.status_code}\n"
            f"{_errlog(auditmodes)[-2000:]}")

    def test_the_grant_only_face_is_a_silent_deny(self, auditmodes):
        """Security-negative.  `grant` is the configuration an operator is most
        likely to get wrong: the refusal still happens, and nothing records it.
        /grant/ must answer 403 on the refused path while writing no line for
        it — and must not borrow /deny/'s line for the same-named leaf."""
        _drive(auditmodes, "grant")
        _drive(auditmodes, "deny")

        lines = _audit(auditmodes)
        assert _for(lines, f"/grant/{REFUSED}") == [], (
            "brix_acc_audit grant logged a denial:\n"
            f"{_errlog(auditmodes)[-3000:]}")
        assert len(_for(lines, f"/deny/{REFUSED}")) == 1, (
            "the deny face must still log its own refusal — otherwise the "
            "assertion above proves only that the engine went quiet")
        assert _get(auditmodes, "grant", REFUSED).status_code == 403

    def test_the_absent_directive_is_silence_not_all(self, auditmodes):
        """/default/ writes no directive at all and is otherwise identical to
        /all/.  It must be silent: the merge default at config.c:181-182 is
        BRIX_AUTHDB_AUDIT_NONE, so turning the xrdacc engine on without naming a
        level yields no authorization trail whatsoever."""
        _drive(auditmodes, "default")
        _drive(auditmodes, "all")

        lines = _audit(auditmodes)
        assert [ln for ln in lines if ln["path"].startswith("/default/")] == [], (
            "the merge default logged something:\n"
            f"{_errlog(auditmodes)[-3000:]}")
        assert len([ln for ln in lines if ln["path"].startswith("/all/")]) == 2, (
            "the /all/ control must log both decisions, or the silence above "
            "says nothing about the default")


# --------------------------------------------------------------------------- #
# §B — the one inheritance path the directive has on this plane.               #
# --------------------------------------------------------------------------- #

class TestTheNestedPair:
    """NGX_HTTP_LOC_CONF only, so `prev` is the enclosing LOCATION."""

    def test_a_nested_location_inherits_the_parent_level(self, auditmodes):
        """/outer/loud/ writes nothing.  It must inherit /outer/'s `all` rather
        than fall to the NONE merge default — the only way a value written in
        one block reaches another on this plane."""
        grants, denials = _verdicts(auditmodes, "outer/loud")
        assert grants and denials, (
            "the nested location fell to the default instead of inheriting:\n"
            f"{_errlog(auditmodes)[-3000:]}")

    def test_a_nested_location_overrides_the_parent_level(self, auditmodes):
        """/outer/quiet/ writes `none` inside a parent that writes `all`.  The
        child replaces the parent's value; it does not OR with it."""
        grants, denials = _verdicts(auditmodes, "outer/quiet")
        assert not grants and not denials, (
            "the nested `none` did not override the parent's `all`:\n"
            f"{_errlog(auditmodes)[-3000:]}")

    def test_the_parent_still_logs_both(self, auditmodes):
        """Attribution control for the two above: a child that inherits and a
        child that overrides are only meaningful if the parent itself is loud."""
        grants, denials = _verdicts(auditmodes, "outer")
        assert grants and denials
        assert grants[0]["path"] == f"/outer/{GRANTED}"
        assert denials[0]["path"] == f"/outer/{REFUSED}"

    def test_the_three_nested_faces_are_judged_independently(self, auditmodes):
        """One request pair to each of the three, then one read of the log: the
        parent and the loud child contribute two lines each and the quiet child
        none, so six lines carrying three distinct path prefixes."""
        for plane in ("outer", "outer/loud", "outer/quiet"):
            _drive(auditmodes, plane)

        lines = [ln for ln in _audit(auditmodes)
                 if ln["path"].startswith("/outer/")]
        def _assert_test_the_three_nested_faces_are_judged_independently_1():
            assert len(lines) == 4, (
                f"expected 4 lines from the nested trio, got {len(lines)}:\n"
                f"{_errlog(auditmodes)[-4000:]}")
            assert {ln["path"] for ln in lines} == {
                f"/outer/{GRANTED}", f"/outer/{REFUSED}",
                f"/outer/loud/{GRANTED}", f"/outer/loud/{REFUSED}"}

        _assert_test_the_three_nested_faces_are_judged_independently_1()


# --------------------------------------------------------------------------- #
# §C — the line's fields are read off the request, not fixed.                  #
# --------------------------------------------------------------------------- #

class TestTheLineDescribesTheDecision:

    @pytest.mark.parametrize("method,leaf,op", [
        ("GET",      REFUSED,          "read"),
        ("HEAD",     REFUSED,          "read"),
        ("PUT",      "granted/new.bin", "create"),
        ("DELETE",   GRANTED,          "delete"),
        ("PROPFIND", "refused/",       "readdir"),
    ])
    def test_the_op_field_follows_the_method(self, auditmodes, method, leaf, op):
        """webdav_method_aop() maps the method to an XrdAcc operation before the
        engine runs, and the audit line reports that operation.  The authdb
        grants `rl` only, so every write verb here is denied on both paths and
        nothing on disk changes."""
        _req(auditmodes, method, "all", leaf,
             data=b"x" if method == "PUT" else None,
             headers={"Depth": "1"} if method == "PROPFIND" else None)

        lines = _for(_audit(auditmodes), f"/all/{leaf}")
        assert lines, (f"{method} /all/{leaf} wrote no audit line:\n"
                       f"{_errlog(auditmodes)[-3000:]}")
        assert lines[-1]["op"] == op, (
            f"{method} was audited as {lines[-1]['op']!r}, expected {op!r}")
        assert lines[-1]["verdict"] == "deny"

    def test_a_write_is_denied_on_the_readable_path_too(self, auditmodes):
        """`rl` is read+lookup and carries no `w`, so the PUT above is refused
        on a prefix the same principal may READ.  Without this the op-name case
        would be indistinguishable from a plain no-rule refusal."""
        assert _get(auditmodes, "all", GRANTED).status_code == 200
        r = _req(auditmodes, "PUT", "all", "granted/new.bin", data=b"x")
        assert r.status_code == 403, (
            f"PUT under `rl` returned {r.status_code}\n"
            f"{_errlog(auditmodes)[-2000:]}")
        assert not (Path(auditmodes.prefix).parent / "new.bin").exists()

    def test_the_line_names_the_path_that_was_judged(self, auditmodes):
        """The path field is r->uri — the LOGICAL namespace path the rule was
        matched against, complete with the location prefix, not the backing
        filesystem path the request would have resolved to."""
        _get(auditmodes, "all", REFUSED)
        lines = _for(_audit(auditmodes), f"/all/{REFUSED}")
        assert lines, _errlog(auditmodes)[-2000:]
        assert lines[-1]["path"] == f"/all/{REFUSED}"

    def test_the_line_carries_the_peer_address(self, auditmodes):
        """The host field is the connection's address text, which is what `h`
        rules in an authdb are matched against."""
        _get(auditmodes, "all", REFUSED)
        lines = _for(_audit(auditmodes), f"/all/{REFUSED}")
        assert lines[-1]["host"] == BIND_HOST, (
            f"host field {lines[-1]['host']!r} != {BIND_HOST!r}")

    def test_the_anonymous_principal_logs_an_empty_id(self, auditmodes):
        """`brix_webdav_auth none` leaves no identity, so the entity is built
        with an empty name and the line begins at the `@`.  That is the shape
        the `u *` default record authorizes, and reading it back is how an
        operator tells an anonymous decision from a named one."""
        _get(auditmodes, "all", REFUSED)
        lines = _for(_audit(auditmodes), f"/all/{REFUSED}")
        assert lines[-1]["id"] == "", (
            f"anonymous request logged id {lines[-1]['id']!r}")


# --------------------------------------------------------------------------- #
# §D — the untrusted fields cannot forge a line.                               #
# --------------------------------------------------------------------------- #

class TestTheLineCannotBeInjected:
    """Security-negative: the path is client-controlled and reaches a log."""

    def test_a_quote_in_the_path_is_escaped(self, auditmodes):
        """A `"` would otherwise close the quoted path field early.  It is
        emitted as `\\"`, so the field still spans the whole path."""
        _get(auditmodes, "all", "refused/a%22b")
        log = _errlog(auditmodes)
        assert 'deny read "/all/refused/a\\"b"' in log, (
            f"quote not escaped:\n{log[-2000:]}")

    def test_a_control_byte_never_reaches_the_log(self, auditmodes):
        """A `%0A` decodes into r->uri as a real newline, which would split one
        audit line into two and let a client forge the second.  Every byte below
        0x20 is replaced by `?` (audit.c:34-35)."""
        _get(auditmodes, "all", "refused/a%0Ab")
        log = _errlog(auditmodes)
        assert 'deny read "/all/refused/a?b"' in log, (
            f"control byte survived:\n{log[-2000:]}")
        assert "\nxrootd authz" not in log.replace("\nxrootd authz: @", ""), (
            "an audit line was split")

    def test_a_high_byte_is_replaced_per_byte(self, auditmodes):
        """The sanitiser works on BYTES, not code points: a two-byte UTF-8
        sequence becomes two `?`, so the escaped length is a function of the
        wire path and never of its decoding."""
        _get(auditmodes, "all", "refused/a%C3%A9b")
        assert 'deny read "/all/refused/a??b"' in _errlog(auditmodes)

    def test_the_forged_path_is_still_refused(self, auditmodes):
        """The sanitiser is about the log, not the verdict: all three paths
        above match no rule and are refused exactly as the plain one is."""
        for leaf in ("refused/a%22b", "refused/a%0Ab", "refused/a%C3%A9b"):
            r = _get(auditmodes, "all", leaf)
            assert r.status_code == 403, f"{leaf}: {r.status_code}"


# --------------------------------------------------------------------------- #
# §E — OPTIONS is exempt from the tier, by design.                             #
# --------------------------------------------------------------------------- #

class TestOptionsIsExempt:

    def test_options_answers_without_consulting_the_engine(self, auditmodes):
        """access_options_preflight() returns NGX_OK before webdav_acc_check()
        runs, so an OPTIONS on a path the authdb grants nothing on succeeds and
        is audited nowhere — even under `all`.  Pinned in both directions: the
        BRIX_AOP_ANY arm of webdav_method_aop() is unreachable today, and wiring
        OPTIONS into the tier would break exactly this test."""
        r = _req(auditmodes, "OPTIONS", "all", REFUSED)
        assert r.status_code == 200, (
            f"OPTIONS on a refused path: {r.status_code}\n"
            f"{_errlog(auditmodes)[-2000:]}")
        assert _for(_audit(auditmodes), f"/all/{REFUSED}") == [], (
            "OPTIONS reached the audit sink:\n"
            f"{_errlog(auditmodes)[-3000:]}")

    def test_the_same_path_under_get_is_refused_and_logged(self, auditmodes):
        """Attribution control: the exemption is a property of the METHOD, not
        of the path or of the face."""
        assert _req(auditmodes, "OPTIONS", "all", REFUSED).status_code == 200
        assert _get(auditmodes, "all", REFUSED).status_code == 403
        assert len(_for(_audit(auditmodes), f"/all/{REFUSED}")) == 1


# --------------------------------------------------------------------------- #
# §F — the parse tier.                                                         #
# --------------------------------------------------------------------------- #

def _knob(value):
    return f"            brix_acc_audit {value};\n"


class TestTheParseTier:
    """Every token the table holds is accepted; nothing else is."""

    @pytest.mark.parametrize("token", ["none", "deny", "grant", "all"])
    def test_each_token_in_the_table_is_accepted(self, tmp_path, token):
        rc, out = _parse_fail(tmp_path, "nginx_rl_http.conf",
                              _http_values(_knob(token)))
        assert rc == 0, f"brix_acc_audit {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["bogus", "deny,grant", "1", '""'])
    def test_a_value_outside_the_table_is_refused(self, tmp_path, token):
        """brix_acc_http_set_enum() (module_acc_directives.c:98-113) walks the
        table and emits `invalid value` on a miss.  `deny,grant` is the mistake
        the bitmask invites — the mask is internal, the config surface is four
        names — and `1` is the raw value behind `deny`."""
        rc, out = _parse_fail(tmp_path, "nginx_rl_http.conf",
                              _http_values(_knob(token)))
        assert rc != 0, f"brix_acc_audit {token} parsed:\n{out}"
        assert "invalid value" in out, out

    def test_the_directive_needs_exactly_one_argument(self, tmp_path):
        rc, out = _parse_fail(tmp_path, "nginx_rl_http.conf",
                              _http_values("            brix_acc_audit;\n"))
        assert rc != 0 and "invalid number of arguments" in out, out

    def test_the_directive_is_accepted_server_wide(self, tmp_path):
        """phase-101 W2 widened the audit level to BRIX_HTTP_ALL_CONF: an
        operator sets it once at server (or http) scope and every location
        below inherits it — the pre-unification loc-only refusal is gone."""
        rc, out = _parse_fail(
            tmp_path, "nginx_rl_http.conf",
            _http_values("", extra_locations="        brix_acc_audit all;\n"))
        assert rc == 0, f"brix_acc_audit was refused in server {{}}:\n{out}"

    def test_the_directive_is_accepted_at_http_level(self, tmp_path):
        rc, out = _parse_fail(
            tmp_path, "nginx_rl_http.conf",
            _http_values("", http_extra="    brix_acc_audit all;"))
        assert rc == 0, f"brix_acc_audit was refused in http {{}}:\n{out}"
