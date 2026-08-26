"""
test_audit15j_zero_coverage_stragglers.py — §A, re-measured against today's
tree (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

The audit's §A is a MEASUREMENT, not a list: "a directive is covered if its
name appears anywhere in that corpus" (§Method step 2).  Nine tranches closed
the 95 names the measurement returned on 08-15 — but the measurement itself
decays, because the directive surface keeps growing.  Re-running §Method steps
1+2 against the tree as it stands puts the surface at **555** names (524 on
08-15) and returns **seven** with zero coverage of any kind, none of them on
the audit's list and none of them in `docs/03-configuration/directives.md`:

    brix_backend_token_audience_ok              brix_idmap_cache_ttl
    brix_backend_token_exchange_client_id       brix_idmap_forbidden_users
    brix_backend_token_exchange_client_secret   brix_idmap_broker_user
    brix_backend_passthrough_persist

§Method step 4 is the half that matters here — "the directive/config field has
a runtime consumer (not dead config)".  Applied to these seven it fails twice,
and the first failure is a security control that has never worked.

DEFECT CANDIDATE #34 (security, fail-open) — the backend audience gate cannot
be turned on.  `brix_backend_token_audience_ok` is declared ONLY in the common
module's table (`http_common.c:153`, writing
`ngx_http_brix_common_conf_t.common.backend_token_aud`).  The protocol modules
do not declare it; they receive unified values through
`brix_http_common_adopt()` -> `brix_shared_adopt_unified()`, which copies 53
fields one by one — and `backend_token_aud` is not one of them.  So the value
an operator writes lands in the common module's conf and stays there.  What
`brix_proto_deleg_gate_bearer()` reads (`deleg_wire.c:63`) is the WebDAV/S3/
root conf's copy, which is still NULL, and `brix_token_backend_aud_ok()` maps
NULL to "no gate configured — passthrough unrestricted" (aud_match.c:45).  The
gate is a permanent no-op.  That is precisely the failure aud_match.c's own
header says it was written to end: "Without this gate the directive was parsed
but never enforced — a silent fail-open (P90-70.9)."  The fail-open came back
one layer up, in the adopt list.

Four more fields have the same adopt gap — `backend_sss_keytab`,
`backend_sts_flavor`, `seccomp`, `verify_write` — but each is ALSO declared in
the stream plane's own tables, so for those the gap costs the http plane only
(`brix_verify_write on` in a WebDAV location cannot reach
`conf->common.verify_write`, which put_setup.c:347 reads).  `backend_token_aud`
is the one with no second declaration anywhere: it is unreachable on both
planes.  test_no_unified_field_is_parsed_without_being_adopted is written as a
class guard so a sixth omission is caught the day it is added.

DEFECT CANDIDATE #35 (dead config) — `brix_backend_passthrough_persist` parses,
merges, and adopts, and nothing ever reads it.  Every mention in `src/ shared/
client/` is plumbing: the command entry, the struct field, the unset init, the
merge, and the BRIX_ADOPT_VAL line.  The documented behaviour ("permit spilling
a captured full proxy into the async stage journal owner dir", phase-70 §5.1)
is not implemented.  Same shape as the audit's existing #14
(`brix_cache_wt_stage()` has no callers at all).

WHAT IS OBSERVABLE, AND WHAT IS NOT.  A missing adopt has no diagnostic — it is
the absence of a copy — so the live half of #34 proves it the only way an
operator could: configure the gate, send a bearer the gate must refuse, and
watch nothing happen.  The refusal has a log line (aud_match.c:85, INFO), the
export runs at `error_log info`, and it never appears.  The control that stops
that silence from meaning "the token machinery is broken" is the front-door
audience pin, which rejects a wrong-`aud` token on the SAME export with 401.
So: the same directive name, on the same request, enforced at the front door
and inert at the back.

The three impersonation names are not defects — they are covered here because
nothing had ever parsed them, and pinned with the one behaviour that surprises:
they write a process-global (`lifecycle.c:42`, "one process-global settings
block") through setters that discard `conf` entirely, while their command
entries advertise `NGX_STREAM_SRV_CONF`.  The visible tell is that a duplicate
is accepted where every `ngx_conf_set_*_slot` directive would be refused.
"""

import os
import re
from pathlib import Path

import pytest
import requests

from _test_phase25_ratelimit_helpers import (
    _parse_fail,
    _http_values,
    _stream_values,
)
from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN
from utils.make_token import TokenIssuer

def _check_test_the_passthrough_persist_flag_is_never_read_1(readers):
    assert readers == [], (
        f"{DEFECT35} It is now referenced at {readers}.")

def _guard_test_the_passthrough_persist_flag_is_never_read_1(line, readers, rel, i):
    if "backend_passthrough_persist" in line:
        readers.append(f"{rel}:{i}")


pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15j-audgate")]

ROOT = Path(__file__).resolve().parents[1]

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK), reason=f"nginx not executable: {NGINX_BIN}")

WRONG_PLANE = "directive is not allowed here"

# The seven, with the smallest value each accepts.  Grouped by the plane that
# declares them: the backend four are BRIX_HTTP_ALL_CONF (http_common.c:61),
# the impersonation three are NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF
# (directives_tier.h:70-90).
HTTP_PLANE = {
    "brix_backend_token_audience_ok": "https://origin.example.test/",
    "brix_backend_token_exchange_client_id": "brix-gateway",
    "brix_backend_token_exchange_client_secret": "s3cr3t",
    "brix_backend_passthrough_persist": "on",
}
STREAM_PLANE = {
    "brix_idmap_cache_ttl": "300",
    "brix_idmap_forbidden_users": "root,daemon",
    "brix_idmap_broker_user": "brixbroker",
}
ALL_SEVEN = {**HTTP_PLANE, **STREAM_PLANE}

# TAKE1 in the source; the array directive is NGX_CONF_1MORE and is excluded
# from the two-argument and duplicate rejections on purpose (see their tests).
TAKE1 = [n for n in ALL_SEVEN if n != "brix_backend_token_audience_ok"]

DEFECT34 = (
    "DEFECT CANDIDATE #34 has been FIXED: brix_backend_token_audience_ok now "
    "reaches the protocol conf. Flip this expectation — the gate should refuse "
    "a bearer whose aud names neither the configured backend nor the WLCG "
    "any-endpoint wildcard, and say so in error.log.")
DEFECT35 = (
    "DEFECT CANDIDATE #35 has been FIXED: brix_backend_passthrough_persist now "
    "has a runtime reader. Flip this expectation and test what it does.")

# Front door and backend disagree on purpose: a token minted for THIS gateway
# is exactly what the gate exists to stop being replayed onward.
ISSUER = "https://test.example.com"
FRONT_AUD = "audit15j-gateway"
BACKEND_AUD = "https://origin.audit15j.example.test/"
WLCG_ANY = "https://wlcg.cern.ch/jwt/v1/any"

PAYLOAD = b"audit15j backend audience gate payload\n"


# --------------------------------------------------------------------------- #
# Parse tier — plane and grammar.                                             #
# --------------------------------------------------------------------------- #

def _prefix(path):
    path.mkdir(parents=True, exist_ok=True)
    return path


def _http_t(tmp_path, knobs):
    return _parse_fail(_prefix(tmp_path), "nginx_rl_http.conf",
                       _http_values(knobs, "", ""))


def _stream_t(tmp_path, knobs):
    return _parse_fail(_prefix(tmp_path), "nginx_rl_stream.conf",
                       _stream_values(knobs, ""))


def _own(tmp_path, name, knobs):
    return (_http_t if name in HTTP_PLANE else _stream_t)(tmp_path, knobs)


def _far(tmp_path, name, knobs):
    return (_stream_t if name in HTTP_PLANE else _http_t)(tmp_path, knobs)


def _line(name, value=None):
    return f"        {name}{'' if value is None else ' ' + value};\n"


@_needs_nginx
@pytest.mark.parametrize("name,value", sorted(ALL_SEVEN.items()))
def test_each_straggler_parses_on_the_plane_that_declares_it(
        tmp_path, name, value):
    """The control every rejection below is measured against."""
    rc, out = _own(tmp_path, name, _line(name, value))
    assert rc == 0, f"{name} was rejected on its own plane:\n{out}"


@_needs_nginx
@pytest.mark.parametrize("name,value", sorted(ALL_SEVEN.items()))
def test_each_straggler_is_refused_on_the_other_plane(tmp_path, name, value):
    """Plane exclusivity is a claim about the surface, and for the backend four
    it is the whole reason #34 bites: there is no stream-plane declaration to
    fall back on."""
    rc, out = _far(tmp_path, name, _line(name, value))
    assert rc != 0 and WRONG_PLANE in out, \
        f"{name} was accepted on the far plane (rc={rc}):\n{out}"
    assert name in out, out


@_needs_nginx
@pytest.mark.parametrize("name", sorted(ALL_SEVEN))
def test_no_straggler_accepts_zero_arguments(tmp_path, name):
    rc, out = _own(tmp_path, name, _line(name))
    assert rc != 0 and "invalid number of arguments" in out, \
        f"{name} accepted no argument at all (rc={rc}):\n{out}"


@_needs_nginx
@pytest.mark.parametrize("name", sorted(TAKE1))
def test_the_take1_stragglers_refuse_a_second_argument(tmp_path, name):
    rc, out = _own(tmp_path, name, _line(name, f"{ALL_SEVEN[name]} extra"))
    assert rc != 0 and "invalid number of arguments" in out, \
        f"{name} is documented TAKE1 but took two arguments (rc={rc}):\n{out}"


@_needs_nginx
def test_the_audience_allow_list_takes_many_and_is_not_a_duplicate(tmp_path):
    """The one 1MORE name: an allow-list must accept several audiences in one
    directive AND accumulate across repeats (ngx_conf_set_str_array_slot
    appends), so neither shape may be a parse error.  A regression to TAKE1
    would silently drop every audience but the first."""
    name = "brix_backend_token_audience_ok"
    rc, out = _http_t(tmp_path / "many",
                      _line(name, "https://a.example/ https://b.example/"))
    assert rc == 0, f"the allow-list refused three audiences:\n{out}"
    rc, out = _http_t(tmp_path / "twice",
                      _line(name, "https://a.example/") +
                      _line(name, "https://b.example/"))
    assert rc == 0, f"a second allow-list line was refused as a duplicate:\n{out}"


@_needs_nginx
def test_the_flag_straggler_refuses_a_non_flag_value(tmp_path):
    rc, out = _http_t(tmp_path, _line("brix_backend_passthrough_persist",
                                      "banana"))
    assert rc != 0 and "invalid value" in out, \
        f"a flag directive accepted a non-flag value (rc={rc}):\n{out}"


@_needs_nginx
@pytest.mark.parametrize("value", ["banana", "-5"])
def test_the_idmap_cache_ttl_refuses_a_non_positive_number(tmp_path, value):
    """Security-negative on a cache TTL: `brix_imp_conf_num` (lifecycle.c:120)
    refuses NGX_ERROR *and* n < 0, so a negative can never be stored and then
    reinterpreted as a huge unsigned lifetime by brix_idmap_init."""
    rc, out = _stream_t(tmp_path, _line("brix_idmap_cache_ttl", value))
    assert rc != 0 and "invalid number" in out, \
        f"brix_idmap_cache_ttl accepted {value!r} (rc={rc}):\n{out}"


@_needs_nginx
@pytest.mark.parametrize("name", sorted(STREAM_PLANE))
def test_the_impersonation_knobs_are_process_global_not_per_server(
        tmp_path, name):
    """Not a defect — lifecycle.c:6 says so outright ("one process-global
    settings block... at most one broker per nginx instance") — but the command
    entries still advertise NGX_STREAM_SRV_CONF, and the setters discard `conf`
    (`(void) conf;`, lifecycle.c:101/125) and write the file-static
    `imp_settings`.  The visible tell is that a repeat is accepted where a
    struct-slot directive would be "directive is duplicate"; the invisible one
    is that two stream servers cannot hold different values.  If these ever
    become genuinely per-server, this test is the thing that notices."""
    rc, out = _stream_t(tmp_path, _line(name, ALL_SEVEN[name]) * 2)
    assert rc == 0, (
        f"{name} is now duplicate-checked, which means it stopped writing a "
        f"process-global — re-read lifecycle.c and re-scope this test:\n{out}")


# --------------------------------------------------------------------------- #
# DEFECT #34 — the adopt gap, at the source.                                  #
# --------------------------------------------------------------------------- #

_COMMON_C = ROOT / "src/core/config/http_common.c"
# phase-101 W2: brix_http_common_commands[] no longer lists its entries inline —
# it #includes three directives_*.h fragment headers, where the actual
# { ngx_string(...), ... offsetof(common.<field>) } rows now live.  Parse those.
_COMMON_DIR = ROOT / "src/core/config"


def _common_table_text():
    """The full brix_http_common_commands[] body: http_common.c's table shell
    plus every directives_*.h fragment it #includes into that table."""
    blob = _COMMON_C.read_text(encoding="utf-8")
    table = blob.split("brix_http_common_commands[] = {", 1)[1]
    table = table.split("ngx_null_command", 1)[0]
    fragments = re.findall(r'#include\s+"(http_directives_[a-z0-9_]+\.h)"', table)
    parts = [table]
    for frag in fragments:
        parts.append((_COMMON_DIR / frag).read_text(encoding="utf-8"))
    return "\n".join(parts)


def _parsed_unified_fields():
    """{field: directive} for every common-module command that writes a
    `common.*` field — the values an http-plane location can set."""
    table = _common_table_text()
    return {m.group(3): m.group(1) for m in re.finditer(
        r'\{\s*ngx_string\("(brix_[a-z0-9_]+)"\)(.*?)offsetof\('
        r'ngx_http_brix_common_conf_t,\s*common\.([a-z0-9_]+)\)', table, re.S)}


def _adopted_fields():
    blob = _COMMON_C.read_text(encoding="utf-8")
    body = blob.split(
        "brix_shared_adopt_unified(ngx_http_brix_shared_conf_t *dst,", 1)[1]
    return set(re.findall(r"BRIX_ADOPT_(?:STR|VAL|PTR)\(\s*([a-z0-9_]+)",
                          body.split("\n}", 1)[0]))


def test_the_extraction_finds_the_common_tables_it_claims_to_read():
    """A regex that silently matched nothing would make every claim below
    vacuously true."""
    parsed, adopted = _parsed_unified_fields(), _adopted_fields()
    assert len(parsed) > 25, f"only {len(parsed)} common directives extracted"
    assert len(adopted) > 45, f"only {len(adopted)} adopted fields extracted"
    assert parsed.get("backend_token_aud") == "brix_backend_token_audience_ok"
    assert "backend_delegation" in adopted, \
        "the adopt list no longer mentions backend_delegation — re-read it"


def test_no_unified_field_is_parsed_without_being_adopted():
    """The class guard.  A common-module directive whose field is never adopted
    is config the operator can write and no protocol can read."""
    parsed, adopted = _parsed_unified_fields(), _adopted_fields()
    orphans = {f: d for f, d in parsed.items() if f not in adopted}
    # The parse/adopt heuristic sees these as parsed-but-not-adopted. Five are
    # the real DEFECT #34 inert class — four also declared on the stream plane
    # (their gap costs the http plane only), and backend_token_aud has no second
    # declaration and is unreachable everywhere. rate_limit is NOT inert: it is a
    # location-scoped SHM zone engine (phase-105 W1) whose brix_rate_limit_directive
    # setter writes common.rate_limit, inherited per-location through the shared
    # merge (shared_conf_merge.h: conf->rate_limit = prev->rate_limit) and read
    # DIRECTLY from the common conf by the rate-limit handler at request time — it
    # never needs adopting into a protocol struct, which is why the heuristic
    # cannot see its reachability (its live arm is covered by test_rate_limit_s3).
    known = {"backend_token_aud", "backend_sss_keytab", "backend_sts_flavor",
             "seccomp", "verify_write", "rate_limit"}
    assert set(orphans) - known == set(), (
        "a NEW common-module directive is parsed but never adopted, so it is "
        f"inert on every http export: {sorted(set(orphans) - known)}")
    assert set(orphans) == known, (
        f"{DEFECT34} Orphans are now {sorted(orphans)}; when the list shrinks, "
        "drop the fixed names from `known` and give them behavioural tests.")


def test_the_audience_gate_has_no_second_declaration_to_fall_back_on():
    """What separates #34 from the other four orphans: nothing else declares
    it, so there is no plane on which an operator can make it take effect.

    The invariant is a SINGLE declaration, and it must live on the shared
    HTTP-common config surface (src/core/config/) — not in any protocol
    module's own table, which is what would make the gate reachable.  It is
    pinned by that property rather than an exact file:line so an intra-surface
    move (phase-101 registered the config surface through #included
    directives_*.h fragment headers) does not falsely redden a real invariant —
    the same path-keyed-audit-breaks-on-moves class as its consumer sibling."""
    hits = []
    for path in ROOT.joinpath("src").rglob("*.[ch]"):
        for i, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if 'ngx_string("brix_backend_token_audience_ok")' in line:
                hits.append(f"{path.relative_to(ROOT)}:{i}")
    assert len(hits) == 1, (
        f"{DEFECT34} Expected exactly one declaration; found {hits}. A second "
        "declaration — especially in a protocol module's own table — could make "
        "the gate reachable; retest the live arm before trusting this pin.")
    assert hits[0].startswith("src/core/config/"), (
        f"{DEFECT34} The directive is now declared at {hits[0]}, outside the "
        "shared HTTP-common config surface — if that is a protocol module's own "
        "table the gate may be reachable; retest the live arm.")


def test_the_audience_gate_still_has_a_real_consumer_waiting_for_it():
    """The gap is in the plumbing, not the policy: the enforcement code exists,
    is called from all three protocols, and fails closed.  Deleting it would be
    a different (and larger) change than fixing the adopt."""
    wire = (ROOT / "src/protocols/shared/deleg_wire.c").read_text(encoding="utf-8")
    assert "brix_token_backend_aud_ok(bearer, cc->backend_token_aud, log)" in wire
    assert "return NULL;   /* wrong audience — never forwarded verbatim */" in wire
    callers = {p.relative_to(ROOT).as_posix()
               for p in ROOT.joinpath("src").rglob("*.c")
               if "brix_proto_deleg_gate_bearer(" in
               p.read_text(encoding="utf-8", errors="replace")}
    # The invariant is a live consumer in each of the three protocol planes, not
    # a specific filename: the webdav caller has already migrated once (access.c
    # -> access_vfs_ctx.c when access.c was split under the 600-line cap), so pin
    # the protocol directory, which survives intra-plane file moves.
    caller_planes = {"/".join(c.split("/")[:3]) for c in callers}
    assert {"src/protocols/webdav", "src/protocols/s3",
            "src/protocols/root"} <= caller_planes, sorted(callers)


# --------------------------------------------------------------------------- #
# DEFECT #35 — dead config.                                                   #
# --------------------------------------------------------------------------- #

def test_the_passthrough_persist_flag_is_never_read(tmp_path):
    """§Method step 4 applied to the flag: it parses (proven above), it merges,
    it adopts — and no line outside the config layer looks at it."""
    readers = []
    for sub in ("src", "shared", "client"):
        for path in ROOT.joinpath(sub).rglob("*.[ch]"):
            rel = path.relative_to(ROOT).as_posix()
            if rel.startswith("src/core/config/"):
                continue           # declaration, struct, init, merge, adopt
            for i, line in enumerate(
                    path.read_text(encoding="utf-8",
                                   errors="replace").splitlines(), 1):
                _guard_test_the_passthrough_persist_flag_is_never_read_1(line, readers, rel, i)
    _check_test_the_passthrough_persist_flag_is_never_read_1(readers)


# --------------------------------------------------------------------------- #
# DEFECT #34 — the operator's view: the gate configured, and silent.          #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def audgate(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    base = tmp_path
    data = base / "data"
    for loc in ("gate", "nogate"):
        (data / loc).mkdir(parents=True)
        (data / loc / "obj.bin").write_bytes(PAYLOAD)
    tmp = base / "ngxtmp"
    tmp.mkdir()

    issuer = TokenIssuer(str(base / "tokens"), issuer=ISSUER,
                         audience=FRONT_AUD)
    issuer.init_keys()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15j-audgate",
        template="nginx_audit15j_audgate.conf",
        protocol="http",
        data_root=str(data),
        template_values={"JWKS": issuer.jwks_path,
                         "ISSUER": ISSUER,
                         "FRONT_AUD": FRONT_AUD,
                         "BACKEND_AUD": BACKEND_AUD,
                         "TMP_DIR": str(tmp)},
        reason="audit-15j §A re-measure: the backend audience gate"))
    return endpoint, issuer


def _get(endpoint, loc, token):
    return requests.get(f"http://{HOST}:{endpoint.port}/{loc}/obj.bin",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=30)


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _gate_lines(endpoint):
    return [ln for ln in _errlog(endpoint).splitlines()
            if "backend audience gate" in ln]


def test_the_front_door_audience_pin_does_reject_a_wrong_audience(audgate):
    """The control.  Same export, same JWKS, same claim name — enforced.  This
    is what makes the gate's silence below a statement about the GATE and not
    about the token machinery."""
    endpoint, issuer = audgate
    resp = _get(endpoint, "gate",
                issuer.generate(audience="somewhere-else.example"))
    assert resp.status_code == 401, (
        "the front-door audience pin let a wrong-aud token through, so the "
        f"backend arm below proves nothing: {resp.status_code}")


def test_a_bearer_the_gate_must_refuse_is_forwarded_anyway(audgate):
    """DEFECT #34, as an operator sees it.

    The token is audienced for the GATEWAY and for nothing else.  The export
    says a bearer may only go to BACKEND_AUD.  The gate's refusal path logs at
    INFO and the export runs at `error_log info` — and the log stays empty."""
    endpoint, issuer = audgate
    before = len(_gate_lines(endpoint))
    resp = _get(endpoint, "gate", issuer.generate(audience=FRONT_AUD))
    assert resp.status_code == 200 and resp.content == PAYLOAD, resp.status_code
    assert len(_gate_lines(endpoint)) == before, (
        f"{DEFECT34} error.log now carries "
        f"{_gate_lines(endpoint)[before:]!r}.")


def test_the_gated_and_ungated_exports_are_indistinguishable(audgate):
    """The comparison the two locations exist for.  /gate/ names an origin the
    token does not; /nogate/ names none at all.  A working gate makes these two
    behave differently for this token — today they do not differ at all."""
    endpoint, issuer = audgate
    token = issuer.generate(audience=FRONT_AUD)
    gated, ungated = _get(endpoint, "gate", token), _get(endpoint, "nogate", token)
    assert (gated.status_code, gated.content) == (200, PAYLOAD)
    assert (ungated.status_code, ungated.content) == (200, PAYLOAD)
    assert _gate_lines(endpoint) == [], (
        f"{DEFECT34} The two exports now differ: {_gate_lines(endpoint)!r}")


@pytest.mark.parametrize("audience,why", [
    ([FRONT_AUD, BACKEND_AUD], "names the configured backend"),
    ([FRONT_AUD, WLCG_ANY], "carries the WLCG any-endpoint wildcard"),
])
def test_the_tokens_the_gate_should_accept_are_accepted(audgate, audience, why):
    """The success side, written so it keeps its meaning after the fix: these
    two shapes are forwardable BY POLICY (aud_match.c:45/67), so they must read
    200 whether the gate works or not.  Today they pass for the wrong reason —
    which is exactly why the refusal arm above is the one that carries #34."""
    endpoint, issuer = audgate
    resp = _get(endpoint, "gate", issuer.generate(audience=audience))
    assert resp.status_code == 200 and resp.content == PAYLOAD, (
        f"a bearer that {why} was refused: {resp.status_code}")
    assert _gate_lines(endpoint) == [], (
        "the gate refused a token it must forward — that is a fail-CLOSED "
        f"regression, not the #34 fail-open: {_gate_lines(endpoint)!r}")
