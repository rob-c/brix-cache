"""2.0 F18 — the TPC identity matrix (`ofs.tpc allow|require|restrict|oids`).

Stock XRootD confines third-party copy with an identity matrix:

    ofs.tpc allow  dn|group|host|vo <pattern>
            require {all|client|dest} <auth>
            restrict <path>
            oids

BriX spells the same four controls `brix_tpc_allow_identity`,
`brix_tpc_require`, `brix_tpc_restrict` and `brix_tpc_oids`.  The names differ
because `brix_tpc_allow_local` / `brix_tpc_allow_private` already own the
`brix_tpc_allow*` prefix on the HOST plane, and the two planes must never be
confused: the host plane is the OUTER gate and the matrix is an INNER one, so a
matrix rule can only ever narrow what the host plane already permits.

Four facts carry the whole feature and each is pinned below:

  * an unconfigured matrix is a no-op — the control pull still completes
    byte-exact, so adopting 2.0 changes nothing for a site that never writes
    one of these directives;
  * every configured stage is fail-CLOSED — a subject or path no rule names is
    DENIED, never defaulted, and `oids` is default-deny even unconfigured;
  * `require dest` constrains the DESTINATION's credential, which on the wire
    is the leg carrying `tpc.org`.  The client's own rendezvous registration
    carries no `tpc.org`, so it is the CLIENT party and a `require dest` rule
    cannot be satisfied — or dodged — by it;
  * a rule can only narrow: a plane whose matrix permits every path is still
    refused by its host-plane egress guard.

The pure decision core (stage order, CSV element boundaries, the
component-aware path prefix, the party scoping, the fixed refusal texts) is
proven exhaustively and without a server by
tests/test_tpc_identity_matrix_unit.py; this suite proves the wiring — that the
gate really runs at the native choke point, before any dial, on both the
destination and the source leg, and that its refusals carry no subject-derived
text (INVARIANT 8).
"""

import os
import subprocess
import time

import pytest

from _release20_tpc_helpers import (
    SRC_LFN, arm, err_text, log_since, log_size, published, pull, start_lab,
)
from _test_audit15g_helpers import pattern
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-r20-tpcmx"),
]

NAME = "lc-r20-tpcmx"

SEED = pattern(256 * 1024 + 77, 0x5A)

KXR_ERROR = 4003
XERR_NOT_AUTHORIZED = 3010

# The fixed refusal phrases, one per stage.  They name the DIRECTIVE that
# refused and nothing else — see test_no_subject_or_path_reaches_a_refusal.
TEXT_OID = "brix_tpc_oids"
TEXT_IDENTITY = "brix_tpc_allow_identity"
TEXT_AUTH = "brix_tpc_require"
TEXT_PATH = "brix_tpc_restrict"


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    node = start_lab(
        tmp_path_factory, name=NAME,
        template="nginx_release20_tpc_identity_matrix.conf",
        roots=("src", "dst", "allow", "req", "path", "destreq", "guard"),
        seed_roots=("src", "destreq"), seed=SEED,
        extra_ports=("DST_PORT", "ALLOW_PORT", "REQ_PORT", "PATH_PORT",
                     "DESTREQ_PORT", "GUARD_PORT"),
        reason="2.0 F18: the TPC identity matrix (ofs.tpc allow/require/"
               "restrict/oids)")
    yield node
    node["harness"].close()


def drive(lab, dst_key, dest, *, src_key="PORT", arm_key=None, tag="f18"):
    """One native pull of SRC_LFN from the `src_key` plane into `dest` on the
    `dst_key` plane, plus the error-log delta it produced."""
    ports = lab["ports"]
    mark = log_size(lab["endpoint"])
    status, body = pull(ports[dst_key], ports[src_key], dest,
                        arm_port=ports[arm_key or src_key], size=len(SEED),
                        tag=tag)
    return status, body, log_since(lab["endpoint"], mark)


def refusal(body):
    """(errcode, message) of a refused pull, asserting it really is an error."""
    code, msg = err_text(body)
    return code, msg


def access_log(lab, face):
    path = os.path.join(lab["endpoint"].prefix, "logs", f"brix_access_{face}.log")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


# -- success ----------------------------------------------------------------


def test_an_unconfigured_matrix_is_a_noop(lab):
    """(success) a plane that writes none of the four directives behaves
    exactly as it did before F18 — the pull completes and publishes the bytes.
    This is what lets 2.0 ship the matrix without changing any site."""
    status, body, _ = drive(lab, "DST_PORT", "/control.bin", tag="ctl")

    assert status != KXR_ERROR, refusal(body)
    assert published(lab["dirs"]["dst"], "/control.bin", SEED)


def test_a_restricted_prefix_admits_a_path_inside_it(lab):
    """(success) `brix_tpc_restrict /allowed` admits /allowed/... — the stage
    permits its own subject rather than merely denying everything."""
    status, body, _ = drive(lab, "PATH_PORT", "/allowed/in.bin", tag="in")

    assert status != KXR_ERROR, refusal(body)
    assert published(lab["dirs"]["path"], "/allowed/in.bin", SEED)


def test_the_client_leg_is_unconstrained_by_a_dest_rule(lab):
    """(success) the client's rendezvous registration on a source carrying
    `brix_tpc_require dest gsi` is accepted: it carries no tpc.org, so it is
    the CLIENT party, which that rule does not name."""
    armed = arm(lab["ports"]["DESTREQ_PORT"], f"f18-client-{os.getpid()}")
    try:
        assert armed is not None
    finally:
        armed.close()


# -- error: every configured stage fails closed ------------------------------


def test_an_unmatched_identity_is_denied_not_defaulted(lab):
    """(error) once ANY `brix_tpc_allow_identity` rule exists the stage is
    fail-closed: the anonymous subject matches no rule and is refused, rather
    than falling through to a permit."""
    status, body, _ = drive(lab, "ALLOW_PORT", "/denied-identity.bin", tag="idn")

    assert status == KXR_ERROR, (status, body)
    code, msg = refusal(body)
    assert code == XERR_NOT_AUTHORIZED, (code, msg)
    assert TEXT_IDENTITY in msg, msg


def test_an_unsatisfiable_require_is_denied(lab):
    """(error) `brix_tpc_require all gsi` cannot be satisfied by an anonymous
    credential, and the refusal names the directive that refused."""
    status, body, _ = drive(lab, "REQ_PORT", "/denied-auth.bin", tag="req")

    assert status == KXR_ERROR, (status, body)
    code, msg = refusal(body)
    assert code == XERR_NOT_AUTHORIZED, (code, msg)
    assert TEXT_AUTH in msg, msg


def test_a_path_outside_every_prefix_is_denied(lab):
    """(error) `brix_tpc_restrict /allowed` refuses anything elsewhere."""
    status, body, _ = drive(lab, "PATH_PORT", "/elsewhere/out.bin", tag="out")

    assert status == KXR_ERROR, (status, body)
    code, msg = refusal(body)
    assert code == XERR_NOT_AUTHORIZED, (code, msg)
    assert TEXT_PATH in msg, msg


def test_the_prefix_match_is_component_aware(lab):
    """(error) /allowedx is NOT inside /allowed.  A plain string prefix — which
    is what stock compares — would admit it, silently widening the operator's
    directory rule; BriX requires a '/' component boundary."""
    status, body, _ = drive(lab, "PATH_PORT", "/allowedx/out.bin", tag="near")

    assert status == KXR_ERROR, (status, body)
    code, msg = refusal(body)
    assert code == XERR_NOT_AUTHORIZED, (code, msg)
    assert TEXT_PATH in msg, msg


def test_object_id_paths_are_refused_by_default(lab):
    """(error) `brix_tpc_oids` defaults to off, and that stage runs FIRST — a
    '*'-prefixed path is refused before identity, auth or path is considered.
    BriX exports no object-id namespace, so this is pure narrowing."""
    status, body, _ = drive(lab, "PATH_PORT", "*oid", tag="oid")

    assert status == KXR_ERROR, (status, body)
    code, msg = refusal(body)
    assert code == XERR_NOT_AUTHORIZED, (code, msg)
    assert TEXT_OID in msg, msg


# -- security negatives ------------------------------------------------------


def test_require_dest_is_not_satisfiable_by_a_client_credential(lab):
    """(security negative) the party mapping is a wire fact, not a label: the
    leg carrying tpc.org was opened by the peer SERVER and presents the
    destination's credential.  A source configured `require dest gsi` therefore
    refuses that leg even though the very same anonymous client just registered
    the rendezvous key on it — the client cannot borrow the destination's
    exemption, and the destination cannot hide behind the client's."""
    status, body, _ = drive(lab, "DST_PORT", "/destreq.bin",
                            src_key="DESTREQ_PORT", tag="dstq")

    assert status == KXR_ERROR, (status, body)
    assert not published(lab["dirs"]["dst"], "/destreq.bin", SEED)
    assert TEXT_AUTH in access_log(lab, "destreq"), access_log(lab, "destreq")


def test_a_matrix_rule_cannot_widen_a_host_denial(lab):
    """(security negative) the GUARD plane's matrix permits every absolute path
    (`brix_tpc_restrict /`) while its host-plane egress allowlist names an
    unrelated host.  The pull must still be refused, and refused by the HOST
    plane — the matrix is an inner gate and can only narrow."""
    status, body, _ = drive(lab, "GUARD_PORT", "/widen.bin", tag="widen")

    assert status == KXR_ERROR, (status, body)
    assert not published(lab["dirs"]["guard"], "/widen.bin", SEED)
    _, msg = refusal(body)
    assert TEXT_PATH not in msg, ("the matrix answered a host-plane denial", msg)
    assert TEXT_IDENTITY not in msg, msg


def test_a_refusal_precedes_any_dial(lab):
    """(security negative) like F5's `permit=`, the whole verdict is reached
    before the destination opens a socket to the source: a refused pull leaves
    no file behind and never reaches the source's own access log.

    This one found the bug it was written for.  The gate's refusal leaves
    through BRIX_RETURN_ERR, whose last act is `return brix_send_error(...)`
    = NGX_OK, so a call site testing `rc != NGX_OK` could not tell a refusal
    from a permit: the refusal was logged and sent AND the pull then ran, the
    destination file appearing a few hundred microseconds after the error the
    client had already read.  The wire looked correct; only the filesystem and
    the access log disagreed.  Hence the sleep — the create is asynchronous
    with respect to the client's error, so a bare existence check straight
    after the refusal can win the race and pass on a broken build."""
    dest = "/nodial.bin"
    before = access_log(lab, "src")
    status, body, _ = drive(lab, "ALLOW_PORT", dest, tag="nodial")

    assert status == KXR_ERROR, (status, body)
    time.sleep(1.0)
    landed = os.path.join(str(lab["dirs"]["allow"]), dest.lstrip("/"))
    assert not os.path.exists(landed), (refusal(body), access_log(lab, "allow")[-800:])
    after = access_log(lab, "src")
    assert "tpc.org" not in after[len(before):], after[len(before):]


def test_a_refused_leg_never_reaches_the_open_handler(lab):
    """(security negative) the same bypass seen from the destination's own
    access log: a refused leg leaves exactly ONE outcome line for the session —
    the `tpc-matrix` refusal.  A second, successful `tpc-pull` OPEN line for the
    same path is the signature of a gate whose "permitted" and "refused" return
    values had collapsed into one."""
    dest = "/nobypass.bin"
    drive(lab, "ALLOW_PORT", dest, tag="nobypass")
    time.sleep(1.0)

    lines = [ln for ln in access_log(lab, "allow").splitlines() if dest in ln]
    assert not [ln for ln in lines if "tpc-pull" in ln], lines
    assert not os.path.exists(os.path.join(str(lab["dirs"]["allow"]),
                                           dest.lstrip("/"))), lines


#: The path a refusal must never echo: distinctive enough that a substring
#: search cannot pass by accident, and it names the subject's own request.
INV8_PATH = "/inv8-secret-path.bin"
INV8_NEEDLE = "inv8-secret-path"


def test_no_subject_or_path_reaches_a_refusal(lab):
    """(security negative, INVARIANT 8) the refusal ON THE WIRE is
    low-cardinality: it names the directive and nothing subject-derived.  A DN,
    VO, group, host or path in that string would land in the client's error and
    in every log that copies it."""
    status, body, _ = drive(lab, "ALLOW_PORT", INV8_PATH, tag="inv8")

    assert status == KXR_ERROR, (status, body)
    _, msg = refusal(body)
    assert msg == "TPC identity not permitted (brix_tpc_allow_identity)", msg
    assert INV8_NEEDLE not in msg
    assert "cms" not in msg, "the VO of the rule that denied it leaked"


def test_a_refusal_logs_the_directive_and_not_the_subject(lab):
    """(security negative, INVARIANT 8) the other half: the refusal reaches the
    access log — a denial nobody can see is not an auditable control — and it
    carries the same fixed phrase there, with no path and no subject.  Any
    metric that ever labels this text stays bounded."""
    _, _, errlog = drive(lab, "ALLOW_PORT", INV8_PATH, tag="inv8log")

    lines = [ln for ln in access_log(lab, "allow").splitlines()
             if "tpc-matrix" in ln]
    assert lines, "the refusal never reached the access log"
    assert TEXT_IDENTITY in lines[-1], lines[-1]
    assert INV8_NEEDLE not in lines[-1], lines[-1]
    assert INV8_NEEDLE not in errlog


# -- grammar ----------------------------------------------------------------


def _render_and_test(lifecycle, tmp_path, line):
    reg = lifecycle.register(NginxInstanceSpec(
        name="lc-r20-tpcmx-validate",
        template="nginx_release20_tpc_validate.conf",
        protocol="none", readiness="none", port=SHARED_PARSE_PLACEHOLDER_PORT,
        data_root=str(tmp_path),
        template_values={"BIND_HOST": BIND_HOST, "TPC_LINES": f"        {line}\n"},
        reason="2.0 F18: identity-matrix grammar"))
    endpoint = lifecycle.launcher.render_nginx(reg)
    return subprocess.run(
        [NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
        capture_output=True, text=True, timeout=30)


class TestGrammar:
    """(error) a malformed matrix is refused at `nginx -t` with a message an
    operator can act on.  A confinement control that silently ignored a line it
    did not understand would be worse than no control at all."""

    @pytest.mark.parametrize("line", [
        "brix_tpc_allow_identity vo cms;",
        'brix_tpc_allow_identity dn "/DC=org/CN=alice" host .example.org;',
        "brix_tpc_allow_identity group atlas;",
        "brix_tpc_require all gsi;",
        "brix_tpc_require client token;",
        "brix_tpc_require dest ztn;",
        "brix_tpc_restrict /data /scratch;",
        "brix_tpc_oids on;",
        "brix_tpc_oids off;",
    ])
    def test_a_well_formed_line_parses(self, lifecycle, tmp_path, line):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("line, needle", [
        ("brix_tpc_allow_identity vo;", "invalid number of arguments"),
        ("brix_tpc_allow_identity vo cms dn;",
         "expects <selector> <pattern> pairs"),
        ("brix_tpc_allow_identity xx cms;", 'unknown selector "xx"'),
        ("brix_tpc_allow_identity vo cms vo atlas;",
         'duplicate selector "vo"'),
        ('brix_tpc_allow_identity vo "";', 'empty pattern "vo"'),
        ("brix_tpc_require nobody gsi;", 'unknown party "nobody"'),
        ("brix_tpc_require dest none;",
         'unknown authentication method "none"'),
        ("brix_tpc_require dest;", "invalid number of arguments"),
        ("brix_tpc_restrict data;", "must be an absolute path"),
        ("brix_tpc_restrict;", "invalid number of arguments"),
        ("brix_tpc_oids maybe;", 'invalid value "maybe"'),
    ], ids=["allow-odd-one", "allow-odd-three", "allow-unknown-selector",
            "allow-duplicate-selector", "allow-empty-pattern",
            "require-unknown-party", "require-unknown-auth",
            "require-one-argument", "restrict-relative", "restrict-empty",
            "oids-non-flag"])
    def test_a_malformed_line_is_refused(self, lifecycle, tmp_path, line, needle):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode != 0, result.stdout
        assert needle in result.stderr, result.stderr

    def test_none_is_not_an_authentication_method(self, lifecycle, tmp_path):
        """(security negative) `require ... none` is deliberately NOT in the
        table: a require rule exists to demand a credential, and a spelling
        that accepted "no credential" would turn the stage into a no-op that
        still reads as configured."""
        result = _render_and_test(lifecycle, tmp_path,
                                  "brix_tpc_require all none;")
        assert result.returncode != 0
        assert "unknown authentication method" in result.stderr
