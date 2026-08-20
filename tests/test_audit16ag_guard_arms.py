# tests/test_audit16ag_guard_arms.py — the 16th audit tranche, file 33.
#
# SUBJECT: the two `net/httpguard` flags whose unwritten arm is the one an
# operator actually reaches for.
#
#   brix_guard                     `on` in eleven configs in this tree; `off`
#       in NONE.  Every "the guard is not running" control the corpus has is
#       rendered as ABSENCE — the same shape file 32 found in the OCI lane,
#       on the WAF this time.  The two routes to enable=0 are an explicit `0`
#       from ngx_conf_set_flag_slot and the default in ngx_conf_merge_value
#       (module.c:365), and nothing had ever compared them.
#   brix_guard_default_signatures  `off` in configs/nginx_guard_knobs.conf,
#       which is the ONE place in the tree the token appears at all; `on` — the
#       arm that carries the thirteen built-in scanner signatures, and the merge
#       default (module.c:366) — in NONE.
#
# The two are not symmetric, which is why they are one file: writing `off` for
# the first says what absence already said, and writing `on` for the second says
# what the merge already said.  Both are therefore lines nobody writes, and both
# are lines an operator auditing a config would expect to be able to read.
#
# WHAT TRANCHE 15 ALREADY HAS, AND WHAT THIS FILE IS NOT RE-MEASURING
#   tests/test_audit15_guard_knobs.py owns the knobs: the operator signature
#   under a custom bounce status, `default_signatures off` admitting the `/.env`
#   built-in against a defaults-on control, the method grammar, and the two
#   parse negatives (`brix_guard_bounce_status 418`, an unknown valid_method).
#   None of that is repeated here.  This file is about the flags' OWN arms and
#   the four states the pair can be in — and every finding below lives in a
#   state tranche 15 never builds.
#
# WHAT THE FILE FOUND
#   #121  `brix_guard_default_signatures off` does not merely admit a scanner
#         probe: it audits it as an ordinary miss.  `/probe.php`, `/.git/config`
#         and `/x/.env` come back 404 with `signal=notfound op=read`, character
#         for character what `/missing.txt` logs.  The audit log is the guard's
#         ONLY telemetry — httpguard publishes no metric — so the one arm the
#         corpus writes turns its own scanner signal into 404 noise.
#   #122  `brix_guard on` with no profile and `default_signatures off` builds a
#         ruleset that cannot bounce anything: guard_ruleset_load_profile("")
#         takes the unknown-profile branch (guard_ruleset.c:180-188), allows
#         every op and clears enforce_grammar.  On the wire that instance is
#         cell-for-cell a DISABLED guard — and it still writes audit lines, five
#         of them, so the only signal an operator has says the WAF is running.
#         A MISSPELT profile reaches the identical state and `nginx -t` says
#         nothing about it.
#   #123  The signature budget is spent by signatures the operator did not
#         write.  GUARD_MAX_SIGS is 64, the built-in set is 13, and both live in
#         the same array — so under the merge default the 52nd operator
#         signature is refused by a diagnostic that says "more than 64
#         signatures".  The number in the message is not the number in force,
#         and the number in force is not written anywhere in the config.
#   #124  `brix_guard off` skips ngx_http_brix_guard_build_ruleset() entirely
#         (module.c:386-389), so a location naming 200 signatures — more than
#         three times the cap — passes `nginx -t`.  The refusal arrives later,
#         on the deploy that turns the guard ON: `nginx -t` is green on the
#         config that has no protection and red on the change that adds it.
#         `brix_guard_bounce_status` is validated in the SAME function four
#         lines earlier, before the enable check, so the module validates half
#         its knobs under a disabled guard and half not.
#   #125  A `brix_guard off` location under a server-wide `brix_guard on` is the
#         only way a child can opt out — and it opts out completely: `/quiet/`
#         admits `.env`, `.git/config` and `.php` with the guard's own audit log
#         open, named by the parent, and not one line written about any of them.
#
# Ports: the lc-audit16ag-guardarms ledger row (eight listeners, one process).
# Config: configs/nginx_audit16ag_guard_arms.conf, rendered by this file and no
# other.  Parse tier: configs/nginx_audit16hparse.conf, REUSED — it writes
# neither flag itself, which is what a duplicate negative needs.
import os
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from guard_http_lib import AuditLog, GuardServer
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

NAME = "lc-audit16ag-guardarms"
_L = LIFECYCLE_SHARED_PORTS[NAME]

#: face name -> listener.  The face name is also the basename of its audit log,
#: which is how the config and this file agree on which log belongs to which
#: server without either of them holding a second table.
PORTS = {
    "off": _L["port"],
    "absent": _L["extra"]["ABS_PORT"],
    "on": _L["extra"]["ON_PORT"],
    "defon": _L["extra"]["DEFON_PORT"],
    "defoff": _L["extra"]["DEFOFF_PORT"],
    "bare": _L["extra"]["BARE_PORT"],
    "srvon": _L["extra"]["SRVON_PORT"],
    "srvoff": _L["extra"]["SRVOFF_PORT"],
}

#: The sweep, in the order it is fired.  Every face answers all seven, so a
#: face is a column and the comparison between two faces is a column diff —
#: which is the whole shape of this file.
#:
#:   /seed.txt          a file that exists: the guard passing is observable
#:   /missing.txt       a file that does not: the `notfound` outcome signal
#:   /probe.php         built-in SUFFIX signature
#:   /.git/config       built-in PREFIX signature
#:   /x/.env            built-in SUBSTR signature — three kinds, because
#:                      `default_signatures` is one flag over all three
#:   /custom-probe      the OPERATOR's signature, written only on defon/defoff
#:   PATCH /seed.txt    method_to_op() maps PATCH to GUARD_OP_UNKNOWN, and the
#:                      xrdhttp profile allows five named ops and not that one,
#:                      so this is the grammar probe.  PUT/DELETE/PROPFIND are
#:                      ALLOWED by that profile and answer 405 from nginx's own
#:                      static module, which would have measured nothing.
PROBES = (
    ("GET", "/seed.txt"),
    ("GET", "/missing.txt"),
    ("GET", "/probe.php"),
    ("GET", "/.git/config"),
    ("GET", "/x/.env"),
    ("GET", "/custom-probe"),
    ("PATCH", "/seed.txt"),
)

#: What a guard that is not running answers.  `off`, its omission, and — this is
#: #122 — an ENABLED guard holding no rule all produce this column.
DISABLED = (200, 404, 404, 404, 404, 404, 405)

#: The merge default: enabled, built-ins in force, no operator signature.
GUARDED = (200, 404, 403, 403, 403, 404, 403)

#: The same plus one operator signature, which is the ONLY cell that moves —
#: `default_signatures on` written out is the merge default, and this proves it.
DEFON = (200, 404, 403, 403, 403, 403, 403)

#: `default_signatures off`: the three built-in kinds are gone together and the
#: operator signature and the profile grammar are untouched.
DEFOFF = (200, 404, 404, 404, 404, 403, 403)

#: The audit signal each sweep leaves, in order.  A passing 200 and a 405 from
#: the static module write nothing, so a seven-probe sweep is six lines or five.
GUARDED_SIGNALS = ["notfound", "signature", "signature", "signature",
                   "notfound", "grammar"]
DEFON_SIGNALS = ["notfound", "signature", "signature", "signature",
                 "signature", "grammar"]
DEFOFF_SIGNALS = ["notfound", "notfound", "notfound", "notfound",
                  "signature", "grammar"]
BARE_SIGNALS = ["notfound"] * 5

TIMEOUT = 10

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Faces:
    """Eight guard fronts in one process, addressed by face name."""

    def __init__(self, instance, root):
        self.instance = instance
        self.root = Path(root)

    def logdir(self):
        return Path(self.instance.prefix) / "logs"

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        log = self.logdir() / "error.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def server(self, face):
        return GuardServer(HOST, PORTS[face])

    def audit(self, face):
        return AuditLog(str(self.logdir() / f"guard-{face}.log"))

    def probe(self, face, method, path):
        return self.server(face).request(method, path).status

    def sweep(self, face, prefix=""):
        """Fire all seven at one face and return the status column.

        `prefix` is for the two inheritance faces, whose second location is
        reached at /quiet/ or /loud/ — the guard classifies the whole r->uri
        (guard_http_req.c:118), so a prefixed sweep is a DIFFERENT question from
        an unprefixed one and the two are never mixed inside a test."""
        return tuple(self.probe(face, method, prefix.rstrip("/") + path)
                     for method, path in PROBES)

    def signals(self, face, baseline, expected):
        """The `signal=` field of every audit line written since `baseline`.

        nginx runs the LOG phase after the response has left for the client, so
        a read that follows the last probe by microseconds can be one line
        short; the count is waited for and only then split."""
        log = self.audit(face)
        assert log.wait_for_count(baseline + len(expected)), (
            f"{face}: expected {len(expected)} new audit lines, saw "
            f"{log.line_count() - baseline}\n" + "\n".join(log.lines()[baseline:]))
        return [_field(line, "signal") for line in log.lines()[baseline:]]

    def new_lines(self, face, baseline):
        return self.audit(face).lines()[baseline:]

    def count(self, face):
        return self.audit(face).line_count()


def _field(line, key):
    """One `key=value` field out of an audit line.

    guard_audit_format writes `path="/x"` quoted and everything else bare, so
    the quotes come off here rather than at every call site."""
    for token in line.split(" "):
        if token.startswith(key + "="):
            return token[len(key) + 1:].strip('"')
    return None


@pytest.fixture(scope="module")
def faces(tmp_path_factory):
    """MODULE-scoped with its own harness, for the reason files 27-32 give: the
    eight ports are fixed by the ledger, so a per-test start/stop races the OS
    releasing them.  Every test takes its own audit baseline instead."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("audit16ag") / "docroot"
    # /quiet/ and /loud/ are the two inheritance faces' second locations, and
    # each needs its own seed file: a 404 where a 200 was meant would be read as
    # the guard bouncing, which is the opposite of what those cells measure.
    for sub in ("", "quiet", "loud"):
        (root / sub).mkdir(parents=True, exist_ok=True)
        (root / sub / "seed.txt").write_text("guard-arms payload\n")

    harness = LifecycleHarness()
    try:
        instance = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16ag_guard_arms.conf",
            protocol="http",
            readiness="tcp",
            data_root=str(root),
            template_values={"BIND_HOST": BIND_HOST},
            reason="audit-16ag the two httpguard flags whose unwritten arm is "
                   "the one an operator reaches for: brix_guard off against "
                   "the absence every control in the tree uses instead, and "
                   "brix_guard_default_signatures on against the merge default "
                   "that has always stood in for it."))
        yield _Faces(instance, root)
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# §A  The never-written `off` and the absence that stands in for it            #
# --------------------------------------------------------------------------- #

class TestTheWrittenOffAndItsOmission:
    """G_OFF and G_ABSENT are the same server twice, one `brix_guard off;`
    apart.  Eleven configs in this tree turn the guard on and none turns it off,
    so every "guard not running" control the corpus has is the second of these
    two — and until this file nothing had checked that they agree."""

    def test_both_answer_the_whole_sweep_identically(self, faces):
        written = faces.sweep("off")
        omitted = faces.sweep("absent")

        assert written == omitted, faces.errlog()

    def test_both_answer_it_the_way_an_unguarded_server_does(self, faces):
        """Agreement alone would be satisfied by two servers that are both
        wrong, so the column is pinned as well: every scanner probe reaches the
        static module and is answered on its merits."""
        assert faces.sweep("off") == DISABLED, faces.errlog()
        assert faces.sweep("absent") == DISABLED, faces.errlog()

    def test_the_comparison_is_not_vacuous(self, faces):
        """The pair above would also agree if the whole guard were dead.  The
        enabled face answers the same sweep differently in four cells, so the
        agreement in §A is a property of the flag and not of the build."""
        assert faces.sweep("on") != DISABLED

    def test_neither_writes_an_audit_line(self, faces):
        """The classify handler self-disables on lcf->enable, and so does the
        log handler — a disabled guard does not audit the requests it lets
        through, in either arm."""
        before = {face: faces.count(face) for face in ("off", "absent")}
        faces.sweep("off")
        faces.sweep("absent")

        assert faces.count("off") == before["off"] == 0
        assert faces.count("absent") == before["absent"] == 0

    def test_both_open_an_audit_file_they_never_write_to(self, faces):
        """ngx_http_brix_guard_audit_log_slot calls ngx_conf_open_file with no
        reference to `enable` (module.c:124), so the file is created at config
        time whatever the flag says.  Not a defect — but it is the reason a
        "the guard's log exists" health check proves nothing, and the reason
        every face in this config needs a log of its own rather than sharing."""
        for face in ("off", "absent"):
            path = Path(faces.audit(face).path)
            assert path.exists(), f"{face}: {path} was never created"
            assert path.stat().st_size == 0, path.read_text()


# --------------------------------------------------------------------------- #
# §B  What the absence-as-control gives up                                     #
# --------------------------------------------------------------------------- #

class TestTheEnabledControl:
    """G_ON is the same server with `brix_guard on;` and
    `brix_guard_default_signatures` left to the merge — i.e. what every one of
    the eleven enabling configs in the tree actually builds."""

    def test_the_enabled_face_bounces_all_three_signature_kinds(self, faces):
        assert faces.sweep("on") == GUARDED, faces.errlog()

    def test_it_audits_six_of_the_seven_with_the_expected_signals(self, faces):
        baseline = faces.count("on")
        faces.sweep("on")

        assert faces.signals("on", baseline, GUARDED_SIGNALS) == GUARDED_SIGNALS

    def test_a_credentials_file_is_the_difference_between_the_two_arms(self,
                                                                       faces):
        """Security-negative, and the one that says what the unwritten arm
        costs: `/x/.env` is a credentials file by convention, the guard's own
        built-in SUBSTR set names it, and the disabled pair hands it to the
        static module to answer on its merits.  Here that is a 404 because the
        file does not exist; on a server where it does, it is the file."""
        assert faces.probe("on", "GET", "/x/.env") == 403
        assert faces.probe("off", "GET", "/x/.env") == 404
        assert faces.probe("absent", "GET", "/x/.env") == 404

    def test_the_audit_line_names_the_profile_it_was_classified_under(self,
                                                                      faces):
        """`proto=` carries the profile, which is how a shared audit log is read
        back to a server.  It matters here because §D's bare face reports
        `proto=http` from the same field — the tell that no profile loaded."""
        baseline = faces.count("on")
        assert faces.probe("on", "GET", "/probe.php") == 403
        assert faces.audit("on").wait_for_count(baseline + 1)

        line = faces.new_lines("on", baseline)[0]
        assert _field(line, "proto") == "xrdhttp", line
        assert _field(line, "signal") == "signature", line
        assert _field(line, "op") == "read", line
        assert _field(line, "path") == "/probe.php", line
        assert _field(line, "status") == "403", line


# --------------------------------------------------------------------------- #
# §C  `default_signatures on`, written out, is the merge default               #
# --------------------------------------------------------------------------- #

class TestTheWrittenOnIsTheMergeDefault:
    """The claim the whole corpus rests on without ever writing it:
    ngx_conf_merge_value(conf->default_sigs, prev->default_sigs, 1) means every
    config that turns the guard on gets the thirteen built-ins whether it says
    so or not.  G_DEFON says so out loud; G_ON does not."""

    def test_the_two_columns_differ_only_where_the_operator_signature_is(self,
                                                                         faces):
        written = faces.sweep("defon")
        implied = faces.sweep("on")

        assert written == DEFON, faces.errlog()
        differ = [i for i in range(len(PROBES)) if written[i] != implied[i]]
        assert differ == [5], [PROBES[i] for i in differ]

    def test_every_built_in_kind_fires_under_both(self, faces):
        """SUFFIX, PREFIX and SUBSTR are three code paths in
        guard_ruleset_match and one flag governs all three, so the arm is only
        proven by a probe of each kind."""
        for path in ("/probe.php", "/.git/config", "/x/.env"):
            assert faces.probe("on", "GET", path) == 403, path
            assert faces.probe("defon", "GET", path) == 403, path

    def test_the_written_arm_audits_the_same_way(self, faces):
        baseline = faces.count("defon")
        faces.sweep("defon")

        assert faces.signals("defon", baseline, DEFON_SIGNALS) == DEFON_SIGNALS

    def test_the_operator_signature_is_indistinguishable_from_a_built_in(self,
                                                                         faces):
        """Both are `signal=signature`, and the line names no rule.  With the
        built-ins in force an operator reading their own audit log cannot tell
        which of the fourteen rules bounced the request — which is the reason
        #121's collapse below is easy to miss in production."""
        baseline = faces.count("defon")
        assert faces.probe("defon", "GET", "/custom-probe") == 403
        assert faces.probe("defon", "GET", "/probe.php") == 403
        assert faces.audit("defon").wait_for_count(baseline + 2)

        mine, builtin = faces.new_lines("defon", baseline)
        assert _field(mine, "signal") == _field(builtin, "signal") == "signature"


# --------------------------------------------------------------------------- #
# §D  The arm the corpus writes turns its own telemetry into noise (#121)      #
# --------------------------------------------------------------------------- #

class TestDefaultSignaturesOffCollapsesTheSignal:
    """DEFECT #121.  `brix_guard_default_signatures off` is documented and
    tested (tranche 15) as admitting the built-in probes.  What nothing had
    measured is what the audit log then SAYS about them — and it says they were
    ordinary missing files.  httpguard publishes no metric of its own, so that
    log is the only place a scanner sweep could have been counted."""

    def test_the_built_ins_are_admitted_and_the_rest_of_the_ruleset_is_not(
            self, faces):
        assert faces.sweep("defoff") == DEFOFF, faces.errlog()

    def test_the_operator_signature_and_the_grammar_survive_the_arm(self,
                                                                    faces):
        """The bound on #121: the flag disables exactly the built-in set.  A
        reader who concluded from the 404s above that the guard was off would be
        wrong, and these two cells are why."""
        assert faces.probe("defoff", "GET", "/custom-probe") == 403
        assert faces.probe("defoff", "PATCH", "/seed.txt") == 403

    def test_a_scanner_probe_is_audited_as_an_ordinary_miss(self, faces):
        baseline = faces.count("defoff")
        faces.sweep("defoff")

        assert faces.signals("defoff", baseline, DEFOFF_SIGNALS) == \
            DEFOFF_SIGNALS

    def test_the_probe_line_and_the_miss_line_differ_only_in_the_path(self,
                                                                      faces):
        """#121 stated as the thing a log reader would have to do: `.env` and a
        typo in a filename produce lines that agree in every field but one, and
        the one they differ in is the field a grep for scanners cannot key on."""
        baseline = faces.count("defoff")
        assert faces.probe("defoff", "GET", "/x/.env") == 404
        assert faces.probe("defoff", "GET", "/missing.txt") == 404
        assert faces.audit("defoff").wait_for_count(baseline + 2)

        scanner, miss = faces.new_lines("defoff", baseline)
        for key in ("proto", "signal", "op", "status"):
            assert _field(scanner, key) == _field(miss, key), key
        assert _field(scanner, "path") == "/x/.env"
        assert _field(miss, "path") == "/missing.txt"

    def test_the_enabled_control_does_distinguish_them(self, faces):
        """The same two requests at G_ON, which is the world #121 describes the
        loss of: one is `signature`, the other `notfound`."""
        baseline = faces.count("on")
        assert faces.probe("on", "GET", "/x/.env") == 403
        assert faces.probe("on", "GET", "/missing.txt") == 404
        assert faces.audit("on").wait_for_count(baseline + 2)

        scanner, miss = faces.new_lines("on", baseline)
        assert _field(scanner, "signal") == "signature"
        assert _field(miss, "signal") == "notfound"


# --------------------------------------------------------------------------- #
# §E  Enabled, reporting enabled, and unable to bounce anything (#122)         #
# --------------------------------------------------------------------------- #

class TestAGuardThatIsOnAndHoldsNoRule:
    """DEFECT #122.  G_BARE is `brix_guard on;` and
    `brix_guard_default_signatures off;` and nothing else — no profile, no
    signature, no prefix, no method list.  guard_ruleset_load_profile is handed
    "" and takes its unknown-profile branch (guard_ruleset.c:180-188): every op
    allowed, enforce_grammar cleared.  The ruleset is then empty in every field
    that could produce a bounce."""

    def test_its_column_is_the_disabled_column(self, faces):
        assert faces.sweep("bare") == DISABLED, faces.errlog()

    def test_it_is_indistinguishable_on_the_wire_from_brix_guard_off(self,
                                                                     faces):
        """Stated as the comparison that matters: an operator probing this
        instance from outside cannot tell it from the one that turned the guard
        off, and the config says the opposite."""
        assert faces.sweep("bare") == faces.sweep("off")

    def test_it_nonetheless_writes_audit_lines(self, faces):
        """And this is why #122 is not merely a misconfiguration: the guard's
        only telemetry fills up, so an operator watching the audit log sees a
        WAF that is running.  Five lines for a sweep that bounced nothing."""
        baseline = faces.count("bare")
        faces.sweep("bare")

        assert faces.signals("bare", baseline, BARE_SIGNALS) == BARE_SIGNALS

    def test_the_only_tell_is_the_proto_field(self, faces):
        """`proto=` carries lcf->profile, so an empty profile shows as the
        fallback `http` while every rule-bearing face shows its profile name.
        It is the one field that distinguishes #122 from a working guard, and
        it distinguishes it from the WORKING guard's `notfound` lines too — so
        a log reader has to know to look at a field that is not about rules."""
        baseline = faces.count("bare")
        assert faces.probe("bare", "GET", "/missing.txt") == 404
        assert faces.audit("bare").wait_for_count(baseline + 1)

        assert _field(faces.new_lines("bare", baseline)[0], "proto") == "http"

    def test_a_scanner_sweep_passes_it_entirely(self, faces):
        """Security-negative.  All three built-in kinds plus the grammar probe,
        against an instance whose config says the guard is on."""
        for method, path in (("GET", "/probe.php"), ("GET", "/.git/config"),
                             ("GET", "/x/.env"), ("PATCH", "/seed.txt")):
            assert faces.probe("bare", method, path) != 403, (method, path)


# --------------------------------------------------------------------------- #
# §F  Inheritance, in both directions, which no config in the tree writes      #
# --------------------------------------------------------------------------- #

class TestServerLevelInheritance:
    """Both flags are MAIN|SRV|LOC (module.c:29,43) and every config in the tree
    writes them in a location.  G_SRVON and G_SRVOFF write `brix_guard` at
    SERVER level with one child location contradicting it, which is the only
    shape in which the merge's inheritance arm is observable."""

    def test_a_child_location_inherits_the_server_wide_guard(self, faces):
        """G_SRVON's `location /` writes no guard directive at all."""
        assert faces.sweep("srvon") == GUARDED, faces.errlog()

    def test_a_child_location_inherits_a_server_wide_off(self, faces):
        assert faces.sweep("srvoff") == DISABLED, faces.errlog()

    def test_the_inherited_guard_audits_to_the_inherited_log(self, faces):
        """`audit_log` is merged by pointer (module.c:371-373), so the child
        that names no log writes to the parent's — which is what makes a
        server-level guard usable at all."""
        baseline = faces.count("srvon")
        faces.sweep("srvon")

        assert faces.signals("srvon", baseline, GUARDED_SIGNALS) == \
            GUARDED_SIGNALS

    def test_a_child_can_turn_a_server_wide_guard_off(self, faces):
        """DEFECT #125's mechanism: `location /quiet/ { brix_guard off; }` under
        a server that turned it on.  This is the never-written token doing the
        only thing it CAN do that absence cannot, and it works."""
        assert faces.sweep("srvon", prefix="/quiet/") == DISABLED

    def test_the_opted_out_child_writes_nothing_to_the_parents_log(self,
                                                                   faces):
        """DEFECT #125.  The audit log is the parent's, is open, and is named by
        a config the operator can read — and a scanner sweep against the child
        leaves no trace in it at all.  A server-wide guard with one carve-out
        therefore has a hole its own telemetry cannot show."""
        baseline = faces.count("srvon")
        for path in ("/quiet/x/.env", "/quiet/.git/config",
                     "/quiet/probe.php"):
            assert faces.probe("srvon", "GET", path) == 404, path

        assert faces.count("srvon") == baseline, \
            faces.new_lines("srvon", baseline)

    def test_a_child_can_turn_a_server_wide_off_back_on(self, faces):
        """The mirror, and the reason #125 is about the carve-out rather than
        about inheritance being broken: the other direction composes exactly as
        it should."""
        column = faces.sweep("srvoff", prefix="/loud/")

        # /loud/ has no custom-probe signature and no /loud/-relative built-in
        # PREFIX match, so it is GUARDED's column with those two cells at their
        # unguarded values: the PREFIX rule is "/.git" against the head of the
        # URI, and under /loud/ the URI does not start with it.
        assert column == (200, 404, 403, 404, 403, 404, 403), faces.errlog()

    def test_the_opted_in_child_audits_under_its_own_full_path(self, faces):
        """The audit line carries r->uri, not the location remainder — which is
        the same fact the config header gives for why this file is eight servers
        and not eight locations."""
        baseline = faces.count("srvoff")
        assert faces.probe("srvoff", "GET", "/loud/probe.php") == 403
        assert faces.audit("srvoff").wait_for_count(baseline + 1)

        line = faces.new_lines("srvoff", baseline)[0]
        assert _field(line, "path") == "/loud/probe.php", line
        assert _field(line, "signal") == "signature", line

    def test_the_prefix_rule_is_measured_against_the_whole_uri(self, faces):
        """Security-negative, and the reason the column above has a 404 in it:
        the built-in PREFIX signature `/.git` does not fire under any location
        that is not at the root.  A guard mounted at /loud/ admits
        /loud/.git/config while bouncing /loud/probe.php."""
        assert faces.probe("srvoff", "GET", "/loud/.git/config") == 404
        assert faces.probe("srvoff", "GET", "/loud/x/.env") == 403


# --------------------------------------------------------------------------- #
# §G  The parse tier                                                           #
# --------------------------------------------------------------------------- #

GUARD = "brix_guard"
DEFSIGS = "brix_guard_default_signatures"

#: GUARD_MAX_SIGS (guard.h:86) and the size of the built-in set
#: (guard_ruleset.c:72).  Both are asserted below rather than assumed — the
#: whole of #123 is that these two numbers are added together somewhere no
#: config can see.
MAX_SIGS = 64
BUILT_INS = 13


def _parse(root, **slots):
    """`nginx -t` on the shared parse scaffold.

    configs/nginx_audit16hparse.conf is REUSED rather than copied, for the
    reason files 29-32 give: it writes neither flag itself, so a duplicate
    negative can be sure the duplicate it is shown is the one it wrote.  Its six
    placement slots are exactly the six this section needs, both flags being
    MAIN|SRV|LOC on the http plane and absent from the stream table."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(exist_ok=True)
    data = root / "data"
    data.mkdir(exist_ok=True)
    values = {"OUTER": "", "HTTP_KNOBS": "", "SRV_KNOBS": "", "KNOBS": "",
              "STREAM_KNOBS": "", "STREAM_MAIN": "", "SUBJECT": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16hparse.conf", root,
                     PORT=PARSE_PLACEHOLDER_PORT,
                     SUBJ_PORT=PARSE_PLACEHOLDER_PORT + 1,
                     STREAM_PORT=PARSE_PLACEHOLDER_PORT + 2,
                     LOG_DIR=str(root / "logs"), DATA=str(data), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _diagnostics(out):
    """Only the lines nginx itself flagged: a tmp_path name can contain the
    token under test, so a substring search over the whole output would match
    the temp directory rather than a diagnostic."""
    return [line for line in out.splitlines()
            if any(tag in line for tag in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


def _sigs(count, indent="            "):
    return "".join(f"{indent}brix_guard_signature /op-{i};\n"
                   for i in range(count))


class TestBothArmsOfBothFlagsParse:

    @pytest.mark.parametrize("flag", (GUARD, DEFSIGS))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_is_accepted_in_a_location(self, tmp_path, flag, arm):
        rc, out = _parse(tmp_path, KNOBS=f"            {flag} {arm};\n")

        assert rc == 0, out

    @pytest.mark.parametrize("flag", (GUARD, DEFSIGS))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_draws_no_diagnostic(self, tmp_path, flag, arm):
        """Accepted is not enough — §A's claim is that a written `off` is a
        normal thing to write, and a NOTICE calling it redundant would be a
        different (and better) world."""
        rc, out = _parse(tmp_path, KNOBS=f"            {flag} {arm};\n")

        assert rc == 0 and _diagnostics(out) == [], _diagnostics(out)

    def test_the_second_flag_needs_no_guard_to_belong_to(self, tmp_path):
        """`brix_guard_default_signatures on` in a location with no guard at all
        is accepted and does nothing: the merge builds no ruleset because
        `enable` is 0, so the flag has no surface to configure."""
        rc, out = _parse(tmp_path, KNOBS=f"            {DEFSIGS} on;\n")

        assert rc == 0, out


class TestTheSignatureBudgetIsSpentBySignaturesNobodyWrote:
    """DEFECT #123.  guard_ruleset_add_default_signatures fills the SAME
    fixed-size array the operator's `brix_guard_signature` lines fill
    (guard.h:94), and the refusal at module.c:262 formats GUARD_MAX_SIGS.  So
    the message names 64 and the operator's ceiling is 51 — a number that
    appears in no config, no diagnostic and no document."""

    def test_the_operator_ceiling_under_the_merge_default_is_not_the_cap(
            self, tmp_path):
        room = MAX_SIGS - BUILT_INS
        assert room == 51

        ok = _parse(tmp_path / "ok",
                    KNOBS=f"            {GUARD} on;\n" + _sigs(room))
        over = _parse(tmp_path / "over",
                      KNOBS=f"            {GUARD} on;\n" + _sigs(room + 1))

        assert ok[0] == 0, ok[1]
        assert over[0] != 0, over[1]

    def test_the_diagnostic_names_a_number_the_operator_cannot_reach(self,
                                                                     tmp_path):
        """#123 as the thing an operator sees: 52 signatures written, and a
        message saying more than 64."""
        rc, out = _parse(tmp_path,
                         KNOBS=f"            {GUARD} on;\n"
                               + _sigs(MAX_SIGS - BUILT_INS + 1))

        assert rc != 0
        assert f"more than {MAX_SIGS} signatures" in out, out

    def test_turning_the_built_ins_off_returns_the_missing_thirteen(self,
                                                                    tmp_path):
        """Which is what proves the two sets share the array rather than the
        cap being 51 for some other reason: with `default_signatures off` the
        operator gets exactly 64, and the 65th is refused."""
        ok = _parse(tmp_path / "ok",
                    KNOBS=f"            {GUARD} on;\n"
                          f"            {DEFSIGS} off;\n" + _sigs(MAX_SIGS))
        over = _parse(tmp_path / "over",
                      KNOBS=f"            {GUARD} on;\n"
                            f"            {DEFSIGS} off;\n"
                            + _sigs(MAX_SIGS + 1))

        assert ok[0] == 0, ok[1]
        assert over[0] != 0, over[1]

    @pytest.mark.parametrize("slot,indent", [("HTTP_KNOBS", "        "),
                                             ("SRV_KNOBS", "        ")])
    def test_the_budget_measures_the_inherited_arm(self, tmp_path, slot,
                                                   indent):
        """The second flag's inheritance, which has no runtime face in this
        file and does not need one: the ceiling moves to 64 when the arm is
        written in a PARENT scope, so the location inherited it."""
        rc, out = _parse(tmp_path,
                         KNOBS=f"            {GUARD} on;\n" + _sigs(MAX_SIGS),
                         **{slot: f"{indent}{DEFSIGS} off;\n"})

        assert rc == 0, out

    def test_a_child_arm_overrides_the_inherited_one(self, tmp_path):
        """And the override direction: `off` in the server, `on` in the
        location, and the ceiling is back to 51."""
        rc, out = _parse(tmp_path,
                         SRV_KNOBS=f"        {DEFSIGS} off;\n",
                         KNOBS=f"            {GUARD} on;\n"
                               f"            {DEFSIGS} on;\n"
                               + _sigs(MAX_SIGS - BUILT_INS + 1))

        assert rc != 0
        assert f"more than {MAX_SIGS} signatures" in out, out


class TestADisabledGuardValidatesHalfOfItself:
    """DEFECT #124.  ngx_http_brix_guard_merge_loc_conf validates
    `bounce_status` and then returns early on `!enable` (module.c:380-389), so
    the ruleset is never built for a disabled location and nothing in it is
    checked.  The half that is checked and the half that is not are four lines
    apart in the same function, and no config says which is which."""

    def test_a_disabled_location_may_name_more_signatures_than_the_cap(
            self, tmp_path):
        rc, out = _parse(tmp_path,
                         KNOBS=f"            {GUARD} off;\n"
                               + _sigs(MAX_SIGS * 3))

        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_the_same_config_is_refused_the_moment_the_guard_is_turned_on(
            self, tmp_path):
        """#124 as the operator's day: `nginx -t` is green on the deployment
        that has no guard, and red on the one-line change that adds one."""
        off = _parse(tmp_path / "off",
                     KNOBS=f"            {GUARD} off;\n" + _sigs(MAX_SIGS * 3))
        on = _parse(tmp_path / "on",
                    KNOBS=f"            {GUARD} on;\n" + _sigs(MAX_SIGS * 3))

        assert off[0] == 0, off[1]
        assert on[0] != 0
        assert f"more than {MAX_SIGS} signatures" in on[1], on[1]

    def test_the_skip_follows_the_inherited_arm_too(self, tmp_path):
        """A server that turned the guard off carries the same blindness down:
        the location is not validated either, because `enable` merged to 0."""
        inherited = _parse(tmp_path / "inh",
                           SRV_KNOBS=f"        {GUARD} off;\n",
                           KNOBS=_sigs(MAX_SIGS * 3))
        overridden = _parse(tmp_path / "ovr",
                            SRV_KNOBS=f"        {GUARD} off;\n",
                            KNOBS=f"            {GUARD} on;\n"
                                  + _sigs(MAX_SIGS * 3))

        assert inherited[0] == 0, inherited[1]
        assert overridden[0] != 0

    def test_a_child_that_turns_the_guard_off_is_not_validated_either(self,
                                                                      tmp_path):
        """The §F carve-out at the parse tier: the location that opts out of a
        server-wide guard also opts out of having its rules checked."""
        rc, out = _parse(tmp_path,
                         SRV_KNOBS=f"        {GUARD} on;\n",
                         KNOBS=f"            {GUARD} off;\n"
                               + _sigs(MAX_SIGS * 3))

        assert rc == 0, out

    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_the_bounce_status_is_validated_under_both_arms(self, tmp_path,
                                                            arm):
        """The other half, and the asymmetry stated as a measurement: this knob
        IS checked when the guard is off, because its check sits before the
        early return.  Tranche 15 owns the 403/444 rule itself; what is new
        here is that it does not depend on `enable` while the ruleset does."""
        rc, out = _parse(tmp_path,
                         KNOBS=f"            {GUARD} {arm};\n"
                               "            brix_guard_bounce_status 500;\n")

        assert rc != 0
        assert "must be 403 or 444" in out, out


class TestAMisspeltProfileIsAcceptedInSilence:
    """The second route into #122.  guard_ruleset_load_profile compares the
    profile against three literals and treats everything else as "unknown" —
    which is not a refusal but a permissive ruleset: every op allowed,
    enforce_grammar cleared.  A typo in a profile name is therefore a silent
    downgrade of the guard, and the bare face in §E is what it looks like."""

    @pytest.mark.parametrize("profile", ("xrdhttp", "arc", "root"))
    def test_the_three_known_profiles_load(self, tmp_path, profile):
        rc, out = _parse(tmp_path,
                         KNOBS=f"            {GUARD} on;\n"
                               f"            brix_guard_profile {profile};\n")

        assert rc == 0, out

    @pytest.mark.parametrize("profile", ("xrdhttps", "XRDHTTP", "webdav", ""))
    def test_a_name_that_is_not_a_profile_is_accepted_without_a_word(
            self, tmp_path, profile):
        line = ("" if profile == ""
                else f"            brix_guard_profile {profile};\n")
        rc, out = _parse(tmp_path, KNOBS=f"            {GUARD} on;\n" + line)

        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)


class TestTheFlagsRefuseWhatIsNotAFlag:

    @pytest.mark.parametrize("flag", (GUARD, DEFSIGS))
    @pytest.mark.parametrize("value", ("yes", "true", "1", "0", "enabled",
                                       "of"))
    def test_a_value_that_is_not_an_arm_is_refused(self, tmp_path, flag,
                                                   value):
        rc, out = _parse(tmp_path, KNOBS=f"            {flag} {value};\n")

        assert rc != 0
        assert 'it must be "on" or "off"' in out, out

    @pytest.mark.parametrize("flag", (GUARD, DEFSIGS))
    @pytest.mark.parametrize("spelling", ("ON", "On", '"on"', "'off'"))
    def test_the_arm_is_case_insensitive_and_quote_transparent(self, tmp_path,
                                                               flag,
                                                               spelling):
        """Not a nicety: `brix_guard ON` starts a WAF and `brix_guard_default_
        signatures OFF` stops thirteen signatures, and an operator auditing the
        corpus by grepping for the lower-case token would find neither.  Both
        inherit this from ngx_conf_set_flag_slot's ngx_strcasecmp and from the
        parser stripping quotes before the setter sees the value — so it is the
        spelling surface an audit of either flag actually has, and the reason
        this file's own census could not be a corpus grep."""
        rc, out = _parse(tmp_path, KNOBS=f"            {flag} {spelling};\n")

        assert rc == 0, out

    @pytest.mark.parametrize("flag", (GUARD, DEFSIGS))
    @pytest.mark.parametrize("line", ("{flag};", "{flag} on off;",
                                      "{flag} on on;"))
    def test_an_arity_other_than_one_is_refused(self, tmp_path, flag, line):
        rc, out = _parse(tmp_path,
                         KNOBS="            " + line.format(flag=flag) + "\n")

        assert rc != 0
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", (GUARD, DEFSIGS))
    def test_writing_it_twice_in_one_scope_is_refused(self, tmp_path, flag):
        rc, out = _parse(tmp_path,
                         KNOBS=f"            {flag} on;\n"
                               f"            {flag} off;\n")

        assert rc != 0
        assert "directive is duplicate" in out, out


class TestTheFlagsAreHttpOnly:
    """Both carry MAIN|SRV|LOC on the http plane and appear in no stream table,
    which is what makes §F's inheritance legal and a stream placement a
    refusal.  Every diagnostic is "not allowed here" rather than "unknown
    directive": nginx searches every module's command table before it checks the
    context, so a misplaced brix_guard is diagnosed by the table it belongs
    to."""

    @pytest.mark.parametrize("flag", (GUARD, DEFSIGS))
    @pytest.mark.parametrize("slot,indent", [("HTTP_KNOBS", "        "),
                                             ("SRV_KNOBS", "        "),
                                             ("KNOBS", "            ")])
    def test_all_three_http_scopes_accept_it(self, tmp_path, flag, slot,
                                             indent):
        rc, out = _parse(tmp_path, **{slot: f"{indent}{flag} off;\n"})

        assert rc == 0, out

    @pytest.mark.parametrize("flag", (GUARD, DEFSIGS))
    @pytest.mark.parametrize("slot,indent", [("OUTER", ""),
                                             ("STREAM_KNOBS", "        "),
                                             ("STREAM_MAIN", "    ")])
    def test_every_other_placement_is_refused(self, tmp_path, flag, slot,
                                              indent):
        rc, out = _parse(tmp_path, **{slot: f"{indent}{flag} off;\n"})

        assert rc != 0
        assert f'"{flag}" directive is not allowed here' in out, out
