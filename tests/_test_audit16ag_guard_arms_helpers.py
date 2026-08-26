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

