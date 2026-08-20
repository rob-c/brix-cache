"""The three acc-engine flags of the stream plane at VALUE granularity — audit
§Method, 16th tranche, file 17.

WHY THIS FILE EXISTS
--------------------
Re-running the audit's Method (steps 1-2) per (directive, VALUE) rather than per
directive NAME leaves a residue of flags whose second arm no config, test or
document in the tree has ever written.  Files 14-16 closed the WebDAV module's
nine.  The stream plane's authorization block declares three more, side by side
in one header, all with the same shape::

    { ngx_string("brix_acc_pgo"),                   directives_auth.h:188
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.pgo),
      NULL },

``brix_acc_resolve_hosts`` (:202) and ``brix_acc_encoding`` (:216) differ only in
the field.  All three merge to 0 (server_conf_merge_security.c:70-72), the corpus
writes ``on`` for each of them, and before this file it wrote ``off`` for none —
so for each of the three, the arm an operator reaches for when TURNING SOMETHING
BACK OFF was never once executed.

Two existing files touch this ground and stop short of it.
``test_acc_residual.py`` covers ``brix_acc_resolve_hosts on`` (RA3) and
``brix_acc_encoding on`` (RB2), and names its control arm "off" while WRITING
ABSENCE — which is the gap, not the closure.  ``test_audit15f_acc_group_
resolution.py`` covers ``brix_acc_pgo on`` against an absent control for the same
reason.  Absence and ``off`` reach the merge as NGX_CONF_UNSET and 0; that they
end up at the same place is a thing to measure, not to assume, and §A does.

WHAT THE OBSERVABLE IS
----------------------
All three flags change how an XrdAcc authdb is read, so the reading is one
kXR_open verdict per authdb rule.  The identity comes from ``brix_auth unix``,
the one scheme where a loopback client simply declares its name
(auth/unix/auth.c): the test authenticates as the account it actually runs as,
and the engine resolves that account's real Unix gidlist through NSS
(acc/groups.c) — the input ``g <group>`` rules match on.  No fixture users, no
privileges.  One authdb serves every arm::

    u <user>               /u-own  rl     the identity arrived
    g <primary group>      /g-prim rl     unaffected by every arm below
    g <supplementary grp>  /g-supp rl     brix_acc_pgo decides this row
    g brix-no-such-group   /g-none rl     never granted, on any arm
    h <reverse name>       /pub    rl     brix_acc_resolve_hosts decides this
    u *                    /a%20b  rl     brix_acc_encoding decides this

so a verdict that moves between two arms names the arm that moved it, and a
verdict that does not move is the attribution control.

WHAT THE SECTIONS ESTABLISH
---------------------------
§A  ``brix_acc_pgo``, one arm per process.  ``off`` and ABSENT are the same
    configuration measured through two different routes; ``on`` drops every
    supplementary group and moves exactly one row.  The refusal is
    kXR_NotAuthorized and never kXR_NotFound, so a narrowing is never read off a
    seeding slip.

§B  ``brix_acc_resolve_hosts``, three arms in ONE process — legitimate here
    because this flag really is per-server (which is what §D's control says and
    what makes §D a finding).  A ``h <name>`` rule is inert until the flag is
    written: an ACL keyed on a hostname grants nothing at all in the ``off`` and
    absent arms.

§C  ``brix_acc_encoding``, likewise three arms in one process, and not a no-op in
    either direction: the flag SWAPS which path the rule ``/a%20b`` covers.
    Written ``off``, the rule guards the literal path ``/a%20b`` and refuses
    ``/a b``; written ``on``, exactly the reverse.  An operator who turns it on
    to gain the decoded path silently loses the escaped one.

§D  THE FINDING (defect candidate #92).  ``brix_acc_pgo`` is declared
    NGX_STREAM_SRV_CONF and is not per-server: ``brix_acc_build()`` installs it
    into a PROCESS global (acc/config.c:47 → acc/groups.c:33,43), and
    ``brix_acc_init_server()`` runs once per server (process.c:235), so the LAST
    engine-carrying server in configuration order decides for every server in the
    worker.  Measured in both directions — a server that writes ``on`` loses it
    to a later server that writes nothing, and a server that writes ``off`` is
    silently narrowed by a later server's ``on``.  The other two flags are read
    per server on every consultation and do NOT travel, which is the control that
    keeps this from being a harness artefact.

§E  The second and third channels of the same finding.  The http plane declares
    the same three names again (webdav/module_commands.c:103,:111,:119) and
    builds its acc tables LAZILY, on the first request that reaches the location
    (acc/config.c:209-217) — so a single anonymous HTTP GET, itself refused 403,
    installs the globals and changes what the root:// servers on other ports do.
    And because the resolved gidlist is cached process-wide per user for
    ``brix_acc_gidlifetime`` seconds (default 43200), the change is invisible
    until the entry expires: the same configuration behaves one way for twelve
    hours and another way afterwards.

§F  The parse tier: both arms in both declared scopes, every other placement, the
    two planes' different invalid-value messages, arity, case, and the duplicate
    divergence — the stream declaration refuses a repeated write, the http
    setter accepts it silently.

§G  The declarations, the merges and the corpus census every reading above rests
    on.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
Nothing here is about whether the narrowing is correct XrdAcc behaviour — §A says
what ``on`` does, and 15f already covers the gidretran neighbours.  §D is about
SCOPE: a directive declared per-server that is not per-server.  And §B's flag
makes reverse DNS an authorization input, which is an XrdAcc property this file
measures rather than endorses.

Ledger: lc-audit16q-acc-engine — three root:// ports (A/B/C) and one http port,
one nginx.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=. TEST_PORT_START=25000 \
        pytest test_audit16q_acc_engine_flag_arms.py -q -p no:randomly
"""

import getpass
import grp
import os
import pwd
import socket
import struct
import time
from pathlib import Path

import pytest
import requests

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN, url_host
# The diagnostic filter belongs to tranche file 10; a substring search over the
# whole `nginx -t` output would match the temp directory rather than a message.
from test_audit16j_root_caps_flags import _diagnostics
from test_pgwrite_cse import _handshake_login, kXR_ok
from test_unix_auth_wire import _auth, _open_read

pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16q-acc-engine")]

NAME = "lc-audit16q-acc-engine"
TEMPLATE = "nginx_audit16q_acc_engine.conf"

ROOT = Path(__file__).resolve().parents[1]
DIRECTIVES_H = ROOT / "src/protocols/root/stream/directives_auth.h"
MERGE_C = ROOT / "src/core/config/server_conf_merge_security.c"
ACC_CONFIG_C = ROOT / "src/auth/authz/acc/config.c"
ACC_GROUPS_C = ROOT / "src/auth/authz/acc/groups.c"
PROCESS_C = ROOT / "src/core/config/process.c"
SERVER_INIT_C = ROOT / "src/core/config/process_server_init.c"
WEBDAV_COMMANDS_C = ROOT / "src/protocols/webdav/module_commands.c"
WEBDAV_ACC_C = ROOT / "src/protocols/webdav/module_acc_directives.c"
CONFIGS_DIR = Path(__file__).resolve().parent / "configs"

# The three subjects, and the conf field each one's value lands in.
SUBJECTS = {"brix_acc_pgo": "acc.pgo",
            "brix_acc_resolve_hosts": "acc.resolve_hosts",
            "brix_acc_encoding": "acc.encoding"}

# The arms, spelled out as literals rather than assembled from a name and a
# value: the audit's own step-1/step-2 measurement is a grep for
# `<directive> <value>;` over the tree, so a token this file only ever builds at
# runtime would leave the gap exactly where it was found.
PGO_ON = "brix_acc_pgo on;"
PGO_OFF = "brix_acc_pgo off;"
RESOLVE_ON = "brix_acc_resolve_hosts on;"
RESOLVE_OFF = "brix_acc_resolve_hosts off;"
ENCODING_ON = "brix_acc_encoding on;"
ENCODING_OFF = "brix_acc_encoding off;"

OFF_ARMS = (PGO_OFF, RESOLVE_OFF, ENCODING_OFF)

# kXR codes.  The distinction is the point: an authorization narrowing and a
# missing file are both "the open failed".
KXR_NOT_AUTHORIZED = 3010
KXR_NOT_FOUND = 3011
GRANTED = "granted"

NO_SUCH_GROUP = "brix-no-such-group"
NO_SUCH_HOST = "brix-no-such-host"
SEED = b"ACC-ARM-SEED\n"

# One rule per row of the authdb, and the two paths the encoding arms swap
# between.  Both of those exist on disk, so neither arm's refusal can be a
# missing file.
RULE_PATHS = {"u-own": "/u-own/f.txt",
              "g-prim": "/g-prim/f.txt",
              "g-supp": "/g-supp/f.txt",
              "g-none": "/g-none/f.txt",
              "host": "/pub/f.txt",
              "space": "/a b/f.txt",
              "escaped": "/a%20b/f.txt"}
RULE_DIRS = ("u-own", "g-prim", "g-supp", "g-none", "pub", "a b", "a%20b")

# Every verdict with no arm written anywhere, measured.  Three of these rows are
# what the three subjects move, and the other four are what none of them touch.
BASELINE = {"u-own": GRANTED,
            "g-prim": GRANTED,
            "g-supp": GRANTED,
            "g-none": KXR_NOT_AUTHORIZED,
            "host": KXR_NOT_AUTHORIZED,
            "space": KXR_NOT_AUTHORIZED,
            "escaped": GRANTED}

# What each `on` arm does to that table, and nothing else.
PGO_ON_VERDICTS = {**BASELINE, "g-supp": KXR_NOT_AUTHORIZED}
RESOLVE_ON_VERDICTS = {**BASELINE, "host": GRANTED}
ENCODING_ON_VERDICTS = {**BASELINE, "space": GRANTED,
                        "escaped": KXR_NOT_AUTHORIZED}


def _identity():
    """(user, primary group name, supplementary group name).

    Skips when the account has no supplementary group: without one there is
    nothing for brix_acc_pgo to narrow, and §A would measure an identity.
    """
    user = getpass.getuser()
    try:
        entry = pwd.getpwnam(user)
    except KeyError:                                     # pragma: no cover
        pytest.skip(f"{user} is not a local NSS account")
    for gid in os.getgrouplist(user, entry.pw_gid):
        if gid == entry.pw_gid:
            continue
        try:
            supp = grp.getgrgid(gid).gr_name
        except KeyError:
            continue
        return user, grp.getgrgid(entry.pw_gid).gr_name, supp
    pytest.skip(f"{user} has no resolvable supplementary group")


def _reverse_name():
    """The loopback address's reverse name, or None.

    ``brix_acc_resolve_hosts`` turns the peer address into a NAME and matches
    ``h`` rules against it; with no reverse record the engine keeps the numeric
    address, both arms agree, and §B has nothing to measure.
    """
    try:
        name = socket.getnameinfo((HOST, 0), 0)[0]
    except OSError:                                      # pragma: no cover
        return None
    return name if name and name != HOST else None


PTR = _reverse_name()
_needs_ptr = pytest.mark.skipif(
    PTR is None,
    reason="the loopback address has no reverse name; a `h` rule is unmeasurable")
_needs_nginx = pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                                  reason=f"nginx not executable: {NGINX_BIN}")


def _acc_block(authdb, arms, gidlifetime, audit=True):
    """One server's whole acc block, or "" for a server with no engine at all.

    ``arms is None`` is not the same as an empty tuple: a server with no
    ``brix_authdb`` never reaches the installer (``brix_acc_init_server``
    returns at acc/config.c:241-242), which is what lets §A measure one arm in
    isolation while three servers are listening.
    """
    if arms is None:
        return ""
    lines = ["brix_authdb_format xrdacc;", f"brix_authdb {authdb};"]
    if audit:
        lines.append("brix_authdb_audit all;")
    if gidlifetime is not None:
        # The resolved gidlist is cached process-wide per user; a one-second TTL
        # keeps a verdict a reading of the CONFIGURATION rather than of when the
        # first probe happened to run.  §E measures what the default does.
        lines.append(f"brix_acc_gidlifetime {gidlifetime};")
    lines.extend(arms)
    return "\n        ".join(lines)


class _Engine:
    """The three root:// listeners, the http listener behind them, and the one
    authdb they share."""

    def __init__(self, endpoint, user, lifecycle):
        self.endpoint = endpoint
        self.user = user
        self.lifecycle = lifecycle
        self.ports = {"A": endpoint.port,
                      "B": endpoint.extra_ports["B_PORT"],
                      "C": endpoint.extra_ports["C_PORT"]}
        self.http_port = endpoint.extra_ports["HTTP_PORT"]
        self.logs = Path(endpoint.prefix) / "logs"

    def swap(self, **slots):
        """Rewrite named template slots and restart, same prefix and same ports.

        The two §A cases that need both arms of one flag use this rather than a
        second instance: everything the verdict could otherwise depend on — the
        authdb, the export, the account, the sockets — is held fixed, and the
        stream declaration refuses two writes in one server anyway (§F).
        """
        self.lifecycle.reconfigure(NAME, **slots)
        self.lifecycle.restart(NAME)
        return self

    def verdict(self, server, rule):
        """Authenticate as the running account on `server` and open `rule`.

        Returns "granted", or the kXR code behind the refusal — so an
        authorization narrowing (3010) is never confused with a seeding slip
        (3011).
        """
        sock = _handshake_login(host=HOST, port=self.ports[server])
        try:
            status, errcode, _ = _auth(sock, b"unix\x00" + self.user.encode())
            assert status == kXR_ok, f"unix auth refused: {status}/{errcode}"
            status, body = _open_read(sock, RULE_PATHS[rule].encode())
            if status == kXR_ok:
                return GRANTED
            return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else None
        finally:
            sock.close()

    def verdicts(self, server):
        """Every rule's verdict on one listener, for whole-arm assertions."""
        return {rule: self.verdict(server, rule) for rule in RULE_PATHS}

    def await_verdict(self, server, rule, expected, timeout=8.0):
        """`verdict()` once it reaches `expected`, or at the deadline.

        Used only where a change is expected to ARRIVE (§E): the gidlist cache
        holds the previous resolution until its TTL expires, so the reading is
        polled rather than taken once behind a fixed sleep.
        """
        deadline = time.monotonic() + timeout
        while True:
            got = self.verdict(server, rule)
            if got == expected or time.monotonic() > deadline:
                return got
            time.sleep(0.25)

    def http_get(self, rule="u-own", timeout=30):
        return requests.get(
            f"http://{url_host(HOST)}:{self.http_port}{RULE_PATHS[rule]}",
            timeout=timeout)

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        try:
            return (self.logs / "error.log").read_text(errors="replace")
        except OSError:                          # pragma: no cover - diagnostic
            return "(error log unavailable)"


@pytest.fixture
def engine(lifecycle, tmp_path):
    """A factory for one nginx carrying whichever acc blocks a case names.

    Every listener exports the same data root and reads the same authdb: a
    verdict that differs between two of them cannot be explained by anything but
    the arm — or, in §D, by the fact that it is not the arm at all.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    user, prim, supp = _identity()
    authdb = tmp_path / "authdb"
    authdb.write_text(f"u {user} /u-own rl\n"
                      f"g {prim} /g-prim rl\n"
                      f"g {supp} /g-supp rl\n"
                      f"g {NO_SUCH_GROUP} /g-none rl\n"
                      f"h {PTR or NO_SUCH_HOST} /pub rl\n"
                      "u * /a%20b rl\n")

    def _start(reason, a=None, b=None, c=None, http=None, gidlifetime=1):
        endpoint = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template=TEMPLATE,
            protocol="root",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "A_ACC": _acc_block(authdb, a, gidlifetime),
                "B_ACC": _acc_block(authdb, b, gidlifetime),
                "C_ACC": _acc_block(authdb, c, gidlifetime),
                "HTTP_ACC": _acc_block(authdb, http, gidlifetime, audit=False)},
            reason=reason))
        for name in RULE_DIRS:
            directory = Path(endpoint.data_root) / name
            directory.mkdir(exist_ok=True)
            (directory / "f.txt").write_bytes(SEED)
        return _Engine(endpoint, user, lifecycle)

    def _block(arms, gidlifetime=1):
        """The acc block a test hands back to ``_Engine.swap``."""
        return _acc_block(authdb, arms, gidlifetime)

    _start.identity = (user, prim, supp)
    _start.block = _block
    return _start


# --------------------------------------------------------------------------- #
# §A — brix_acc_pgo, one arm per process                                      #
# --------------------------------------------------------------------------- #

class TestThePgoArms:
    """One engine, on listener A alone.  B and C carry no authdb, so they never
    reach the installer and cannot answer for A — which §D shows is a real risk
    and not a precaution."""

    def test_the_absent_arm_resolves_the_full_gidlist(self, engine):
        """The control every arm below is read against: with no arm written the
        merge default is 0, the engine resolves the whole gidlist, and BOTH the
        primary-group and the supplementary-group rule grant."""
        acc = engine("audit-16q pgo absent", a=())
        assert acc.verdicts("A") == BASELINE

    def test_the_written_off_arm_is_the_absent_arm(self, engine):
        """The arm the corpus never wrote.  ``off`` reaches the merge as 0 and
        absence reaches it as NGX_CONF_UNSET, so the two routes are measured
        rather than assumed to meet — the whole table, not just the row this
        flag owns."""
        acc = engine("audit-16q pgo off", a=(PGO_OFF,))
        assert acc.verdicts("A") == BASELINE

    def test_the_on_arm_drops_every_supplementary_group(self, engine):
        """What the flag is for: the gidlist becomes the passwd entry's primary
        gid alone, so a rule keyed on a supplementary group stops applying while
        the primary one still grants.  A narrowing, not a loss of group
        resolution."""
        acc = engine("audit-16q pgo on", a=(PGO_ON,))
        assert acc.verdicts("A") == PGO_ON_VERDICTS

    def test_the_two_arms_differ_in_exactly_one_rule(self, engine):
        """Both arms in one process and one prefix, swapped in place.  The
        difference is the whole reading: one row, in one direction."""
        acc = engine("audit-16q pgo off then on", a=(PGO_OFF,))
        before = acc.verdicts("A")
        after = acc.swap(A_ACC=engine.block((PGO_ON,))).verdicts("A")
        moved = {rule for rule in RULE_PATHS if before[rule] != after[rule]}
        assert moved == {"g-supp"}, (before, after)

    def test_turning_it_back_off_restores_the_supplementary_rule(self, engine):
        """The mirror, and the reason it is not redundant: it says the row
        follows the TOKEN and not the age of the process.  ``off`` is the arm an
        operator reaches for after trying ``on``, and it is the arm nothing in
        the corpus had ever executed."""
        acc = engine("audit-16q pgo on then off", a=(PGO_ON,))
        assert acc.verdict("A", "g-supp") == KXR_NOT_AUTHORIZED
        assert acc.swap(A_ACC=engine.block((PGO_OFF,))).verdicts("A") == BASELINE

    def test_the_narrowed_rule_is_refused_and_not_missing(self, engine):
        """security-negative: the refusal must be an authorization verdict.
        kXR_NotFound here would mean the seeding failed and the whole section
        was reading an empty export."""
        acc = engine("audit-16q pgo denial code", a=(PGO_ON,))
        assert acc.verdict("A", "g-supp") == KXR_NOT_AUTHORIZED
        assert acc.verdict("A", "g-none") == KXR_NOT_AUTHORIZED
        # The same open on a path the identity DOES hold proves the file, the
        # export and the login are all in place.
        assert acc.verdict("A", "u-own") == GRANTED
        assert KXR_NOT_FOUND not in acc.verdicts("A").values()


# --------------------------------------------------------------------------- #
# §B — brix_acc_resolve_hosts, three arms in one process                      #
# --------------------------------------------------------------------------- #

@_needs_ptr
class TestTheResolveHostsArms:
    """A: written ``off``.  B: written ``on``.  C: nothing.  One process — which
    is only legitimate because this flag is read per server on every
    consultation, and §D's control is what says so."""

    @pytest.fixture
    def three(self, engine):
        return engine("audit-16q resolve_hosts three arms",
                      a=(RESOLVE_OFF,), b=(RESOLVE_ON,), c=())

    def test_the_arms_disagree_within_one_process(self, three):
        """The per-server reading, stated as the disagreement: the same rule,
        the same authdb, the same peer address, three listeners, two answers."""
        assert three.verdict("A", "host") == KXR_NOT_AUTHORIZED
        assert three.verdict("B", "host") == GRANTED
        assert three.verdict("C", "host") == KXR_NOT_AUTHORIZED

    def test_the_written_off_arm_is_the_absent_arm(self, three):
        """The arm the corpus never wrote, measured against the arm it writes by
        omission — every rule, not just the host one."""
        assert three.verdicts("A") == three.verdicts("C") == BASELINE

    def test_the_on_arm_moves_only_the_host_rule(self, three):
        """And the attribution control: turning reverse resolution on must not
        change what the identity or the group rules decide."""
        assert three.verdicts("B") == RESOLVE_ON_VERDICTS

    def test_a_host_rule_grants_nothing_until_the_flag_is_written(self, three):
        """security-negative, and the operator-visible half of §B: an ACL keyed
        on a hostname is INERT in the arm nothing had executed.  Writing
        ``h <name> /pub rl`` and leaving the flag alone produces no grant and no
        diagnostic — the authdb parses, the rule loads, and the entity it is
        matched against carries an address where the rule expects a name."""
        assert three.verdict("A", "host") == KXR_NOT_AUTHORIZED
        assert three.verdict("C", "host") == KXR_NOT_AUTHORIZED
        assert "emerg" not in three.errlog()


# --------------------------------------------------------------------------- #
# §C — brix_acc_encoding, three arms in one process                           #
# --------------------------------------------------------------------------- #

class TestTheEncodingArms:
    """A: written ``off``.  B: written ``on``.  C: nothing.  Both candidate paths
    exist on disk, so every verdict below is an authorization decision."""

    @pytest.fixture
    def three(self, engine):
        return engine("audit-16q encoding three arms",
                      a=(ENCODING_OFF,), b=(ENCODING_ON,), c=())

    def test_the_arms_disagree_within_one_process(self, three):
        assert three.verdict("A", "space") == KXR_NOT_AUTHORIZED
        assert three.verdict("B", "space") == GRANTED
        assert three.verdict("C", "space") == KXR_NOT_AUTHORIZED

    def test_the_written_off_arm_is_the_absent_arm(self, three):
        assert three.verdicts("A") == three.verdicts("C") == BASELINE

    def test_the_on_arm_decodes_the_rule(self, three):
        """``u * /a%20b rl`` becomes a rule about ``/a b``."""
        assert three.verdicts("B") == ENCODING_ON_VERDICTS

    def test_the_flag_swaps_which_path_the_rule_covers(self, three):
        """security-negative, and the reason ``off`` is not "the feature turned
        off": the escaped path is GRANTED in the arms that do not decode and
        REFUSED in the arm that does.  The rule always covers exactly one path;
        the flag chooses which."""
        assert three.verdict("A", "escaped") == GRANTED
        assert three.verdict("C", "escaped") == GRANTED
        assert three.verdict("B", "escaped") == KXR_NOT_AUTHORIZED

    def test_an_operator_turning_it_on_loses_the_escaped_path(self, three):
        """The same swap read as the migration it would be: every path the
        ``off`` arm granted through this rule, the ``on`` arm refuses, and the
        exchange is silent."""
        off_granted = {rule for rule, verdict in three.verdicts("A").items()
                       if verdict == GRANTED}
        on_granted = {rule for rule, verdict in three.verdicts("B").items()
                      if verdict == GRANTED}
        assert off_granted - on_granted == {"escaped"}
        assert on_granted - off_granted == {"space"}


# --------------------------------------------------------------------------- #
# §D — the finding: a per-server declaration that is not per-server            #
# --------------------------------------------------------------------------- #

class TestThePgoScopeIsNotTheDeclaredOne:
    """DEFECT CANDIDATE #92.  Each case below writes an arm on ONE listener and
    reads it on that same listener; what the other listeners carry is the only
    thing that changes."""

    def test_a_later_engine_without_the_flag_undoes_this_servers_on(self,
                                                                    engine):
        """security-negative, the headline: A writes ``brix_acc_pgo on`` and
        gets no narrowing at all, because B — which merely runs the engine and
        says nothing about pgo — installs its merged 0 into the process global
        afterwards.  The server that ASKED to be narrowed is the one that is
        widened, and nothing is logged."""
        acc = engine("audit-16q pgo lost to a later engine",
                     a=(PGO_ON,), b=())
        assert acc.verdict("A", "g-supp") == GRANTED
        assert acc.verdicts("A") == BASELINE

    def test_a_later_engines_on_reaches_the_server_that_wrote_off(self, engine):
        """The mirror, and the one an operator is likelier to hit: A writes
        ``off``, B writes ``on``, and A is narrowed anyway.  Two servers in one
        worker cannot hold two values of a flag their declaration says is
        per-server."""
        acc = engine("audit-16q pgo reaches the off server",
                     a=(PGO_OFF,), b=(PGO_ON,))
        assert acc.verdict("A", "g-supp") == KXR_NOT_AUTHORIZED
        assert acc.verdicts("A") == PGO_ON_VERDICTS

    def test_the_last_engine_in_configuration_order_decides(self, engine):
        """Three servers, two of them writing ``off``, and all three answer with
        the third one's ``on``.  It is not a majority and not the first writer:
        ``brix_acc_init_server`` runs once per server in configuration order and
        the last call wins."""
        acc = engine("audit-16q pgo last writer wins",
                     a=(PGO_OFF,), b=(PGO_OFF,), c=(PGO_ON,))
        for server in ("A", "B", "C"):
            assert acc.verdict(server, "g-supp") == KXR_NOT_AUTHORIZED, server

    def test_the_mirror_confirms_order_and_not_precedence(self, engine):
        """The same three servers with the values exchanged: two ``on`` and a
        trailing ``off`` widen ALL of them.  So ``on`` has no precedence — the
        install is a plain assignment, and position is the whole rule."""
        acc = engine("audit-16q pgo last writer wins, mirrored",
                     a=(PGO_ON,), b=(PGO_ON,), c=(PGO_OFF,))
        for server in ("A", "B", "C"):
            assert acc.verdict(server, "g-supp") == GRANTED, server

    def test_the_encoding_flag_does_not_travel(self, engine):
        """The attribution control.  Same file, same fixture, same two
        listeners, a flag from the same header and the same declaration shape —
        and A keeps its own value.  Whatever is happening to pgo is not a
        property of the harness."""
        acc = engine("audit-16q encoding stays per-server",
                     a=(ENCODING_OFF,), b=(ENCODING_ON,))
        assert acc.verdict("A", "space") == KXR_NOT_AUTHORIZED
        assert acc.verdict("B", "space") == GRANTED

    @_needs_ptr
    def test_the_resolve_hosts_flag_does_not_travel(self, engine):
        """The second control, for the third subject: two servers, two values,
        both honoured.  Two of the three flags in this header are read out of
        the per-server conf at every consultation; one is not."""
        acc = engine("audit-16q resolve_hosts stays per-server",
                     a=(RESOLVE_OFF,), b=(RESOLVE_ON,))
        assert acc.verdict("A", "host") == KXR_NOT_AUTHORIZED
        assert acc.verdict("B", "host") == GRANTED

    def test_the_value_is_installed_into_a_process_global(self):
        """The C behind §D: the per-server value is passed to a setter that
        assigns a file-scope static.  There is no per-server copy to read back,
        which is why the last writer decides."""
        squashed = " ".join(ACC_CONFIG_C.read_text().split())
        assert "brix_acc_groups_set_primary_only(pgo);" in squashed
        groups = " ".join(ACC_GROUPS_C.read_text().split())
        assert "static int acc_primary_only = 0;" in groups
        assert ("void brix_acc_groups_set_primary_only(ngx_int_t on) "
                "{ acc_primary_only = on ? 1 : 0; }") in groups
        # And the reader: one global consulted at resolution time, with no
        # server in scope to ask instead.
        assert "if (acc_primary_only) {" in groups

    def test_every_engine_carrying_server_runs_the_installer(self):
        """Why "the last one" is a rule and not an accident: worker init walks
        cmcf->servers in configuration order and each pass calls
        brix_acc_init_server, which calls brix_acc_build for every server that
        selected the engine and named an authdb."""
        process = " ".join(PROCESS_C.read_text().split())
        assert "for (i = 0; i < cmcf->servers.nelts; i++) {" in process
        init = " ".join(SERVER_INIT_C.read_text().split())
        assert "if (brix_acc_init_server(xcf, cycle) != NGX_OK) {" in init
        acc = " ".join(ACC_CONFIG_C.read_text().split())
        # The early return is what lets §A isolate an arm: no authdb, no install.
        assert ("if (xcf->acc.format != BRIX_AUTHDB_FORMAT_XRDACC "
                "|| xcf->authdb.len == 0) { return NGX_OK; }") in acc
        assert "xcf->acc.tables = brix_acc_build(" in acc

    def test_the_same_call_installs_three_more_process_wide_tunables(self):
        """#92 is a family and not a directive: gidlifetime, nisdomain and
        gidretran ride the same call into the same file-scope statics, so
        test_audit15f_acc_group_resolution.py's gidretran arms inherit the
        finding — its every arm is its own process for exactly this reason."""
        squashed = " ".join(ACC_CONFIG_C.read_text().split())
        for setter in ("brix_acc_groups_set_gidlifetime((time_t) gidlifetime);",
                       "brix_acc_groups_set_nisdomain(nisdomain);",
                       "brix_acc_groups_set_gidretran(gidretran);"):
            assert setter in squashed, setter


# --------------------------------------------------------------------------- #
# §E — the runtime channel, and the cache that hides it                       #
# --------------------------------------------------------------------------- #

class TestTheRequestTriggeredInstall:
    """The http plane declares the same three names and builds its tables on
    first use, so the install is reachable from the network."""

    def test_an_anonymous_request_installs_the_flag_for_the_root_servers(
            self, engine):
        """security-negative, and the sharpest form of #92: A writes
        ``brix_acc_pgo off`` and honours it — until one HTTP GET arrives at a
        location on a different port, whose own ``on`` is installed process-wide
        while the request that carried it is being refused.  A configuration
        that was correct at worker start is narrowed by traffic."""
        acc = engine("audit-16q http request installs pgo",
                     a=(PGO_OFF,), http=(PGO_ON,))
        assert acc.verdict("A", "g-supp") == GRANTED
        assert acc.http_get().status_code == 403
        assert acc.await_verdict("A", "g-supp",
                                 KXR_NOT_AUTHORIZED) == KXR_NOT_AUTHORIZED
        # The rest of A's table is untouched: this is the pgo row moving, not
        # the export or the login breaking.
        assert acc.verdicts("A") == PGO_ON_VERDICTS

    def test_the_request_that_installs_it_is_itself_refused(self, engine):
        """The request needs no credential and no success: it is refused by the
        very tables its arrival built.  Removing the location's acc block and
        restarting serves the same GET 200, so the 403 is the engine's verdict
        and not a WebDAV or export failure."""
        acc = engine("audit-16q the installing request is refused",
                     a=(PGO_OFF,), http=(PGO_ON,))
        refused = acc.http_get()
        assert refused.status_code == 403
        assert SEED not in refused.content
        served = acc.swap(HTTP_ACC="").http_get()
        assert served.status_code == 200
        assert served.content == SEED
        # And with the location's engine gone, A's own `off` stands.
        assert acc.verdict("A", "g-supp") == GRANTED

    def test_the_default_group_cache_hides_the_change_for_twelve_hours(
            self, engine):
        """The third channel: the same configuration, minus the one-second
        ``brix_acc_gidlifetime`` every other case writes.  The resolved gidlist
        is cached process-wide per user for 43200 seconds, so the flip §E's
        first case measures in a second is INVISIBLE here — a server that has
        answered one request keeps answering the old way until the entry
        expires, and one that has not starts answering the new way at once."""
        acc = engine("audit-16q the gid cache hides the install",
                     a=(PGO_OFF,), http=(PGO_ON,), gidlifetime=None)
        assert acc.verdict("A", "g-supp") == GRANTED       # populates the cache
        assert acc.http_get().status_code == 403
        time.sleep(2.0)
        assert acc.verdict("A", "g-supp") == GRANTED
        groups = " ".join(ACC_GROUPS_C.read_text().split())
        assert "static time_t acc_gidlifetime = 43200;" in groups
        assert "e->expiry = now + acc_gidlifetime;" in groups

    def test_the_http_tables_are_built_on_the_first_request(self):
        """Why a REQUEST can install anything at all: the http plane has no
        per-location init hook, so the build is lazy and its trigger is
        traffic."""
        squashed = " ".join(ACC_CONFIG_C.read_text().split())
        assert "if (acc->tables == NULL) {" in squashed
        assert "acc->tables = brix_acc_http_build(acc, log);" in squashed

    def test_the_http_plane_installs_through_the_same_builder(self):
        """And why the install is the same install: brix_acc_http_build passes
        the location's pgo into brix_acc_build, which is the function that
        assigns the global."""
        squashed = " ".join(ACC_CONFIG_C.read_text().split())
        assert ("return brix_acc_build((const char *) acc->authdb.data, "
                "acc->gidlifetime, acc->pgo,") in squashed


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                         #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on file 14's scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about: the
    scaffold's probe location and stream server write nothing about the acc
    engine, so a negative is never answered by a duplicate diagnostic first.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "STREAM_PORT": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "DATA": str(data),
              "LOC_KNOBS": "", "SRV_KNOBS": "", "HTTP_KNOBS": "",
              "OUTER": "", "STREAM_KNOBS": "", "STREAM_MAIN": "",
              "EXTRA_LOC": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16nparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


# The two scopes these three names are declared at — one per plane, and NOT the
# same scope: the stream declaration is a server, the http one a location.
RIGHT_SCOPES = {"STREAM_KNOBS": "        ", "LOC_KNOBS": "            "}
# Every placement neither declaration names.  SRV_KNOBS is here because the http
# twin's mask is NGX_HTTP_LOC_CONF alone, and STREAM_MAIN because the stream
# declaration's is NGX_STREAM_SRV_CONF alone.
WRONG_SCOPES = ("SRV_KNOBS", "HTTP_KNOBS", "OUTER", "STREAM_MAIN")


@_needs_nginx
class TestTheParseTier:
    """Values, arity, duplicates and the placement matrix, asked with nothing
    else in the file that could answer instead."""

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, arm,
                                                       directive):
        """The audit's step-1 question at the declared stream scope.  Three of
        these six cases are the arm the corpus never wrote, and none of them
        advises anything: turning an engine knob off is not a
        misconfiguration."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        {directive} {arm};\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_an_http_location(self, tmp_path, arm,
                                                        directive):
        """The other plane's declaration of the same three names, which is a
        TAKE1 with a hand-written setter rather than a flag slot — so its arms
        are a separate measurement, not a corollary of the ones above."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {directive} {arm};\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("scope", WRONG_SCOPES)
    def test_no_other_placement_is_allowed(self, tmp_path, scope, directive):
        """Every placement the two masks leave out must refuse, and the refusal
        must be about the CONTEXT: nginx searches every module's command table
        before it checks scope, so "unknown directive" here would mean the name
        had been dropped from both tables rather than misplaced.  With two
        modules declaring the same name in different planes, this is also what
        says neither declaration is quietly covering for the other."""
        rc, out = _parse(tmp_path, **{scope: f"    {directive} on;\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_an_unknown_value_is_refused_on_the_stream_plane(self, tmp_path,
                                                             directive):
        """``ngx_conf_set_flag_slot`` compares against exactly two tokens; a
        flag that silently read anything else as true would arm an
        authorization change its operator never wrote."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        {directive} maybe;\n")
        assert rc != 0, out
        assert f'invalid value "maybe" in "{directive}" directive' in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_an_unknown_value_is_refused_on_the_http_plane(self, tmp_path,
                                                           directive):
        """The hand-written setter validates too — with its own message."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {directive} maybe;\n")
        assert rc != 0, out
        assert 'invalid value "maybe" (expected on|off)' in out, out

    def test_the_http_refusal_does_not_name_the_directive(self, tmp_path):
        """A divergence worth having a test for rather than a habit: the stream
        plane's message names the directive and the http plane's does not, so a
        location carrying several acc knobs reports a typo without saying which
        line it is on.  A fix belongs in brix_acc_http_set_flag; this is the
        test that would notice it."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS="            brix_acc_pgo maybe;\n")
        assert rc != 0, out
        assert "brix_acc_pgo" not in out.split("invalid value", 1)[1], out

    @pytest.mark.parametrize("scope,indent", sorted(RIGHT_SCOPES.items()))
    @pytest.mark.parametrize("token", ("ON", "OFF"))
    def test_case_is_not_significant_on_either_plane(self, tmp_path, token,
                                                     scope, indent):
        """Both planes compare case-insensitively — nginx's flag slot with
        ngx_strcasecmp, and the http setter with the same call by hand.  Worth
        pinning: it is the one respect in which the two validators agree."""
        rc, out = _parse(tmp_path,
                         **{scope: f"{indent}brix_acc_pgo {token};\n"})
        assert rc == 0, out

    @pytest.mark.parametrize("scope,indent", sorted(RIGHT_SCOPES.items()))
    def test_no_argument_is_refused(self, tmp_path, scope, indent):
        rc, out = _parse(tmp_path, **{scope: f"{indent}brix_acc_pgo;\n"})
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("scope,indent", sorted(RIGHT_SCOPES.items()))
    def test_two_arguments_are_refused(self, tmp_path, scope, indent):
        """NGX_CONF_FLAG is NGX_CONF_TAKE1 plus a value check, and the http twin
        is a TAKE1 outright, so a second argument is an arity error on both
        planes rather than a silently ignored token."""
        rc, out = _parse(tmp_path, **{scope: f"{indent}brix_acc_pgo on off;\n"})
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    def test_a_repeated_write_is_a_duplicate_on_the_stream_plane(self,
                                                                 tmp_path):
        """``ngx_conf_set_flag_slot`` refuses a second write to the same slot,
        which is why §A's two arms needed a reconfigure rather than two lines."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS="        brix_acc_pgo on;\n"
                                      "        brix_acc_pgo off;\n")
        assert rc != 0, out
        assert "is duplicate" in out, out

    def test_a_repeated_write_is_accepted_on_the_http_plane(self, tmp_path):
        """And the http setter does not: it writes the loc-confs and returns, so
        two contradictory lines in one location parse clean and the last one
        wins in silence.  The divergence is measured here rather than described,
        because the two declarations of one directive name are what an operator
        reads as a single feature."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS="            brix_acc_pgo on;\n"
                                   "            brix_acc_pgo off;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out


# --------------------------------------------------------------------------- #
# §G — the declarations, the merges and the corpus                            #
# --------------------------------------------------------------------------- #

def _squashed(path):
    return " ".join(path.read_text().split())


# Where the audit's step-1/step-2 grep looks, and the suffixes it counts.  These
# three directives are configured from test sources and documented in prose;
# unlike files 14-16's subjects, no rendered template writes them at all, so a
# census restricted to configs/ would report a gap that is not there and miss the
# one that is.
CORPUS_ROOTS = (ROOT / "tests", ROOT / "docs", ROOT / "k8s-tests")
CORPUS_SUFFIXES = (".py", ".conf", ".md")


def _corpus_writes(token):
    """Every file OUTSIDE this one that spells `token` literally."""
    here = Path(__file__).resolve()
    hits = []
    for root in CORPUS_ROOTS:
        for path in root.rglob("*"):
            if path.suffix not in CORPUS_SUFFIXES or not path.is_file():
                continue
            if path.resolve() == here:
                continue
            try:
                if token in path.read_text(errors="replace"):
                    hits.append(str(path.relative_to(ROOT)))
            except OSError:                      # pragma: no cover - diagnostic
                continue
    return sorted(hits)


class TestTheDeclarationsAndTheCorpus:
    """Every reading above is an inference from a handful of lines of C and from
    what the corpus does not contain.  If either changes, the tests would keep
    passing while measuring something else."""

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_stream_declaration_is_a_server_scoped_flag_slot(self,
                                                                 directive):
        """One scope, ``ngx_conf_set_flag_slot``, NGX_STREAM_SRV_CONF_OFFSET —
        the declaration that promises §D what §D does not get."""
        text = DIRECTIVES_H.read_text()
        marker = f'{{ ngx_string("{directive}"),'
        assert marker in text, directive
        # splitlines()[0] is the tail of the marker's own line, which is empty.
        lines = [ln.strip() for ln in text.split(marker, 1)[1].splitlines()[1:5]]
        assert lines[0] == "NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,", lines
        assert lines[1] == "ngx_conf_set_flag_slot,", lines
        assert lines[2] == "NGX_STREAM_SRV_CONF_OFFSET,", lines
        assert lines[3] == ("offsetof(ngx_stream_brix_srv_conf_t, "
                            f"{SUBJECTS[directive]}),"), lines

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_it_merges_to_zero(self, directive):
        """The bare arm reads this 0, which is what makes ``off`` the arm nobody
        needed to write and ``on`` the arm everybody did.  A merge default of 1
        would have made the corpus census come out the other way round."""
        field = SUBJECTS[directive]
        assert (f"ngx_conf_merge_value(conf->{field}, prev->{field}, 0);"
                in _squashed(MERGE_C))

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_http_twin_is_a_take1_with_its_own_setter(self, directive):
        """The same name on the other plane, declared NGX_HTTP_LOC_CONF |
        NGX_CONF_TAKE1 behind a hand-written setter — which is why §F measures
        the two planes separately and why their diagnostics differ."""
        text = WEBDAV_COMMANDS_C.read_text()
        marker = f'{{ ngx_string("{directive}"),'
        assert marker in text, directive
        lines = [ln.strip() for ln in text.split(marker, 1)[1].splitlines()[1:3]]
        assert lines[0] == "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,", lines
        setter = directive.replace("brix_acc_", "brix_acc_http_set_")
        assert lines[1] == f"{setter}, 0, 0, NULL }},", lines

    def test_the_http_setter_writes_both_loc_confs_and_validates_by_hand(self):
        """One call site writes the WebDAV and S3 loc-confs together, and the
        validation is a pair of ngx_strcasecmp calls with no duplicate check —
        the source behind §F's last two cases."""
        squashed = _squashed(WEBDAV_ACC_C)
        assert ('if (ngx_strcasecmp(val->data, (u_char *) "on") == 0) '
                "{ *wp = *sp = 1; }") in squashed
        assert ('else if (ngx_strcasecmp(val->data, (u_char *) "off") == 0) '
                "{ *wp = *sp = 0; }") in squashed
        assert ('"invalid value \\"%V\\" (expected on|off)", val);') in squashed
        # No slot is compared against its unset marker anywhere in the file, so
        # there is nothing that could refuse a second write.
        assert "is duplicate" not in squashed
        assert "NGX_CONF_UNSET" not in squashed

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_corpus_writes_the_on_arm_and_never_the_off_arm(self,
                                                               directive):
        """Steps 1 and 2 of the audit's own measurement, as this file found
        them: the ``on`` arm is written — in test sources and in the
        authorization docs — and the ``off`` arm was written nowhere.  If
        another file starts writing ``off``, re-run the gap table rather than
        relaxing this."""
        assert _corpus_writes(f"{directive} on;"), \
            f"{directive} is written nowhere at all"
        assert _corpus_writes(f"{directive} off;") == []

    @pytest.mark.parametrize("arm", OFF_ARMS)
    def test_this_file_writes_every_off_arm_literally(self, arm):
        """The closure itself.  The audit greps the tree for
        ``<directive> <value>;``, so an arm assembled at runtime from a name and
        a token would leave the gap open while the tests passed."""
        assert arm in Path(__file__).read_text()

    def test_the_template_carries_four_engine_slots_and_writes_no_arm(self):
        """The template offers a whole acc block per listener and takes no
        position on any subject: three root:// servers, one http location, and
        not one of the six arms written in the file itself."""
        text = (CONFIGS_DIR / TEMPLATE).read_text()
        for slot in ("{A_ACC}", "{B_ACC}", "{C_ACC}", "{HTTP_ACC}"):
            assert slot in text, slot
        squashed = " ".join(text.split())
        for directive in SUBJECTS:
            assert f"{directive} on;" not in squashed, directive
            assert f"{directive} off;" not in squashed, directive
        assert squashed.count("brix_root on;") == 3
        assert squashed.count("brix_auth unix;") == 3

    def test_the_ledger_owns_one_port_per_listener(self):
        """Four sockets, four ledger allocations, all distinct.  Two root://
        servers sharing a port would not be a slower test: holding three arms
        side by side in one process is what §B, §C and §D each measure."""
        slot = LIFECYCLE_SHARED_PORTS[NAME]
        ports = [slot["port"], *slot["extra"].values()]
        assert sorted(slot["extra"]) == ["B_PORT", "C_PORT", "HTTP_PORT"]
        assert len(set(ports)) == 4, ports
