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

def _expression_1(path):
    return (
        path.suffix not in CORPUS_SUFFIXES or not path.is_file()
    )


def _guard_corpus_writes_1(token, path, hits):
    if token in path.read_text(errors="replace"):
        hits.append(str(path.relative_to(ROOT)))


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
# phase-101 W2: the HTTP-plane acc on|off arms are no longer hand-written
# per-directive setters in module_acc_directives.c (deleted); one bare name is
# registered once on the shared HTTP-common table via nginx's ngx_conf_set_flag_slot.
HTTP_AUTH_H = ROOT / "src/core/config/http_directives_auth.h"
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


def _acc_block(authdb, arms, gidlifetime, audit=True, plane="stream"):
    """One server's whole acc block, or "" for a server with no engine at all.

    ``arms is None`` is not the same as an empty tuple: a server with no
    ``brix_authdb`` never reaches the installer (``brix_acc_init_server``
    returns at acc/config.c:241-242), which is what lets §A measure one arm in
    isolation while three servers are listening.

    The engine selector + rule-file directives are spelled per plane since the
    W5 rename: stream = brix_authdb_engine / brix_authdb, http = brix_acc_format
    / brix_acc_authdb (XrdAcc is reached only through brix_acc_* on HTTP).  The
    tunables (brix_acc_audit / brix_acc_gidlifetime / the arms) are one bare
    family on both planes.
    """
    if arms is None:
        return ""
    if plane == "http":
        lines = ["brix_acc_format xrdacc;", f"brix_acc_authdb {authdb};"]
    else:
        lines = ["brix_authdb_engine xrdacc;", f"brix_authdb {authdb};"]
    if audit:
        lines.append("brix_acc_audit all;")
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
                "HTTP_ACC": _acc_block(authdb, http, gidlifetime, audit=False,
                                       plane="http")},
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

