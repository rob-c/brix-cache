"""tests/test_audit16ai_gridftp_write_gate.py — audit tranche 16, file 35.

WHY THIS FILE EXISTS
    `brix_gridftp_allow_write` is the fourth GridFTP gate and the one file 31
    (test_audit16ae_gridftp_gate_off_arms.py) left behind.  It is written `on` by
    THIRTY-ONE configs in this tree.  The token `off` is written by NONE of them.

    The two places in the corpus that mean to be a read-only export are both
    absences, and one of them says otherwise:

        configs/nginx_gridftp_plain_ev_ro.conf  deletes the line, and its header
                                                says it deletes the line
        configs/nginx_gridftp_metrics.conf      its header says the RO_PORT
                                                gateway writes
                                                `brix_gridftp_allow_write off`
                                                — the server block below writes
                                                no such line

    So the disarming arm has never been written, and the only live probe of a
    disabled gate anywhere in the suite is a single STOR
    (test_gridftp_metrics.py::test_read_only_export_refuses_stor_as_forbidden).
    One verb, on one of the seven the gate governs, on the plane whose
    read-onliness is an omission.

    §A writes the missing token and compares it, verb by verb, against the
    omission it has always stood in for.  The equality holds — the merge default
    is 0 at ftp_module_merge.c:159 — and, as in files 31-34, what writing the
    arm turned out to be worth is everything after it.

THE GATE'S SHAPE
    Seven verbs, four call sites, and they do not behave alike:

        ev_xfer_guards          ftp_ev_xfer.c:333   STOR, APPE
        ftp_ev_ns_mutate        ftp_ev_cmd.c:177    MKD/XMKD, DELE, RMD/XRMD
        brix_ftp_ev_cmd_rnfr    ftp_ev_cmd.c:406    RNFR
        brix_ftp_ev_cmd_rnto    ftp_ev_cmd.c:431    RNTO

    Only the first meters anything.  Its own comment says why it meters what it
    meters — "Only the permission verdict is metered: it is an authorization
    outcome for the requested op" — and the other three call sites, which are
    also permission verdicts for a requested op, meter nothing.

THE FINDINGS
    DEFECT CANDIDATE #133 — the tree's one config that claims to write
    `brix_gridftp_allow_write off` does not write it.
    configs/nginx_gridftp_metrics.conf:11 documents its RO_PORT gateway as
    "brix_gridftp_allow_write off, the security-negative path"; the block at
    :48-52 carries `brix_gridftp` and `brix_gridftp_export` and nothing else.
    The gateway is read-only anyway — by merge, not by the line — so the test
    that rests on it passes, which is exactly why the mismatch survived.  §K
    reads both files and states it as a measurement rather than a claim about a
    comment.

    DEFECT CANDIDATE #134 — five of the seven gated verbs refuse in total
    silence.  A client that issues MKD, XMKD, DELE, RMD, XRMD, RNFR and RNTO
    against a read-only export gets seven refusals, and afterwards:

        * no `brix_io_ops_total` row moved at all — not `forbidden`, not
          anything.  The only counter that moved in the whole scrape was
          `brix_auth_total{proto="gridftp",method="none",status="ok"}`, from the
          login;
        * the error log gained three lines, and all three are session lifecycle
          (connect, session start, session end).  Not one names a refusal, at
          any level, with `error_log ... info` — the most verbose setting an
          operator can practically run.

    A refused STOR books `brix_io_ops_total{proto="gridftp",op="write",
    status="forbidden"}`, so the plane is not that the gateway cannot meter
    refusals; it is that six of the seven do not.  §D and §E measure it.

    DEFECT CANDIDATE #135 — RNTO's own permission check is unreachable.
    brix_ftp_ev_cmd_rnto tests `fc->rnfr_set` first and CONSUMES it ("single-shot
    pairing", :430) before it tests `allow_write` at :431.  `rnfr_set` is set in
    exactly one place — the tail of brix_ftp_ev_cmd_rnfr — which is itself behind
    the same gate.  On a read-only export `rnfr_set` is therefore always 0, RNTO
    always answers `503 RNFR required first`, and the `550 Permission denied
    (read-only)` two lines below it can never be emitted.  §F measures the
    reachability, not the reading.

    DEFECT CANDIDATE #136 — `SITE` answers `200 OK` to every subcommand,
    including ones the gateway does not implement and would refuse if it did.
    ev_grp_session (ftp_ev_dispatch.c:259) is a bare `return brix_ftp_ev_reply(fc,
    "200 OK\\r\\n")` with the argument unread, so `SITE CHMOD 000 /seed.txt` on a
    READ-ONLY export is answered `200 OK` and the file's mode is unchanged.  The
    gate is not bypassed — nothing happened — but a client is told a mutation
    succeeded on an export that refuses mutations.  §H measures both halves: the
    reply, and the unchanged mode on disk.

    DEFECT CANDIDATE #137 — `brix_gridftp_verify_write on` beside
    `brix_gridftp_allow_write off` parses clean and draws no diagnostic.  It is
    the inert-companion shape #101 and #102 found on other planes: an integrity
    knob armed on a server that can never write, which is a configuration that
    can only be a mistake and which nothing in the merge cross-validates.  §I
    measures it on the wire and §L at parse time.

WHAT THIS FILE DOES NOT CLAIM
    Not that the gate leaks.  It does not: across four faces and every verb
    behind it, nothing on a disabled face reached the disk — no directory
    created, no file deleted, no rename, no mode change, no byte written.  §A
    and §B are as much a proof of that as they are of the equality.

    Not that `503 RNFR required first` is the wrong reply to a bare RNTO — it is
    the right one.  #135 is that the reply BELOW it is dead, and a reader of
    brix_ftp_ev_cmd_rnto would reasonably believe a read-only export answers 550
    to a paired RNTO.

    Not that a refusal must be logged at `[error]`.  #134 is that it is logged at
    NO level: the file's measurement is against `info`, which is what
    configs/nginx_audit16ai_gridftp_write_gate.conf sets.

HOW THE PLANES WORK
    The directive is NGX_STREAM_SRV_CONF|NGX_CONF_FLAG (ftp_module.c:222), so a
    plane is a `listen` and not a location, and
    configs/nginx_audit16ai_gridftp_write_gate.conf stands four of them plus one
    HTTP /metrics face in one process:

        G_ON   `allow_write on`     the control — every gated verb must succeed
        G_OFF  `allow_write off`    the never-written token
        G_ABS  the line deleted     what nginx_gridftp_plain_ev_ro.conf renders
        G_VER  `off` + `verify_write on`   the inert companion, §I

    Each has its OWN export subtree.  The gate is the only thing between a
    client and the tree, so a shared root would make one face's refused mutation
    indistinguishable from another face's successful one — and the whole file is
    about which face let what through.

    The metrics zone is process-wide, so the HTTP face reads the counters all
    four gateways feed; that is the only way to see #134's asymmetry inside one
    scrape.
"""

import ftplib
import os
import re
import socket
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from metrics_helpers import value as metric_value
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST

NAME = "lc-audit16ai-ftpwrite"
_L = LIFECYCLE_SHARED_PORTS[NAME]

G_ON = _L["port"]
G_OFF = _L["extra"]["OFF_PORT"]
G_ABS = _L["extra"]["ABS_PORT"]
G_VER = _L["extra"]["VER_PORT"]
HTTP_PORT = _L["extra"]["HTTP_PORT"]

# The export subtree each face is rooted at, by the name the face is known by.
SUBTREE = {"on": "on", "off": "off", "absent": "abs", "verify": "ver"}

# The pair §A exists to compare: the written token against the omission it has
# always stood in for.
DISARMED = (("off", G_OFF), ("absent", G_ABS))

# Every disabled face, including the one carrying the inert companion — §A's
# equality is worth stating three-wide, because a companion knob that changed a
# refusal would be a different bug from a companion knob that did nothing.
ALL_DISARMED = DISARMED + (("verify", G_VER),)

TIMEOUT = 30

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Gateways:
    """Four gateways over four exports plus one /metrics face, by port."""

    def __init__(self, instance, root):
        self.instance = instance
        self.root = Path(root)
        self.metrics_url = f"http://{SERVER_HOST}:{HTTP_PORT}/metrics"

    def export(self, face):
        """The on-disk root the named face serves."""
        return self.root / SUBTREE[face]

    def errlog_path(self):
        return Path(self.instance.prefix) / "logs" / "error.log"

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        log = self.errlog_path()
        return log.read_text(errors="replace") if log.exists() else ""

    def errlog_size(self):
        log = self.errlog_path()
        return log.stat().st_size if log.exists() else 0

    def errlog_since(self, offset):
        """The bytes appended since `offset` — the whole of what a cell's own
        dialogue caused the server to say."""
        log = self.errlog_path()
        if not log.exists():
            return ""
        with log.open(errors="replace") as fh:
            fh.seek(offset)
            return fh.read()

    def scrape(self):
        """Raw /metrics text.

        metrics_helpers.fetch() is pinned to the session fleet's exporter; this
        instance owns its own, so only the GET is local — the parsing is the
        shared metrics_helpers.value.
        """
        import urllib.request
        with urllib.request.urlopen(self.metrics_url, timeout=TIMEOUT) as resp:
            return resp.read().decode()

    def ops(self, text, op, status):
        return metric_value(text, "brix_io_ops_total",
                            {"proto": "gridftp", "op": op, "status": status})

    def gridftp_rows(self, text):
        """Every {proto="gridftp"} sample as {series: value}.

        §D's claim is about the WHOLE plane — "no op row moved" — so it needs the
        set of series, not a named one.
        """
        rows = {}
        for line in text.splitlines():
            if line.startswith("#") or 'proto="gridftp"' not in line:
                continue
            series, _, value = line.rpartition(" ")
            rows[series] = value
        return rows


@pytest.fixture(scope="module")
def gw(tmp_path_factory):
    """MODULE-scoped with its own harness, for the reason files 27-34 give: the
    ports are fixed by the ledger, so a per-test start/stop races the OS
    releasing them.

    Every cell seeds its own fixtures under its own face's export and names them
    after itself, so the four subtrees need no cleanup between cells and a rerun
    cannot read the previous run's bytes.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("audit16ai") / "exports"
    for sub in SUBTREE.values():
        (root / sub).mkdir(parents=True)

    harness = LifecycleHarness()
    try:
        instance = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16ai_gridftp_write_gate.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(root),
            template_values={"BIND_HOST": BIND_HOST},
            reason="audit-16ai brix_gridftp_allow_write — the write gate whose "
                   "disarming token no config in the tree writes, against the "
                   "omission that has always stood in for it."))
        yield _Gateways(instance, root)
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# FTP helpers — a real client's dialogue, not ftplib's convenience API          #
# --------------------------------------------------------------------------- #

def _connect(port):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, port, timeout=TIMEOUT)
    ftp.login()
    ftp.sendcmd("TYPE I")
    return ftp


def _cmd(ftp, command):
    """One command, one reply, as the raw reply string.

    ftplib raises on 4xx/5xx and every cell here has a refusal case, so the reply
    is what the helper returns rather than an exception the caller re-derives.
    """
    try:
        return ftp.sendcmd(command)
    except ftplib.Error as exc:
        return str(exc)


def _code(reply):
    return int(reply[:3])


def _one(port, command):
    """A command on its own connection.  Used wherever a cell's claim is about a
    verb in isolation and a preceding verb could have changed the answer."""
    ftp = _connect(port)
    try:
        return _cmd(ftp, command)
    finally:
        ftp.close()


def _sequence(port, commands):
    """Several commands on ONE control connection, replies in order.

    RNFR/RNTO is a pairing carried on the connection, so the two cannot be split
    across sockets and still be the thing under test.
    """
    ftp = _connect(port)
    try:
        return [_cmd(ftp, c) for c in commands]
    finally:
        ftp.close()


def _stor(port, name, payload, verb="STOR"):
    """A stream-mode STOR (or APPE) closing the data channel after exactly
    len(payload) bytes.

    A raw PASV socket rather than ftplib.storbinary, for the reason file 31
    gives: the completion signal IS the close, so the close has to be the test's
    to make.  Returns the completion code — or the refusal code, when the verb
    never got as far as a data channel.
    """
    ftp = _connect(port)
    try:
        host, dport = ftp.makepasv()
        data = socket.create_connection((host, dport), timeout=TIMEOUT)
        try:
            ftp.putcmd(f"{verb} {name}")
            try:
                resp = ftp.getresp()
            except ftplib.Error as exc:
                return int(str(exc)[:3])        # refused before any data
            if not resp.startswith("150"):
                return int(resp[:3])
            data.sendall(payload)
            data.shutdown(socket.SHUT_WR)
            try:
                return int(ftp.getresp()[:3])
            except ftplib.Error as exc:
                return int(str(exc)[:3])
        finally:
            data.close()
    finally:
        ftp.close()


def _retr(port, name):
    """RETR to EOF.  Returns (completion code, bytes)."""
    ftp = _connect(port)
    try:
        host, dport = ftp.makepasv()
        data = socket.create_connection((host, dport), timeout=TIMEOUT)
        try:
            ftp.putcmd("RETR " + name)
            try:
                resp = ftp.getresp()
            except ftplib.Error as exc:
                return int(str(exc)[:3]), b""
            if not resp.startswith("150"):
                return int(resp[:3]), b""
            buf = b""
            while True:
                chunk = data.recv(65536)
                if not chunk:
                    break
                buf += chunk
            try:
                return int(ftp.getresp()[:3]), buf
            except ftplib.Error as exc:
                return int(str(exc)[:3]), buf
        finally:
            data.close()
    finally:
        ftp.close()


def _uid(request):
    """A name unique to the calling cell, so no cleanup is needed and a rerun
    cannot see the previous run's tree."""
    return (request.node.name.replace("[", "_").replace("]", "")
            .replace("/", "_").replace(" ", "_"))


def _seed_file(gw, face, name, body=b"gridftp write-gate payload\n"):
    path = gw.export(face) / name
    path.write_bytes(body)
    os.chmod(path, 0o644)
    return path


def _seed_dir(gw, face, name):
    path = gw.export(face) / name
    path.mkdir()
    return path


# The seven verbs the gate governs, as (label, how to seed, how to fire, the
# refusal a disabled face gives).  The refusal strings are the C's, verbatim:
# ftp_ev_cmd.c's three ns_mutate verbs and RNFR share one, RNTO is the 503 #135
# is about, and ev_xfer_guards has its own.
NS_VERBS = (
    ("MKD", "none", "MKD /{n}", "550 Permission denied (read-only)"),
    ("XMKD", "none", "XMKD /{n}", "550 Permission denied (read-only)"),
    ("DELE", "file", "DELE /{n}", "550 Permission denied (read-only)"),
    ("RMD", "dir", "RMD /{n}", "550 Permission denied (read-only)"),
    ("XRMD", "dir", "XRMD /{n}", "550 Permission denied (read-only)"),
    ("RNFR", "file", "RNFR /{n}", "550 Permission denied (read-only)"),
)


def _seed_for(gw, face, kind, name):
    if kind == "file":
        _seed_file(gw, face, name)
    elif kind == "dir":
        _seed_dir(gw, face, name)


# --------------------------------------------------------------------------- #
# A. The written `off` against its omission                                    #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("verb,seed,template,refusal", NS_VERBS,
                         ids=[v[0] for v in NS_VERBS])
class TestTheWrittenOffEqualsItsOmission:
    """`brix_gridftp_allow_write off` written out, against the same server with
    the line deleted, verb by verb.

    This is the claim the corpus has rested on without making it: every
    "read-only gateway" in the tree is read-only by omission, and the merge
    default is the only reason it is.  `ngx_conf_merge_value` is reached only
    with the slot still NGX_CONF_UNSET, so the two spellings are genuinely
    different paths through ftp_module_merge.c:159 — which is what makes the
    equality a measurement rather than a restatement.
    """

    def test_the_two_disarmed_planes_answer_identically(self, gw, request,
                                                        verb, seed, template,
                                                        refusal):
        name = _uid(request)
        replies = {}
        for label, port in DISARMED:
            _seed_for(gw, label, seed, name)
            replies[label] = _one(port, template.format(n=name))
        assert replies["off"] == replies["absent"], replies

    def test_the_refusal_is_the_string_the_c_carries(self, gw, request, verb,
                                                     seed, template, refusal):
        """Equality alone would be satisfied by two planes that both broke the
        same way, so the shared answer is pinned to the literal in the source."""
        name = _uid(request)
        for label, port in DISARMED:
            _seed_for(gw, label, seed, name)
            reply = _one(port, template.format(n=name))
            assert reply.startswith(refusal), (label, reply)

    def test_neither_disarmed_plane_touched_its_export(self, gw, request, verb,
                                                       seed, template, refusal):
        """The half a reply-code comparison cannot make: a plane that answered
        550 and mutated anyway would pass every cell above."""
        name = _uid(request)
        for label, port in DISARMED:
            _seed_for(gw, label, seed, name)
            before = sorted(p.name for p in gw.export(label).iterdir())
            _one(port, template.format(n=name))
            after = sorted(p.name for p in gw.export(label).iterdir())
            assert before == after, (label, before, after)


class TestTheWrittenOffEqualsItsOmissionForTheTransferVerbs:
    """STOR and APPE, which are refused at the OTHER call site
    (ev_xfer_guards) and carry the other refusal string.

    Split from the parametrized class above because a transfer verb needs a data
    channel and the namespace verbs do not — and because §D's whole subject is
    that these two are the only gated verbs that meter anything.
    """

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_the_two_disarmed_planes_refuse_identically(self, gw, request, verb):
        name = _uid(request) + ".bin"
        codes = {label: _stor(port, "/" + name, b"x" * 512, verb=verb)
                 for label, port in DISARMED}
        assert codes["off"] == codes["absent"] == 550, codes

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_no_object_appears_on_either_disarmed_export(self, gw, request,
                                                         verb):
        name = _uid(request) + ".bin"
        for label, port in DISARMED:
            _stor(port, "/" + name, b"x" * 512, verb=verb)
            assert not (gw.export(label) / name).exists(), label

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_the_refusal_names_the_export_and_not_the_path(self, gw, request,
                                                           verb):
        """ev_xfer_guards' string differs from ns_mutate's by one word —
        "(read-only export)" against "(read-only)" — and that word is the only
        thing on the wire that tells an operator which of the two call sites
        refused.  If they are ever unified, this cell says so."""
        name = _uid(request) + ".bin"
        ftp = _connect(G_OFF)
        try:
            ftp.putcmd("STOR /" + name)
            reply = ftp.getresp()
        except ftplib.Error as exc:
            reply = str(exc)
        finally:
            ftp.close()
        assert reply.startswith("550 Permission denied (read-only export)"), reply


class TestTheInertCompanionChangesNothing:
    """The G_VER face — `allow_write off` beside `verify_write on` — answers
    every gated verb exactly as the two plain disabled faces do.

    #137 is that the composition is accepted; this is that it is also inert.  A
    verify knob that changed a refusal would be a worse bug than a verify knob
    that does nothing, so the equality is stated three-wide rather than two.
    """

    @pytest.mark.parametrize("verb,seed,template,refusal", NS_VERBS,
                             ids=[v[0] for v in NS_VERBS])
    def test_all_three_disarmed_planes_answer_identically(self, gw, request,
                                                          verb, seed, template,
                                                          refusal):
        name = _uid(request)
        replies = {}
        for label, port in ALL_DISARMED:
            _seed_for(gw, label, seed, name)
            replies[label] = _one(port, template.format(n=name))
        assert len(set(replies.values())) == 1, replies
        assert replies["verify"].startswith(refusal), replies

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_the_verify_plane_refuses_transfers_too(self, gw, request, verb):
        name = _uid(request) + ".bin"
        assert _stor(G_VER, "/" + name, b"x" * 512, verb=verb) == 550
        assert not (gw.export("verify") / name).exists()


# --------------------------------------------------------------------------- #
# B. The armed control                                                         #
# --------------------------------------------------------------------------- #

class TestTheArmedGateLetsEveryGovernedVerbThrough:
    """The positive half, in the same process, so §A is a statement about the
    flag and not about the build.

    Without these cells a gateway that refused MKD for some unrelated reason
    would satisfy every equality above.
    """

    def test_mkd_creates_a_directory(self, gw, request):
        name = _uid(request)
        reply = _one(G_ON, f"MKD /{name}")
        assert reply.startswith("257"), reply
        assert (gw.export("on") / name).is_dir()

    def test_xmkd_creates_a_directory(self, gw, request):
        name = _uid(request)
        assert _code(_one(G_ON, f"XMKD /{name}")) == 257
        assert (gw.export("on") / name).is_dir()

    def test_dele_removes_a_file(self, gw, request):
        name = _uid(request)
        path = _seed_file(gw, "on", name)
        reply = _one(G_ON, f"DELE /{name}")
        assert reply.startswith("250"), reply
        assert not path.exists()

    @pytest.mark.parametrize("verb", ("RMD", "XRMD"))
    def test_rmd_removes_a_directory(self, gw, request, verb):
        name = _uid(request)
        path = _seed_dir(gw, "on", name)
        reply = _one(G_ON, f"{verb} /{name}")
        assert reply.startswith("250"), reply
        assert not path.exists()

    def test_rnfr_rnto_renames(self, gw, request):
        name = _uid(request)
        src = _seed_file(gw, "on", name, b"rename me\n")
        replies = _sequence(G_ON, [f"RNFR /{name}", f"RNTO /{name}-moved"])
        assert replies[0].startswith("350"), replies
        assert replies[1].startswith("250"), replies
        assert not src.exists()
        assert (gw.export("on") / f"{name}-moved").read_bytes() == b"rename me\n"

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_a_transfer_commits(self, gw, request, verb):
        name = _uid(request) + ".bin"
        payload = os.urandom(2048)
        assert _stor(G_ON, "/" + name, payload, verb=verb) == 226
        assert (gw.export("on") / name).read_bytes() == payload

    def test_the_control_writes_land_in_its_own_export(self, gw, request):
        """Four exports under one data root, and the gate is the only thing
        keeping a write on the writable one — so the neighbour check is part of
        the control, not decoration."""
        name = _uid(request) + ".bin"
        assert _stor(G_ON, "/" + name, b"y" * 64) == 226
        for face in ("off", "absent", "verify"):
            assert not (gw.export(face) / name).exists(), face


# --------------------------------------------------------------------------- #
# C. What the runtime says it merged                                           #
# --------------------------------------------------------------------------- #

class TestTheSessionLineReportsTheMergedFlag:
    """ftp_ev_io.c:292 logs `session start (export=%s write=%d)` — the ONE place
    in the whole system where the merged value of the flag is observable without
    provoking it.

    It is at `[info]`, which is a level no production deployment runs, so in
    practice an operator cannot tell a read-only gateway from a writable one
    except by trying to write to it.  That is a smaller finding than #134 and is
    stated here rather than numbered, because the line does exist and does carry
    the right value.
    """

    @pytest.mark.parametrize("face,port,expected", (("on", G_ON, 1),
                                                    ("off", G_OFF, 0),
                                                    ("absent", G_ABS, 0),
                                                    ("verify", G_VER, 0)))
    def test_the_line_carries_the_value_the_face_was_configured_with(
            self, gw, face, port, expected):
        offset = gw.errlog_size()
        ftp = _connect(port)
        ftp.close()
        text = gw.errlog_since(offset)
        lines = [ln for ln in text.splitlines() if "gateway session start" in ln]
        assert lines, text
        assert f"write={expected}" in lines[-1], lines[-1]

    def test_the_written_off_and_the_omission_log_the_same_value(self, gw):
        """The merge default, read off the runtime rather than off the source:
        `write=0` on both, which is the whole of §A's premise in one line."""
        values = {}
        for label, port in DISARMED:
            offset = gw.errlog_size()
            ftp = _connect(port)
            ftp.close()
            text = gw.errlog_since(offset)
            match = re.search(r"gateway session start \(export=\S+ write=(\d)\)",
                              text)
            assert match, text
            values[label] = match.group(1)
        assert values["off"] == values["absent"] == "0", values

    def test_the_line_names_the_export_the_face_serves(self, gw):
        """Four faces, four subtrees: the same line that carries the flag also
        proves the plane under test is the plane that answered."""
        offset = gw.errlog_size()
        ftp = _connect(G_OFF)
        ftp.close()
        text = gw.errlog_since(offset)
        assert f"export={gw.export('off')} write=0" in text, text


# --------------------------------------------------------------------------- #
# D. DEFECT CANDIDATE #134 — the metric asymmetry                              #
# --------------------------------------------------------------------------- #

class TestARefusedTransferIsMeteredAndARefusedMutationIsNot:
    """ev_xfer_guards meters its permission verdict; the other three call sites
    do not meter theirs.

    The comment above ev_xfer_guards explains what it does NOT meter and why —
    "protocol misuse ... the verb never became an operation" — which is a good
    reason that does not apply to MKD, DELE, RMD, RNFR or RNTO.  Each of those
    IS a requested operation with an authorization outcome, and each books
    nothing.
    """

    def test_a_refused_stor_books_a_forbidden_write(self, gw, request):
        before = gw.scrape()
        assert _stor(G_OFF, "/" + _uid(request) + ".bin", b"z" * 128) == 550
        after = gw.scrape()
        assert (gw.ops(after, "write", "forbidden")
                - gw.ops(before, "write", "forbidden")) == 1

    def test_a_refused_appe_books_one_too(self, gw, request):
        before = gw.scrape()
        assert _stor(G_OFF, "/" + _uid(request) + ".bin", b"z" * 128,
                     verb="APPE") == 550
        after = gw.scrape()
        assert (gw.ops(after, "write", "forbidden")
                - gw.ops(before, "write", "forbidden")) == 1

    @pytest.mark.parametrize("verb,seed,template,refusal", NS_VERBS,
                             ids=[v[0] for v in NS_VERBS])
    def test_a_refused_namespace_verb_books_nothing_at_all(self, gw, request,
                                                           verb, seed, template,
                                                           refusal):
        """Not `forbidden` under another op name, not `ok`, not `io` — nothing.

        The comparison is over the whole {proto="gridftp"} plane rather than a
        named series, because "the refusal was booked somewhere else" and "the
        refusal was not booked" are different worlds and only the second one is
        the finding.
        """
        name = _uid(request)
        _seed_for(gw, "off", seed, name)
        before = gw.gridftp_rows(gw.scrape())
        reply = _one(G_OFF, template.format(n=name))
        assert reply.startswith(refusal), reply
        after = gw.gridftp_rows(gw.scrape())

        moved = {k: (before.get(k), after.get(k))
                 for k in set(before) | set(after)
                 if before.get(k) != after.get(k)}
        # The login books an auth row; nothing else may move.
        moved.pop('brix_auth_total{proto="gridftp",method="none",status="ok"}',
                  None)
        assert moved == {}, moved

    def test_seven_refusals_in_one_session_book_two_rows(self, gw, request):
        """The finding in one cell: a client that tries every gated verb once
        leaves a trace of exactly the two the transfer path meters.

        This is what a metrics-based alert on a read-only export would see — two
        `write/forbidden` increments out of nine refusals — and it is why an
        operator watching {proto="gridftp"} cannot distinguish a client probing
        for a writable path from one that never tried.
        """
        name = _uid(request)
        _seed_file(gw, "off", name)
        _seed_dir(gw, "off", name + "-d")

        before = gw.scrape()
        replies = _sequence(G_OFF, [f"MKD /{name}-a", f"XMKD /{name}-b",
                                    f"DELE /{name}", f"RMD /{name}-d",
                                    f"XRMD /{name}-d", f"RNFR /{name}",
                                    f"RNTO /{name}-x"])
        assert all(r[:3] in ("550", "503") for r in replies), replies
        _stor(G_OFF, f"/{name}.bin", b"q" * 32)
        _stor(G_OFF, f"/{name}.bin", b"q" * 32, verb="APPE")
        after = gw.scrape()

        rows_before, rows_after = gw.gridftp_rows(before), gw.gridftp_rows(after)
        ops_moved = {k for k in set(rows_before) | set(rows_after)
                     if k.startswith("brix_io_ops_total")
                     and rows_before.get(k) != rows_after.get(k)}
        assert ops_moved == {
            'brix_io_ops_total{proto="gridftp",op="write",status="forbidden"}'
        }, ops_moved
        assert (gw.ops(after, "write", "forbidden")
                - gw.ops(before, "write", "forbidden")) == 2


# --------------------------------------------------------------------------- #
# E. DEFECT CANDIDATE #134, second half — the log says nothing either          #
# --------------------------------------------------------------------------- #

class TestNoRefusalIsLoggedAtAnyLevel:
    """The template sets `error_log ... info`, the most verbose level an
    operator can practically run, and a refusal produces no line at it.

    A metric that does not move and a log that says nothing are the same finding
    from two directions, and the second is the one that matters to an incident
    responder: after the fact, there is no record that the attempt happened.
    """

    @pytest.mark.parametrize("verb,seed,template,refusal", NS_VERBS,
                             ids=[v[0] for v in NS_VERBS])
    def test_a_refused_namespace_verb_leaves_no_line(self, gw, request, verb,
                                                     seed, template, refusal):
        name = _uid(request)
        _seed_for(gw, "off", seed, name)
        offset = gw.errlog_size()
        reply = _one(G_OFF, template.format(n=name))
        assert reply.startswith(refusal), reply

        text = gw.errlog_since(offset)
        session = ("connected to", "gateway session start",
                   "gateway session end")
        residue = [ln for ln in text.splitlines()
                   if ln.strip() and not any(tag in ln for tag in session)]
        assert residue == [], residue

    def test_a_refused_stor_leaves_no_line_either(self, gw, request):
        """The metered path is no better logged than the unmetered ones, so the
        two halves of #134 do not cancel: nothing anywhere names the refusal."""
        offset = gw.errlog_size()
        assert _stor(G_OFF, "/" + _uid(request) + ".bin", b"z" * 64) == 550
        text = gw.errlog_since(offset)
        assert "denied" not in text.lower(), text
        assert "forbidden" not in text.lower(), text
        assert "read-only" not in text.lower(), text

    def test_the_writable_face_does_log_its_mutations(self, gw, request):
        """The control that makes the silence a finding rather than a property
        of the log: a SUCCESSFUL mkdir on the armed face writes a
        brix_access_json line naming the op, the path and the status."""
        name = _uid(request)
        offset = gw.errlog_size()
        assert _code(_one(G_ON, f"MKD /{name}")) == 257
        text = gw.errlog_since(offset)
        assert "brix_access_json" in text, text
        assert '"op":"mkdir"' in text, text
        assert '"status":"ok"' in text, text

    def test_the_refused_mkdir_produces_no_access_json(self, gw, request):
        """Stated against the cell above: the access log is where a refusal
        would naturally go, and phase-97 §5's "success path only" rule for the
        CNS emitter has, in effect, been applied to the audit record too."""
        name = _uid(request)
        offset = gw.errlog_size()
        assert _one(G_OFF, f"MKD /{name}").startswith("550"), name
        assert "brix_access_json" not in gw.errlog_since(offset)


# --------------------------------------------------------------------------- #
# F. DEFECT CANDIDATE #135 — RNTO's permission branch is unreachable           #
# --------------------------------------------------------------------------- #

class TestRntoNeverReachesItsOwnPermissionCheck:
    """brix_ftp_ev_cmd_rnto tests `rnfr_set` and consumes it BEFORE it tests
    `allow_write`.  `rnfr_set` is set in one place — the tail of
    brix_ftp_ev_cmd_rnfr — which is behind the same gate.

    So on a read-only export the second check is dead: no dialogue can arrive at
    RNTO with a pairing armed.  The cells below try the three shapes a client
    could use to arm one and measure that none does.
    """

    def test_a_bare_rnto_is_503_and_not_550(self, gw, request):
        reply = _one(G_OFF, f"RNTO /{_uid(request)}")
        assert reply.startswith("503 RNFR required first"), reply

    def test_rnfr_then_rnto_is_still_503(self, gw, request):
        """The pairing a client would actually send.  RNFR is refused, so it
        never sets `rnfr_set`, so RNTO answers as though RNFR had not been sent
        — which is true, and is why the 550 below it is unreachable."""
        name = _uid(request)
        _seed_file(gw, "off", name)
        replies = _sequence(G_OFF, [f"RNFR /{name}", f"RNTO /{name}-moved"])
        assert replies[0].startswith("550 Permission denied (read-only)"), replies
        assert replies[1].startswith("503 RNFR required first"), replies
        assert (gw.export("off") / name).exists()
        assert not (gw.export("off") / f"{name}-moved").exists()

    def test_a_repeated_rnfr_rnto_pair_does_not_arm_it(self, gw, request):
        """The one shape that could in principle differ: state left by a first
        failed pairing changing the answer to a second.  It does not — the
        refusal is before every assignment to `rnfr_set`."""
        name = _uid(request)
        _seed_file(gw, "off", name)
        replies = _sequence(G_OFF, [f"RNFR /{name}", f"RNTO /{name}-1",
                                    f"RNFR /{name}", f"RNTO /{name}-2"])
        assert [r[:3] for r in replies] == ["550", "503", "550", "503"], replies

    def test_the_armed_face_proves_the_dead_line_is_the_only_difference(
            self, gw, request):
        """On the writable face the same dialogue reaches RNTO with the pairing
        armed and renames — so `rnfr_set` is reachable, and it is the GATE on
        RNFR, not a broken pairing, that makes the RNTO check dead."""
        name = _uid(request)
        _seed_file(gw, "on", name)
        replies = _sequence(G_ON, [f"RNFR /{name}", f"RNTO /{name}-moved"])
        assert replies[0].startswith("350"), replies
        assert replies[1].startswith("250"), replies

    def test_a_bare_rnto_on_the_armed_face_is_also_503(self, gw, request):
        """The pairing check itself is not the finding and behaves the same on
        both faces; without this cell the 503 in the first case could be read as
        a read-only artefact."""
        assert _one(G_ON, f"RNTO /{_uid(request)}").startswith("503"), "armed"


# --------------------------------------------------------------------------- #
# G. Ordering — the verdict is reached before the data channel is              #
# --------------------------------------------------------------------------- #

class TestThePermissionVerdictPrecedesTheDataChannelCheck:
    """ev_xfer_guards tests `allow_write` first and `fc->active || pasv_fd` second,
    so a STOR with no data channel is answered 550 on a read-only export and 425
    on a writable one.

    Worth pinning: the order is what stops a probe from distinguishing "no data
    channel" from "no permission", and reversing it would leak the export's
    writability to a client that never opened a data connection.
    """

    def test_a_storless_data_channel_is_refused_on_permission(self, gw, request):
        ftp = _connect(G_OFF)
        try:
            reply = _cmd(ftp, "STOR /" + _uid(request) + ".bin")
        finally:
            ftp.close()
        assert reply.startswith("550 Permission denied (read-only export)"), reply

    def test_the_armed_face_answers_425_to_the_same_command(self, gw, request):
        """The control, and the reason the cell above is about ordering rather
        than about STOR: with the gate open the SECOND check is what fires."""
        ftp = _connect(G_ON)
        try:
            reply = _cmd(ftp, "STOR /" + _uid(request) + ".bin")
        finally:
            ftp.close()
        assert reply.startswith("425 Use PASV or PORT first"), reply

    @pytest.mark.parametrize("verb", ("PASV", "EPSV"))
    def test_a_read_only_export_still_opens_a_data_listener(self, gw, verb):
        """PASV is not gated — a read-only export binds a listener for a client
        that has no verb to use it for.  Not a defect (RETR needs it), but it is
        the reason the ordering above is load-bearing: the listener's existence
        says nothing about writability, and the 550 must not either."""
        ftp = _connect(G_OFF)
        try:
            reply = _cmd(ftp, verb)
        finally:
            ftp.close()
        assert reply[:3] in ("227", "229"), reply


# --------------------------------------------------------------------------- #
# H. What the gate does not cover                                              #
# --------------------------------------------------------------------------- #

class TestTheUngatedVerbsAnswerTheSameOnBothFaces:
    """The read side and the transfer-parameter verbs are outside the gate, and
    must be: a read-only export that could not be read would be useless.

    Stated explicitly so that a future change which put one of them behind the
    flag is a failure here rather than a surprise in the field.
    """

    def test_retr_serves_a_file_from_a_read_only_export(self, gw, request):
        name = _uid(request)
        payload = b"readable\n" * 16
        _seed_file(gw, "off", name, payload)
        code, body = _retr(G_OFF, "/" + name)
        assert code == 226, code
        assert body == payload

    def test_size_and_mdtm_answer(self, gw, request):
        name = _uid(request)
        _seed_file(gw, "off", name, b"1234567890")
        replies = _sequence(G_OFF, [f"SIZE /{name}", f"MDTM /{name}"])
        assert replies[0] == "213 10", replies
        assert replies[1].startswith("213 "), replies

    @pytest.mark.parametrize("command,prefix", (("ALLO 1048576", "200"),
                                                ("REST 5", "350"),
                                                ("MODE E", "200"),
                                                ("TYPE I", "200"),
                                                ("SYST", "215"),
                                                ("NOOP", "200"),
                                                ("PWD", "257")))
    def test_a_transfer_parameter_verb_is_ungated(self, gw, command, prefix):
        assert _one(G_OFF, command).startswith(prefix), command

    def test_cksm_is_ungated(self, gw, request):
        """A checksum is a read, and the gate does not cover it — which also
        means it is available on the face whose `verify_write` can never fire."""
        name = _uid(request)
        _seed_file(gw, "off", name, b"checksum me\n")
        reply = _one(G_OFF, f"CKSM ADLER32 0 -1 /{name}")
        assert reply.startswith("213 "), reply

    def test_feat_does_not_advertise_writability(self, gw):
        """FEAT is identical on both faces, so a client cannot learn from the
        capability list whether the export will accept a STOR — it has to try,
        and trying is what #134 says nobody records."""
        on = _one(G_ON, "FEAT")
        off = _one(G_OFF, "FEAT")
        assert on == off, (on, off)


class TestSiteAnswersOkToEverything:
    """DEFECT CANDIDATE #136 — ev_grp_session's SITE arm
    (ftp_ev_dispatch.c:259) is a bare `200 OK` with the argument never read.

    The gate is not bypassed: nothing happens.  What is wrong is the reply — a
    client that issues `SITE CHMOD 000` against a read-only export is told the
    mutation succeeded.
    """

    def test_site_chmod_is_answered_ok_on_a_read_only_export(self, gw, request):
        name = _uid(request)
        _seed_file(gw, "off", name)
        assert _one(G_OFF, f"SITE CHMOD 000 /{name}") == "200 OK"

    def test_and_the_mode_is_unchanged(self, gw, request):
        """The second half, and the one that makes it a reply bug rather than a
        gate bypass."""
        name = _uid(request)
        path = _seed_file(gw, "off", name)
        _one(G_OFF, f"SITE CHMOD 000 /{name}")
        assert (path.stat().st_mode & 0o777) == 0o644

    def test_the_armed_face_answers_ok_and_changes_nothing_either(self, gw,
                                                                  request):
        """SITE is unimplemented, not gated — so the finding is about the reply
        on every face, and an operator cannot use `allow_write on` to make
        `SITE CHMOD` work."""
        name = _uid(request)
        path = _seed_file(gw, "on", name)
        assert _one(G_ON, f"SITE CHMOD 000 /{name}") == "200 OK"
        assert (path.stat().st_mode & 0o777) == 0o644

    @pytest.mark.parametrize("argument", ("HELP", "UMASK 022", "EXEC /bin/sh",
                                          "NONSENSE", ""))
    def test_every_site_argument_gets_the_same_answer(self, gw, argument):
        """Including ones no server should accept.  `SITE EXEC` is the classic
        wu-ftpd remote-execution verb; answering it `200 OK` executes nothing
        here, but it tells a scanner the verb is supported."""
        assert _one(G_OFF, ("SITE " + argument).strip()) == "200 OK", argument


# --------------------------------------------------------------------------- #
# I. Security-negative                                                         #
# --------------------------------------------------------------------------- #

class TestAReadOnlyExportIsNotEscapable:
    """Invariant 4's resolve_path runs before every open, and the gate runs
    before resolve_path — so a traversal aimed at a mutation is refused by the
    gate and one aimed at a read is refused by the resolver.

    Both need saying: a reader who knows only §A might conclude that a
    read-only face is safe because nothing can be written, which says nothing
    about what can be read.
    """

    @pytest.mark.parametrize("escape", ("../../../../etc/passwd",
                                        "/etc/passwd",
                                        "..%2f..%2f..%2fetc%2fpasswd",
                                        "....//etc/passwd"))
    def test_a_traversal_read_is_refused(self, gw, escape):
        code, body = _retr(G_OFF, escape)
        assert code in (550, 553), (escape, code)
        assert b"root:x:" not in body, escape

    @pytest.mark.parametrize("escape", ("../../../../tmp",
                                        "/tmp",
                                        "..%2f..%2f..%2ftmp"))
    def test_a_traversal_mutation_is_refused_by_the_gate_first(self, gw, escape):
        """The gate is upstream of the resolver, so the refusal an escape gets
        is the PERMISSION one — the path is never resolved and the attempt is
        indistinguishable, on the wire, from a well-formed one."""
        reply = _one(G_OFF, f"MKD {escape}")
        assert reply.startswith("550 Permission denied (read-only)"), reply

    def test_a_traversal_mutation_on_the_armed_face_is_refused_by_the_resolver(
            self, gw, request):
        """The control: with the gate open the resolver is what refuses, and it
        does.  Without this cell §A could be satisfied by a build whose resolver
        had stopped working, since the gate would hide it."""
        reply = _one(G_ON, "MKD ../../../../tmp/" + _uid(request))
        assert reply[:3] in ("550", "553"), reply
        assert not Path("/tmp", _uid(request)).exists()

    def test_a_disarmed_export_cannot_be_written_through_a_symlink(self, gw,
                                                                   request):
        """A symlink inside the export pointing out of it — the shape that
        defeats a purely lexical path check.  The gate refuses before the link
        is ever followed, which is the right order."""
        name = _uid(request)
        target = gw.export("off") / (name + "-link")
        target.symlink_to("/tmp")
        reply = _one(G_OFF, f"MKD /{name}-link/{name}")
        assert reply.startswith("550 Permission denied (read-only)"), reply
        assert not Path("/tmp", name).exists()


# --------------------------------------------------------------------------- #
# J. Parse tier                                                                #
# --------------------------------------------------------------------------- #

FLAG = "brix_gridftp_allow_write"


def _parse(tmp_path, **slots):
    """`nginx -t` on the shared parse scaffold.

    configs/nginx_audit16jparse.conf is reused rather than copied, for the reason
    files 29-34 give: it writes the flag nowhere itself, so a duplicate negative
    can be sure the duplicate it is shown is the one it wrote.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "PORT2": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "BACKEND": f"posix:{data}",
              "KNOBS": "", "STREAM_KNOBS": "", "HTTP_KNOBS": "",
              "LOC_KNOBS": "", "OUTER": "", "EXTRA": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16jparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _diagnostics(out):
    """Only the lines nginx itself flagged: a tmp_path name can contain the token
    under test, so a substring search over the whole output would match the
    temp directory rather than a diagnostic."""
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


class TestBothArmsParse:
    """The parse half of §A's claim, in the scope the directive declares."""

    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_is_accepted_in_a_stream_server(self, tmp_path, arm):
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_draws_no_diagnostic(self, tmp_path, arm):
        """Accepted is not enough — §A's premise is that a written `off` is a
        normal thing to write, and a notice saying the line is redundant would
        be a different (and better) world."""
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {arm};\n")
        assert rc == 0 and _diagnostics(out) == [], _diagnostics(out)

    @pytest.mark.parametrize("arm", ("ON", "Off", '"on"'))
    def test_the_setter_is_case_insensitive_and_unquotes(self, tmp_path, arm):
        """ngx_conf_set_flag_slot compares case-insensitively and the tokenizer
        strips quotes, so all three are the same line.  Pinned because a config
        in the wild will eventually be written one of these ways."""
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {arm};\n")
        assert rc == 0, out

    def test_a_sibling_server_may_write_the_other_arm(self, tmp_path):
        """The whole config's shape: four gateways in one process, each with its
        own arm.  The scaffold's EXTRA slot is a whole second stream server, so
        this is the sibling question and not the scope one — nothing at parse
        time cross-validates two servers' arms against each other."""
        extra = ("    server {\n"
                 f"        listen {PARSE_PLACEHOLDER_PORT + 2};\n"
                 "        brix_root on;\n"
                 "        brix_auth none;\n"
                 f"        {FLAG} off;\n"
                 "    }\n")
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} on;\n", EXTRA=extra)
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)


class TestTheFlagRefusesWhatIsNotAFlag:
    """Arity and value.  `ngx_conf_set_flag_slot` produces both messages, and it
    names the DIRECTIVE as well as the value — unlike the enum setter, which
    names only the value.  Both halves are asserted, because the directive name
    is the whole of what makes the diagnostic actionable on a server carrying a
    dozen gridftp lines.
    """

    @pytest.mark.parametrize("value", ("1", "0", "yes", "no", "true", "false",
                                       "enable", '""'))
    def test_a_non_flag_value_is_refused_by_name(self, tmp_path, value):
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {value};\n")
        assert rc != 0, out
        assert f'in "{FLAG}" directive' in out, out
        assert 'it must be "on" or "off"' in out, out

    @pytest.mark.parametrize("line", (f"{FLAG};", f"{FLAG} on off;",
                                      f"{FLAG} on on;"))
    def test_a_wrong_arity_is_refused(self, tmp_path, line):
        rc, out = _parse(tmp_path, KNOBS=f"        {line}\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out
        assert FLAG in out, out

    @pytest.mark.parametrize("pair", (("on", "on"), ("off", "off"),
                                      ("on", "off")))
    def test_a_duplicate_is_refused_even_when_the_arms_agree(self, tmp_path,
                                                             pair):
        """Including the opposed pair, which is the one an operator would most
        want a diagnostic for — and gets the same generic one."""
        rc, out = _parse(tmp_path, KNOBS="".join(
            f"        {FLAG} {arm};\n" for arm in pair))
        assert rc != 0, out
        assert "is duplicate" in out, out


class TestTheFlagIsRefusedOutsideItsScope:
    """NGX_STREAM_SRV_CONF only: not `main`, not `events`, not the stream block
    itself, not an http location.

    A flag accepted in a scope that never reads it is the silently-ignored shape
    this tranche has found repeatedly; here the parser refuses all four.
    """

    @pytest.mark.parametrize("slot", ("OUTER", "STREAM_KNOBS", "HTTP_KNOBS",
                                      "LOC_KNOBS"))
    def test_a_foreign_scope_is_refused(self, tmp_path, slot):
        rc, out = _parse(tmp_path, **{slot: f"    {FLAG} on;\n"})
        assert rc != 0, out
        assert f'"{FLAG}" directive is not allowed here' in out, out


class TestTheCompanionKnobsAreNotCrossValidated:
    """DEFECT CANDIDATE #137 and its neighbours: three gridftp knobs that only
    have meaning on a writable export are accepted, without a word, beside
    `allow_write off`.

    The merge has every fact it needs to say so — all four flags are merged in
    the same function, ftp_module_merge.c:159-164 — and says nothing.
    """

    @pytest.mark.parametrize("companion", ("brix_gridftp_verify_write",
                                           "brix_gridftp_require_allo_size"))
    def test_a_write_only_knob_is_accepted_beside_a_closed_gate(self, tmp_path,
                                                               companion):
        rc, out = _parse(tmp_path, KNOBS=(f"        {FLAG} off;\n"
                                          f"        {companion} on;\n"))
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_both_companions_at_once_are_accepted_too(self, tmp_path):
        """The G_VER plane's shape, plus one — the composition is not merely
        unvalidated pairwise."""
        rc, out = _parse(tmp_path, KNOBS=(
            f"        {FLAG} off;\n"
            "        brix_gridftp_verify_write on;\n"
            "        brix_gridftp_require_allo_size on;\n"))
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_a_bogus_companion_value_is_still_refused_by_name(self, tmp_path):
        """The companion's own setter runs regardless, so the composition being
        unvalidated is about MEANING and not about parsing — a malformed
        companion is caught, an inert one is not."""
        rc, out = _parse(tmp_path, KNOBS=(
            f"        {FLAG} off;\n"
            "        brix_gridftp_verify_write bogus;\n"))
        assert rc != 0, out
        assert 'in "brix_gridftp_verify_write" directive' in out, out


# --------------------------------------------------------------------------- #
# K. DEFECT CANDIDATE #133 — the corpus's own claim about itself               #
# --------------------------------------------------------------------------- #

CONFIGS = Path(__file__).resolve().parent / "configs"


def _balanced_server_block(body, match):
    depth, index = 0, match.end() - 1
    while index < len(body):
        if body[index] == "{":
            depth += 1
        elif body[index] == "}":
            depth -= 1
            if depth == 0:
                break
        index += 1
    return body[match.start():index + 1]


def _server_block(body, needle):
    """The `server { ... }` whose text contains `needle`, brace-counted.

    A regex cannot do it: the template's own placeholders are braced, so
    `[^}]*` stops at `{RO_PORT}` rather than at the block's end.
    """
    for match in re.finditer(r"\bserver\s*\{", body):
        block = _balanced_server_block(body, match)
        if needle in block:
            return block
    return None


class TestTheCorpusDoesNotWriteTheTokenItDocuments:
    """Read off the tree rather than argued: which configs write the flag, and
    what the two read-only ones actually contain.

    A guard rather than a finding once it is fixed — the cells state the current
    truth and will fail the moment someone writes the token, which is the point.
    """

    def _bodies(self):
        return {p.name: p.read_text(errors="replace")
                for p in CONFIGS.glob("*.conf")}

    def test_no_config_but_this_file_s_own_writes_the_disarming_token(self):
        """The census that opened the file.  The template this suite renders is
        the exception, and is excluded by name so the cell keeps measuring the
        rest of the corpus."""
        mine = "nginx_audit16ai_gridftp_write_gate.conf"
        writers = sorted(
            name for name, body in self._bodies().items()
            if name != mine
            and re.search(rf"^\s*{FLAG}\s+off\s*;", body, re.MULTILINE))
        assert writers == [], writers

    def test_the_arming_token_is_written_widely(self):
        """The other half, so the cell above is a statement about the DISARMING
        arm and not about the directive being unused."""
        writers = [name for name, body in self._bodies().items()
                   if re.search(rf"^\s*{FLAG}\s+on\s*;", body, re.MULTILINE)]
        assert len(writers) >= 20, writers

    def test_the_metrics_config_documents_a_line_its_server_does_not_carry(self):
        """#133.  The header names the directive; the RO_PORT server block does
        not contain it.  The gateway is read-only by merge, so the suite that
        rests on it passes — which is how the mismatch survived."""
        body = (CONFIGS / "nginx_gridftp_metrics.conf").read_text()
        assert f"{FLAG} off" in body, "header no longer claims it"

        block = _server_block(body, "{RO_PORT}")
        assert block, body
        assert FLAG not in block, block

    def test_the_other_read_only_config_says_what_it_does(self):
        """The control: nginx_gridftp_plain_ev_ro.conf is read-only by omission
        too, and its header says so rather than claiming a line.  The two
        together are why #133 is about the comment and not about the
        omission."""
        body = (CONFIGS / "nginx_gridftp_plain_ev_ro.conf").read_text()
        assert not re.search(rf"^\s*{FLAG}", body, re.MULTILINE), body
        assert "allow_write" in body, "the header no longer explains itself"
